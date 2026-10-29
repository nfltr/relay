// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

package p2p

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// FrameType identifies the purpose of a framed message.
type FrameType string

const (
	FrameFile     FrameType = "file"      // single file transfer (header + body)
	FrameDir      FrameType = "dir"       // tar+gzip bundle of a directory
	FrameChat     FrameType = "chat"      // UTF-8 text message
	FrameAck      FrameType = "ack"       // transfer confirmed by receiver
	FrameErr      FrameType = "err"       // error from receiver
	FrameDone     FrameType = "done"      // all transfers finished
	FrameRTC      FrameType = "rtc"       // WebRTC signaling (SDP/ICE) relayed via Text field
	FrameRTCReady FrameType = "rtc-ready" // browser connected to local WS, ready for WebRTC
	FrameDataPath FrameType = "path"      // file data path the sender chose (Text: pathWebRTC or pathRelay)
)

// Frame is the on-wire header for every P2P message.  It is JSON-encoded,
// length-prefixed with a 4-byte big-endian uint32.
type Frame struct {
	Type FrameType `json:"type"`
	// File/dir fields
	Name   string `json:"name,omitempty"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	// Chat
	Text string `json:"text,omitempty"`
	// Ack / err
	Error string `json:"error,omitempty"`
	// Seq numbers signaling frames on a SignalConn (1, 2, …); the receiver
	// dedupes and orders by it. Unused on a byte-stream transfer.
	Seq uint64 `json:"seq,omitempty"`
}

// writeFrame encodes a Frame as a 4-byte length-prefixed JSON header.
// For file/dir frames the raw byte body follows immediately after — the
// caller must write exactly frame.Size additional bytes.
func writeFrame(w io.Writer, f *Frame) error {
	b, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("p2p: marshal frame: %w", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(b)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// readFrame reads a 4-byte length-prefixed JSON Frame.
func readFrame(r io.Reader) (*Frame, error) {
	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("p2p: read frame length: %w", err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n > 1<<20 { // 1 MiB header limit
		return nil, fmt.Errorf("p2p: frame header too large (%d bytes)", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("p2p: read frame header: %w", err)
	}
	var f Frame
	if err := json.Unmarshal(buf, &f); err != nil {
		return nil, fmt.Errorf("p2p: unmarshal frame: %w", err)
	}
	return &f, nil
}

// ProgressFunc is called periodically during a transfer with the number of
// bytes transferred so far and the total (0 = unknown).
type ProgressFunc func(transferred, total int64)

// SendFile sends a single file over an authenticated P2P net.Conn.
func SendFile(conn net.Conn, path string, progress ProgressFunc) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("p2p: open file: %w", err)
	}
	defer f.Close() //nolint:errcheck

	stat, err := f.Stat()
	if err != nil {
		return fmt.Errorf("p2p: stat file: %w", err)
	}

	// Compute SHA-256 for integrity.
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("p2p: hash file: %w", err)
	}
	checksum := hex.EncodeToString(h.Sum(nil))
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("p2p: seek: %w", err)
	}

	bw := bufio.NewWriterSize(conn, 64<<10)
	frame := &Frame{
		Type:   FrameFile,
		Name:   filepath.Base(path),
		Size:   stat.Size(),
		SHA256: checksum,
	}
	if err := writeFrame(bw, frame); err != nil {
		return err
	}

	pr := io.Reader(f)
	if progress != nil {
		pr = &progressReader{r: f, total: stat.Size(), fn: progress}
	}

	if _, err := io.Copy(bw, pr); err != nil {
		return fmt.Errorf("p2p: send file body: %w", err)
	}
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("p2p: flush: %w", err)
	}

	// Wait for ack.
	ackFrame, err := readFrame(conn)
	if err != nil {
		return fmt.Errorf("p2p: the file was sent but the receiver did not confirm it: %w", err)
	}
	if ackFrame.Type == FrameErr {
		return fmt.Errorf("p2p: receiver error: %s", ackFrame.Error)
	}
	if ackFrame.Type != FrameAck {
		return fmt.Errorf("p2p: unexpected frame type %q after send", ackFrame.Type)
	}
	return nil
}

// ReceiveFile reads a file sent by SendFile and writes it to outputDir.
// Returns the local path of the written file.
func ReceiveFile(conn net.Conn, outputDir string, progress ProgressFunc) (string, error) {
	frame, err := readFrame(conn)
	if err != nil {
		return "", err
	}
	if frame.Type != FrameFile {
		return "", fmt.Errorf("p2p: expected file frame, got %q", frame.Type)
	}

	// Sanitize file name — must not escape the output directory.
	name := filepath.Base(frame.Name)
	if name == "." || name == ".." || strings.Contains(name, "/") {
		return "", fmt.Errorf("p2p: unsafe file name %q", frame.Name)
	}

	outPath := filepath.Join(outputDir, name)
	out, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("p2p: create output file: %w", err)
	}
	defer out.Close() //nolint:errcheck

	h := sha256.New()
	w := io.MultiWriter(out, h)
	lr := io.LimitReader(conn, frame.Size)

	if progress != nil {
		lr = io.LimitReader(&progressReader{r: conn, total: frame.Size, fn: progress}, frame.Size)
	}

	if _, err := io.Copy(w, lr); err != nil {
		_ = os.Remove(outPath)
		return "", fmt.Errorf("p2p: receive file body: %w", err)
	}

	// Verify integrity.
	got := hex.EncodeToString(h.Sum(nil))
	if got != frame.SHA256 {
		_ = os.Remove(outPath)
		// Send error ack.
		_ = writeFrame(conn, &Frame{Type: FrameErr, Error: "sha256 mismatch"})
		return "", fmt.Errorf("p2p: integrity check failed (got %s, want %s)", got, frame.SHA256)
	}

	// Send success ack.
	if err := writeFrame(conn, &Frame{Type: FrameAck, Name: name}); err != nil {
		return outPath, fmt.Errorf("p2p: send ack: %w", err)
	}
	AwaitPeerClose(conn, ackDeliveryWait)
	return outPath, nil
}

// ackDeliveryWait bounds how long a receiver waits, after its ack, for the
// sender to close.
var ackDeliveryWait = 10 * time.Second

// AwaitPeerClose waits up to d for the peer to close conn (Read returns an
// error, io.EOF on a clean close), discarding what it reads. A receiver calls
// it after its ack: a sender closes only once it read the ack, so returning
// then means the ack was delivered. Without it a receiver that exited right
// after writing the ack could take the ack with it on the relay path (R3-G10:
// the file arrived intact, the sender exited 1 on "waiting for ack").
func AwaitPeerClose(conn net.Conn, d time.Duration) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(io.Discard, conn)
	}()
	select {
	case <-done:
	case <-time.After(d):
	}
}

// SendDir sends a directory as a gzip-compressed tar archive.
func SendDir(conn net.Conn, dirPath string, progress ProgressFunc) error {
	// Count files and compute size via a dry-run tar.
	var totalSize int64
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, werr error) error {
		if werr != nil {
			return werr
		}
		if !info.IsDir() {
			totalSize += info.Size()
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("p2p: walk dir: %w", err)
	}

	// Build tar+gzip in memory.  For large directories use os.Pipe to stream.
	pr, pw, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("p2p: pipe: %w", err)
	}

	errCh := make(chan error, 1)
	go func() {
		defer pw.Close() //nolint:errcheck
		gz := gzip.NewWriter(pw)
		tw := tar.NewWriter(gz)
		base := filepath.Base(dirPath)

		walkErr := filepath.Walk(dirPath, func(path string, info os.FileInfo, werr error) error {
			if werr != nil {
				return werr
			}
			rel, err := filepath.Rel(dirPath, path)
			if err != nil {
				return err
			}
			hdr := &tar.Header{
				Name:    filepath.Join(base, rel),
				ModTime: info.ModTime(),
				Mode:    int64(info.Mode()),
			}
			if info.IsDir() {
				hdr.Typeflag = tar.TypeDir
				hdr.Name += "/"
				return tw.WriteHeader(hdr)
			}
			hdr.Typeflag = tar.TypeReg
			hdr.Size = info.Size()
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close() //nolint:errcheck
			_, err = io.Copy(tw, f)
			return err
		})
		if walkErr == nil {
			walkErr = tw.Close()
		}
		if walkErr == nil {
			walkErr = gz.Close()
		}
		errCh <- walkErr
	}()

	// We don't know the exact archive size ahead of time, so use -1 to signal
	// streaming mode.  The receiver reads until EOF of the body.
	bw := bufio.NewWriterSize(conn, 64<<10)
	frame := &Frame{
		Type: FrameDir,
		Name: filepath.Base(dirPath),
		Size: -1, // streaming
	}
	if err := writeFrame(bw, frame); err != nil {
		pr.Close() //nolint:errcheck
		return err
	}
	if err := bw.Flush(); err != nil {
		pr.Close() //nolint:errcheck
		return err
	}

	// Stream archive.
	src := io.Reader(pr)
	if progress != nil {
		src = &progressReader{r: pr, total: totalSize, fn: progress}
	}
	if _, err := io.Copy(conn, src); err != nil {
		pr.Close() //nolint:errcheck
		return fmt.Errorf("p2p: send dir archive: %w", err)
	}
	pr.Close() //nolint:errcheck

	if err := <-errCh; err != nil {
		return fmt.Errorf("p2p: build archive: %w", err)
	}

	// Signal done.
	if err := writeFrame(conn, &Frame{Type: FrameDone}); err != nil {
		return err
	}

	ackFrame, err := readFrame(conn)
	if err != nil {
		return fmt.Errorf("p2p: waiting for dir ack: %w", err)
	}
	if ackFrame.Type == FrameErr {
		return fmt.Errorf("p2p: receiver dir error: %s", ackFrame.Error)
	}
	return nil
}

// ReceiveDir receives a directory tar+gzip bundle and extracts it to outputDir.
func ReceiveDir(conn net.Conn, outputDir string) error {
	frame, err := readFrame(conn)
	if err != nil {
		return err
	}
	if frame.Type != FrameDir {
		return fmt.Errorf("p2p: expected dir frame, got %q", frame.Type)
	}

	// The body is a tar+gzip stream until a FrameDone marker.
	// We use a separate reader that stops at the done frame.
	gz, err := gzip.NewReader(conn)
	if err != nil {
		_ = writeFrame(conn, &Frame{Type: FrameErr, Error: "gzip init: " + err.Error()})
		return fmt.Errorf("p2p: gzip: %w", err)
	}
	defer gz.Close() //nolint:errcheck

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			_ = writeFrame(conn, &Frame{Type: FrameErr, Error: err.Error()})
			return fmt.Errorf("p2p: tar: %w", err)
		}

		outPath := filepath.Join(outputDir, filepath.Clean(hdr.Name))
		// Security: reject paths that escape outputDir.
		if !strings.HasPrefix(outPath, filepath.Clean(outputDir)+string(os.PathSeparator)) &&
			outPath != filepath.Clean(outputDir) {
			_ = writeFrame(conn, &Frame{Type: FrameErr, Error: "unsafe path: " + hdr.Name})
			return fmt.Errorf("p2p: unsafe tar path %q", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(outPath, 0o755); err != nil {
				return fmt.Errorf("p2p: mkdir %s: %w", outPath, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
				return fmt.Errorf("p2p: mkdir for file %s: %w", outPath, err)
			}
			f, err := os.Create(outPath)
			if err != nil {
				return fmt.Errorf("p2p: create %s: %w", outPath, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close() //nolint:errcheck
				return fmt.Errorf("p2p: write %s: %w", outPath, err)
			}
			f.Close() //nolint:errcheck
			// Restore modification time.
			_ = os.Chtimes(outPath, hdr.ModTime, hdr.ModTime)
		}
	}

	if err := writeFrame(conn, &Frame{Type: FrameAck}); err != nil {
		return fmt.Errorf("p2p: send dir ack: %w", err)
	}
	AwaitPeerClose(conn, ackDeliveryWait)
	return nil
}

// Chat runs an interactive text chat session over the connection.
// localTag is the display name for locally-typed lines (e.g., "you").
// remoteTag is the display name for received lines.
// stdin/stdout are the I/O streams; os.Stdin / os.Stdout in normal use.
func Chat(conn net.Conn, localTag, remoteTag string,
	stdin io.Reader, stdout io.Writer) error {
	_ = conn.SetDeadline(time.Time{}) // no deadline for interactive chat

	errCh := make(chan error, 2)

	// Send goroutine: read from stdin, write as chat frames.
	go func() {
		scanner := bufio.NewScanner(stdin)
		for scanner.Scan() {
			line := scanner.Text()
			f := &Frame{Type: FrameChat, Text: line}
			if err := writeFrame(conn, f); err != nil {
				errCh <- err
				return
			}
		}
		// EOF on stdin — send done frame.
		_ = writeFrame(conn, &Frame{Type: FrameDone})
		errCh <- scanner.Err()
	}()

	// Receive goroutine: read chat frames, print to stdout.
	go func() {
		for {
			f, err := readFrame(conn)
			if err != nil {
				errCh <- err
				return
			}
			switch f.Type {
			case FrameChat:
				_, _ = fmt.Fprintf(stdout, "\r\033[K%s: %s\n%s> ", remoteTag, f.Text, localTag)
			case FrameDone:
				_, _ = fmt.Fprintf(stdout, "\n%s disconnected.\n", remoteTag)
				errCh <- io.EOF
				return
			}
		}
	}()

	err := <-errCh
	if err == io.EOF {
		return nil
	}
	return err
}

// progressReader wraps an io.Reader and calls fn after each Read.
type progressReader struct {
	r           io.Reader
	total       int64
	transferred int64
	fn          ProgressFunc
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)
	pr.transferred += int64(n)
	if pr.fn != nil {
		pr.fn(pr.transferred, pr.total)
	}
	return n, err
}
