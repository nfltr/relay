// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package orgaudit

// No process locks on these platforms: one process per machine directory.

import "os"

func syncDir(string) error      { return nil }
func lock(*os.File) error       { return nil }
func unlockFile(*os.File) error { return nil }
func tryLock(*os.File) error    { return nil }
