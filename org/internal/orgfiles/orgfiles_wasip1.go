// Copyright 2026 nfltr
// SPDX-License-Identifier: Apache-2.0

//go:build wasip1

package orgfiles

import "os"

func syncDir(string) error      { return nil }
func lock(*os.File) error       { return nil }
func unlockFile(*os.File) error { return nil }
func tryLock(*os.File) error    { return nil }
