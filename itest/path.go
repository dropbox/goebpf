package itest

import (
	"fmt"
	"os"
	"path"
)

const progSubdir = "ebpf_prog"

// Helper to get the absolute path of a test program.
func progPath(imageName string) string {
	// within `go test`, the test executable lives in a temporary directory, so
	// we check the WD first.
	exePath, err := os.Executable()
	if err != nil {
		panic(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	relPath := path.Join(progSubdir, imageName)
	wdPath := path.Join(wd, relPath)
	absPath := path.Join(path.Dir(exePath), relPath)

	if _, err = os.Stat(wdPath); err == nil {
		return wdPath
	}

	if _, err = os.Stat(absPath); err == nil {
		return absPath
	}

	panic(
		fmt.Sprintf(
			"eBPF executable not found, checked paths:\n  %q\n  %q",
			wdPath, absPath))
}
