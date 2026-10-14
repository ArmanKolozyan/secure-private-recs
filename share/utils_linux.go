//go:build linux

package share

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// openMemFile returns an *os.File whose pages live only in RAM.
func openMemFile(name string) (*os.File, error) {
	fd, err := unix.MemfdCreate(name, unix.MFD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("memfd_create: %w", err)
	}
	return os.NewFile(uintptr(fd), name), nil
}
