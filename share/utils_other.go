//go:build !linux

package share

import "os"

// openMemFile falls back to an unlinked temporary file on platforms without
// memfd_create (e.g., macOS). The file is removed from its directory right away, so it is
// released when the descriptor is closed, like a memfd, but its pages may be
// backed by disk rather than RAM. Intended for development builds only.
func openMemFile(name string) (*os.File, error) {
	f, err := os.CreateTemp("", name)
	if err != nil {
		return nil, err
	}
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
