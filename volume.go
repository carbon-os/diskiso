package diskiso

import (
	"io/fs"
	"os"
)

// Volume is a read-only view into a single filesystem layer of an ISO image.
// All paths are absolute (e.g. "/sources/install.wim").
//
// Obtain a Volume via Disc.Mount; it is valid for the lifetime of the Disc.
type Volume interface {
	// Type returns the layer name: "iso9660", "joliet", "rockridge", or "udf".
	Type() string

	// Label returns the volume label embedded in the image.
	Label() string

	// ReadFile reads the entire contents of a file.
	ReadFile(path string) ([]byte, error)

	// Open opens a file for streaming. The caller must Close it.
	Open(path string) (fs.File, error)

	// ReadDir lists the entries in a directory.
	ReadDir(path string) ([]fs.DirEntry, error)

	// Stat returns metadata for a path.
	Stat(path string) (os.FileInfo, error)

	// Readlink returns the symlink target. Only meaningful on RockRidge volumes;
	// all others return an error.
	Readlink(path string) (string, error)
}