package diskiso

import "os"

// Disc represents an attached ISO image.
// Obtain one via Attach; release resources with Detach.
type Disc struct {
	f    *os.File
	fses []Filesystem // detected layers, descending priority
}

// Filesystems returns the detected layers in descending priority order.
// The first entry is what Mount selects automatically.
//
//	disc.Filesystems() // → [UDF Joliet ISO9660]
func (d *Disc) Filesystems() []Filesystem {
	out := make([]Filesystem, len(d.fses))
	copy(out, d.fses)
	return out
}

// FilesystemNames returns the same list as human-readable strings.
//
//	disc.FilesystemNames() // → ["udf", "joliet", "iso9660"]
func (d *Disc) FilesystemNames() []string {
	names := make([]string, len(d.fses))
	for i, f := range d.fses {
		names[i] = f.String()
	}
	return names
}