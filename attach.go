package diskiso

import (
	"fmt"
	"io"
	"os"

	"github.com/carbon-os/diskiso/iso9660"
	"github.com/carbon-os/diskiso/udf"
)

// Attach opens an ISO image file and probes it for recognised filesystem layers.
// The file handle is held open until Detach is called.
//
//	disc, err := diskiso.Attach("windows-arm64.iso")
func Attach(path string) (*Disc, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("diskiso: open %q: %w", path, err)
	}

	fses, err := probeFilesystems(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("diskiso: probe %q: %w", path, err)
	}
	if len(fses) == 0 {
		f.Close()
		return nil, fmt.Errorf("diskiso: %q: no recognised ISO filesystem", path)
	}

	return &Disc{f: f, fses: fses}, nil
}

// probeFilesystems detects all layers present and returns them in descending priority.
func probeFilesystems(r io.ReaderAt) ([]Filesystem, error) {
	isoResult, err := iso9660.Probe(r)
	if err != nil {
		return nil, err
	}

	hasUDF, err := udf.Probe(r)
	if err != nil {
		return nil, err
	}

	var fses []Filesystem
	if hasUDF {
		fses = append(fses, UDF)
	}
	if isoResult.HasJoliet {
		fses = append(fses, Joliet)
	}
	if isoResult.HasRockRidge {
		fses = append(fses, RockRidge)
	}
	if isoResult.HasISO9660 {
		fses = append(fses, ISO9660)
	}
	return fses, nil
}