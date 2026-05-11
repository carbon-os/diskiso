package udf

import (
	"bytes"
	"io"

	"github.com/carbon-os/diskiso/internal/region"
)

// UDF Volume Recognition Sequence signatures (ECMA-167 §8)
var (
	sigBEA01 = []byte("BEA01") // Beginning Extended Area Descriptor
	sigNSR02 = []byte("NSR02") // OSTA UDF 1.x
	sigNSR03 = []byte("NSR03") // OSTA UDF 2.x
	sigTEA01 = []byte("TEA01") // Terminating Extended Area Descriptor
)

const udfAnchorSector = 256

// Probe scans the Volume Recognition Sequence for UDF presence.
// Returns true if NSR02 or NSR03 is found and confirmed by an AVDP at sector 256.
//
// VRS layout (following the ISO9660 VDS):
//
//	sector N+0: BEA01 — beginning of UDF extended area
//	sector N+1: NSR02 or NSR03 — UDF version marker
//	sector N+2: TEA01 — end of extended area
func Probe(r io.ReaderAt) (bool, error) {
	sr := region.NewSectorReader(r)

	foundBEA := false
	for lba := uint32(16); lba < 32; lba++ {
		sec, err := sr.ReadSector(lba)
		if err != nil {
			return false, err
		}
		id := sec[1:6]
		switch {
		case bytes.Equal(id, sigBEA01):
			foundBEA = true
		case foundBEA && (bytes.Equal(id, sigNSR02) || bytes.Equal(id, sigNSR03)):
			return probeAnchor(sr), nil
		case bytes.Equal(id, sigTEA01):
			return false, nil
		}
	}
	return false, nil
}

// probeAnchor verifies the UDF Anchor Volume Descriptor Pointer at sector 256.
// The AVDP descriptor tag has TagIdentifier == 2.
func probeAnchor(sr *region.SectorReader) bool {
	sec, err := sr.ReadSector(udfAnchorSector)
	if err != nil {
		return false
	}
	tagID := uint16(sec[0]) | uint16(sec[1])<<8
	return tagID == 2
}