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
// Returns true only if NSR02/NSR03 is found AND sector 256 contains a
// structurally valid Anchor Volume Descriptor Pointer (AVDP).
//
// Two checks are required to avoid false positives on ISOs that carry the
// UDF VRS markers (BEA01/NSR02/TEA01) purely for compatibility — as
// oscdimg and several other tools do — but have no actual UDF filesystem:
//
//  1. Tag ID at bytes [0:2] of sector 256 must be 2 (AVDP).
//  2. Descriptor tag checksum (ECMA-167 7.2) must be valid: the sum of all
//     16 tag bytes with the checksum byte (offset 4) treated as 0 must equal
//     the value stored at offset 4. Random ISO data will almost never satisfy
//     this constraint.
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

// probeAnchor verifies that sector 256 contains a genuine AVDP by checking
// both the tag ID and the ECMA-167 descriptor tag checksum.
//
// Descriptor Tag layout (ECMA-167 7.2, 16 bytes):
//
//	[0:2]  Tag Identifier          (uint16 LE) — must be 2 for AVDP
//	[2:4]  Descriptor Version
//	[4]    Tag Checksum            — sum of bytes [0:4] and [5:16] mod 256
//	[5]    Tag Serial Number
//	[6:8]  Descriptor CRC
//	[8:10] Descriptor CRC Length
//	[10:14] Tag Location
//	... (remaining bytes part of the AVDP body)
func probeAnchor(sr *region.SectorReader) bool {
	sec, err := sr.ReadSector(udfAnchorSector)
	if err != nil {
		return false
	}

	// Check tag ID.
	tagID := uint16(sec[0]) | uint16(sec[1])<<8
	if tagID != 2 {
		return false
	}

	// Validate descriptor tag checksum over the 16-byte tag.
	// The checksum byte at offset 4 is excluded from the sum, then compared.
	var sum uint8
	for i := 0; i < 16; i++ {
		if i == 4 {
			continue
		}
		sum += sec[i]
	}
	return sum == sec[4]
}