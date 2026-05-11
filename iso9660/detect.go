package iso9660

import (
	"bytes"
	"io"

	"github.com/carbon-os/diskiso/internal/region"
)

// Volume Descriptor types (ISO 9660 §8.1)
const (
	vdTypeBoot       = 0
	vdTypePrimary    = 1   // PVD — ISO9660
	vdTypeSupp       = 2   // SVD — Joliet uses type 2
	vdTypePartition  = 3
	vdTypeTerminator = 255
	vdsStartSector   = 16  // VDS begins at logical sector 16
)

var (
	isoMagic = []byte("CD001")

	// Joliet escape sequences at SVD offset 88 (§8.5.6)
	jolietEscapes = [][]byte{
		{0x25, 0x2F, 0x40}, // %/@ — UCS-2 Level 1
		{0x25, 0x2F, 0x43}, // %/C — UCS-2 Level 2
		{0x25, 0x2F, 0x45}, // %/E — UCS-2 Level 3
	}
)

// ProbeResult reports which ISO 9660 family layers are present.
type ProbeResult struct {
	HasISO9660   bool
	HasJoliet    bool
	HasRockRidge bool
	PvdSector    uint32
	SvdSector    uint32
}

// Probe scans the Volume Descriptor Set and returns what layers are present.
// It stops at the VDS Terminator or when it encounters a non-ISO9660 sector.
func Probe(r io.ReaderAt) (ProbeResult, error) {
	sr := region.NewSectorReader(r)
	var res ProbeResult

	for lba := uint32(vdsStartSector); ; lba++ {
		sec, err := sr.ReadSector(lba)
		if err != nil {
			return res, err
		}
		if !bytes.Equal(sec[1:6], isoMagic) {
			break // entered UDF area or end of image
		}
		switch sec[0] {
		case vdTypePrimary:
			res.HasISO9660 = true
			res.PvdSector = lba
			if !res.HasRockRidge {
				res.HasRockRidge = probeRockRidge(sr, sec)
			}
		case vdTypeSupp:
			esc := sec[88:120]
			for _, je := range jolietEscapes {
				if bytes.Contains(esc, je) {
					res.HasJoliet = true
					res.SvdSector = lba
					break
				}
			}
		case vdTypeTerminator:
			return res, nil
		}
	}
	return res, nil
}

// probeRockRidge checks the root directory's "." entry for SUSP System Use fields.
func probeRockRidge(sr *region.SectorReader, pvd []byte) bool {
	rootRecord := pvd[156:190]
	rootLBA := region.BothEndian32(rootRecord[2:10])

	sec, err := sr.ReadSector(rootLBA)
	if err != nil {
		return false
	}

	recLen := int(sec[0])
	if recLen < 34 {
		return false
	}
	idLen := int(sec[32])
	suaStart := 33 + idLen
	if suaStart%2 != 0 {
		suaStart++
	}
	if suaStart >= recLen {
		return false
	}

	return suaHasSignature(sec[suaStart:recLen], "SP") ||
		suaHasSignature(sec[suaStart:recLen], "RR")
}

// suaHasSignature scans System Use Area bytes for a 2-byte SUSP signature.
func suaHasSignature(sua []byte, sig string) bool {
	for i := 0; i+4 <= len(sua); {
		if sua[i] == sig[0] && sua[i+1] == sig[1] {
			return true
		}
		length := int(sua[i+2])
		if length < 4 {
			break
		}
		i += length
	}
	return false
}