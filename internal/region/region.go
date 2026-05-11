// Package region provides low-level 2048-byte sector I/O and both-endian
// integer helpers shared by the iso9660 and udf packages.
package region

import (
	"encoding/binary"
	"fmt"
	"io"
)

const SectorSize = 2048

// SectorReader reads logical 2048-byte sectors from an ISO image.
type SectorReader struct {
	r io.ReaderAt
}

func NewSectorReader(r io.ReaderAt) *SectorReader {
	return &SectorReader{r: r}
}

// ReadSector reads logical sector n into a fresh buffer.
func (s *SectorReader) ReadSector(n uint32) ([]byte, error) {
	buf := make([]byte, SectorSize)
	if _, err := s.r.ReadAt(buf, int64(n)*SectorSize); err != nil {
		return nil, fmt.Errorf("sector %d: %w", n, err)
	}
	return buf, nil
}

// ReadSectors reads count consecutive sectors starting at n.
func (s *SectorReader) ReadSectors(n, count uint32) ([]byte, error) {
	buf := make([]byte, int(count)*SectorSize)
	if _, err := s.r.ReadAt(buf, int64(n)*SectorSize); err != nil {
		return nil, fmt.Errorf("sectors %d+%d: %w", n, count, err)
	}
	return buf, nil
}

// ReadBytes reads exactly length bytes at a given byte offset.
func (s *SectorReader) ReadBytes(offset int64, length int) ([]byte, error) {
	buf := make([]byte, length)
	if _, err := s.r.ReadAt(buf, offset); err != nil {
		return nil, fmt.Errorf("offset 0x%x len %d: %w", offset, length, err)
	}
	return buf, nil
}

// NewExtentReader returns an io.Reader that streams a file extent
// without loading it entirely into memory.
func (s *SectorReader) NewExtentReader(lba uint32, size int64) io.Reader {
	return io.NewSectionReader(s.r, int64(lba)*SectorSize, size)
}

// BothEndian32 reads the LE half of an ISO 9660 both-endian 32-bit field (8 bytes).
func BothEndian32(b []byte) uint32 {
	return binary.LittleEndian.Uint32(b[:4])
}

// BothEndian16 reads the LE half of an ISO 9660 both-endian 16-bit field (4 bytes).
func BothEndian16(b []byte) uint16 {
	return binary.LittleEndian.Uint16(b[:2])
}