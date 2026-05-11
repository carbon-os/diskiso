package iso9660

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"unicode/utf16"

	"github.com/carbon-os/diskiso/internal/region"
)

// Mode selects which view of the ISO 9660 data tree to use.
type Mode int

const (
	ModeISO9660  Mode = iota // Plain ISO 9660 PVD
	ModeJoliet               // Joliet SVD — UCS-2BE names
	ModeRockRidge            // ISO 9660 PVD + Rock Ridge SUSP extensions
)

// Volume is a read-only ISO 9660 / Joliet / RockRidge filesystem view.
// It satisfies the diskiso.Volume interface.
type Volume struct {
	sr      *region.SectorReader
	mode    Mode
	rootLBA uint32
	rootLen uint32
	label   string
	size    int64
}

// NewVolume opens the requested ISO 9660 / Joliet / RockRidge view of an image.
func NewVolume(r io.ReaderAt, mode Mode) (*Volume, error) {
	sr := region.NewSectorReader(r)

	vdLBA, err := findVD(sr, mode)
	if err != nil {
		return nil, err
	}

	vd, err := sr.ReadSector(vdLBA)
	if err != nil {
		return nil, fmt.Errorf("iso9660: read VD sector %d: %w", vdLBA, err)
	}

	// Root directory record is embedded at PVD/SVD offset 156 (34 bytes)
	root    := vd[156:190]
	rootLBA := region.BothEndian32(root[2:10])
	rootLen := region.BothEndian32(root[10:18])

	// Volume space size (both-endian 32 at offset 80, unit = sectors)
	totalSectors := region.BothEndian32(vd[80:88])
	size := int64(totalSectors) * region.SectorSize

	// Volume identifier at offset 40, 32 bytes
	label := strings.TrimRight(string(vd[40:72]), " ")
	if mode == ModeJoliet {
		label = decodeUCS2BE(vd[40:72])
	}

	return &Volume{
		sr:      sr,
		mode:    mode,
		rootLBA: rootLBA,
		rootLen: rootLen,
		label:   label,
		size:    size,
	}, nil
}

// findVD locates the appropriate Volume Descriptor sector for the given mode.
func findVD(sr *region.SectorReader, mode Mode) (uint32, error) {
	if mode != ModeJoliet {
		return vdsStartSector, nil // PVD is always sector 16
	}
	for lba := uint32(vdsStartSector); ; lba++ {
		sec, err := sr.ReadSector(lba)
		if err != nil {
			return 0, err
		}
		if sec[0] == vdTypeTerminator {
			return 0, errors.New("iso9660: Joliet SVD not found")
		}
		if sec[0] == vdTypeSupp && bytes.Equal(sec[1:6], isoMagic) {
			esc := sec[88:120]
			for _, je := range jolietEscapes {
				if bytes.Contains(esc, je) {
					return lba, nil
				}
			}
		}
	}
}

// --- diskiso.Volume interface ---

func (v *Volume) Type() string {
	switch v.mode {
	case ModeJoliet:
		return "joliet"
	case ModeRockRidge:
		return "rockridge"
	default:
		return "iso9660"
	}
}

func (v *Volume) Label() string { return v.label }

func (v *Volume) ReadFile(filePath string) ([]byte, error) {
	e, err := v.lookup(filePath)
	if err != nil {
		return nil, err
	}
	if e.isDir {
		return nil, fmt.Errorf("iso9660: %s: is a directory", filePath)
	}
	return v.sr.ReadBytes(int64(e.extentLBA)*region.SectorSize, int(e.dataLen))
}

func (v *Volume) Open(filePath string) (fs.File, error) {
	e, err := v.lookup(filePath)
	if err != nil {
		return nil, err
	}
	return &isoFile{
		vol:  v,
		e:    *e,
		r:    v.sr.NewExtentReader(e.extentLBA, int64(e.dataLen)),
		path: filePath,
	}, nil
}

func (v *Volume) ReadDir(dirPath string) ([]fs.DirEntry, error) {
	lba, length, err := v.dirExtent(dirPath)
	if err != nil {
		return nil, err
	}
	entries, err := v.readDir(lba, length)
	if err != nil {
		return nil, err
	}
	out := make([]fs.DirEntry, len(entries))
	for i, e := range entries {
		out[i] = e.toDirEntry()
	}
	return out, nil
}

func (v *Volume) Stat(filePath string) (os.FileInfo, error) {
	e, err := v.lookup(filePath)
	if err != nil {
		return nil, err
	}
	return e.toFileInfo(), nil
}

func (v *Volume) Readlink(filePath string) (string, error) {
	if v.mode != ModeRockRidge {
		return "", fmt.Errorf("iso9660: readlink not supported on %s volumes", v.Type())
	}
	e, err := v.lookup(filePath)
	if err != nil {
		return "", err
	}
	if !e.rrIsLink {
		return "", fmt.Errorf("iso9660: %s: not a symlink", filePath)
	}
	return e.rrTarget, nil
}

// --- Path resolution ---

func (v *Volume) lookup(p string) (*dirEntry, error) {
	p = path.Clean("/" + p)
	if p == "/" {
		return &dirEntry{
			isDir:     true,
			extentLBA: v.rootLBA,
			dataLen:   v.rootLen,
		}, nil
	}

	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	curLBA, curLen := v.rootLBA, v.rootLen

	for i, part := range parts {
		entries, err := v.readDir(curLBA, curLen)
		if err != nil {
			return nil, err
		}
		var found *dirEntry
		for j := range entries {
			if v.nameMatch(entries[j], part) {
				found = &entries[j]
				break
			}
		}
		if found == nil {
			return nil, &os.PathError{Op: "stat", Path: p, Err: os.ErrNotExist}
		}
		if i == len(parts)-1 {
			return found, nil
		}
		if !found.isDir {
			return nil, fmt.Errorf("iso9660: %s: not a directory", part)
		}
		curLBA, curLen = found.extentLBA, found.dataLen
	}
	return nil, os.ErrNotExist
}

func (v *Volume) dirExtent(dirPath string) (lba, length uint32, err error) {
	if dirPath == "/" || dirPath == "" || dirPath == "." {
		return v.rootLBA, v.rootLen, nil
	}
	e, err := v.lookup(dirPath)
	if err != nil {
		return 0, 0, err
	}
	if !e.isDir {
		return 0, 0, fmt.Errorf("iso9660: %s: not a directory", dirPath)
	}
	return e.extentLBA, e.dataLen, nil
}

// nameMatch compares a directory entry name to the target, honouring mode semantics.
// ISO9660 is case-insensitive; Joliet and RockRidge are case-sensitive.
func (v *Volume) nameMatch(e dirEntry, target string) bool {
	name := e.name
	if v.mode == ModeRockRidge && e.rrName != "" {
		name = e.rrName
	}
	if v.mode == ModeISO9660 {
		return strings.EqualFold(name, target)
	}
	return name == target
}

func (v *Volume) readDir(lba, length uint32) ([]dirEntry, error) {
	sectorCount := (length + region.SectorSize - 1) / region.SectorSize
	data, err := v.sr.ReadSectors(lba, sectorCount)
	if err != nil {
		return nil, err
	}

	var entries []dirEntry
	skip := 2 // skip "." and ".." — always the first two records

	for offset := 0; offset < int(length); {
		recLen := int(data[offset])
		if recLen == 0 {
			// Zero padding — advance to next sector boundary
			next := (offset/region.SectorSize + 1) * region.SectorSize
			if next >= int(length) {
				break
			}
			offset = next
			continue
		}
		if offset+recLen > len(data) {
			break
		}
		if skip > 0 {
			skip--
			offset += recLen
			continue
		}
		if e, ok := parseRecord(data[offset:offset+recLen], v.mode); ok {
			entries = append(entries, e)
		}
		offset += recLen
	}
	return entries, nil
}

// decodeUCS2BE decodes a big-endian UCS-2 / UTF-16BE byte slice to a Go string.
func decodeUCS2BE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = uint16(b[i*2])<<8 | uint16(b[i*2+1])
	}
	runes := utf16.Decode(u16)
	for i, r := range runes {
		if r == 0 {
			runes = runes[:i]
			break
		}
	}
	return string(runes)
}

// --- isoFile: implements fs.File for streaming reads ---

type isoFile struct {
	vol  *Volume
	e    dirEntry
	r    io.Reader
	path string
}

func (f *isoFile) Read(b []byte) (int, error)        { return f.r.Read(b) }
func (f *isoFile) Close() error                       { return nil }
func (f *isoFile) Stat() (fs.FileInfo, error)         { return f.e.toFileInfo(), nil }
func (f *isoFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if !f.e.isDir {
		return nil, fmt.Errorf("iso9660: %s: not a directory", f.path)
	}
	entries, err := f.vol.readDir(f.e.extentLBA, f.e.dataLen)
	if err != nil {
		return nil, err
	}
	if n > 0 && n < len(entries) {
		entries = entries[:n]
	}
	out := make([]fs.DirEntry, len(entries))
	for i, e := range entries {
		out[i] = e.toDirEntry()
	}
	return out, nil
}