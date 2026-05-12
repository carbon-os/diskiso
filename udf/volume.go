package udf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/carbon-os/diskiso/internal/region"
)

// Volume implements diskiso.Volume for UDF (ECMA-167 / OSTA UDF 1.x–2.x).
type Volume struct {
	sr          *region.SectorReader
	partStart   uint32
	partLen     uint32
	rootICBLBA  uint32
	label       string
	size        int64
	efeFECompat bool // EFEs on this volume use FE-compatible body (no objectSize)
}

func NewVolume(r io.ReaderAt) (*Volume, error) {
	sr := region.NewSectorReader(r)
	v := &Volume{sr: sr}
	if err := v.parseAnchor(); err != nil {
		return nil, fmt.Errorf("udf: anchor: %w", err)
	}
	return v, nil
}

func (v *Volume) parseAnchor() error {
	sec, err := v.sr.ReadSector(udfAnchorSector)
	if err != nil {
		return err
	}
	mainLen := binary.LittleEndian.Uint32(sec[16:20])
	mainLBA := binary.LittleEndian.Uint32(sec[20:24])
	return v.parseVDS(mainLBA, mainLen)
}

func (v *Volume) parseVDS(startLBA, length uint32) error {
	sectorCount := (length + region.SectorSize - 1) / region.SectorSize

	var (
		partStart, partLen uint32
		fsdLBA             uint32
		partFound, fsdFound bool
	)

	for i := uint32(0); i < sectorCount; i++ {
		sec, err := v.sr.ReadSector(startLBA + i)
		if err != nil {
			return err
		}
		tagID := binary.LittleEndian.Uint16(sec[0:2])
		switch tagID {
		case 5:
			partStart = binary.LittleEndian.Uint32(sec[188:192])
			partLen   = binary.LittleEndian.Uint32(sec[192:196])
			partFound = true
		case 6:
			fsdLBA   = binary.LittleEndian.Uint32(sec[252:256])
			fsdFound = true
		case 8:
			goto done
		}
	}
done:
	if !partFound || !fsdFound {
		return errors.New("udf: missing Partition or Logical Volume Descriptor")
	}
	v.partStart = partStart
	v.partLen   = partLen
	v.size      = int64(partStart+partLen) * region.SectorSize
	return v.parseFSD(v.partStart + fsdLBA)
}

func (v *Volume) parseFSD(lba uint32) error {
	sec, err := v.sr.ReadSector(lba)
	if err != nil {
		return err
	}
	tagID := binary.LittleEndian.Uint16(sec[0:2])
	if tagID != 256 {
		return fmt.Errorf("udf: expected FSD (tag 256) at sector %d, got %d", lba, tagID)
	}
	v.rootICBLBA = v.partStart + binary.LittleEndian.Uint32(sec[404:408])
	field  := sec[112:240]
	strLen := int(field[127])
	if strLen > 0 && strLen <= 127 {
		v.label = decodeCS0(field[:strLen])
	}
	// Detect EFE body style from the root file entry before any other parsing.
	v.probeEFELayout()
	return nil
}

// probeEFELayout reads the root file entry once at volume-open time and
// determines whether Extended File Entries (tag 261) on this volume use the
// standard ECMA-167 body layout (objectSize at BP 64, eaLen@208) or the
// FE-compatible layout (no objectSize, eaLen@168).
//
// Some UDF generators emit tag=261 descriptors whose body is identical to a
// tag=260 File Entry — i.e. no objectSize, no streamDirectoryICB.  The two
// variants cannot be distinguished reliably on a per-entry basis when the AD
// area happens to contain non-zero bytes at the standard EFE offset, so we
// detect the style once and apply it uniformly across the whole volume.
//
// Detection uses the root directory entry because it is always present and
// always a non-empty file (infoLen > 0), which lets us validate the candidate
// AD layout by checking that the first allocation descriptor's partition-
// relative LBA falls within the partition.
func (v *Volume) probeEFELayout() {
	sec, err := v.sr.ReadSector(v.rootICBLBA)
	if err != nil {
		return
	}
	tagID := binary.LittleEndian.Uint16(sec[0:2])
	if tagID != 261 {
		// Root is a regular FE; standard EFE offsets are assumed correct.
		return
	}

	icbFlags  := binary.LittleEndian.Uint16(sec[34:36])
	allocType := uint32(icbFlags & 0x0007)

	// Try the standard EFE layout (eaLen@208).
	efeEALen   := binary.LittleEndian.Uint32(sec[208:212])
	efeADLen   := binary.LittleEndian.Uint32(sec[212:216])
	efeADStart := 216 + int(efeEALen)

	if v.adRangeValid(sec, efeADStart, efeADLen, allocType) {
		// Standard layout is consistent — use it.
		v.efeFECompat = false
		return
	}

	// Standard layout failed — this volume uses FE-compatible EFE bodies.
	v.efeFECompat = true
}

// adRangeValid returns true when adStart/adLen fit in the sector AND the first
// allocation descriptor's partition-relative LBA is within the partition.
// Checking the LBA bound is far more discriminating than checking extLen alone,
// because an incorrect offset position will typically produce a byte sequence
// whose lower 32 bits, interpreted as a partition-relative LBA, exceed partLen.
func (v *Volume) adRangeValid(sec []byte, adStart int, adLen uint32, allocType uint32) bool {
	if adStart < 0 || adLen == 0 || adStart+int(adLen) > len(sec) {
		return false
	}
	// Minimum AD sizes: Short=8, Long=16, Extended=20
	minSize := 8
	posOff  := 4 // byte offset of LBA within the AD
	switch allocType {
	case 1:
		minSize = 16
	case 2:
		minSize = 20
		posOff  = 12
	case 3:
		return true // inline — no LBA to check
	}
	if adStart+posOff+4 > len(sec) {
		return false
	}
	extLen := binary.LittleEndian.Uint32(sec[adStart:adStart+4]) & 0x3FFFFFFF
	if extLen == 0 {
		return false
	}
	extPos := binary.LittleEndian.Uint32(sec[adStart+posOff : adStart+posOff+4])
	_ = minSize
	return extPos < v.partLen
}

// resolveADLayout returns the adLen, adStart, and modificationTime byte offset
// for this file entry sector, using the EFE body style detected at volume open.
//
//	tag 260 (FE) or FE-compatible EFE: eaLen@168  adLen@172  adBase=176  modTime@84
//	tag 261 standard EFE:              eaLen@208  adLen@212  adBase=216  modTime@92
func (v *Volume) resolveADLayout(sec []byte, tagID uint16) (adLen uint32, adStart, modOff int) {
	if tagID == 261 && !v.efeFECompat {
		eaLen   := binary.LittleEndian.Uint32(sec[208:212])
		adLen    = binary.LittleEndian.Uint32(sec[212:216])
		adStart  = 216 + int(eaLen)
		modOff   = 92
	} else {
		eaLen   := binary.LittleEndian.Uint32(sec[168:172])
		adLen    = binary.LittleEndian.Uint32(sec[172:176])
		adStart  = 176 + int(eaLen)
		modOff   = 84
	}
	return
}

// --- diskiso.Volume interface ---

func (v *Volume) Type() string  { return "udf" }
func (v *Volume) Label() string { return v.label }

func (v *Volume) ReadFile(filePath string) ([]byte, error) {
	fe, err := v.lookupFileEntry(filePath)
	if err != nil {
		return nil, err
	}
	if fe.isDir {
		return nil, fmt.Errorf("udf: %s: is a directory", filePath)
	}
	if fe.inlineData != nil {
		return fe.inlineData, nil
	}
	buf := make([]byte, fe.totalLen)
	var offset uint64
	for _, ext := range fe.extents {
		b, err := v.sr.ReadBytes(int64(ext.lba)*region.SectorSize, int(ext.len))
		if err != nil {
			return nil, err
		}
		n := copy(buf[offset:], b)
		offset += uint64(n)
	}
	return buf, nil
}

func (v *Volume) Open(filePath string) (fs.File, error) {
	fe, err := v.lookupFileEntry(filePath)
	if err != nil {
		return nil, err
	}
	var r io.Reader
	if fe.inlineData != nil {
		r = bytes.NewReader(fe.inlineData)
	} else {
		var readers []io.Reader
		for _, ext := range fe.extents {
			readers = append(readers, v.sr.NewExtentReader(ext.lba, int64(ext.len)))
		}
		r = io.LimitReader(io.MultiReader(readers...), int64(fe.totalLen))
	}
	return &udfFile{
		vol:  v,
		fe:   *fe,
		r:    r,
		path: filePath,
	}, nil
}

func (v *Volume) ReadDir(dirPath string) ([]fs.DirEntry, error) {
	fe, err := v.dirFileEntry(dirPath)
	if err != nil {
		return nil, err
	}
	return v.readDir(fe)
}

func (v *Volume) Stat(filePath string) (os.FileInfo, error) {
	fe, err := v.lookupFileEntry(filePath)
	if err != nil {
		return nil, err
	}
	return fe.toFileInfo(), nil
}

func (v *Volume) Readlink(filePath string) (string, error) {
	return "", fmt.Errorf("udf: %s: symlinks not supported", filePath)
}

// --- UDF File Entry and Extent Tracking ---

type extent struct {
	lba uint32
	len uint32
}

type fileEntry struct {
	name       string
	isDir      bool
	feLBA      uint32
	extents    []extent
	totalLen   uint64
	modTime    time.Time
	mode       os.FileMode
	inlineData []byte
}

func (v *Volume) parseFileEntry(lba uint32) (*fileEntry, error) {
	sec, err := v.sr.ReadSector(lba)
	if err != nil {
		return nil, err
	}
	tagID := binary.LittleEndian.Uint16(sec[0:2])
	if tagID != 260 && tagID != 261 {
		return nil, fmt.Errorf("udf: expected File Entry at sector %d (tag 260/261), got %d", lba, tagID)
	}

	icbFileType := sec[27]
	isDir       := icbFileType == 4
	infoLen     := binary.LittleEndian.Uint64(sec[56:64])
	icbFlags    := binary.LittleEndian.Uint16(sec[34:36])
	allocType   := uint32(icbFlags & 0x0007)
	posixPerm   := binary.LittleEndian.Uint32(sec[44:48])
	mode        := udfPermToFileMode(posixPerm, isDir)

	adLen, adStart, modOff := v.resolveADLayout(sec, tagID)
	modTime := parseUDFTimestamp(sec[modOff : modOff+12])

	fe := &fileEntry{
		isDir:    isDir,
		feLBA:    lba,
		totalLen: infoLen,
		modTime:  modTime,
		mode:     mode,
	}

	if allocType == 3 {
		if adLen > 0 && adStart+int(adLen) <= len(sec) {
			fe.inlineData = make([]byte, adLen)
			copy(fe.inlineData, sec[adStart:adStart+int(adLen)])
		}
		return fe, nil
	}

	var parseADs func(adData []byte) error
	parseADs = func(adData []byte) error {
		offset := 0
		for offset < len(adData) {
			var extLen, extPos uint32
			var step int

			switch allocType {
			case 0: // Short AD
				if offset+8 > len(adData) {
					return nil
				}
				extLen = binary.LittleEndian.Uint32(adData[offset : offset+4])
				extPos = binary.LittleEndian.Uint32(adData[offset+4 : offset+8])
				step = 8
			case 1: // Long AD
				if offset+16 > len(adData) {
					return nil
				}
				extLen = binary.LittleEndian.Uint32(adData[offset : offset+4])
				extPos = binary.LittleEndian.Uint32(adData[offset+4 : offset+8])
				step = 16
			case 2: // Extended AD
				if offset+20 > len(adData) {
					return nil
				}
				extLen = binary.LittleEndian.Uint32(adData[offset : offset+4])
				extPos = binary.LittleEndian.Uint32(adData[offset+12 : offset+16])
				step = 20
			default:
				return fmt.Errorf("udf: unsupported allocType %d", allocType)
			}

			eType := extLen >> 30
			eLen  := extLen & 0x3FFFFFFF
			offset += step

			if eLen == 0 {
				continue
			}
			switch eType {
			case 3: // Allocation Extent Descriptor — continuation
				adSecs, err := v.sr.ReadSectors(v.partStart+extPos, (eLen+2047)/2048)
				if err != nil {
					return err
				}
				if binary.LittleEndian.Uint16(adSecs[0:2]) == 328 {
					adListLen := binary.LittleEndian.Uint32(adSecs[20:24])
					if 24+int(adListLen) <= len(adSecs) {
						if err := parseADs(adSecs[24 : 24+int(adListLen)]); err != nil {
							return err
						}
					}
				}
			case 0, 1:
				fe.extents = append(fe.extents, extent{
					lba: v.partStart + extPos,
					len: eLen,
				})
			}
		}
		return nil
	}

	if adLen > 0 && adStart+int(adLen) <= len(sec) {
		if err := parseADs(sec[adStart : adStart+int(adLen)]); err != nil {
			return nil, err
		}
	}
	return fe, nil
}

func (v *Volume) lookupFileEntry(p string) (*fileEntry, error) {
	p = cleanPath(p)
	if p == "/" {
		fe, err := v.parseFileEntry(v.rootICBLBA)
		if err != nil {
			return nil, err
		}
		fe.name = ""
		return fe, nil
	}

	parts  := strings.Split(strings.TrimPrefix(p, "/"), "/")
	curLBA := v.rootICBLBA

	for i, part := range parts {
		curFE, err := v.parseFileEntry(curLBA)
		if err != nil {
			return nil, err
		}
		if !curFE.isDir {
			return nil, fmt.Errorf("udf: %s: not a directory", part)
		}
		children, err := v.readDirEntries(curFE)
		if err != nil {
			return nil, err
		}
		var found *fileEntry
		for _, child := range children {
			if child.name == part {
				found = child
				break
			}
		}
		if found == nil {
			return nil, &os.PathError{Op: "stat", Path: p, Err: os.ErrNotExist}
		}
		if i == len(parts)-1 {
			return found, nil
		}
		curLBA = found.feLBA
	}
	return nil, os.ErrNotExist
}

func (v *Volume) dirFileEntry(dirPath string) (*fileEntry, error) {
	if dirPath == "/" || dirPath == "" || dirPath == "." {
		return v.parseFileEntry(v.rootICBLBA)
	}
	fe, err := v.lookupFileEntry(dirPath)
	if err != nil {
		return nil, err
	}
	if !fe.isDir {
		return nil, fmt.Errorf("udf: %s: not a directory", dirPath)
	}
	return fe, nil
}

func (v *Volume) readDir(fe *fileEntry) ([]fs.DirEntry, error) {
	children, err := v.readDirEntries(fe)
	if err != nil {
		return nil, err
	}
	out := make([]fs.DirEntry, len(children))
	for i, e := range children {
		out[i] = e.toDirEntry()
	}
	return out, nil
}

func (v *Volume) readDirEntries(fe *fileEntry) ([]*fileEntry, error) {
	var data []byte
	if fe.inlineData != nil {
		data = fe.inlineData
	} else {
		data = make([]byte, fe.totalLen)
		var offset uint64
		for _, ext := range fe.extents {
			b, err := v.sr.ReadBytes(int64(ext.lba)*region.SectorSize, int(ext.len))
			if err != nil {
				return nil, err
			}
			n := copy(data[offset:], b)
			offset += uint64(n)
		}
	}

	var entries []*fileEntry
	for offset := 0; offset+38 <= len(data); {
		tagID := binary.LittleEndian.Uint16(data[offset : offset+2])
		if tagID != 257 {
			break
		}
		fileChars := data[offset+18]
		lfi       := int(data[offset+19])
		icbLBA    := binary.LittleEndian.Uint32(data[offset+24 : offset+28])
		liu       := int(binary.LittleEndian.Uint16(data[offset+36 : offset+38]))

		isParent := fileChars&0x08 != 0
		isDir    := fileChars&0x02 != 0

		nameStart := offset + 38 + liu
		name := ""
		if lfi > 0 && nameStart+lfi <= len(data) {
			name = decodeCS0(data[nameStart : nameStart+lfi])
		}

		totalLen := 38 + liu + lfi
		if totalLen%4 != 0 {
			totalLen += 4 - (totalLen % 4)
		}
		if totalLen == 0 {
			break
		}

		if !isParent && name != "" {
			child, err := v.parseFileEntry(v.partStart + icbLBA)
			if err == nil {
				child.name  = name
				child.isDir = isDir
				entries = append(entries, child)
			}
		}
		offset += totalLen
	}
	return entries, nil
}

// --- Helpers ---

func cleanPath(p string) string {
	if p == "" || p == "." {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	return path.Clean(p)
}

func decodeCS0(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	compressionID := b[0]
	content       := b[1:]
	switch compressionID {
	case 8:
		return string(content)
	case 16:
		if len(content)%2 != 0 {
			content = content[:len(content)-1]
		}
		u16 := make([]uint16, len(content)/2)
		for i := range u16 {
			u16[i] = uint16(content[i*2])<<8 | uint16(content[i*2+1])
		}
		return string(utf16.Decode(u16))
	default:
		return string(content)
	}
}

func parseUDFTimestamp(b []byte) time.Time {
	if len(b) < 12 {
		return time.Time{}
	}
	year  := int(binary.LittleEndian.Uint16(b[2:4]))
	month := time.Month(b[4])
	day   := int(b[5])
	hour  := int(b[6])
	min   := int(b[7])
	sec   := int(b[8])
	tzRaw := int(binary.LittleEndian.Uint16(b[0:2]) & 0x0FFF)
	if tzRaw&0x800 != 0 {
		tzRaw -= 0x1000
	}
	return time.Date(year, month, day, hour, min, sec, 0, time.FixedZone("", tzRaw*60))
}

func udfPermToFileMode(perm uint32, isDir bool) os.FileMode {
	other := os.FileMode((perm>>0)&0x04>>2) | os.FileMode((perm>>0)&0x02>>1) | os.FileMode((perm>>0)&0x01)
	group := os.FileMode((perm>>5)&0x04>>2) | os.FileMode((perm>>5)&0x02>>1) | os.FileMode((perm>>5)&0x01)
	owner := os.FileMode((perm>>10)&0x04>>2) | os.FileMode((perm>>10)&0x02>>1) | os.FileMode((perm>>10)&0x01)
	mode  := owner<<6 | group<<3 | other
	if mode == 0 {
		mode = 0444
	}
	if isDir {
		mode |= os.ModeDir | 0111
	}
	return mode
}

// --- fs.DirEntry / os.FileInfo adapters ---

type feAdapter struct{ e *fileEntry }

func (e *fileEntry) toDirEntry() fs.DirEntry { return feAdapter{e} }
func (e *fileEntry) toFileInfo() os.FileInfo { return feAdapter{e} }

func (a feAdapter) Name() string               { return a.e.name }
func (a feAdapter) Size() int64                { return int64(a.e.totalLen) }
func (a feAdapter) Mode() os.FileMode          { return a.e.mode }
func (a feAdapter) ModTime() time.Time         { return a.e.modTime }
func (a feAdapter) IsDir() bool                { return a.e.isDir }
func (a feAdapter) Sys() any                   { return nil }
func (a feAdapter) Type() fs.FileMode          { return fs.FileMode(a.e.mode.Type()) }
func (a feAdapter) Info() (fs.FileInfo, error) { return a, nil }

// --- udfFile: implements fs.File and io.ReaderAt ---

type udfFile struct {
	vol  *Volume
	fe   fileEntry
	r    io.Reader
	path string
}

func (f *udfFile) Read(b []byte) (int, error) { return f.r.Read(b) }
func (f *udfFile) Close() error               { return nil }
func (f *udfFile) Stat() (fs.FileInfo, error) { return f.fe.toFileInfo(), nil }

func (f *udfFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if !f.fe.isDir {
		return nil, fmt.Errorf("udf: %s: not a directory", f.path)
	}
	entries, err := f.vol.readDirEntries(&f.fe)
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

// ReadAt implements io.ReaderAt by mapping logical byte offsets across UDF
// extents, letting random-access readers (e.g. the WIM parser) work directly
// against the ISO without spooling to a temporary file.
func (f *udfFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("udf: ReadAt: negative offset")
	}
	if off >= int64(f.fe.totalLen) {
		return 0, io.EOF
	}
	if int64(len(p)) > int64(f.fe.totalLen)-off {
		p = p[:int64(f.fe.totalLen)-off]
	}

	if f.fe.inlineData != nil {
		n := copy(p, f.fe.inlineData[off:])
		if n < len(p) {
			return n, io.EOF
		}
		return n, nil
	}

	var (
		n      int
		cursor int64
	)
	for _, ext := range f.fe.extents {
		if n == len(p) {
			break
		}
		extLen := int64(ext.len)
		if off >= cursor+extLen {
			cursor += extLen
			continue
		}
		inOff   := off - cursor
		diskOff := int64(ext.lba)*region.SectorSize + inOff
		canRead := extLen - inOff
		if canRead > int64(len(p)-n) {
			canRead = int64(len(p) - n)
		}
		got, err := f.vol.sr.ReadBytes(diskOff, int(canRead))
		nc     := copy(p[n:], got)
		n      += nc
		off    += int64(nc)
		cursor += extLen
		if err != nil {
			return n, err
		}
	}

	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}