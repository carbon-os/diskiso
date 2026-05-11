package udf

import (
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
//
// UDF structural summary:
//
//	sector 256      Anchor Volume Descriptor Pointer (AVDP, tag=2)
//	AVDP → VDS     Volume Descriptor Sequence
//	VDS contains   Logical Volume Descriptor (tag=6) + Partition Descriptor (tag=5)
//	Partition      File Set Descriptor (tag=256) → root ICB (File Entry, tag=260/261)
//	File Entry     Allocation Descriptors → file data
type Volume struct {
	sr         *region.SectorReader
	partStart  uint32 // first sector of the UDF partition
	partLen    uint32 // length of partition in sectors
	rootICBLBA uint32 // absolute LBA of root directory File Entry
	label      string
	size       int64
}

// NewVolume parses UDF structural metadata and returns a ready-to-use Volume.
func NewVolume(r io.ReaderAt) (*Volume, error) {
	sr := region.NewSectorReader(r)
	v := &Volume{sr: sr}
	if err := v.parseAnchor(); err != nil {
		return nil, fmt.Errorf("udf: anchor: %w", err)
	}
	return v, nil
}

// parseAnchor reads the AVDP at sector 256, then walks the Main VDS.
func (v *Volume) parseAnchor() error {
	sec, err := v.sr.ReadSector(udfAnchorSector)
	if err != nil {
		return err
	}
	// AVDP: tag(16) mainVDS_extent(8) reserveVDS_extent(8)
	// Extent: length(4 LE) + location(4 LE)
	mainLen := binary.LittleEndian.Uint32(sec[16:20])
	mainLBA := binary.LittleEndian.Uint32(sec[20:24])
	return v.parseVDS(mainLBA, mainLen)
}

// parseVDS walks the Volume Descriptor Sequence for the Logical Volume
// Descriptor and Partition Descriptor.
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
		case 5: // Partition Descriptor
			partStart = binary.LittleEndian.Uint32(sec[188:192])
			partLen   = binary.LittleEndian.Uint32(sec[192:196])
			partFound = true

		case 6: // Logical Volume Descriptor
			// FSD location: long_ad at LVD offset 248
			// long_ad: length(4) + location: LBA(4) + partNum(2)
			fsdLBA  = binary.LittleEndian.Uint32(sec[252:256])
			fsdFound = true

		case 8: // Terminating Descriptor
			goto done
		}
	}
done:
	if !partFound || !fsdFound {
		return errors.New("udf: missing Partition or Logical Volume Descriptor")
	}

	v.partStart = partStart
	v.partLen   = partLen
	v.size = int64(partStart+partLen) * region.SectorSize

	return v.parseFSD(v.partStart + fsdLBA)
}

// parseFSD reads the File Set Descriptor to obtain the root ICB location
// and volume label.
func (v *Volume) parseFSD(lba uint32) error {
	sec, err := v.sr.ReadSector(lba)
	if err != nil {
		return err
	}
	tagID := binary.LittleEndian.Uint16(sec[0:2])
	if tagID != 256 {
		return fmt.Errorf("udf: expected FSD (tag 256) at sector %d, got %d", lba, tagID)
	}

	// Root Directory ICB: long_ad at FSD offset 400
	// long_ad: extentLength(4) + extentLocation: LBA(4) + partNum(2)
	v.rootICBLBA = v.partStart + binary.LittleEndian.Uint32(sec[404:408])

	// Logical Volume Identifier: CS0 string at FSD offset 84, length 128
	v.label = decodeCS0(trimNull(sec[84:212]))

	return nil
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
	return v.sr.ReadBytes(int64(fe.dataLBA)*region.SectorSize, int(fe.dataLen))
}

func (v *Volume) Open(filePath string) (fs.File, error) {
	fe, err := v.lookupFileEntry(filePath)
	if err != nil {
		return nil, err
	}
	return &udfFile{
		vol:  v,
		fe:   *fe,
		r:    v.sr.NewExtentReader(fe.dataLBA, int64(fe.dataLen)),
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

// --- UDF File Entry ---

type fileEntry struct {
	name    string
	isDir   bool
	dataLBA uint32
	dataLen uint32
	modTime time.Time
	mode    os.FileMode
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

	// File Entry layout (ECMA-167 §14.9):
	//   offset 16: ICB Tag (20 bytes); file type at ICB tag offset 11 → absolute offset 27
	//   offset 40: Permissions (4 bytes LE)
	//   offset 56: Information Length (8 bytes LE)
	//   offset 72: Modification Time (12-byte UDF timestamp)
	//   offset 168: Length of Extended Attributes (4 bytes LE)
	//   offset 172: Length of Allocation Descriptors (4 bytes LE)
	//   offset 176+eaLen: Allocation Descriptors

	icbFileType := sec[27]
	infoLen     := binary.LittleEndian.Uint64(sec[56:64])
	eaLen       := binary.LittleEndian.Uint32(sec[168:172])
	adLen       := binary.LittleEndian.Uint32(sec[172:176])
	adStart     := 176 + int(eaLen)

	isDir   := icbFileType == 4
	modTime := parseUDFTimestamp(sec[72:84])

	posixPerm := binary.LittleEndian.Uint32(sec[40:44])
	mode := udfPermToFileMode(posixPerm, isDir)

	fe := &fileEntry{
		isDir:   isDir,
		modTime: modTime,
		mode:    mode,
		dataLen: uint32(infoLen),
	}

	// Parse the first Short Allocation Descriptor for the data LBA.
	// Short AD: extentLength(4 LE) + extentPosition(4 LE)
	// High 2 bits of extentLength encode the extent type; mask them off.
	if adLen >= 8 && adStart+8 <= len(sec) {
		adData  := sec[adStart : adStart+int(adLen)]
		extLen  := binary.LittleEndian.Uint32(adData[0:4]) & 0x3FFFFFFF
		extPos  := binary.LittleEndian.Uint32(adData[4:8])
		fe.dataLBA = v.partStart + extPos
		if extLen > 0 {
			fe.dataLen = extLen
		}
	}

	return fe, nil
}

// lookupFileEntry resolves an absolute path to its File Entry.
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

	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
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
		curLBA = found.dataLBA
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

// readDirEntries reads File Identifier Descriptors from a directory's data extent.
func (v *Volume) readDirEntries(fe *fileEntry) ([]*fileEntry, error) {
	data, err := v.sr.ReadBytes(int64(fe.dataLBA)*region.SectorSize, int(fe.dataLen))
	if err != nil {
		return nil, err
	}

	var entries []*fileEntry
	for offset := 0; offset+38 <= len(data); {
		tagID := binary.LittleEndian.Uint16(data[offset : offset+2])
		if tagID != 257 {
			break
		}

		// FID layout (ECMA-167 §14.4):
		//   0   16  Descriptor Tag
		//   16   2  File Version Number
		//   18   1  File Characteristics (bit 3=parent, bit 1=directory)
		//   19   1  Length of File Identifier (L_FI)
		//   20   8  ICB long_ad: length(4) + location: LBA(4) + partNum(2)
		//   28   2  Length of Implementation Use (L_IU)
		//   30  L_IU  Implementation Use
		//   30+L_IU  L_FI  File Identifier (CS0 string)
		fileChars := data[offset+18]
		lfi       := int(data[offset+19])
		icbLBA    := binary.LittleEndian.Uint32(data[offset+24 : offset+28])
		liu       := int(binary.LittleEndian.Uint16(data[offset+28 : offset+30]))

		isParent := fileChars&0x08 != 0
		isDir    := fileChars&0x02 != 0

		nameStart := offset + 30 + liu
		name := ""
		if lfi > 0 && nameStart+lfi <= len(data) {
			name = decodeCS0(data[nameStart : nameStart+lfi])
		}

		// FID total size = 30 + L_IU + L_FI, padded to a 4-byte boundary
		totalLen := 30 + liu + lfi
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

func trimNull(b []byte) []byte {
	for i, v := range b {
		if v == 0 {
			return b[:i]
		}
	}
	return b
}

// decodeCS0 decodes a UDF CS0 "Compressed Unicode" string.
// Compression ID 8 = 8-bit chars, 16 = UTF-16BE.
func decodeCS0(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	compressionID := b[0]
	content := b[1:]
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

// parseUDFTimestamp decodes a 12-byte UDF timestamp (ECMA-167 §7.3).
//
//	type+tz(2) year(2) month(1) day(1) hour(1) min(1) sec(1) centi(1) micro(1) nano(1)
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
	// Timezone: lower 12 bits of b[0:2], signed, in minutes
	tzRaw := int(binary.LittleEndian.Uint16(b[0:2]) & 0x0FFF)
	if tzRaw&0x800 != 0 {
		tzRaw -= 0x1000 // sign-extend 12-bit
	}
	return time.Date(year, month, day, hour, min, sec, 0, time.FixedZone("", tzRaw*60))
}

// udfPermToFileMode converts UDF POSIX-style permissions to os.FileMode.
// UDF permission layout: other(5 bits: rwxDA) | group(5) | owner(5)
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
func (a feAdapter) Size() int64                { return int64(a.e.dataLen) }
func (a feAdapter) Mode() os.FileMode          { return a.e.mode }
func (a feAdapter) ModTime() time.Time         { return a.e.modTime }
func (a feAdapter) IsDir() bool                { return a.e.isDir }
func (a feAdapter) Sys() any                   { return nil }
func (a feAdapter) Type() fs.FileMode          { return fs.FileMode(a.e.mode.Type()) }
func (a feAdapter) Info() (fs.FileInfo, error) { return a, nil }

// --- udfFile: implements fs.File for streaming reads ---

type udfFile struct {
	vol  *Volume
	fe   fileEntry
	r    io.Reader
	path string
}

func (f *udfFile) Read(b []byte) (int, error)        { return f.r.Read(b) }
func (f *udfFile) Close() error                       { return nil }
func (f *udfFile) Stat() (fs.FileInfo, error)         { return f.fe.toFileInfo(), nil }
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