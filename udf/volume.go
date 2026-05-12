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
//
// AVDP layout (ECMA-167 3/10.2):
//
//	BP  0  Descriptor Tag           (16 bytes)
//	BP 16  Main VDS Extent          (extent_ad: length=4, location=4)
//	BP 24  Reserve VDS Extent       (extent_ad: 8 bytes)
//	BP 32  Reserved                 (480 bytes)
func (v *Volume) parseAnchor() error {
	sec, err := v.sr.ReadSector(udfAnchorSector)
	if err != nil {
		return err
	}
	mainLen := binary.LittleEndian.Uint32(sec[16:20])
	mainLBA := binary.LittleEndian.Uint32(sec[20:24])
	return v.parseVDS(mainLBA, mainLen)
}

// parseVDS walks the Volume Descriptor Sequence for the Logical Volume
// Descriptor and Partition Descriptor.
//
// Partition Descriptor (tag=5) layout (ECMA-167 3/10.5):
//
//	BP   0  Descriptor Tag          (16)
//	BP  16  VDS Sequence Number     (4)
//	BP  20  Partition Flags         (2)
//	BP  22  Partition Number        (2)
//	BP  24  Partition Contents regid(32)
//	BP  56  Partition Contents Use  (128)
//	BP 184  Access Type             (4)
//	BP 188  Partition Starting LBA  (4)  ← partStart
//	BP 192  Partition Length        (4)  ← partLen
//
// Logical Volume Descriptor (tag=6) layout (ECMA-167 3/10.6):
//
//	BP   0  Descriptor Tag          (16)
//	BP  16  VDS Sequence Number     (4)
//	BP  20  Descriptor Char Set     (charspec=64)
//	BP  84  unused padding to 128…  actually charspec is 64 bytes:
//	        descCharSet             (64) → [20:84]
//	BP  84  Logical Vol Identifier  (dstring[128]) → [84:212]
//	BP 212  Logical Block Size      (4)
//	BP 216  Domain Identifier       (regid=32)
//	BP 248  Logical Vol Contents Use(long_ad=16): FSD location
//	            extLength           [248:252]
//	            logicalBlockNum     [252:256]  ← fsdLBA (partition-relative)
//	            partitionRef        [256:258]
//	            impUse              [258:264]
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
			// BP 188: Partition Starting Location (ECMA-167 3/10.5)
			partStart = binary.LittleEndian.Uint32(sec[188:192])
			partLen   = binary.LittleEndian.Uint32(sec[192:196])
			partFound = true

		case 6: // Logical Volume Descriptor
			// BP 248: Logical Volume Contents Use (long_ad).
			// long_ad: extLength(4) + lb_addr{ logicalBlockNum(4) partRef(2) } + impUse(6)
			// FSD LBA is the logicalBlockNum at BP 252 (partition-relative).
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
	v.size      = int64(partStart+partLen) * region.SectorSize

	return v.parseFSD(v.partStart + fsdLBA)
}

// parseFSD reads the File Set Descriptor to obtain the root ICB location
// and volume label.
//
// File Set Descriptor (tag=256) layout (ECMA-167 4/14.1):
//
//	BP   0  Descriptor Tag                  (16)
//	BP  16  Recording Date and Time         (12)
//	BP  28  Interchange Level               (2)
//	BP  30  Maximum Interchange Level       (2)
//	BP  32  Character Set List              (4)
//	BP  36  Maximum Character Set List      (4)
//	BP  40  File Set Number                 (4)
//	BP  44  File Set Descriptor Number      (4)
//	BP  48  Logical Vol Identifier Char Set (charspec=64)
//	BP 112  Logical Vol Identifier          (dstring[128]) ← volume label
//	BP 240  File Set Char Set               (charspec=64)
//	BP 304  File Set Identifier             (dstring[32])
//	BP 336  Copyright File Identifier       (dstring[32])
//	BP 368  Abstract File Identifier        (dstring[32])
//	BP 400  Root Directory ICB              (long_ad=16)
//	            extLength                   [400:404]
//	            logicalBlockNum             [404:408]  ← root ICB LBA (partition-relative)
//	            partitionRef                [408:410]
//	            impUse                      [410:416]
func (v *Volume) parseFSD(lba uint32) error {
	sec, err := v.sr.ReadSector(lba)
	if err != nil {
		return err
	}
	tagID := binary.LittleEndian.Uint16(sec[0:2])
	if tagID != 256 {
		return fmt.Errorf("udf: expected FSD (tag 256) at sector %d, got %d", lba, tagID)
	}

	// Root Directory ICB: long_ad at FSD BP 400; logicalBlockNum at BP 404.
	v.rootICBLBA = v.partStart + binary.LittleEndian.Uint32(sec[404:408])

	// Logical Volume Identifier (dstring[128]) at FSD BP 112
	// For a dstring, the actual length is stored in the final byte of the field.
	field := sec[112:240]
	strLen := int(field[127])
	if strLen > 0 && strLen <= 127 {
		v.label = decodeCS0(field[:strLen])
	}

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
	if fe.inlineData != nil {
		return fe.inlineData, nil
	}
	return v.sr.ReadBytes(int64(fe.dataLBA)*region.SectorSize, int(fe.dataLen))
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
		r = v.sr.NewExtentReader(fe.dataLBA, int64(fe.dataLen))
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

// --- UDF File Entry ---

type fileEntry struct {
	name       string
	isDir      bool
	feLBA      uint32 // First Fix: Added feLBA
	dataLBA    uint32
	dataLen    uint32
	modTime    time.Time
	mode       os.FileMode
	inlineData []byte // Holds data if allocType == 3
}

// parseFileEntry handles both File Entry (tag 260, ECMA-167 4/14.9) and
// Extended File Entry (tag 261, ECMA-167 4/14.17).
//
// File Entry (tag 260) layout:
//
//	BP   0  Descriptor Tag          (16)
//	BP  16  ICB Tag                 (20)  fileType at RBP 11 → BP 27
//	BP  36  UID                     (4)
//	BP  40  GID                     (4)
//	BP  44  Permissions             (4)   ← POSIX mode bits
//	BP  48  File Link Count         (2)
//	BP  50  Record Format           (1)
//	BP  51  Record Display Attribs  (1)
//	BP  52  Record Length           (4)
//	BP  56  Information Length      (8)
//	BP  64  Logical Blocks Recorded (8)
//	BP  72  Access Date/Time        (12)
//	BP  84  Modification Date/Time  (12)  ← modTime
//	BP  96  Attribute Date/Time     (12)
//	BP 108  Checkpoint              (4)
//	BP 112  Extended Attribute ICB  (long_ad=16)
//	BP 128  Implementation Ident    (regid=32)
//	BP 160  Unique ID               (8)
//	BP 168  Length of Ext Attribs   (4)   ← eaLen
//	BP 172  Length of Alloc Descs   (4)   ← adLen
//	BP 176  Extended Attributes     (eaLen bytes)
//	BP 176+eaLen  Allocation Descs  (adLen bytes)
//
// Extended File Entry (tag 261) differs from BP 96 onward — it inserts
// createDateAndTime (12) and a reserved (8) field, shifting the remainder:
//
//	BP  96  Create Date/Time        (12)  ← extra
//	BP 108  Attribute Date/Time     (12)
//	BP 120  Checkpoint              (4)
//	BP 124  Reserved                (8)   ← extra
//	BP 132  Extended Attribute ICB  (long_ad=16)
//	BP 148  Stream Directory ICB    (long_ad=16)  ← extra
//	BP 164  Implementation Ident    (regid=32)
//	BP 196  Unique ID               (8)
//	BP 204  Length of Ext Attribs   (4)   ← eaLen
//	BP 208  Length of Alloc Descs   (4)   ← adLen
//	BP 212  Extended Attributes     (eaLen bytes)
//	BP 212+eaLen  Allocation Descs  (adLen bytes)
func (v *Volume) parseFileEntry(lba uint32) (*fileEntry, error) {
	sec, err := v.sr.ReadSector(lba)
	if err != nil {
		return nil, err
	}
	tagID := binary.LittleEndian.Uint16(sec[0:2])
	if tagID != 260 && tagID != 261 {
		return nil, fmt.Errorf("udf: expected File Entry at sector %d (tag 260/261), got %d", lba, tagID)
	}

	// ICB Tag: BP 16, fileType at RBP 11 → absolute BP 27.
	icbFileType := sec[27]
	isDir       := icbFileType == 4

	// Information Length: BP 56 for both tag 260 and 261.
	infoLen := binary.LittleEndian.Uint64(sec[56:64])

	// Modification Date/Time: BP 84 for both tag 260 and 261.
	modTime := parseUDFTimestamp(sec[84:96])

	// Permissions: BP 44 for both tag 260 and 261.
	posixPerm := binary.LittleEndian.Uint32(sec[44:48])
	mode      := udfPermToFileMode(posixPerm, isDir)

	// ICB flags: BP 34
	icbFlags := binary.LittleEndian.Uint16(sec[34:36])
	allocType := icbFlags & 0x0007

	// eaLen / adLen / allocDesc base differ between tag 260 and tag 261.
	var eaLenOff, adLenOff, adBase int
	if tagID == 261 { // Extended File Entry (ECMA-167 4/14.17)
		eaLenOff = 208
		adLenOff = 212
		adBase   = 216
	} else { // Regular File Entry
		eaLenOff = 168
		adLenOff = 172
		adBase   = 176
	}

	eaLen := binary.LittleEndian.Uint32(sec[eaLenOff : eaLenOff+4])
	adLen := binary.LittleEndian.Uint32(sec[adLenOff : adLenOff+4])
	adStart := adBase + int(eaLen)

	// WORKAROUND: Microsoft oscdimg bug.
	// Windows ISOs often master Extended File Entries (Tag 261) using
	// the internal offsets of a Regular File Entry (Tag 260).
	if tagID == 261 {
		feEaLen := binary.LittleEndian.Uint32(sec[168:172])
		feAdLen := binary.LittleEndian.Uint32(sec[172:176])
		feAdStart := 176 + int(feEaLen)

		if allocType == 3 {
			// For inline data, adLen should match infoLen
			if adLen != uint32(infoLen) && feAdLen == uint32(infoLen) {
				adStart, adLen = feAdStart, feAdLen
			}
		} else {
			// For pointers, the extLen inside the pointer should match infoLen (or > 0)
			efeExtLen := uint32(0)
			if adStart+4 <= len(sec) {
				efeExtLen = binary.LittleEndian.Uint32(sec[adStart:adStart+4]) & 0x3FFFFFFF
			}
			feExtLen := uint32(0)
			if feAdStart+4 <= len(sec) {
				feExtLen = binary.LittleEndian.Uint32(sec[feAdStart:feAdStart+4]) & 0x3FFFFFFF
			}

			// If EFE gives a garbage 0-length pointer, but the FE offset is valid:
			if efeExtLen == 0 && feExtLen > 0 {
				adStart, adLen = feAdStart, feAdLen
			}
		}
	}

	fe := &fileEntry{
		isDir:   isDir,
		feLBA:   lba,     // Second Fix: Save the feLBA here
		modTime: modTime,
		mode:    mode,
		dataLen: uint32(infoLen),
	}

	// Extract Allocation Descriptors or Inline Data
	if allocType == 3 {
		// Inline data: The data is embedded directly in the AD space
		fe.dataLBA = 0
		if adLen > 0 && adStart+int(adLen) <= len(sec) {
			fe.inlineData = make([]byte, adLen)
			copy(fe.inlineData, sec[adStart:adStart+int(adLen)])
		}
	} else if adLen >= 8 && adStart+8 <= len(sec) {
		// Short/Long AD fallback: The first 8 bytes of both Short and Long ADs 
		// contain the Length and partition-relative LBA.
		adData := sec[adStart : adStart+int(adLen)]
		extLen := binary.LittleEndian.Uint32(adData[0:4]) & 0x3FFFFFFF
		extPos := binary.LittleEndian.Uint32(adData[4:8])
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
		curLBA = found.feLBA // Third Fix: Jump to the File Entry LBA instead of dataLBA
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
//
// File Identifier Descriptor (FID, tag=257) layout (ECMA-167 4/14.4):
//
//	BP  0  Descriptor Tag           (16)
//	BP 16  File Version Number      (2)
//	BP 18  File Characteristics     (1)  bit1=directory, bit3=parent
//	BP 19  Length of File Ident L_FI(1)
//	BP 20  ICB                      (long_ad=16)
//	           extLength            [20:24]
//	           logicalBlockNum      [24:28]  ← child File Entry LBA (partition-relative)
//	           partitionRef         [28:30]
//	           impUse               [30:36]
//	BP 36  Length of Impl Use L_IU  (2)      ← liu
//	BP 38  Implementation Use       (L_IU bytes)
//	BP 38+L_IU  File Identifier     (L_FI bytes, CS0 string)
//	            Padding to 4-byte boundary
//
// Total size = 38 + L_IU + L_FI, rounded up to next multiple of 4.
func (v *Volume) readDirEntries(fe *fileEntry) ([]*fileEntry, error) {
	var data []byte
	var err error
	if fe.inlineData != nil {
		data = fe.inlineData
	} else {
		data, err = v.sr.ReadBytes(int64(fe.dataLBA)*region.SectorSize, int(fe.dataLen))
		if err != nil {
			return nil, err
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

		// ICB long_ad: logicalBlockNum at FID BP 24 (partition-relative LBA).
		icbLBA := binary.LittleEndian.Uint32(data[offset+24 : offset+28])

		// Length of Implementation Use at FID BP 36.
		liu := int(binary.LittleEndian.Uint16(data[offset+36 : offset+38]))

		isParent := fileChars&0x08 != 0
		isDir    := fileChars&0x02 != 0

		// File Identifier starts at FID BP 38 + L_IU.
		nameStart := offset + 38 + liu
		name := ""
		if lfi > 0 && nameStart+lfi <= len(data) {
			name = decodeCS0(data[nameStart : nameStart+lfi])
		}

		// FID total size = 38 + L_IU + L_FI, padded to 4-byte boundary.
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
	tzRaw := int(binary.LittleEndian.Uint16(b[0:2]) & 0x0FFF)
	if tzRaw&0x800 != 0 {
		tzRaw -= 0x1000
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