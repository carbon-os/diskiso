package iso9660

import (
	"io/fs"
	"os"
	"time"

	"github.com/carbon-os/diskiso/internal/region"
)

// dirEntry holds the parsed contents of one ISO 9660 directory record.
type dirEntry struct {
	name      string
	isDir     bool
	extentLBA uint32
	dataLen   uint32
	modTime   time.Time
	mode      os.FileMode

	// Rock Ridge fields (zero value = not present)
	rrName   string // alternate POSIX name from "NM" entries
	rrTarget string // symlink target from "SL" entries
	rrIsLink bool
}

// parseRecord parses one ISO 9660 / Joliet directory record from raw bytes.
//
// ISO 9660 directory record layout (§9.1):
//
//	0     1   Record length (including padding)
//	1     1   Extended attribute record length (usually 0)
//	2     8   Location of extent  — both-endian 32
//	10    8   Data length         — both-endian 32
//	18    7   Recording date/time
//	25    1   File flags
//	26    1   File unit size
//	27    1   Interleave gap size
//	28    4   Volume sequence number — both-endian 16
//	32    1   File identifier length (L)
//	33    L   File identifier
//	33+L      System Use Area (Rock Ridge lives here)
func parseRecord(rec []byte, mode Mode) (dirEntry, bool) {
	if len(rec) < 34 {
		return dirEntry{}, false
	}

	extentLBA := region.BothEndian32(rec[2:10])
	dataLen   := region.BothEndian32(rec[10:18])
	flags     := rec[25]
	idLen     := int(rec[32])
	isDir     := flags&0x02 != 0

	modTime := parseDateTime(rec[18:25])

	fm := os.FileMode(0444)
	if isDir {
		fm = 0555 | os.ModeDir
	}

	name := ""
	if idLen > 0 && 33+idLen <= len(rec) {
		raw := rec[33 : 33+idLen]
		if mode == ModeJoliet {
			name = decodeUCS2BE(raw)
		} else {
			name = stripVersion(string(raw))
		}
	}

	e := dirEntry{
		name:      name,
		isDir:     isDir,
		extentLBA: extentLBA,
		dataLen:   dataLen,
		modTime:   modTime,
		mode:      fm,
	}

	if mode == ModeRockRidge {
		suaStart := 33 + idLen
		if suaStart%2 != 0 {
			suaStart++
		}
		if suaStart < len(rec) {
			parseRockRidge(rec[suaStart:], &e)
		}
	}

	return e, true
}

// parseDateTime decodes the 7-byte ISO 9660 directory record date/time.
//
//	0  Years since 1900
//	1  Month (1–12)
//	2  Day   (1–31)
//	3  Hour  (0–23)
//	4  Minute
//	5  Second
//	6  GMT offset in 15-minute intervals (signed)
func parseDateTime(b []byte) time.Time {
	if len(b) < 7 {
		return time.Time{}
	}
	year   := int(b[0]) + 1900
	month  := time.Month(b[1])
	day    := int(b[2])
	hour   := int(b[3])
	min    := int(b[4])
	sec    := int(b[5])
	offset := int(int8(b[6])) * 15 * int(time.Minute)
	return time.Date(year, month, day, hour, min, sec, 0, time.FixedZone("", offset))
}

// stripVersion removes the ISO 9660 version suffix (";1") and trailing dot.
func stripVersion(name string) string {
	for i, c := range name {
		if c == ';' {
			name = name[:i]
			break
		}
	}
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}

// effectiveName returns the Rock Ridge name when present, otherwise the ISO name.
func (e *dirEntry) effectiveName() string {
	if e.rrName != "" {
		return e.rrName
	}
	return e.name
}

// --- fs.DirEntry / os.FileInfo adapters ---

type dirEntryAdapter struct{ e dirEntry }
type fileInfoAdapter struct{ e dirEntry }

func (d dirEntry) toDirEntry() fs.DirEntry { return dirEntryAdapter{d} }
func (d dirEntry) toFileInfo() os.FileInfo { return fileInfoAdapter{d} }

func (a dirEntryAdapter) Name() string               { return a.e.effectiveName() }
func (a dirEntryAdapter) IsDir() bool                { return a.e.isDir }
func (a dirEntryAdapter) Type() fs.FileMode          { return fs.FileMode(a.e.mode.Type()) }
func (a dirEntryAdapter) Info() (fs.FileInfo, error) { return fileInfoAdapter{a.e}, nil }

func (a fileInfoAdapter) Name() string       { return a.e.effectiveName() }
func (a fileInfoAdapter) Size() int64        { return int64(a.e.dataLen) }
func (a fileInfoAdapter) Mode() os.FileMode  { return a.e.mode }
func (a fileInfoAdapter) ModTime() time.Time { return a.e.modTime }
func (a fileInfoAdapter) IsDir() bool        { return a.e.isDir }
func (a fileInfoAdapter) Sys() any           { return nil }