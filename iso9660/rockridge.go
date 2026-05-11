package iso9660

import (
	"encoding/binary"
	"os"
	"strings"
	"time"
)

// parseRockRidge reads SUSP System Use fields from a directory record and
// updates the entry in-place.
//
// SUSP field layout:
//
//	0  2  Signature ("NM", "SL", "PX", "TF", "CE", "SP", "RR" …)
//	2  1  Length of this field (including header)
//	3  1  System Use Entry Version
//	4+    Field-specific data
func parseRockRidge(sua []byte, e *dirEntry) {
	for i := 0; i+4 <= len(sua); {
		sig    := string(sua[i : i+2])
		length := int(sua[i+2])
		if length < 4 || i+length > len(sua) {
			break
		}
		data := sua[i+4 : i+length]

		switch sig {
		case "NM": // Alternate Name
			parseNM(data, e)
		case "SL": // Symbolic Link
			parseSL(data, e)
		case "PX": // POSIX File Attributes
			parsePX(data, e)
		case "TF": // Timestamps
			parseTF(data, e)
		// "CE" (Continuation Area) skipped — complex, rarely needed
		}
		i += length
	}
}

// parseNM decodes a Rock Ridge "NM" (alternate name) field.
// Flags: bit 0 = continued, bit 1 = current dir, bit 2 = parent dir.
func parseNM(data []byte, e *dirEntry) {
	if len(data) < 1 {
		return
	}
	if data[0]&0x06 != 0 {
		return // "." or ".." — skip
	}
	e.rrName += string(data[1:])
}

// parseSL decodes a Rock Ridge "SL" (symbolic link) field.
func parseSL(data []byte, e *dirEntry) {
	if len(data) < 1 {
		return
	}
	var parts []string
	i := 1
	for i < len(data) {
		if i+2 > len(data) {
			break
		}
		compFlags  := data[i]
		compLength := int(data[i+1])
		i += 2
		switch {
		case compFlags&0x08 != 0: // root
			parts = append(parts, "")
		case compFlags&0x04 != 0: // parent
			parts = append(parts, "..")
		case compFlags&0x02 != 0: // current
			parts = append(parts, ".")
		default:
			if i+compLength > len(data) {
				break
			}
			parts = append(parts, string(data[i:i+compLength]))
			i += compLength
		}
	}
	e.rrTarget = strings.Join(parts, "/")
	if e.rrTarget != "" {
		e.rrIsLink = true
		e.mode |= os.ModeSymlink
	}
}

// parsePX decodes a Rock Ridge "PX" (POSIX attributes) field.
func parsePX(data []byte, e *dirEntry) {
	if len(data) < 8 {
		return
	}
	// mode is a both-endian 32-bit field; take the LE half
	posixMode := binary.LittleEndian.Uint32(data[:4])
	e.mode = os.FileMode(posixMode & 0x1FF)
	switch posixMode & 0xF000 {
	case 0x4000:
		e.mode |= os.ModeDir
	case 0xA000:
		e.mode |= os.ModeSymlink
	}
}

// parseTF decodes a Rock Ridge "TF" (timestamps) field.
// Only the modification time (flag bit 1) is extracted.
func parseTF(data []byte, e *dirEntry) {
	if len(data) < 1 {
		return
	}
	flags     := data[0]
	longForm  := flags&0x80 != 0 // 17-byte dec-datetime vs 7-byte binary
	fieldSize := 7
	if longForm {
		fieldSize = 17
	}

	// Bit layout: creation(0) modify(1) access(2) attrib(3) backup(4) expire(5) effect(6)
	idx := 1
	for bit := 0; bit < 7; bit++ {
		if idx+fieldSize > len(data) {
			break
		}
		if flags&(1<<uint(bit)) != 0 {
			if bit == 1 { // modification time
				if longForm {
					e.modTime = parseDecDateTime(data[idx : idx+17])
				} else {
					e.modTime = parseDateTime(data[idx : idx+7])
				}
			}
			idx += fieldSize
		}
	}
}

// parseDecDateTime decodes a 17-byte ISO 9660 PVD dec-datetime string.
//
//	"YYYYMMDDHHMMSSCC" + timezone offset byte (17 bytes total)
func parseDecDateTime(b []byte) time.Time {
	if len(b) < 17 {
		return time.Time{}
	}
	parse := func(s []byte) int {
		n := 0
		for _, c := range s {
			n = n*10 + int(c-'0')
		}
		return n
	}
	year   := parse(b[0:4])
	month  := time.Month(parse(b[4:6]))
	day    := parse(b[6:8])
	hour   := parse(b[8:10])
	min    := parse(b[10:12])
	sec    := parse(b[12:14])
	offset := int(int8(b[16])) * 15 * int(time.Minute)
	return time.Date(year, month, day, hour, min, sec, 0, time.FixedZone("", offset))
}