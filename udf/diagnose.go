package udf

import (
	"encoding/binary"
	"fmt"
	"os"

	"github.com/carbon-os/diskiso/internal/region"
)

// Diagnose opens an ISO and walks the entire UDF chain, printing every
// intermediate value so broken offsets are immediately visible.
func Diagnose(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	sr := region.NewSectorReader(f)

	fmt.Println("=== UDF Diagnostic ===")
	fmt.Printf("Image: %s\n\n", path)

	// ── 1. AVDP at sector 256 ──────────────────────────────────────────────
	fmt.Println("── AVDP (sector 256) ──────────────────────────────────────────────")
	avdp, err := sr.ReadSector(udfAnchorSector)
	if err != nil {
		return fmt.Errorf("AVDP read: %w", err)
	}
	avdpTag := binary.LittleEndian.Uint16(avdp[0:2])
	mainLen := binary.LittleEndian.Uint32(avdp[16:20])
	mainLBA := binary.LittleEndian.Uint32(avdp[20:24])
	resLen  := binary.LittleEndian.Uint32(avdp[24:28])
	resLBA  := binary.LittleEndian.Uint32(avdp[28:32])
	fmt.Printf("  Tag ID             : %d (want 2)\n", avdpTag)
	fmt.Printf("  Main  VDS extent   : LBA=%-6d  len=%d bytes (%d sectors)\n",
		mainLBA, mainLen, (mainLen+2047)/2048)
	fmt.Printf("  Reserve VDS extent : LBA=%-6d  len=%d bytes\n\n", resLBA, resLen)

	if avdpTag != 2 {
		return fmt.Errorf("sector 256 is not an AVDP (tag=%d)", avdpTag)
	}

	// ── 2. Walk VDS ────────────────────────────────────────────────────────
	numSectors := (mainLen + 2047) / 2048
	fmt.Printf("── VDS (starting sector %d, %d sectors) ──────────────────────────\n",
		mainLBA, numSectors)

	var partStart, partLen, fsdRelLBA uint32
	var partFound, lvdFound bool

	for i := uint32(0); i < numSectors; i++ {
		lba := mainLBA + i
		sec, err := sr.ReadSector(lba)
		if err != nil {
			fmt.Printf("  sector %d: read error: %v\n", lba, err)
			break
		}
		tid := binary.LittleEndian.Uint16(sec[0:2])

		switch tid {
		case 0:
			fmt.Printf("  sector %d: empty (tag=0)\n", lba)

		case 1:
			seqNum := binary.LittleEndian.Uint32(sec[16:20])
			fmt.Printf("  sector %d: Primary Volume Descriptor       (tag=1, seq=%d)\n", lba, seqNum)

		case 4:
			seqNum := binary.LittleEndian.Uint32(sec[16:20])
			fmt.Printf("  sector %d: Implementation Use VD           (tag=4, seq=%d)\n", lba, seqNum)

		case 5: // Partition Descriptor
			// Layout (ECMA-167 3/10.5):
			//   BP  0: tag (16)
			//   BP 16: volDescSeqNum (4)
			//   BP 20: partitionFlags (2)
			//   BP 22: partitionNumber (2)
			//   BP 24: partitionContents regid (32)
			//   BP 56: partitionContentsUse (128)
			//   BP 184: accessType (4)
			//   BP 188: partitionStartingLocation (4)
			//   BP 192: partitionLength (4)
			seqNum := binary.LittleEndian.Uint32(sec[16:20])
			pNum   := binary.LittleEndian.Uint16(sec[22:24])
			pStart := binary.LittleEndian.Uint32(sec[188:192])
			pLen   := binary.LittleEndian.Uint32(sec[192:196])
			fmt.Printf("  sector %d: Partition Descriptor            (tag=5, seq=%d)\n", lba, seqNum)
			fmt.Printf("             partNum=%-4d  startLBA=%-6d  length=%d sectors\n",
				pNum, pStart, pLen)
			partStart = pStart
			partLen   = pLen
			partFound = true

		case 6: // Logical Volume Descriptor
			// Layout (ECMA-167 3/10.6):
			//   BP   0: tag (16)
			//   BP  16: volDescSeqNum (4)
			//   BP  20: descCharSet charspec (64)
			//   BP  84: logicalVolIdent dstring (128)
			//   BP 212: logicalBlockSize (4)
			//   BP 216: domainIdent regid (32)
			//   BP 248: logicalVolContentsUse long_ad (16)
			//              extLength    [248:252]
			//              logBlockNum  [252:256]  ← FSD partition-relative LBA
			//              partRef      [256:258]
			//              impUse       [258:264]
			//   BP 264: mapTableLength (4)
			//   BP 268: numPartitionMaps (4)
			//   BP 272: impIdent regid (32)
			//   BP 304: impUse (128)
			//   BP 432: integritySeqExt extent_ad (8)
			//   BP 440: partitionMaps[]
			seqNum       := binary.LittleEndian.Uint32(sec[16:20])
			lvcExtLen    := binary.LittleEndian.Uint32(sec[248:252])
			lvcLBA       := binary.LittleEndian.Uint32(sec[252:256])
			lvcPart      := binary.LittleEndian.Uint16(sec[256:258])
			mapTableLen  := binary.LittleEndian.Uint32(sec[264:268])
			numMaps      := binary.LittleEndian.Uint32(sec[268:272])
			fmt.Printf("  sector %d: Logical Volume Descriptor       (tag=6, seq=%d)\n", lba, seqNum)
			fmt.Printf("             LVC long_ad: extLen=%-6d  relLBA=%-6d  partRef=%d\n",
				lvcExtLen, lvcLBA, lvcPart)
			fmt.Printf("             mapTableLen=%-4d  numPartMaps=%d\n", mapTableLen, numMaps)

			// Partition maps start at BP 440 (after impIdent+impUse+integritySeqExt)
			mapOff := 440
			for m := uint32(0); m < numMaps && mapOff+2 <= len(sec); m++ {
				pmType := sec[mapOff]
				pmLen  := int(sec[mapOff+1])
				if pmType == 1 && pmLen >= 6 {
					volSeq  := binary.LittleEndian.Uint16(sec[mapOff+2 : mapOff+4])
					partNum := binary.LittleEndian.Uint16(sec[mapOff+4 : mapOff+6])
					fmt.Printf("             PartMap[%d]: type=1 (Type1)  volSeq=%-3d  partNum=%d\n",
						m, volSeq, partNum)
				} else if pmType == 2 && pmLen >= 2 {
					fmt.Printf("             PartMap[%d]: type=2 (Type2/virtual/sparing)  len=%d\n",
						m, pmLen)
				} else {
					fmt.Printf("             PartMap[%d]: type=%d  len=%d  raw=% x\n",
						m, pmType, pmLen, sec[mapOff:minI(mapOff+pmLen, len(sec))])
				}
				if pmLen == 0 {
					break
				}
				mapOff += pmLen
			}
			fsdRelLBA = lvcLBA
			lvdFound  = true

		case 7:
			fmt.Printf("  sector %d: Logical Volume Integrity Desc Ptr (tag=7)\n", lba)

		case 8:
			fmt.Printf("  sector %d: Terminating Descriptor           (tag=8)\n", lba)
			goto vdsDone

		case 9:
			fmt.Printf("  sector %d: Logical Volume Integrity Descriptor (tag=9)\n", lba)

		default:
			fmt.Printf("  sector %d: Unknown tag=%d\n", lba, tid)
		}
	}
vdsDone:
	fmt.Println()

	if !partFound {
		return fmt.Errorf("no Partition Descriptor found in VDS")
	}
	if !lvdFound {
		return fmt.Errorf("no Logical Volume Descriptor found in VDS")
	}
	fmt.Printf("── Resolved: partStart=%-6d  partLen=%d sectors\n\n", partStart, partLen)

	// ── 3. File Set Descriptor ─────────────────────────────────────────────
	fsdAbsLBA := partStart + fsdRelLBA
	fmt.Printf("── FSD  partRelLBA=%-4d  absLBA=%d ────────────────────────────────\n",
		fsdRelLBA, fsdAbsLBA)
	fsd, err := sr.ReadSector(fsdAbsLBA)
	if err != nil {
		return fmt.Errorf("FSD read at sector %d: %w", fsdAbsLBA, err)
	}
	fsdTag := binary.LittleEndian.Uint16(fsd[0:2])
	fmt.Printf("  Tag ID             : %d (want 256)\n", fsdTag)
	if fsdTag != 256 {
		fmt.Printf("  !! WRONG TAG — first 32 bytes: % x\n", fsd[:32])
		altSec, _ := sr.ReadSector(fsdRelLBA)
		altTag := binary.LittleEndian.Uint16(altSec[0:2])
		fmt.Printf("  Trying without partStart (absLBA=%d): tag=%d\n", fsdRelLBA, altTag)
		return fmt.Errorf("FSD not found")
	}
	// FSD layout (ECMA-167 4/14.1):
	//   BP 112: logicalVolIdent dstring (128)
	//   BP 400: rootDirectoryICB long_ad (16)
	//              extLength    [400:404]
	//              logBlockNum  [404:408]  ← root ICB partition-relative LBA
	//              partRef      [408:410]
	
	field := fsd[112:240]
	strLen := int(field[127])
	label := ""
	if strLen > 0 && strLen <= 127 {
		label = decodeCS0(field[:strLen])
	}

	rootExtLen  := binary.LittleEndian.Uint32(fsd[400:404])
	rootRelLBA  := binary.LittleEndian.Uint32(fsd[404:408])
	rootPartRef := binary.LittleEndian.Uint16(fsd[408:410])
	fmt.Printf("  Volume label       : %q\n", label)
	fmt.Printf("  Root ICB long_ad   : extLen=%-6d  relLBA=%-6d  partRef=%d\n\n",
		rootExtLen, rootRelLBA, rootPartRef)

	// ── 4. Root File Entry ─────────────────────────────────────────────────
	rootAbsLBA := partStart + rootRelLBA
	fmt.Printf("── Root File Entry  partRelLBA=%-4d  absLBA=%d ──────────────────────\n",
		rootRelLBA, rootAbsLBA)
	rfe, err := sr.ReadSector(rootAbsLBA)
	if err != nil {
		return fmt.Errorf("root FE read at sector %d: %w", rootAbsLBA, err)
	}
	rfeTag    := binary.LittleEndian.Uint16(rfe[0:2])
	fileType  := rfe[27]
	icbFlags  := binary.LittleEndian.Uint16(rfe[34:36])
	allocType := icbFlags & 0x0007
	infoLen   := binary.LittleEndian.Uint64(rfe[56:64])
	fmt.Printf("  Tag ID             : %d (want 260=FE or 261=EFE)\n", rfeTag)
	fmt.Printf("  ICB file type      : %d (4=directory)\n", fileType)
	fmt.Printf("  ICB flags          : 0x%04x  allocType=%d  (0=Short 1=Long 2=Ext 3=Inline)\n",
		icbFlags, allocType)
	fmt.Printf("  Information length : %d bytes\n", infoLen)

	// Probe both FE and EFE offsets and print what each gives
	fmt.Println()
	fmt.Println("  ── Offset probes (trying both FE and EFE layouts) ──────────")

	// Regular File Entry (tag 260): eaLen@168, adLen@172, base=176
	fe_eaLen := binary.LittleEndian.Uint32(rfe[168:172])
	fe_adLen := binary.LittleEndian.Uint32(rfe[172:176])
	fe_base  := 176 + int(fe_eaLen)
	fmt.Printf("  FE  (tag=260): eaLen=%-6d adLen=%-6d adStart=%-4d", fe_eaLen, fe_adLen, fe_base)
	dumpFirstShortAD(rfe, fe_base, partStart)

	// Extended File Entry (tag 261) with 8-byte reserved: eaLen@204, adLen@208, base=212
	efe_eaLen := binary.LittleEndian.Uint32(rfe[204:208])
	efe_adLen := binary.LittleEndian.Uint32(rfe[208:212])
	efe_base  := 212 + int(efe_eaLen)
	fmt.Printf("  EFE (tag=261, reserved=8): eaLen=%-6d adLen=%-6d adStart=%-4d", efe_eaLen, efe_adLen, efe_base)
	dumpFirstShortAD(rfe, efe_base, partStart)

	// Extended File Entry (tag 261) without 8-byte reserved: eaLen@196, adLen@200, base=204
	efe2_eaLen := binary.LittleEndian.Uint32(rfe[196:200])
	efe2_adLen := binary.LittleEndian.Uint32(rfe[200:204])
	efe2_base  := 204 + int(efe2_eaLen)
	fmt.Printf("  EFE (tag=261, reserved=0): eaLen=%-6d adLen=%-6d adStart=%-4d", efe2_eaLen, efe2_adLen, efe2_base)
	dumpFirstShortAD(rfe, efe2_base, partStart)

	// Raw hex dump of the region where eaLen/adLen/allocDescs live
	fmt.Println()
	fmt.Println("  ── Raw hex [160:256] of root File Entry ────────────────────")
	end := minI(256, len(rfe))
	for i := 160; i < end; i += 16 {
		chunk := rfe[i:minI(i+16, end)]
		fmt.Printf("  [%3d]  ", i)
		for _, b := range chunk {
			fmt.Printf("%02x ", b)
		}
		// ASCII side
		fmt.Printf(" | ")
		for _, b := range chunk {
			if b >= 0x20 && b < 0x7f {
				fmt.Printf("%c", b)
			} else {
				fmt.Printf(".")
			}
		}
		fmt.Println()
	}

	// ── 5. Verify what's at each candidate directory data LBA ─────────────
	fmt.Println()
	fmt.Println("── Directory data sector probes ───────────────────────────────────")
	// Try a few candidate LBAs around partStart
	candidates := []uint32{}
	if fe_base+8 <= len(rfe) && fe_adLen >= 8 {
		sp := binary.LittleEndian.Uint32(rfe[fe_base+4 : fe_base+8])
		candidates = append(candidates, partStart+sp)
	}
	if efe_base+8 <= len(rfe) && efe_adLen >= 8 {
		sp := binary.LittleEndian.Uint32(rfe[efe_base+4 : efe_base+8])
		candidates = append(candidates, partStart+sp)
	}
	if efe2_base+8 <= len(rfe) && efe2_adLen >= 8 {
		sp := binary.LittleEndian.Uint32(rfe[efe2_base+4 : efe2_base+8])
		candidates = append(candidates, partStart+sp)
	}
	// Also just probe sectors near partStart
	for _, rel := range []uint32{1, 2, 3, 4, 5, 6} {
		candidates = append(candidates, partStart+rel)
	}
	seen := map[uint32]bool{}
	for _, absLBA := range candidates {
		if seen[absLBA] || absLBA == 0 || absLBA > partStart+partLen {
			continue
		}
		seen[absLBA] = true
		sec, err := sr.ReadSector(absLBA)
		if err != nil {
			fmt.Printf("  sector %d: read error\n", absLBA)
			continue
		}
		tid := binary.LittleEndian.Uint16(sec[0:2])
		fmt.Printf("  absLBA=%-6d  tag=%-4d", absLBA, tid)
		if tid == 257 {
			// FID — print first entry name
			lfi := int(sec[19])
			liu := int(binary.LittleEndian.Uint16(sec[36:38]))
			nameStart := 38 + liu
			name := ""
			if lfi > 0 && nameStart+lfi <= len(sec) {
				name = decodeCS0(sec[nameStart : nameStart+lfi])
			}
			fmt.Printf("  ← FID! first entry name=%q", name)
		}
		fmt.Println()
	}

	fmt.Println()
	return nil
}

// dumpFirstShortAD prints the first Short AD at adStart, along with the tag at its target sector.
func dumpFirstShortAD(sec []byte, adStart int, partStart uint32) {
	if adStart+8 > len(sec) {
		fmt.Printf("  → adStart out of range\n")
		return
	}
	rawExtLen := binary.LittleEndian.Uint32(sec[adStart : adStart+4])
	extLen    := rawExtLen & 0x3FFFFFFF
	extType   := rawExtLen >> 30
	relLBA    := binary.LittleEndian.Uint32(sec[adStart+4 : adStart+8])
	absLBA    := partStart + relLBA
	fmt.Printf("  → first Short AD: type=%d extLen=%-8d relLBA=%-8d absLBA=%d\n",
		extType, extLen, relLBA, absLBA)
}

func minI(a, b int) int {
	if a < b {
		return a
	}
	return b
}