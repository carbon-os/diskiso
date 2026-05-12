package diskiso

import (
	"errors"
	"fmt"

	"github.com/carbon-os/diskiso/iso9660"
	"github.com/carbon-os/diskiso/udf"
)

// Mount returns a read-only Volume backed by the requested filesystem layer.
// With no argument the best available layer is chosen automatically:
// UDF > Joliet > RockRidge > ISO9660.
//
// When auto-selecting, each candidate layer is validated by reading the root
// directory. A layer whose root is unreadable or empty is skipped and the next
// candidate is tried. This handles ISOs that carry UDF Volume Recognition
// Sequence markers (as oscdimg and several other tools emit by default) but
// contain no actual UDF structures — without this check the UDF layer would
// be selected and return an empty filesystem.
//
//	vol, err := disc.Mount()                    // auto-pick best readable layer
//	vol, err := disc.Mount(diskiso.UDF)         // explicit — no fallback
//	vol, err := disc.Mount(diskiso.Joliet)      // explicit — no fallback
func (d *Disc) Mount(want ...Filesystem) (Volume, error) {
	// Explicit layer requested — open it directly, no fallback.
	if len(want) > 0 {
		target := want[0]
		for _, have := range d.fses {
			if have == target {
				return d.openLayer(target)
			}
		}
		return nil, fmt.Errorf("diskiso: filesystem %s not present in image", target)
	}

	if len(d.fses) == 0 {
		return nil, errors.New("diskiso: no supported filesystem found")
	}

	// Auto-select: walk layers in priority order and return the first one
	// that can successfully read at least one entry from the root directory.
	// An empty root almost always indicates a false-positive probe result
	// (UDF VRS markers present but no real UDF filesystem on the disc).
	var lastErr error
	for _, fs := range d.fses {
		vol, err := d.openLayer(fs)
		if err != nil {
			lastErr = err
			continue
		}
		entries, err := vol.ReadDir("/")
		if err != nil {
			lastErr = fmt.Errorf("diskiso: %s root unreadable: %w", fs, err)
			continue
		}
		if len(entries) == 0 {
			lastErr = fmt.Errorf("diskiso: %s root is empty", fs)
			continue
		}
		return vol, nil
	}

	if lastErr != nil {
		return nil, fmt.Errorf("diskiso: no readable filesystem layer found: %w", lastErr)
	}
	return nil, errors.New("diskiso: no readable filesystem layer found")
}

func (d *Disc) openLayer(layer Filesystem) (Volume, error) {
	switch layer {
	case UDF:
		return udf.NewVolume(d.f)
	case Joliet:
		return iso9660.NewVolume(d.f, iso9660.ModeJoliet)
	case RockRidge:
		return iso9660.NewVolume(d.f, iso9660.ModeRockRidge)
	case ISO9660:
		return iso9660.NewVolume(d.f, iso9660.ModeISO9660)
	default:
		return nil, fmt.Errorf("diskiso: unknown filesystem layer %v", layer)
	}
}