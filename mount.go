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
//	vol, err := disc.Mount()                    // auto-pick
//	vol, err := disc.Mount(diskiso.UDF)         // explicit
//	vol, err := disc.Mount(diskiso.Joliet)      // fallback
func (d *Disc) Mount(want ...Filesystem) (Volume, error) {
	target := Filesystem(-1)
	if len(want) > 0 {
		target = want[0]
	}

	if target == -1 {
		if len(d.fses) == 0 {
			return nil, errors.New("diskiso: no supported filesystem found")
		}
		return d.openLayer(d.fses[0])
	}

	for _, have := range d.fses {
		if have == target {
			return d.openLayer(target)
		}
	}
	return nil, fmt.Errorf("diskiso: filesystem %s not present in image", target)
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