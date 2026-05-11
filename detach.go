package diskiso

import "fmt"

// Detach closes the underlying image file and releases all resources.
// Calling Detach on an already-detached Disc is a no-op.
func (d *Disc) Detach() error {
	if d.f == nil {
		return nil
	}
	if err := d.f.Close(); err != nil {
		return fmt.Errorf("diskiso: detach: %w", err)
	}
	d.f = nil
	return nil
}