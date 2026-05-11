package diskiso

// Filesystem identifies a filesystem layer present within an ISO image.
// A single .iso typically carries several overlapping layers
// (e.g. ISO9660 + Joliet + UDF) that all reference the same underlying data.
type Filesystem int

const (
	// ISO9660 is the base ECMA-119 layer. Uppercase ASCII names, 8.3 or 31 chars.
	// Always present for compatibility.
	ISO9660 Filesystem = iota

	// Joliet is Microsoft's Unicode extension. UCS-2BE names up to 64 chars.
	// Stored in a Supplementary Volume Descriptor.
	Joliet

	// RockRidge adds POSIX semantics: long mixed-case names, symlinks, permissions.
	// Stored in the System Use fields of ISO9660 directory records.
	RockRidge

	// UDF is Universal Disk Format (ECMA-167). The modern standard used by DVDs,
	// Windows ISOs, and Linux-generated images.
	UDF
)

func (f Filesystem) String() string {
	switch f {
	case ISO9660:
		return "iso9660"
	case Joliet:
		return "joliet"
	case RockRidge:
		return "rockridge"
	case UDF:
		return "udf"
	default:
		return "unknown"
	}
}