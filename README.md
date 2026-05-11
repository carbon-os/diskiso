# diskiso

A pure-Go library for reading ISO 9660 disc images. `diskiso` detects and
exposes all filesystem layers present in an image — ISO 9660, Joliet,
Rock Ridge, and UDF — behind a single clean interface.

## Features

- **Multi-layer detection** — probes every layer in one pass and ranks them by richness
- **UDF** (ECMA-167) — full partition/FSD/ICB chain, handles the `oscdimg` EFE offset bug found in Windows ISOs
- **Joliet** — UCS-2BE long Unicode filenames via the Supplementary Volume Descriptor
- **Rock Ridge** — POSIX names, symlinks, and permissions via SUSP extensions
- **ISO 9660** — baseline ECMA-119 compatibility layer, always present
- **Streaming reads** — `Open` returns an `fs.File` backed by a section reader; large files are never fully buffered
- **No CGo, no OS mounts** — works on Linux, macOS, and Windows from a single binary

## Installation

```sh
go get github.com/carbon-os/diskiso
```

Requires Go 1.21 or later.

## Quick start

```go
package main

import (
    "fmt"
    "github.com/carbon-os/diskiso"
)

func main() {
    disc, err := diskiso.Attach("windows-arm64.iso")
    if err != nil {
        panic(err)
    }
    defer disc.Detach()

    // Auto-picks the best available layer: UDF > Joliet > Rock Ridge > ISO 9660
    vol, err := disc.Mount()
    if err != nil {
        panic(err)
    }

    entries, err := vol.ReadDir("/")
    if err != nil {
        panic(err)
    }
    for _, e := range entries {
        fmt.Println(e.Name())
    }
}
```

## Selecting a layer explicitly

```go
disc, _ := diskiso.Attach("image.iso")
defer disc.Detach()

fmt.Println(disc.FilesystemNames()) // ["udf", "joliet", "iso9660"]

vol, err := disc.Mount(diskiso.Joliet)  // explicit layer
```

## The Volume interface

Every layer is accessed through the same `Volume` interface:

```go
type Volume interface {
    Type()     string                            // "udf", "joliet", "rockridge", "iso9660"
    Label()    string                            // volume label from the image

    ReadFile(path string) ([]byte, error)        // read whole file into memory
    Open(path string)     (fs.File, error)       // streaming read; caller must Close
    ReadDir(path string)  ([]fs.DirEntry, error) // list a directory
    Stat(path string)     (os.FileInfo, error)   // metadata for any path
    Readlink(path string) (string, error)        // symlink target (Rock Ridge only)
}
```

All paths are absolute (`"/sources/install.wim"`).

## Filesystem layers

| Constant | String | Description |
|---|---|---|
| `ISO9660` | `"iso9660"` | Baseline ECMA-119; uppercase ASCII, 8.3 or 31-char names |
| `Joliet` | `"joliet"` | Microsoft Unicode extension; UCS-2BE names up to 64 chars |
| `RockRidge` | `"rockridge"` | POSIX names, symlinks, and permissions via SUSP |
| `UDF` | `"udf"` | Universal Disk Format (ECMA-167); used by DVDs and modern Windows ISOs |

When `Mount()` is called without arguments, the first detected layer in the
priority order **UDF → Joliet → Rock Ridge → ISO 9660** is used.

## Package layout

```
diskiso/
├── attach.go       Attach / Detach and filesystem probing
├── disc.go         Disc type — holds the file handle and layer list
├── filesystem.go   Filesystem constants and their String() names
├── mount.go        Mount — opens a Volume for a given layer
├── volume.go       Volume interface definition
├── internal/
│   └── region/     Low-level 2048-byte sector I/O and both-endian helpers
├── iso9660/
│   ├── detect.go   PVD/SVD/Rock Ridge probe
│   ├── dirent.go   Directory record parser
│   ├── rockridge.go SUSP NM/SL/PX/TF field decoders
│   └── volume.go   iso9660.Volume implementation
└── udf/
    ├── detect.go   VRS + AVDP probe
    ├── diagnose.go UDF chain debugger (--diagnose)
    └── volume.go   udf.Volume implementation
```

---

## CLI — `diskiso`

A command-line tool is included under `./diskiso`.

```sh
go install github.com/carbon-os/diskiso/cmd/diskiso@latest
```

### Usage

```
diskiso <image.iso> --info | --diagnose | --fs <cmd> [args] [--layer <fs>]
```

#### `--info` — inspect an image

Prints the detected layers, per-layer volume labels, and a root directory
listing from the best available layer.

```
$ diskiso windows11-arm64.iso --info
Image : windows11-arm64.iso (5.4 GB)
Layers: udf, joliet, iso9660

LAYER    LABEL
-----    -----
udf      CCCOMA_X64FRE_EN-GB_DV9
joliet   CCCOMA_X64FRE_EN-GB_DV9
iso9660  CCCOMA_X64FRE_EN-GB_DV9

Root directory (udf):
  boot/          512 B    2024-11-14 03:12
  efi/           512 B    2024-11-14 03:12
  sources/       512 B    2024-11-14 03:12
  setup.exe      85.3 KB  2024-11-14 03:12
  ...
```

#### `--fs` — filesystem commands

```sh
# List a directory (default layer)
diskiso image.iso --fs ls /sources

# Force a specific layer
diskiso image.iso --fs ls / --layer joliet

# Print a text file to stdout
diskiso image.iso --fs cat /README.TXT

# Extract a file
diskiso image.iso --fs get /sources/install.wim ./install.wim
```

Available sub-commands: `ls`, `cat`, `get`.

#### `--diagnose` — debug UDF structure

Walks the full UDF chain (AVDP → VDS → FSD → root ICB) and prints every
parsed field and raw byte offset. Useful when `--info` shows an empty root
on a malformed image.

```sh
diskiso tricky.iso --diagnose
```

---

## License

MIT — see [LICENSE](LICENSE).