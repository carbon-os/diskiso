// cmd/diskiso/main.go
//
// Usage:
//
//	diskiso <image.iso> --info
//	diskiso <image.iso> --fs <command> [args] [--layer udf|joliet|rockridge|iso9660]
//
// Commands:
//
//	ls  <path>        list directory contents (default: /)
//	cat <path>        stream file to stdout
//	get <src> <dst>   extract a file from the ISO to the host filesystem
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/carbon-os/diskiso"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "diskiso: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: diskiso <image.iso> --info | --fs <cmd> [args] [--layer <fs>]")
	}

	isoPath := args[0]
	rest    := args[1:]

	fset := flag.NewFlagSet("diskiso", flag.ContinueOnError)
	var (
		info  = fset.Bool("info", false, "print detected layers and root listing")
		fscmd = fset.Bool("fs",   false, "run a filesystem command: ls, cat, get")
		layer = fset.String("layer", "", "layer to mount: udf, joliet, rockridge, iso9660")
	)
	if err := fset.Parse(rest); err != nil {
		return err
	}

	switch {
	case *info:
		return runInfo(isoPath)
	case *fscmd:
		return runFS(isoPath, *layer, fset.Args())
	default:
		return errors.New("one of --info or --fs is required")
	}
}

// ── --info ────────────────────────────────────────────────────────────────────

func runInfo(isoPath string) error {
	disc, err := diskiso.Attach(isoPath)
	if err != nil {
		return err
	}
	defer disc.Detach()

	fi, err := os.Stat(isoPath)
	if err != nil {
		return err
	}

	fmt.Printf("Image : %s (%s)\n", isoPath, formatBytes(fi.Size()))
	fmt.Printf("Layers: %s\n\n", strings.Join(disc.FilesystemNames(), ", "))

	// Print label for each detected layer.
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "LAYER\tLABEL")
	fmt.Fprintln(tw, "-----\t-----")
	for _, layer := range disc.Filesystems() {
		vol, err := disc.Mount(layer)
		if err != nil {
			fmt.Fprintf(tw, "%s\t(mount error: %v)\n", layer, err)
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\n", layer, vol.Label())
	}
	tw.Flush()

	// Root listing using the best available layer.
	fmt.Println()
	vol, err := disc.Mount()
	if err != nil {
		return err
	}
	entries, err := vol.ReadDir("/")
	if err != nil {
		return err
	}

	fmt.Printf("Root directory (%s):\n", vol.Type())
	tw = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, e := range entries {
		info, _ := e.Info()
		suffix := ""
		if e.IsDir() {
			suffix = "/"
		}
		fmt.Fprintf(tw, "  %s%s\t%s\t%s\n",
			e.Name(),
			suffix,
			formatBytes(info.Size()),
			info.ModTime().Format("2006-01-02 15:04"),
		)
	}
	tw.Flush()
	return nil
}

// ── --fs ──────────────────────────────────────────────────────────────────────

func runFS(isoPath, layerName string, args []string) error {
	if len(args) == 0 {
		return errors.New("--fs requires a command: ls, cat, get")
	}

	disc, err := diskiso.Attach(isoPath)
	if err != nil {
		return err
	}
	defer disc.Detach()

	var mountArgs []diskiso.Filesystem
	if layerName != "" {
		layer, err := parseLayer(layerName)
		if err != nil {
			return err
		}
		mountArgs = append(mountArgs, layer)
	}

	vol, err := disc.Mount(mountArgs...)
	if err != nil {
		return err
	}

	cmd  := args[0]
	rest := args[1:]

	switch cmd {
	case "ls":
		return cmdLS(vol, rest)
	case "cat":
		return cmdCat(vol, rest)
	case "get":
		return cmdGet(vol, rest)
	default:
		return fmt.Errorf("unknown command %q — available: ls, cat, get", cmd)
	}
}

// ── Commands ──────────────────────────────────────────────────────────────────

// ls [path]
func cmdLS(vol diskiso.Volume, args []string) error {
	dir := "/"
	if len(args) > 0 {
		dir = args[0]
	}

	entries, err := vol.ReadDir(dir)
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, e := range entries {
		info, _ := e.Info()
		suffix := " "
		if e.IsDir() {
			suffix = "/"
		}
		fmt.Fprintf(tw, "%s\t%s%s\t%s\t%s\n",
			info.Mode(),
			e.Name(),
			suffix,
			formatBytes(info.Size()),
			info.ModTime().Format("2006-01-02 15:04"),
		)
	}
	return tw.Flush()
}

// cat <path>
func cmdCat(vol diskiso.Volume, args []string) error {
	if len(args) == 0 {
		return errors.New("cat: requires a path argument")
	}
	f, err := vol.Open(args[0])
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(os.Stdout, f.(io.Reader))
	return err
}

// get <iso-src> <host-dst>
func cmdGet(vol diskiso.Volume, args []string) error {
	if len(args) < 2 {
		return errors.New("get: requires <src> and <dst> arguments")
	}
	src, dst := args[0], args[1]

	// If dst is an existing directory, preserve the source filename.
	if fi, err := os.Stat(dst); err == nil && fi.IsDir() {
		dst = filepath.Join(dst, filepath.Base(src))
	}

	// Stream directly to disk rather than reading the whole file into memory.
	f, err := vol.Open(src)
	if err != nil {
		return fmt.Errorf("get: open %s: %w", src, err)
	}
	defer f.Close()

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("get: create %s: %w", dst, err)
	}
	defer out.Close()

	n, err := io.Copy(out, f.(io.Reader))
	if err != nil {
		return fmt.Errorf("get: copy: %w", err)
	}
	fmt.Printf("extracted %s → %s (%s)\n", src, dst, formatBytes(n))
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// ensure fs.DirEntry is imported (used by ReadDir return type)
var _ fs.DirEntry

func parseLayer(name string) (diskiso.Filesystem, error) {
	switch strings.ToLower(name) {
	case "udf":
		return diskiso.UDF, nil
	case "joliet":
		return diskiso.Joliet, nil
	case "rockridge", "rock-ridge":
		return diskiso.RockRidge, nil
	case "iso9660", "iso":
		return diskiso.ISO9660, nil
	default:
		return 0, fmt.Errorf("unknown layer %q — choose: udf, joliet, rockridge, iso9660", name)
	}
}

func formatBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}