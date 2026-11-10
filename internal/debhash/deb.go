// Package debhash computes trusted file hashes from Debian packages, so
// package files on a target can be verified without trusting its dpkg data.
package debhash

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"xdr/internal/baseline"
)

// DebFile is one filesystem object shipped by a package.
type DebFile struct {
	Path   string // normalized absolute path
	Type   baseline.FileType
	Mode   uint32 // os.FileMode bits
	SHA256 string
	Link   string
}

// Deb is a parsed package.
type Deb struct {
	Package, Version, Arch string
	Files                  []DebFile
}

const arMagic = "!<arch>\n"

// ParseDeb reads a .deb (an ar archive holding control and data tarballs).
func ParseDeb(r io.Reader) (*Deb, error) {
	br := bufio.NewReader(r)
	magic := make([]byte, len(arMagic))
	if _, err := io.ReadFull(br, magic); err != nil || string(magic) != arMagic {
		return nil, errors.New("not a deb: bad ar magic")
	}
	d := &Deb{}
	var sawControl, sawData bool
	for {
		hdr := make([]byte, 60)
		if _, err := io.ReadFull(br, hdr); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("truncated ar header: %w", err)
		}
		if string(hdr[58:60]) != "`\n" {
			return nil, errors.New("corrupt ar header")
		}
		name := strings.TrimSuffix(strings.TrimSpace(string(hdr[0:16])), "/")
		size, err := strconv.ParseInt(strings.TrimSpace(string(hdr[48:58])), 10, 64)
		if err != nil || size < 0 {
			return nil, errors.New("corrupt ar member size")
		}
		member := io.LimitReader(br, size)
		switch {
		case strings.HasPrefix(name, "control.tar"):
			if err := parseControl(d, name, member); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			sawControl = true
		case strings.HasPrefix(name, "data.tar"):
			if err := parseData(d, name, member); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			sawData = true
		}
		if _, err := io.Copy(io.Discard, member); err != nil {
			return nil, err
		}
		if size%2 == 1 {
			br.ReadByte()
		}
	}
	if !sawControl || !sawData {
		return nil, errors.New("not a deb: missing control or data member")
	}
	return d, nil
}

func decompress(name string, r io.Reader) (io.Reader, error) {
	switch path.Ext(name) {
	case ".tar":
		return r, nil
	case ".gz":
		return gzip.NewReader(r)
	case ".xz":
		return xz.NewReader(r)
	case ".zst":
		zr, err := zstd.NewReader(r)
		if err != nil {
			return nil, err
		}
		return zr.IOReadCloser(), nil
	}
	return nil, fmt.Errorf("unsupported compression %q", path.Ext(name))
}

func parseControl(d *Deb, name string, r io.Reader) error {
	dr, err := decompress(name, r)
	if err != nil {
		return err
	}
	tr := tar.NewReader(dr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return errors.New("no control file")
		}
		if err != nil {
			return err
		}
		if path.Clean(h.Name) != "control" {
			continue
		}
		s := bufio.NewScanner(tr)
		for s.Scan() {
			k, v, ok := strings.Cut(s.Text(), ":")
			if !ok {
				continue
			}
			v = strings.TrimSpace(v)
			switch k {
			case "Package":
				d.Package = v
			case "Version":
				d.Version = v
			case "Architecture":
				d.Arch = v
			}
		}
		return s.Err()
	}
}

func parseData(d *Deb, name string, r io.Reader) error {
	dr, err := decompress(name, r)
	if err != nil {
		return err
	}
	tr := tar.NewReader(dr)
	hashes := map[string]string{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		p := Normalize(h.Name)
		if p == "/" {
			continue
		}
		f := DebFile{Path: p, Mode: uint32(h.FileInfo().Mode())}
		switch h.Typeflag {
		case tar.TypeReg:
			sum := sha256.New()
			if _, err := io.Copy(sum, tr); err != nil {
				return err
			}
			f.Type, f.SHA256 = baseline.TypeFile, hex.EncodeToString(sum.Sum(nil))
			hashes[p] = f.SHA256
		case tar.TypeLink:
			target, ok := hashes[Normalize(h.Linkname)]
			if !ok {
				return fmt.Errorf("hardlink %s to unknown %s", h.Name, h.Linkname)
			}
			f.Type, f.SHA256 = baseline.TypeFile, target
			hashes[p] = target
		case tar.TypeSymlink:
			f.Type, f.Link = baseline.TypeLink, h.Linkname
		case tar.TypeDir:
			f.Type = baseline.TypeDir
		default:
			f.Type = baseline.TypeOther
		}
		d.Files = append(d.Files, f)
	}
}

// mergedDirs are top-level directories that are symlinks into /usr on
// usr-merged systems such as Ubuntu 24.04.
var mergedDirs = []string{"/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32"}

// Normalize turns a tar member name into the absolute path the filesystem
// walker sees, rewriting usr-merged top-level directories into /usr.
func Normalize(name string) string {
	p := path.Clean("/" + strings.TrimPrefix(name, "./"))
	for _, m := range mergedDirs {
		if p == m || strings.HasPrefix(p, m+"/") {
			return "/usr" + p
		}
	}
	return p
}
