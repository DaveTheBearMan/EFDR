package debhash

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"sort"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz"

	"xdr/internal/baseline"
)

func sum(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func compress(t *testing.T, comp string, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w io.WriteCloser
	var err error
	switch comp {
	case "gz":
		w = gzip.NewWriter(&buf)
	case "xz":
		w, err = xz.NewWriter(&buf)
	case "zst":
		w, err = zstd.NewWriter(&buf)
	default:
		return raw
	}
	if err != nil {
		t.Fatal(err)
	}
	w.Write(raw)
	w.Close()
	return buf.Bytes()
}

func tarOf(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c := files[n]
		switch {
		case strings.HasSuffix(n, "/"):
			tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeDir, Mode: 0o755})
		case strings.HasPrefix(c, "->"):
			tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeSymlink, Linkname: c[2:], Mode: 0o777})
		case strings.HasPrefix(c, "=>"):
			tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeLink, Linkname: c[2:], Mode: 0o755})
		default:
			tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o4755, Size: int64(len(c))})
			tw.Write([]byte(c))
		}
	}
	tw.Close()
	return buf.Bytes()
}

func arMember(name string, data []byte) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%-16s%-12d%-6d%-6d%-8s%-10d`\n", name, 0, 0, 0, "100644", len(data))
	b.Write(data)
	if len(data)%2 == 1 {
		b.WriteByte('\n')
	}
	return b.Bytes()
}

func buildDeb(t *testing.T, pkg, ver string, files map[string]string, comp string) []byte {
	t.Helper()
	control := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: amd64\n", pkg, ver)
	ext := ".tar"
	if comp != "" {
		ext += "." + comp
	}
	var b bytes.Buffer
	b.WriteString("!<arch>\n")
	b.Write(arMember("debian-binary", []byte("2.0\n")))
	b.Write(arMember("control"+ext, compress(t, comp, tarOf(t, map[string]string{"./control": control}))))
	b.Write(arMember("data"+ext, compress(t, comp, tarOf(t, files))))
	return b.Bytes()
}

func byPath(d *Deb) map[string]DebFile {
	m := map[string]DebFile{}
	for _, f := range d.Files {
		m[f.Path] = f
	}
	return m
}

func testComp(t *testing.T, comp string) {
	d, err := ParseDeb(bytes.NewReader(buildDeb(t, "postfix", "3.8.6-1", map[string]string{"./usr/": "", "./usr/sbin/postfix": "bin"}, comp)))
	if err != nil {
		t.Fatal(err)
	}
	if d.Package != "postfix" || d.Version != "3.8.6-1" || d.Arch != "amd64" {
		t.Fatalf("control %+v", d)
	}
	f, ok := byPath(d)["/usr/sbin/postfix"]
	if !ok || f.SHA256 != sum("bin") || f.Type != baseline.TypeFile {
		t.Fatalf("files %+v", d.Files)
	}
}

func TestParseDeb_Gzip(t *testing.T) { testComp(t, "gz") }
func TestParseDeb_Xz(t *testing.T)   { testComp(t, "xz") }
func TestParseDeb_Zstd(t *testing.T) { testComp(t, "zst") }
func TestParseDeb_Tar(t *testing.T)  { testComp(t, "") }

func TestParseDeb_UsrMerge(t *testing.T) {
	d, err := ParseDeb(bytes.NewReader(buildDeb(t, "p", "1", map[string]string{"./bin/foo": "f", "./lib/x/y": "y", "./libfoo/z": "z"}, "gz")))
	if err != nil {
		t.Fatal(err)
	}
	m := byPath(d)
	for _, p := range []string{"/usr/bin/foo", "/usr/lib/x/y", "/libfoo/z"} {
		if _, ok := m[p]; !ok {
			t.Errorf("missing %s in %+v", p, d.Files)
		}
	}
}

func TestParseDeb_LinksAndHardlinks(t *testing.T) {
	d, err := ParseDeb(bytes.NewReader(buildDeb(t, "p", "1", map[string]string{
		"./usr/bin/a": "A", "./usr/bin/b": "=>./usr/bin/a", "./usr/bin/c": "->a"}, "gz")))
	if err != nil {
		t.Fatal(err)
	}
	m := byPath(d)
	if m["/usr/bin/b"].SHA256 != sum("A") || m["/usr/bin/b"].Type != baseline.TypeFile {
		t.Errorf("hardlink %+v", m["/usr/bin/b"])
	}
	if m["/usr/bin/c"].Type != baseline.TypeLink || m["/usr/bin/c"].Link != "a" {
		t.Errorf("symlink %+v", m["/usr/bin/c"])
	}
}

func TestParseDeb_Garbage(t *testing.T) {
	buf := make([]byte, 4096)
	rand.New(rand.NewSource(1)).Read(buf)
	if _, err := ParseDeb(bytes.NewReader(buf)); err == nil {
		t.Fatal("want error")
	}
	if _, err := ParseDeb(bytes.NewReader([]byte("!<arch>\ndebian-binary   0     "))); err == nil {
		t.Fatal("want error on truncated archive")
	}
}

func TestParseStatus(t *testing.T) {
	in := "Package: a\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n\nPackage: b\nStatus: deinstall ok config-files\nVersion: 2\n\nPackage: c\nStatus: install ok installed\nArchitecture: all\nVersion: 3\nDescription: x\n continued\n"
	got := ParseStatus(strings.NewReader(in))
	if len(got) != 2 || got[0] != (Installed{"a", "1.0", "amd64"}) || got[1] != (Installed{"c", "3", "all"}) {
		t.Fatalf("got %+v", got)
	}
}

func TestLayer_HashOnly(t *testing.T) {
	d, _ := ParseDeb(bytes.NewReader(buildDeb(t, "p", "1", map[string]string{"./usr/bin/a": "A"}, "gz")))
	l := Layer([]*Deb{d})
	e, ok := l.Files["/usr/bin/a"]
	if !ok || !e.HashOnly || e.Layer != baseline.LayerPackage || e.SHA256 != sum("A") {
		t.Fatalf("%+v", l.Files)
	}
}
