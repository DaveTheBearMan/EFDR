package proc

import "testing"

func TestClass(t *testing.T) {
	for _, c := range []struct{ exe, comm, want string }{
		{"/usr/bin/bash", "", "shell"},
		{"/usr/bin/python3.12", "", "interp"},
		{"/usr/bin/nc.openbsd", "", "nettool"},
		{"/usr/sbin/apache2", "", ""},
		{"", "sh", "shell"},
		{"/usr/sbin/apache2", "bash", ""},
	} {
		if got := Class(c.exe, c.comm); got != c.want {
			t.Errorf("Class(%q, %q) = %q, want %q", c.exe, c.comm, got, c.want)
		}
	}
}
