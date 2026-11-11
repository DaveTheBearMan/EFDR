// Package classify maps a path to its persistence category and severity.
package classify

import (
	"path"
	"strings"

	"xdr/internal/model"
)

// Class is what a path means for persistence detection.
type Class struct {
	Category    string
	Severity    model.Severity
	KeepContent bool // retain small file contents for byte diffs
}

type rule struct {
	class    Class
	patterns []string
}

// home stands in for every home directory. Homes are wherever passwd says
// they are (service accounts live under /var/lib, /var/spool, /var/www or
// even "/"), so a per-user file is matched at any depth.
const home = "{,/**}"

var rules = []rule{
	{Class{"preload", model.SevCritical, true}, []string{"/etc/ld.so.preload"}},
	{Class{"systemd-generator", model.SevCritical, true}, []string{"/{etc,run,usr/lib,usr/local/lib}/systemd/{system,user}-generators/**"}},
	{Class{"systemd-unit", model.SevHigh, true}, []string{"/{etc,run,usr/lib,usr/local/lib}/systemd/{system,user}/**", home + "/.config/systemd/user/**",
		"/run/user/*/systemd/{user,user.control}/**", "/var/lib/systemd/linger/**"}},
	{Class{"cron", model.SevHigh, true}, []string{"/etc/crontab", "/etc/cron.d/**", "/etc/cron.{hourly,daily,weekly,monthly}/**", "/var/spool/cron/crontabs/**"}},
	{Class{"at", model.SevHigh, true}, []string{"/var/spool/cron/atjobs/**", "/var/spool/at/**"}},
	{Class{"pkg-hook", model.SevHigh, true}, []string{"/etc/apt/apt.conf.d/**", "/etc/dpkg/dpkg.cfg.d/**", "/var/lib/dpkg/info/*.{preinst,postinst,prerm,postrm}"}},
	{Class{"ssh-key", model.SevHigh, true}, []string{home + "/.ssh/authorized_keys*", "/etc/ssh/authorized_keys/**"}},
	{Class{"sudo", model.SevCritical, true}, []string{"/etc/sudoers", "/etc/sudoers.d/**"}},
	{Class{"sshd", model.SevCritical, true}, []string{"/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/**"}},
	{Class{"pam", model.SevCritical, true}, []string{"/etc/pam.d/**", "/etc/security/**"}},
	{Class{"pam", model.SevCritical, false}, []string{"/usr/lib/x86_64-linux-gnu/security/**"}},
	{Class{"kmod-config", model.SevCritical, true}, []string{"/etc/modules", "/etc/modules-load.d/**", "/etc/modprobe.d/**", "/usr/lib/modules-load.d/**"}},
	{Class{"login-hook", model.SevHigh, true}, []string{"/etc/update-motd.d/**", "/etc/rc.local", "/etc/profile", "/etc/profile.d/**", "/etc/bash.bashrc", "/etc/environment", home + "/.{bashrc,profile,bash_profile,bash_login,bash_logout,zshrc}"}},
	{Class{"resolver", model.SevHigh, true}, []string{"/etc/nsswitch.conf", "/etc/hosts", "/etc/resolv.conf", "/etc/ld.so.conf", "/etc/ld.so.conf.d/**"}},
	{Class{"resolver", model.SevHigh, false}, []string{"/etc/ld.so.cache"}},
	{Class{"cloud-init", model.SevHigh, true}, []string{"/etc/cloud/**", "/var/lib/cloud/scripts/**", "/var/lib/cloud/{instance,instances/*}/scripts/**"}},
	{Class{"udev", model.SevHigh, true}, []string{"/etc/udev/rules.d/**", "/usr/lib/udev/rules.d/**"}},
	{Class{"mail", model.SevHigh, true}, []string{"/etc/aliases", "/etc/postfix/**", home + "/.forward"}},
	// smb.conf can run commands (root preexec, magic script); usershares
	// define shares outside it.
	{Class{"samba", model.SevHigh, true}, []string{"/etc/samba/**", "/var/lib/samba/usershares/**"}},
	{Class{"account-db", model.SevMedium, true}, []string{"/etc/{passwd,group}"}},
	// Password hashes are compared by digest only, never copied into a baseline.
	{Class{"account-db", model.SevMedium, false}, []string{"/etc/{shadow,gshadow}"}},
	{Class{"system-binary", model.SevHigh, false}, []string{"/usr/{bin,sbin,lib,lib64,libexec,local/bin,local/sbin}/**", "/opt/**"}},
}

// Fallback is the category of a path no rule names.
const Fallback = "file"

var fallback = Class{Fallback, model.SevMedium, false}

type compiled struct {
	class    Class
	patterns [][]string // each pattern split into segments
}

var table = compile()

func compile() []compiled {
	out := make([]compiled, 0, len(rules))
	for _, r := range rules {
		var ps [][]string
		for _, p := range r.patterns {
			for _, e := range Expand(p) {
				ps = append(ps, strings.Split(e, "/"))
			}
		}
		out = append(out, compiled{r.class, ps})
	}
	return out
}

// Path classifies a decoded absolute path. The first matching rule wins.
func Path(p string) Class {
	segs := strings.Split(p, "/")
	for _, c := range table {
		for _, pat := range c.patterns {
			if matchSegs(pat, segs) {
				return c.class
			}
		}
	}
	return fallback
}

// Expand performs shell-style brace expansion: "a{b,c}d" → ["abd", "acd"].
func Expand(p string) []string {
	open := strings.IndexByte(p, '{')
	if open < 0 {
		return []string{p}
	}
	depth := 0
	for i := open; i < len(p); i++ {
		switch p[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				var out []string
				for _, alt := range splitTop(p[open+1 : i]) {
					out = append(out, Expand(p[:open]+alt+p[i+1:])...)
				}
				return out
			}
		}
	}
	return []string{p}
}

func splitTop(s string) []string {
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, s[start:i])
				start = i + 1
			}
		}
	}
	return append(parts, s[start:])
}

// Match reports whether p matches pattern. Segments use path.Match syntax.
// A "**" segment matches one or more whole segments; as the last segment it
// also matches none, so "/etc/cron.d/**" covers the directory itself.
func Match(pattern, p string) bool {
	return matchSegs(strings.Split(pattern, "/"), strings.Split(p, "/"))
}

func matchSegs(pat, segs []string) bool {
	for len(pat) > 0 {
		if pat[0] == "**" {
			rest := pat[1:]
			if len(rest) == 0 {
				return true
			}
			for i := 1; i <= len(segs); i++ {
				if matchSegs(rest, segs[i:]) {
					return true
				}
			}
			return false
		}
		if len(segs) == 0 {
			return false
		}
		if ok, _ := path.Match(pat[0], segs[0]); !ok {
			return false
		}
		pat, segs = pat[1:], segs[1:]
	}
	return len(segs) == 0
}
