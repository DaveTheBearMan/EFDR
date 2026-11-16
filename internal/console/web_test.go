package console

import (
	"regexp"
	"strings"
	"testing"
)

func asset(t *testing.T, name string) string {
	t.Helper()
	b, err := webFS.ReadFile("web/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Text from an agent (a process name, a path) must reach the page as text.
func TestPage_NoInnerHTMLOfData(t *testing.T) {
	js := asset(t, "app.js")
	for _, bad := range []string{"innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setAttribute('style'", `setAttribute("style"`, "srcdoc", "javascript:"} {
		if strings.Contains(js, bad) {
			t.Errorf("app.js uses %s", bad)
		}
	}
	if !strings.Contains(js, "textContent") {
		t.Error("app.js never sets textContent")
	}
}

func TestPage_NoExternalResources(t *testing.T) {
	for _, f := range []string{"index.html", "app.js", "app.css"} {
		body := asset(t, f)
		if m := regexp.MustCompile(`https?://`).FindString(body); m != "" {
			t.Errorf("%s names an external URL", f)
		}
		if strings.Contains(body, "@import") || strings.Contains(body, "url(") {
			t.Errorf("%s loads another resource", f)
		}
	}
	html := asset(t, "index.html")
	for _, m := range regexp.MustCompile(`(?:src|href)="([^"]*)"`).FindAllStringSubmatch(html, -1) {
		if m[1] != "/app.js" && m[1] != "/app.css" {
			t.Errorf("index.html points at %s", m[1])
		}
	}
}

// The CSP forbids inline script and style: the page must not need either.
func TestPage_NoInlineScriptOrStyle(t *testing.T) {
	html := asset(t, "index.html")
	if m := regexp.MustCompile(`<script[^>]*>\s*[^<\s]`).FindString(html); m != "" {
		t.Errorf("an inline script: %q", m)
	}
	if regexp.MustCompile(`<style|\sstyle=|\son[a-z]+=`).MatchString(html) {
		t.Error("index.html has inline style or an event attribute")
	}
	if strings.Contains(asset(t, "app.js"), ".style.") {
		t.Error("app.js sets styles from script")
	}
}

func TestPage_Served(t *testing.T) {
	r := newServerRig(t)
	for path, ctype := range map[string]string{"/": "text/html", "/app.js": "text/javascript", "/app.css": "text/css"} {
		resp := r.do("GET", path, "", nil, nil)
		if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), ctype) {
			t.Errorf("%s: %d %q", path, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
	}
	html := asset(t, "index.html")
	for _, want := range []string{"<title>XDR Control Plane</title>", `<script src="/app.js">`, `<link rel="stylesheet" href="/app.css">`, `id="login"`} {
		if !strings.Contains(html, want) {
			t.Errorf("index.html lacks %s", want)
		}
	}
	if resp := r.do("GET", "/nope", "", nil, nil); resp.StatusCode != 404 {
		t.Errorf("/nope: %d", resp.StatusCode)
	}
}

func TestPage_Phone(t *testing.T) {
	if !strings.Contains(asset(t, "index.html"), `name="viewport" content="width=device-width`) {
		t.Error("no viewport meta")
	}
	if !regexp.MustCompile(`@media \(max-width:\s*520px\)`).MatchString(asset(t, "app.css")) {
		t.Error("no phone media query")
	}
	if !strings.Contains(asset(t, "app.css"), "prefers-color-scheme: dark") {
		t.Error("no dark mode")
	}
}

// The kill switch is on the Hosts panel: one per host and one for all, each
// asking first.
func TestPage_KillToggle(t *testing.T) {
	if !strings.Contains(asset(t, "index.html"), `id="p-killall" data-panel="hosts"`) {
		t.Error("index.html has no all-hosts kill control")
	}
	js := asset(t, "app.js")
	for _, want := range []string{"'/api/mode'", "window.confirm(what)", "killWord(x.Kill)", "'from config'"} {
		if !strings.Contains(js, want) {
			t.Errorf("app.js lacks %s", want)
		}
	}
}
