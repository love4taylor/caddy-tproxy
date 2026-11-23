package bridge

import (
	"strings"
	"testing"
)

func TestBridgeRenderingPolicy(t *testing.T) {
	const hostile = `</script><script>alert("unsafe")</script>`
	page, err := Render("proxy.example.com", "prefix/lane", hostile, "https-lanes", 1<<20, 1<<19)
	if err != nil {
		t.Fatal(err)
	}
	document := string(page.Body)
	if strings.Count(document, "<script") != 1 || strings.Count(document, "</script>") != 1 {
		t.Fatal("operator input can terminate the inline script")
	}
	if !strings.Contains(document, `nonce="`+page.Nonce+`"`) || !strings.Contains(page.CSP, `script-src 'nonce-`+page.Nonce+`'`) {
		t.Fatal("the page and its CSP do not share a nonce")
	}
	for _, directive := range []string{
		"default-src 'none'", "connect-src 'self' wss://proxy.example.com",
		"base-uri 'none'", "frame-ancestors http://127.0.0.1:*", "form-action 'none'",
		"sandbox allow-same-origin allow-scripts", "worker-src 'none'",
	} {
		if !strings.Contains(page.CSP, directive) {
			t.Errorf("missing CSP directive %q", directive)
		}
	}
	second, err := Render("proxy.example.com", "prefix/lane", hostile, "https-lanes", 1<<20, 1<<19)
	if err != nil || second.Nonce == page.Nonce {
		t.Fatalf("script nonce was reused: %v", err)
	}
	if !strings.Contains(document, `relayBase="https://proxy.example.com/prefix/lane/"`) ||
		!strings.Contains(document, `carrierMode="https-lanes",batchLimit=1048576,uplinkDataLimit=524288`) {
		t.Fatal("operator settings missing from generated bridge")
	}
}

func TestBridgeRejectsUnsafeSettings(t *testing.T) {
	for _, settings := range []struct {
		host, prefix, carrier string
		limit                 int
	}{
		{"proxy.example.com; script-src *", "", "https", 1 << 20},
		{"proxy.example.com", "../admin", "https", 1 << 20},
		{"proxy.example.com", "", "unknown", 1 << 20},
		{"proxy.example.com", "", "https", 0},
		{"proxy.example.com", "", "https", 2<<20 + 1},
	} {
		if _, err := Render(settings.host, settings.prefix, "ticket", settings.carrier, settings.limit, 1<<20); err == nil {
			t.Errorf("invalid bridge settings accepted: %+v", settings)
		}
	}
}
