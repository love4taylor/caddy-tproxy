package bridge

import "testing"

func BenchmarkRenderBridge(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		page, err := Render("proxy.example.com", "relay", "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", "https-lanes", 2<<20, 1<<20)
		if err != nil || len(page.Body) == 0 {
			b.Fatal(err)
		}
	}
}
