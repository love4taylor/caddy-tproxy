package server

import (
	"fmt"
	"strings"
	"testing"

	"github.com/love4taylor/caddy-tproxy/internal/config"
	"github.com/love4taylor/caddy-tproxy/internal/session"
)

func FuzzAuthenticatedMetadataContainment(f *testing.F) {
	value := config.Defaults()
	profile := config.Profile{Capability: [32]byte{237, 81, 17, 9}}
	value.Profiles = []config.Profile{profile}
	manager := session.NewManager(value, [32]byte{9})
	f.Cleanup(manager.Shutdown)
	credential := config.CapabilityString(profile.Capability)
	f.Add("alpha", "z-", uint64(0))
	f.Add("%02", "%2e", ^uint64(0))
	f.Fuzz(func(t *testing.T, before, after string, escape uint64) {
		if len(before)+len(after) > 8192 {
			t.Skip()
		}
		var field strings.Builder
		field.WriteString(before)
		field.WriteByte('.')
		field.WriteString("Abc"[0 : escape>>61&3])
		for i := range len(credential) {
			if escape&(1<<i) != 0 {
				fmt.Fprintf(&field, "%%%02x", credential[i])
			} else {
				field.WriteByte(credential[i])
			}
		}
		field.WriteString(after)
		guard := metadataGuard{manager: manager}
		if !guard.has(field.String()) {
			t.Fatal("an authentic capability escaped metadata filtering")
		}
	})
}
