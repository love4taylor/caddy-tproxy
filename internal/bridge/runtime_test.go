package bridge

import (
	"bytes"
	"context"
	"os/exec"
	"testing"
	"time"
)

func TestBridgeRunsAllCarriers(t *testing.T) {
	for _, mode := range []string{"https", "https-lanes", "websocket", "websocket-lanes"} {
		for _, boundary := range []string{"native", "loopback"} {
			t.Run(mode+"/"+boundary, func(t *testing.T) {
				runBridgeScript(t, mode, boundary, 2<<20, 1<<20)
			})
		}
	}
}

func TestBridgeRejectsInvalidUplinkBeforeDispatch(t *testing.T) {
	for _, mode := range []string{"https", "https-lanes", "websocket", "websocket-lanes"} {
		t.Run(mode, func(t *testing.T) {
			runBridgeScript(t, mode, "loopback", 2<<20, 1<<20, "invalid-uplink-batch")
		})
	}
}

func TestBridgeWebSocketSendBudget(t *testing.T) {
	for _, scenario := range []string{"drained", "closing", "closed"} {
		t.Run(scenario, func(t *testing.T) {
			runBridgeScript(t, "websocket-lanes", "loopback", 2<<20, 1<<20, scenario)
		})
	}
}

func TestBridgeWebSocketDrainsReadyBatches(t *testing.T) {
	for _, mode := range []string{"websocket", "websocket-lanes"} {
		t.Run(mode, func(t *testing.T) {
			runBridgeScript(t, mode, "loopback", 256<<10, 1<<20, "socket-burst")
		})
	}
}

func TestBridgeWebSocketStopsSendingDuringClosingHandshake(t *testing.T) {
	for _, mode := range []string{"websocket", "websocket-lanes"} {
		t.Run(mode, func(t *testing.T) {
			runBridgeScript(t, mode, "loopback", 2<<20, 1<<20, "socket-closing")
		})
	}
}

func TestBridgeHTTPSDownlinkRetry(t *testing.T) {
	for _, mode := range []string{"https", "https-lanes"} {
		t.Run(mode, func(t *testing.T) {
			runBridgeScript(t, mode, "loopback", 2<<20, 1<<20, "downlink-retry")
		})
	}
}

func TestBridgeClosesUnfinishedSession(t *testing.T) {
	for _, boundary := range []string{"native", "loopback"} {
		for _, scenario := range []string{"session-close-before-headers", "session-close-after-headers", "session-live-retry"} {
			t.Run(boundary+"/"+scenario, func(t *testing.T) {
				runBridgeScript(t, "https", boundary, 2<<20, 1<<20, scenario)
			})
		}
	}
}

func TestBridgeHTTPSLaneCloseNotifiesAppOnce(t *testing.T) {
	for _, scenario := range []string{"closed-lane", "closed-lane-after-frame"} {
		t.Run(scenario, func(t *testing.T) {
			runBridgeScript(t, "https-lanes", "loopback", 2<<20, 1<<20, scenario)
		})
	}
}

func TestBridgeSplitsDataToFitCarrierLimits(t *testing.T) {
	for _, mode := range []string{"https", "https-lanes", "websocket", "websocket-lanes"} {
		t.Run(mode+"/frame", func(t *testing.T) {
			runBridgeScript(t, mode, "loopback", 256<<10, 32<<10, "split-data")
		})
		t.Run(mode+"/batch", func(t *testing.T) {
			runBridgeScript(t, mode, "native", 256<<10, 1<<20, "split-data")
		})
		t.Run(mode+"/minimum", func(t *testing.T) {
			runBridgeScript(t, mode, "loopback", 256<<10, 4, "split-data-minimum")
		})
	}
}

func runBridgeScript(t *testing.T, mode, boundary string, batchLimit, maxFramePayload int, scenario ...string) {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required to execute the bridge lifecycle test")
	}
	page, err := Render("proxy.example.com", "relay", "bootstrap", mode, batchLimit, maxFramePayload)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	args := append([]string{"testdata/carriers.js", mode, boundary}, scenario...)
	command := exec.CommandContext(ctx, node, args...)
	command.Stdin = bytes.NewReader(page.Body)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("bridge lifecycle test: %v\n%s", err, output)
	}
}
