package bridge

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/love4taylor/caddy-tproxy/internal/config"
	"github.com/love4taylor/caddy-tproxy/internal/frame"
)

//go:embed runtime.js
var runtimeScript string

type Page struct {
	Body  []byte
	Nonce string
	CSP   string
}

// The bridge needs network and script access. It uses no interactive browser
// features, even when the client uses the bridge in an embedded WebView.
const (
	denyCapture     = "camera=(), microphone=(), display-capture=()"
	denySensors     = "geolocation=(), accelerometer=(), gyroscope=(), magnetometer=(), xr-spatial-tracking=()"
	denyDevices     = "usb=(), serial=(), hid=(), midi=()"
	denyMedia       = "autoplay=(), encrypted-media=(), fullscreen=(), picture-in-picture=(), screen-wake-lock=()"
	denyIdentity    = "payment=(), publickey-credentials-create=(), publickey-credentials-get=()"
	denyIntegration = "clipboard-read=(), clipboard-write=(), idle-detection=(), web-share=()"

	PermissionsPolicy = denyCapture + ", " + denySensors + ", " + denyDevices + ", " + denyMedia + ", " + denyIdentity + ", " + denyIntegration
)

const pageStart = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Telegram WEB proxy</title></head><body><script nonce="`
const pageEnd = "</script></body></html>\n"

func Render(host, prefix, ticket, mode string, batchLimit, maxFramePayload int) (Page, error) {
	if err := config.ValidateHostname(host); err != nil {
		return Page{}, err
	}
	if err := config.ValidateBasePath(prefix); err != nil {
		return Page{}, err
	}
	if batchLimit < frame.HeaderSize+4 || batchLimit > config.MaxCarrierBatchBytes ||
		maxFramePayload < 4 || maxFramePayload > frame.MaxPayload || !config.CarrierMode(mode).Valid() {
		return Page{}, errors.New("invalid WEB bridge carrier settings")
	}
	var entropy [18]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return Page{}, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(entropy[:])
	origin, _ := json.Marshal("https://" + host + config.Base(prefix))
	credential, _ := json.Marshal(ticket)
	carrier, _ := json.Marshal(mode)
	out := make([]byte, 0, len(runtimeScript)+len(pageStart)+len(pageEnd)+len(origin)+len(credential)+160)
	out = append(out, pageStart...)
	out = append(out, nonce...)
	out = append(out, `">"use strict";`+"\n"+`const relayBase=`...)
	out = append(out, origin...)
	out = append(out, `,bootstrap=`...)
	out = append(out, credential...)
	out = append(out, `,carrierMode=`...)
	out = append(out, carrier...)
	out = append(out, `,batchLimit=`...)
	out = strconv.AppendInt(out, int64(batchLimit), 10)
	out = append(out, `,uplinkDataLimit=`...)
	out = strconv.AppendInt(out, int64(min(maxFramePayload, batchLimit-frame.HeaderSize)), 10)
	out = append(out, ';', '\n')
	out = append(out, runtimeScript...)
	out = append(out, pageEnd...)

	const embedding = "sandbox allow-same-origin allow-scripts; frame-ancestors http://127.0.0.1:*"
	const isolation = "default-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; " +
		"frame-src 'none'; child-src 'none'; worker-src 'none'; style-src 'none'; font-src 'none'; " +
		"media-src 'none'; img-src 'none'; manifest-src 'none'"
	csp := "script-src 'nonce-" + nonce + "'; connect-src 'self' wss://" + host + "; " + embedding + "; " + isolation
	return Page{Body: out, Nonce: nonce, CSP: csp}, nil
}
