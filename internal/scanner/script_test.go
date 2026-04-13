package scanner

import (
	"testing"
)

func TestParseCDNCGITrace(t *testing.T) {
	body := `fl=123f456
h=www.cloudflare.com
ip=1.2.3.4
ts=1234567890.123
visit_scheme=https
uag=Go-http-client/2.0
colo=IAD
sliver=none
http=http/2
loc=US
tls=TLSv1.3
sni=plaintext
warp=off
gateway=off
rbi=off
kex=X25519`

	res := &ProbeResult{}
	parseCDNCGITrace(res, body)

	if res.ServiceName != "cloudflare/IAD" {
		t.Errorf("ServiceName = %q, want %q", res.ServiceName, "cloudflare/IAD")
	}
}

func TestParseCDNCGITrace_NoColo(t *testing.T) {
	body := "h=example.com\nip=1.2.3.4"
	res := &ProbeResult{}
	parseCDNCGITrace(res, body)

	if res.ServiceName != "" {
		t.Errorf("ServiceName = %q, want empty when no colo", res.ServiceName)
	}
}

func TestParseCDNCGITrace_EmptyBody(t *testing.T) {
	res := &ProbeResult{}
	parseCDNCGITrace(res, "")
	if res.ServiceName != "" {
		t.Errorf("ServiceName = %q, want empty", res.ServiceName)
	}
}

func TestParseCDNCGITrace_MalformedLines(t *testing.T) {
	body := "no-equals-sign\n=value-only\n\ncolo=SFO"
	res := &ProbeResult{}
	parseCDNCGITrace(res, body)

	if res.ServiceName != "cloudflare/SFO" {
		t.Errorf("ServiceName = %q, want %q", res.ServiceName, "cloudflare/SFO")
	}
}
