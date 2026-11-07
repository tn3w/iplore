package caddyiplore

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func databasePath(t *testing.T) string {
	t.Helper()
	for _, directory := range []string{"../.scratch", "../../bindings/data"} {
		path := filepath.Join(directory, "iplore-country.ipl")
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	t.Skip("iplore-country.ipl not available")
	return ""
}

func parse(text string) (*Handler, error) {
	handler := new(Handler)
	return handler, handler.UnmarshalCaddyfile(caddyfile.NewTestDispenser(text))
}

func TestCaddyfileRejectsBadDirectives(t *testing.T) {
	blocks := []string{
		"block_countries AU",
		"block_country",
		"block_risk",
		"block_risk high",
		"block_risk NaN",
		"block_risk -1",
		"block_risk 0",
		"block_risk 1.5",
		"block_risk 0.5 0.6",
		"block_country AU\n block_country US",
		"block_risk 0.5\n block_risk 0.6",
		"Block_Country AU",
		"allow_provider",
		"trusted_proxies",
		"trusted_proxies ::/0\n trusted_proxies ::/0",
	}
	for _, text := range []string{"iplore", "iplore db.ipl extra"} {
		if _, err := parse(text); err == nil {
			t.Errorf("%q accepted", text)
		}
	}
	for _, block := range blocks {
		if _, err := parse("iplore db.ipl {\n " + block + "\n}"); err == nil {
			t.Errorf("%q accepted", block)
		}
	}
}

func TestCaddyfileParsesRules(t *testing.T) {
	handler, err := parse(`iplore db.ipl {
		block_risk 0.5
		block_service tor_exit_node anonymous_vpn
		allow_country US DE
		allow_provider Googlebot
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if handler.File != "db.ipl" || handler.BlockRisk != 0.5 ||
		len(handler.BlockService) != 2 || len(handler.AllowCountry) != 2 ||
		handler.AllowProvider[0] != "Googlebot" {
		t.Errorf("parsed %+v", handler.Config)
	}
}

func TestProvisionRejectsBadConfig(t *testing.T) {
	for _, risk := range []float64{-1, 2} {
		handler := &Handler{}
		handler.File, handler.BlockRisk = databasePath(t), risk
		if handler.Provision(caddy.Context{}) == nil {
			t.Errorf("risk %v accepted", risk)
		}
	}
	if (&Handler{}).Provision(caddy.Context{}) == nil {
		t.Error("missing file accepted")
	}
}

func serve(t *testing.T, proxies []string, peer string, forwarded ...string) int {
	t.Helper()
	handler := &Handler{TrustedProxies: proxies}
	handler.File = databasePath(t)
	handler.BlockCountry = []string{"au"}
	if err := handler.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = peer
	for _, line := range forwarded {
		request.Header.Add("X-Forwarded-For", line)
	}
	err := handler.ServeHTTP(httptest.NewRecorder(), request, passThrough)
	if err == nil {
		return http.StatusOK
	}
	return err.(caddyhttp.HandlerError).StatusCode
}

var passThrough = caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
	return nil
})

func TestHandlerFailsClosed(t *testing.T) {
	proxies := []string{"172.16.0.0/12"}
	cases := []struct {
		name, peer string
		forwarded  []string
		want       int
	}{
		{"blocked peer", "1.1.1.1:5", nil, http.StatusForbidden},
		{"allowed peer", "8.8.8.8:5", nil, http.StatusOK},
		{"untrusted peer hides behind header", "1.1.1.1:5", []string{"8.8.8.8"}, 403},
		{"trusted peer, allowed client", "172.18.0.1:5", []string{"8.8.8.8"}, 200},
		{"trusted peer, blocked client", "172.18.0.1:5", []string{"1.1.1.1"}, 403},
		{"last line wins", "172.18.0.1:5", []string{"1.1.1.1", "8.8.8.8"}, 200},
		{"malformed hop", "172.18.0.1:5", []string{"8.8.8.8, nope"}, 403},
		{"malformed only", "172.18.0.1:5", []string{"nope"}, 403},
		{"malformed second line", "172.18.0.1:5", []string{"8.8.8.8", "nope"}, 403},
		{"empty header", "172.18.0.1:5", []string{""}, 403},
		{"invalid peer", "garbage", nil, http.StatusForbidden},
	}
	for _, c := range cases {
		if code := serve(t, proxies, c.peer, c.forwarded...); code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, code, c.want)
		}
	}
}

func TestHandlerWithoutProxiesJudgesThePeer(t *testing.T) {
	if code := serve(t, nil, "8.8.8.8:5", "1.1.1.1"); code != http.StatusOK {
		t.Errorf("forwarded header honored without trusted proxies: %d", code)
	}
}

func TestProvisionRejectsBadProxies(t *testing.T) {
	handler := &Handler{TrustedProxies: []string{"10.0.0.0/8", "nope"}}
	handler.File = databasePath(t)
	if handler.Provision(caddy.Context{}) == nil {
		t.Error("accepted invalid trusted proxy")
	}
}

func TestHandlerStripsClientHeaders(t *testing.T) {
	header := http.Header{"X-Other": {"kept"}}
	handler := &Handler{}
	handler.File = databasePath(t)
	if err := handler.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "10.0.0.1:5"
	request.Header = header
	for _, name := range []string{
		"X-Iplore-Country", "X_Iplore_Country", "X-Iplore_Provider", "X_IPLORE_RISK",
	} {
		header[name] = []string{"forged"}
	}
	recorder := httptest.NewRecorder()
	if err := handler.ServeHTTP(recorder, request, passThrough); err != nil {
		t.Fatal(err)
	}
	if len(header) != 1 || header.Get("X-Other") != "kept" {
		t.Errorf("headers %v", header)
	}
}
