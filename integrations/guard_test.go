package iplore

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func databasePath(t *testing.T, name string) string {
	t.Helper()
	for _, directory := range []string{".scratch", "../bindings/data"} {
		path := filepath.Join(directory, name)
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	t.Skipf("%s not available", name)
	return ""
}

func TestRules(t *testing.T) {
	risk := 0.7
	config := Config{
		BlockRisk:     0.5,
		BlockService:  []string{"tor_exit_node", "anonymous_vpn"},
		BlockCountry:  []string{"ru"},
		AllowCountry:  []string{"US", "DE"},
		BlockCategory: []string{"hosting"},
		AllowProvider: []string{"Googlebot"},
	}
	cases := []struct {
		name    string
		info    Info
		blocked bool
	}{
		{"clean", Info{Country: "US", Category: "cdn"}, false},
		{"risk at threshold", Info{Country: "US", Risk: &risk}, true},
		{"service", Info{Country: "US", Service: "TOR_EXIT_NODE"}, true},
		{"denied country", Info{Country: "RU"}, true},
		{"outside allow list", Info{Country: "FR"}, true},
		{"unknown country passes", Info{}, false},
		{"hosting", Info{Country: "DE", Category: "hosting"}, true},
		{"allowed provider", Info{Provider: "googlebot", Risk: &risk}, false},
		{"other provider", Info{Country: "FR", Provider: "Hetzner"}, true},
		{"provider label on anonymizer", Info{
			Country: "US", Provider: "Googlebot", Service: "anonymous_vpn",
		}, true},
		{"provider label on risky anonymizer", Info{
			Country: "FR", Provider: "Googlebot", Service: "private_relay", Risk: &risk,
		}, true},
	}
	for _, c := range cases {
		if got := config.Blocks(c.info); got != c.blocked {
			t.Errorf("%s: got %v, want %v", c.name, got, c.blocked)
		}
	}
}

func TestClientAddress(t *testing.T) {
	const proxy = "172.18.0.1:5"
	proxies := []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")}
	cases := []struct {
		name, peer string
		forwarded  []string
		want       string
	}{
		{"untrusted peer ignores header", "8.8.8.8:5000", []string{"1.1.1.1"}, "8.8.8.8"},
		{"untrusted ipv6 peer", "[2606:4700::1]:5", []string{"1.1.1.1"}, "2606:4700::1"},
		{"trusted peer without header", proxy, nil, "172.18.0.1"},
		{"single client", proxy, []string{"1.1.1.1"}, "1.1.1.1"},
		{"proxy appended", proxy, []string{"1.1.1.1, 172.18.0.1"}, "1.1.1.1"},
		{"spoofed prefix", proxy, []string{"6.6.6.6, 1.1.1.1"}, "1.1.1.1"},
		{"spoofed first line", proxy, []string{"6.6.6.6", "1.1.1.1"}, "1.1.1.1"},
		{"ipv6 client", proxy, []string{"2606:4700::1, 172.17.0.2"}, "2606:4700::1"},
		{"hop with port", proxy, []string{" 1.1.1.1:443 "}, "1.1.1.1"},
		{"only proxies", proxy, []string{"172.17.0.2, 172.18.0.1"}, "172.18.0.1"},
		{"garbage after client", proxy, []string{"1.1.1.1, nope"}, ""},
		{"garbage in later line", proxy, []string{"1.1.1.1", "nope"}, ""},
		{"garbage before proxy", proxy, []string{"nope, 172.17.0.2"}, ""},
		{"unknown token", proxy, []string{"unknown"}, ""},
		{"empty header", proxy, []string{""}, ""},
		{"empty hop", proxy, []string{"1.1.1.1,,172.17.0.2"}, ""},
		{"garbage left of client", proxy, []string{"nope, 1.1.1.1"}, "1.1.1.1"},
		{"invalid peer", "garbage", []string{"1.1.1.1"}, ""},
	}
	for _, c := range cases {
		request := &http.Request{RemoteAddr: c.peer, Header: http.Header{}}
		for _, line := range c.forwarded {
			request.Header.Add("X-Forwarded-For", line)
		}
		if got := ClientAddress(request, proxies); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestParseAddress(t *testing.T) {
	var cases struct {
		Valid   map[string]string
		Invalid []string
	}
	content, err := os.ReadFile("../reader/tests/addresses.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, &cases); err != nil {
		t.Fatal(err)
	}
	for input, want := range cases.Valid {
		if got := parseAddress(input); got.String() != want {
			t.Errorf("%q: got %v, want %s", input, got, want)
		}
	}
	for _, input := range cases.Invalid {
		if got := parseAddress(input); got.IsValid() {
			t.Errorf("%q: accepted as %v", input, got)
		}
	}
}

func TestApplySanitizesHeaders(t *testing.T) {
	info := Info{
		Country:  "US",
		Provider: "Evil\r\nX-Injected: 1\x00\x7f" + strings.Repeat("é", 200),
		Service:  "\r\n",
	}
	header := http.Header{}
	info.Apply(header)
	provider := header.Get("X-Iplore-Provider")
	if strings.ContainsAny(provider, "\r\n\x00\x7f") || len(provider) > headerLimit {
		t.Errorf("unsafe provider header %q", provider)
	}
	if !strings.HasPrefix(provider, "EvilX-Injected: 1") {
		t.Errorf("provider header %q", provider)
	}
	if _, found := header["X-Iplore-Service"]; found {
		t.Error("empty value after sanitizing must not be set")
	}
}

func TestProtectStripsClientHeaders(t *testing.T) {
	guard, err := NewGuard(Config{File: databasePath(t, "iplore-country.ipl")})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/", nil)
	for _, name := range []string{
		"X-Iplore-Country", "x-iplore-foo", "X_Iplore_Country", "X-Iplore_Country",
		"x_iplore-provider", "X_IPLORE_RISK",
	} {
		request.Header[name] = []string{"forged"}
	}
	request.Header.Set("X-Other", "kept")
	if _, err := guard.Protect(request, "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if len(request.Header) != 1 || request.Header.Get("X-Other") != "kept" {
		t.Errorf("headers after protect: %v", request.Header)
	}
	if _, err := guard.Protect(request, "1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if request.Header.Get("X-Iplore-Country") == "" {
		t.Error("lookup headers missing")
	}
}

func TestProtectFailsClosedOnBadAddress(t *testing.T) {
	guard, err := NewGuard(Config{File: databasePath(t, "iplore-country.ipl")})
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"", " ", "nope", "1.1.1.1,2.2.2.2", "1.1.1.1 "} {
		request := httptest.NewRequest("GET", "/", nil)
		blocked, err := guard.Protect(request, address)
		if err == nil || blocked {
			t.Errorf("%q: got blocked=%v err=%v, want error", address, blocked, err)
		}
	}
}

func TestParseRisk(t *testing.T) {
	invalid := []string{"", " ", "abc", "NaN", "Inf", "-0.1", "0", "1.01", "1e999"}
	for _, text := range invalid {
		if _, err := ParseRisk(text); err == nil {
			t.Errorf("accepted %q", text)
		}
	}
	for _, text := range []string{"0.5", "1", "0.0001", "1e-3"} {
		if _, err := ParseRisk(text); err != nil {
			t.Errorf("rejected %q: %v", text, err)
		}
	}
}

func TestValidate(t *testing.T) {
	cases := map[string]Config{
		"no file":  {},
		"negative": {File: "x", BlockRisk: -0.5},
		"too high": {File: "x", BlockRisk: 5},
	}
	for name, config := range cases {
		if config.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := (Config{File: "x", BlockRisk: 0.5}).Validate(); err != nil {
		t.Error(err)
	}
}

func TestReloadKeepsPreviousDatabase(t *testing.T) {
	original, err := os.ReadFile(databasePath(t, "iplore-country.ipl"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "database.ipl")
	write := func(content []byte, age time.Duration) {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
		modified := time.Now().Add(age)
		if err := os.Chtimes(path, modified, modified); err != nil {
			t.Fatal(err)
		}
	}
	write(original, -time.Hour)
	guard, err := NewGuard(Config{File: path})
	if err != nil {
		t.Fatal(err)
	}
	var logged bytes.Buffer
	log.SetOutput(&logged)
	defer log.SetOutput(os.Stderr)
	write(original[:len(original)/2], 0)
	for range 3 {
		guard.checked = time.Time{}
		guard.current()
	}
	info, err := guard.Inspect("1.1.1.1")
	if err != nil || info.Country == "" {
		t.Fatalf("old data lost: %v %v", info, err)
	}
	if lines := strings.Count(logged.String(), "\n"); lines != 1 {
		t.Errorf("logged %d lines, want 1: %q", lines, logged.String())
	}
	write(original, time.Minute)
	guard.checked = time.Time{}
	guard.current()
	if guard.failure != "" {
		t.Errorf("failure not cleared: %s", guard.failure)
	}
}

func TestNewGuardRejectsBrokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database.ipl")
	broken := []byte("IPLORE\x00\x01\xff\xff\xff\xff")
	if err := os.WriteFile(path, broken, 0o600); err != nil {
		t.Fatal(err)
	}
	if guard, err := NewGuard(Config{File: path}); err == nil || guard != nil {
		t.Errorf("accepted broken file: %v %v", guard, err)
	}
}
