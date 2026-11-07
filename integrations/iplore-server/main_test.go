package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	iplore "github.com/tn3w/iplore/integrations"
)

func newHandler(t *testing.T) http.Handler {
	t.Helper()
	path := ""
	for _, directory := range []string{"../.scratch", "../../bindings/data"} {
		candidate := filepath.Join(directory, "iplore-country.ipl")
		if _, err := os.Stat(candidate); err == nil {
			path = candidate
		}
	}
	if path == "" {
		t.Skip("iplore-country.ipl not available")
	}
	guard, err := iplore.NewGuard(iplore.Config{File: path})
	if err != nil {
		t.Fatal(err)
	}
	proxies, err := parseProxies("172.16.0.0/12,127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	return handler(guard, proxies)
}

type call struct {
	method, query, peer string
	forwarded           []string
}

func (c call) serve(handler http.Handler) *httptest.ResponseRecorder {
	method := c.method
	if method == "" {
		method = http.MethodGet
	}
	request := httptest.NewRequest(method, "/?"+c.query, nil)
	request.RemoteAddr = c.peer
	for _, line := range c.forwarded {
		request.Header.Add("X-Forwarded-For", line)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func TestRuleQueryFailsClosed(t *testing.T) {
	handler := newHandler(t)
	queries := []string{
		"unknown_rule=1",
		"Block_Country=AU",
		"block_countries=AU",
		"block_risk=",
		"block_risk=abc",
		"block_risk=NaN",
		"block_risk=Inf",
		"block_risk=-0.5",
		"block_risk=0",
		"block_risk=1.5",
		"block_risk=1e999",
		"block_risk=0.5&block_risk=0.9",
		"block_country=AU&block_country=US",
		"block_country=",
		"block_country=AU,,US",
		"block_country=%zz",
		"block_country=AU;block_service=x",
		"block_country=AU&unknown=1",
	}
	for _, query := range queries {
		got := call{query: query, peer: "172.18.0.1:1", forwarded: []string{"1.1.1.1"}}
		if code := got.serve(handler).Code; code != http.StatusBadRequest {
			t.Errorf("%q: status %d, want 400", query, code)
		}
	}
}

func TestRulesApply(t *testing.T) {
	handler := newHandler(t)
	cases := []struct {
		query string
		want  int
	}{
		{"", http.StatusNoContent},
		{"block_country=au", http.StatusForbidden},
		{"block_country=US,AU", http.StatusForbidden},
		{"block_country=us", http.StatusNoContent},
		{"allow_country=us", http.StatusForbidden},
		{"allow_country=AU", http.StatusNoContent},
		{"block_risk=0.5", http.StatusNoContent},
	}
	for _, c := range cases {
		got := call{query: c.query, peer: "172.18.0.1:1", forwarded: []string{"1.1.1.1"}}
		if code := got.serve(handler).Code; code != c.want {
			t.Errorf("%q: status %d, want %d", c.query, code, c.want)
		}
	}
}

func TestClientAddressFailsClosed(t *testing.T) {
	handler := newHandler(t)
	bad := []call{
		{peer: "172.18.0.1:1", forwarded: []string{"nope"}},
		{peer: "172.18.0.1:1", forwarded: []string{"1.1.1.1, nope"}},
		{peer: "172.18.0.1:1", forwarded: []string{"1.1.1.1", "nope"}},
		{peer: "172.18.0.1:1", forwarded: []string{""}},
		{peer: "garbage", forwarded: []string{"1.1.1.1"}},
	}
	for _, got := range bad {
		if code := got.serve(handler).Code; code != http.StatusForbidden {
			t.Errorf("%v: status %d, want 403", got, code)
		}
	}
}

func TestForwardedHeaderNeedsTrustedPeer(t *testing.T) {
	handler := newHandler(t)
	query := "block_country=AU"
	spoofed := call{query: query, peer: "8.8.8.8:1", forwarded: []string{"10.0.0.1"}}
	if code := spoofed.serve(handler).Code; code != http.StatusNoContent {
		t.Errorf("untrusted peer 8.8.8.8 must be judged by itself: status %d", code)
	}
	direct := call{query: query, peer: "1.1.1.1:1", forwarded: []string{"8.8.8.8"}}
	if code := direct.serve(handler).Code; code != http.StatusForbidden {
		t.Errorf("untrusted peer 1.1.1.1 hides behind header: status %d", code)
	}
	lines := []string{"1.1.1.1", "8.8.8.8, 127.0.0.1"}
	multiple := call{query: query, peer: "127.0.0.1:1", forwarded: lines}
	if code := multiple.serve(handler).Code; code != http.StatusNoContent {
		t.Errorf("rightmost hop must win over earlier lines: status %d", code)
	}
}

func TestOnlyReadMethods(t *testing.T) {
	handler := newHandler(t)
	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		got := call{method: method, peer: "127.0.0.1:1", forwarded: []string{"1.1.1.1"}}
		if code := got.serve(handler).Code; code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d, want 405", method, code)
		}
	}
	head := call{method: "HEAD", peer: "127.0.0.1:1", forwarded: []string{"1.1.1.1"}}
	if code := head.serve(handler).Code; code != http.StatusNoContent {
		t.Errorf("HEAD: status %d", code)
	}
}

func TestResponseHeaders(t *testing.T) {
	handler := newHandler(t)
	got := call{peer: "127.0.0.1:1", forwarded: []string{"1.1.1.1"}}
	recorder := got.serve(handler)
	if recorder.Header().Get("X-Iplore-Country") == "" {
		t.Error("country header missing")
	}
	for name := range recorder.Header() {
		if !strings.HasPrefix(name, "X-Iplore-") {
			t.Errorf("unexpected response header %s", name)
		}
	}
}

func TestParseProxies(t *testing.T) {
	for _, text := range []string{"nope", "1.2.3.4/33", "10.0.0.0/8,x", "10.0.0.0/8;x"} {
		if _, err := parseProxies(text); err == nil {
			t.Errorf("accepted %q", text)
		}
	}
	proxies, err := parseProxies("127.0.0.0/8, ::1/128")
	if err != nil || len(proxies) != 2 || proxies[1] != netip.MustParsePrefix("::1/128") {
		t.Errorf("got %v %v", proxies, err)
	}
}
