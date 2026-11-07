package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	iplore "github.com/tn3w/iplore/integrations"
)

func parseList(text string) ([]string, error) {
	items := strings.Split(text, ",")
	for _, item := range items {
		if strings.TrimSpace(item) == "" {
			return nil, fmt.Errorf("empty item in %q", text)
		}
	}
	return items, nil
}

func rules(query url.Values) (iplore.Config, error) {
	var config iplore.Config
	lists := map[string]*[]string{
		"block_service":  &config.BlockService,
		"block_country":  &config.BlockCountry,
		"allow_country":  &config.AllowCountry,
		"block_category": &config.BlockCategory,
		"allow_provider": &config.AllowProvider,
	}
	for name, values := range query {
		if len(values) != 1 {
			return config, fmt.Errorf("%s given %d times", name, len(values))
		}
		var err error
		if target, known := lists[name]; known {
			*target, err = parseList(values[0])
		} else if name == "block_risk" {
			config.BlockRisk, err = iplore.ParseRisk(values[0])
		} else {
			err = fmt.Errorf("unknown rule %q", name)
		}
		if err != nil {
			return config, err
		}
	}
	return config, nil
}

func parseProxies(text string) ([]netip.Prefix, error) {
	var proxies []netip.Prefix
	for _, item := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' }) {
		network, err := netip.ParsePrefix(strings.TrimSpace(item))
		if err != nil {
			return nil, err
		}
		proxies = append(proxies, network)
	}
	return proxies, nil
}

func handler(guard *iplore.Guard, proxies []netip.Prefix) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet && request.Method != http.MethodHead {
			writer.Header().Set("Allow", "GET, HEAD")
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		query, err := url.ParseQuery(request.URL.RawQuery)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		config, err := rules(query)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		info, err := guard.Inspect(iplore.ClientAddress(request, proxies))
		if errors.Is(err, iplore.ErrAddress) {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		info.Apply(writer.Header())
		if config.Blocks(info) {
			writer.WriteHeader(http.StatusForbidden)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
}

func main() {
	file := flag.String("file", "", "iplore database")
	listen := flag.String("listen", "127.0.0.1:8080", "listen address")
	trusted := flag.String("trusted", "127.0.0.0/8,::1/128", "proxy CIDRs")
	flag.Parse()
	proxies, err := parseProxies(*trusted)
	if err != nil {
		log.Fatal(err)
	}
	guard, err := iplore.NewGuard(iplore.Config{File: *file})
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{
		Addr:              *listen,
		Handler:           handler(guard, proxies),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	log.Fatal(server.ListenAndServe())
}
