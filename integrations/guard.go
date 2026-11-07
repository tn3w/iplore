package iplore

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	headerPrefix   = "X-Iplore-"
	headerLimit    = 128
	reloadInterval = 5 * time.Second
)

type Config struct {
	File          string   `json:"file"`
	BlockRisk     float64  `json:"block_risk,omitempty"`
	BlockService  []string `json:"block_service,omitempty"`
	BlockCountry  []string `json:"block_country,omitempty"`
	AllowCountry  []string `json:"allow_country,omitempty"`
	BlockCategory []string `json:"block_category,omitempty"`
	AllowProvider []string `json:"allow_provider,omitempty"`
}

type Info struct {
	Country  string
	ASN      uint64
	Category string
	Risk     *float64
	Service  string
	Provider string
}

type Guard struct {
	config   Config
	mutex    sync.Mutex
	reader   *Reader
	modified time.Time
	checked  time.Time
	failure  string
}

func NewGuard(config Config) (*Guard, error) {
	guard := &Guard{config: config}
	if err := guard.reload(); err != nil {
		return nil, err
	}
	return guard, nil
}

func (g *Guard) reload() error {
	stat, err := os.Stat(g.config.File)
	if err != nil {
		return err
	}
	if g.reader != nil && stat.ModTime().Equal(g.modified) {
		return nil
	}
	reader, err := Open(g.config.File)
	if err != nil {
		return err
	}
	g.reader = reader
	g.modified = stat.ModTime()
	return nil
}

func (g *Guard) current() *Reader {
	g.mutex.Lock()
	defer g.mutex.Unlock()
	if time.Since(g.checked) <= reloadInterval {
		return g.reader
	}
	g.checked = time.Now()
	g.report(g.reload())
	return g.reader
}

func (g *Guard) report(err error) {
	if err == nil {
		g.failure = ""
		return
	}
	if err.Error() != g.failure {
		log.Printf("iplore: keeping previous database: %v", err)
	}
	g.failure = err.Error()
}

func (g *Guard) Inspect(address string) (Info, error) {
	values, err := g.current().Lookup(address)
	if err != nil {
		return Info{}, err
	}
	info := Info{
		Country:  text(values["place.country.code"]),
		Category: text(values["network.operator.category"]),
		Service:  text(values["abuse.service"]),
		Provider: text(values["abuse.provider"]),
	}
	asn, _ := values["network.asn"].(float64)
	info.ASN = uint64(asn)
	if risk, found := values["abuse.risk"].(float64); found {
		info.Risk = &risk
	}
	return info, nil
}

func text(value any) string {
	result, _ := value.(string)
	return result
}

func (i Info) Apply(header http.Header) {
	for name, value := range i.headers() {
		if value = sanitize(value); value != "" {
			header.Set(headerPrefix+name, value)
		}
	}
}

func sanitize(value string) string {
	value = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return -1
		}
		return character
	}, value)
	if len(value) > headerLimit {
		value = strings.ToValidUTF8(value[:headerLimit], "")
	}
	return value
}

func (i Info) headers() map[string]string {
	headers := map[string]string{
		"Country":  i.Country,
		"Category": i.Category,
		"Service":  i.Service,
		"Provider": i.Provider,
	}
	if i.ASN > 0 {
		headers["Asn"] = strconv.FormatUint(i.ASN, 10)
	}
	if i.Risk != nil {
		headers["Risk"] = strconv.FormatFloat(*i.Risk, 'f', -1, 64)
	}
	return headers
}

func ParseRisk(text string) (float64, error) {
	risk, err := strconv.ParseFloat(text, 64)
	if err != nil || !(risk > 0 && risk <= 1) {
		return 0, fmt.Errorf("block_risk %q must be a number in (0, 1]", text)
	}
	return risk, nil
}

func (c Config) Validate() error {
	if c.File == "" {
		return errors.New("database file missing")
	}
	if !(c.BlockRisk >= 0 && c.BlockRisk <= 1) {
		return fmt.Errorf("block_risk %v must be in (0, 1]", c.BlockRisk)
	}
	return nil
}

func (c Config) Blocks(info Info) bool {
	if info.Service == "" && contains(c.AllowProvider, info.Provider) {
		return false
	}
	highRisk := c.BlockRisk > 0 && info.Risk != nil && *info.Risk >= c.BlockRisk
	foreign := len(c.AllowCountry) > 0 && info.Country != "" &&
		!contains(c.AllowCountry, info.Country)
	return highRisk || foreign ||
		contains(c.BlockService, info.Service) ||
		contains(c.BlockCountry, info.Country) ||
		contains(c.BlockCategory, info.Category)
}

func isInternalHeader(name string) bool {
	normalized := strings.ReplaceAll(strings.ToLower(name), "_", "-")
	return strings.HasPrefix(normalized, strings.ToLower(headerPrefix))
}

func (g *Guard) Protect(request *http.Request, address string) (bool, error) {
	for name := range request.Header {
		if isInternalHeader(name) {
			delete(request.Header, name)
		}
	}
	info, err := g.Inspect(address)
	if err != nil {
		return false, err
	}
	info.Apply(request.Header)
	return g.config.Blocks(info), nil
}

func ClientAddress(request *http.Request, proxies []netip.Prefix) string {
	peer := parseAddress(request.RemoteAddr)
	if !peer.IsValid() {
		return ""
	}
	if !isProxy(peer, proxies) {
		return peer.String()
	}
	lines := request.Header.Values("X-Forwarded-For")
	if len(lines) == 0 {
		return peer.String()
	}
	hops := strings.Split(strings.Join(lines, ","), ",")
	for index := len(hops) - 1; index >= 0; index-- {
		hop := parseAddress(strings.TrimSpace(hops[index]))
		if !hop.IsValid() {
			return ""
		}
		if !isProxy(hop, proxies) {
			return hop.String()
		}
	}
	return peer.String()
}

func isProxy(address netip.Addr, proxies []netip.Prefix) bool {
	return slices.ContainsFunc(proxies, func(network netip.Prefix) bool {
		return network.Contains(address)
	})
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if value != "" && strings.EqualFold(item, value) {
			return true
		}
	}
	return false
}
