package caddyiplore

import (
	"errors"
	"net/http"
	"net/netip"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"

	iplore "github.com/tn3w/iplore/integrations"
)

func init() {
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("iplore", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("iplore", httpcaddyfile.Before, "header")
}

type Handler struct {
	iplore.Config
	TrustedProxies []string `json:"trusted_proxies,omitempty"`
	guard          *iplore.Guard
	proxies        []netip.Prefix
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.iplore",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (h *Handler) Provision(caddy.Context) error {
	if err := h.Config.Validate(); err != nil {
		return err
	}
	for _, item := range h.TrustedProxies {
		network, err := netip.ParsePrefix(item)
		if err != nil {
			return err
		}
		h.proxies = append(h.proxies, network)
	}
	guard, err := iplore.NewGuard(h.Config)
	h.guard = guard
	return err
}

func (h *Handler) ServeHTTP(
	writer http.ResponseWriter, request *http.Request, next caddyhttp.Handler,
) error {
	address := iplore.ClientAddress(request, h.proxies)
	blocked, err := h.guard.Protect(request, address)
	if errors.Is(err, iplore.ErrAddress) {
		return caddyhttp.Error(http.StatusForbidden, err)
	}
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}
	if blocked {
		return caddyhttp.Error(http.StatusForbidden, nil)
	}
	return next.ServeHTTP(writer, request)
}

func (h *Handler) lists() map[string]*[]string {
	return map[string]*[]string{
		"block_service":   &h.BlockService,
		"block_country":   &h.BlockCountry,
		"allow_country":   &h.AllowCountry,
		"block_category":  &h.BlockCategory,
		"allow_provider":  &h.AllowProvider,
		"trusted_proxies": &h.TrustedProxies,
	}
}

func (h *Handler) parseOption(dispenser *caddyfile.Dispenser, option string) error {
	if option == "block_risk" {
		var text string
		if !dispenser.Args(&text) || dispenser.NextArg() {
			return dispenser.ArgErr()
		}
		risk, err := iplore.ParseRisk(text)
		h.BlockRisk = risk
		return err
	}
	target, known := h.lists()[option]
	if !known {
		return dispenser.Errf("unknown option %q", option)
	}
	*target = dispenser.RemainingArgs()
	if len(*target) == 0 {
		return dispenser.ArgErr()
	}
	return nil
}

func (h *Handler) UnmarshalCaddyfile(dispenser *caddyfile.Dispenser) error {
	dispenser.Next()
	if !dispenser.Args(&h.File) || dispenser.NextArg() {
		return dispenser.ArgErr()
	}
	seen := map[string]bool{}
	for dispenser.NextBlock(0) {
		option := dispenser.Val()
		if seen[option] {
			return dispenser.Errf("duplicate option %q", option)
		}
		seen[option] = true
		if err := h.parseOption(dispenser, option); err != nil {
			return err
		}
	}
	return nil
}

func parseCaddyfile(helper httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	handler := new(Handler)
	err := handler.UnmarshalCaddyfile(helper.Dispenser)
	return handler, err
}
