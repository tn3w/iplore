<p align="center">
  <img src=".github/header.svg" width="100%" alt="iplore: offline IP lookup from one file">
</p>

<p align="center">
  <a href="https://github.com/tn3w/iplore/releases/latest"><img src="https://img.shields.io/github/v/release/tn3w/iplore?filter=db-*&label=database" alt="database"></a>
  <a href="https://github.com/tn3w/iplore/actions/workflows/ci.yml"><img src="https://github.com/tn3w/iplore/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/tn3w/iplore" alt="license"></a>
</p>

```sh
cargo install --git https://github.com/tn3w/iplore reader
curl -LO https://github.com/tn3w/iplore/releases/latest/download/iplore-full.ipl

iplore iplore-full.ipl 1.1.1.1
```

```json
{
  "place": {"lat": -33.8679, "lon": 151.2073, "accuracy": 100, "confidence": 60,
    "city": {"name": "Sydney", "timezone": "Australia/Sydney"},
    "country": {"code": "AU", "name": "Australia", "currency": "AUD"}},
  "network": {"asn": 13335, "handle": "CLOUDFLARENET", "prefix": 24, "rpki": "valid",
    "operator": {"company": "Cloudflare, Inc.", "category": "cdn",
      "abuse_email": "abuse@cloudflare.com"}},
  "abuse": {"risk": null, "service": null, "flags": ["anycast"]}
}
```

Missing values are `null`. Reserved addresses (private, loopback, …) answer nothing.
IPv4, IPv6, v4-mapped, `[addr]:port` and `%zone` are accepted (no surrounding whitespace);
anything else is an invalid address (CLI exit 2).

## CLI

| command | does |
| --- | --- |
| `iplore <file> <address>` | JSON answer |
| `iplore <file> --about` | fields, vocabularies, sources, licenses |
| `iplore <file> --bench` | open time, cold and warm lookups, peak memory |

## Python, JavaScript, edge

```sh
release=https://github.com/tn3w/iplore/releases
pip install iplore --no-index -f $release/expanded_assets/bindings   # Python 3.9+
curl -LO $release/download/bindings/iplore.tgz && npm install ./iplore.tgz   # Node, Bun, Deno, Workers
```

```python
iplore.open("iplore-full.ipl").lookup("1.1.1.1")["network"]["asn"]  # 13335
```

```ts
(await open(await fetch(url))).lookup("1.1.1.1").network?.asn;  // 13335
```

Workers setup and a full example: [CONTRIBUTING](.github/CONTRIBUTING.md#edge-workers).

## Downloads

Built every Sunday, newest 3 releases kept.
`releases/latest/download/<file>` always points at the current build. Verify with
`sha256sum -c SHA256SUMS --ignore-missing` or `gh attestation verify <file> -R tn3w/iplore`.

| file | use case | size |
| --- | --- | ---: |
| `iplore-full.ipl` | IP intelligence, everything | 19.2 MB |
| `iplore-place.ipl` | geolocation, geo-routing, analytics | 6.4 MB |
| `iplore-country.ipl` | country blocking, compliance, localization | 0.5 MB |
| `iplore-network.ipl` | ASN and operator lookup, abuse contacts | 6.2 MB |
| `iplore-traffic.ipl` | bot and fraud triage: ASN, hosting / residential / mobile | 1.5 MB |
| `iplore-anonymizer.ipl` | detect VPN, proxy, Tor, private relay | 2.2 MB |
| `iplore-abuse.ipl` | risk scoring: services, providers, threat risk | 5.3 MB |
| `blocklist.netset` | web server protection: 418k CIDRs for nginx, ipset, nftables | 7.2 MB |

Need another cut? `builder abuse.service=tor_exit_node` builds a 10 KB Tor-only file,
see [CONTRIBUTING](.github/CONTRIBUTING.md).

## Fields

| group | fields |
| --- | --- |
| `place` | `lat` `lon` `accuracy` (km) `confidence` (0–100), `city`, `region`, `country` |
| `network` | `asn` `handle` `prefix` `rir` `year` `rpki` `users` `mobile_code` `risk`, `operator` |
| `abuse` | `risk` `threat` `reports` `last_seen_days` `service` `evidence` `provider` `user_type` `flags` |

49 fields in total, `iplore <file> --about` lists them.

## Web servers

Caddy, Traefik and nginx add `X-Iplore-Country`, `-Asn`, `-Category`, `-Risk`, `-Service`
and `-Provider` upstream and answer `403` on a match. Bad rules or an unreadable client
address fail closed.

```sh
xcaddy build --with github.com/tn3w/iplore/integrations/caddy
go install github.com/tn3w/iplore/integrations/iplore-server@latest
iplore-server -file iplore-full.ipl -listen 127.0.0.1:8080 -trusted 127.0.0.0/8

# Caddyfile  iplore * iplore-full.ipl { block_risk 0.5; block_service tor_exit_node }
# nginx      auth_request /_iplore;  (proxy_pass http://127.0.0.1:8080/?block_risk=0.5)
# Traefik    forwardAuth address http://127.0.0.1:8080/?block_risk=0.5, trustForwardHeader: true
```

Rules, setup and tests: [CONTRIBUTING](.github/CONTRIBUTING.md#integrations).

## Performance

Single thread.

| build | warm lookups/s |
| --- | ---: |
| full | 256k |
| place | 700k |
| country | 3.3M |
| Tor exits (custom) | 7.8M |

Open 0.4–3.5 ms, cold lookup 0.2 µs–0.58 ms, peak memory 16–215 MB.

## Accuracy

- City agreement against held-out operator geofeeds: 81.6% (v4), 81.8% (v6)
- Each answer carries `confidence` and `accuracy`, filter on them
- `risk` is a signal from 414 feeds weighted by threat, age and quality, not a verdict

## Data and license

Code is MIT. Data comes from MaxMind GeoLite2, DB-IP, IPinfo, GeoNames, CAIDA,
RouteViews, RPKI, RIR dumps, PeeringDB, bgp.tools, APNIC and public threat feeds. Each
source keeps its own license: [LICENSES](data/LICENSES), also embedded in every file header.

## Contributing

Build from source, data files, scoring and file format:
[CONTRIBUTING.md](.github/CONTRIBUTING.md). New feed ideas: open an issue with URL and
license.
