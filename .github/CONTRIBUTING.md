# Contributing

Bug reports, new feeds and code are welcome. Fork, branch off `master`, keep one topic per
pull request, and update this file when behaviour or layout changes.

```sh
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
```

Style: self-documenting names, no comments, max 90 chars per line, early returns, nesting
below 4. Domain data (lists, URLs, weights, regexes) lives in `data/*.json`, code holds
mechanisms only. Adding a feed or source is a JSON entry in `data/feeds.json` or
`data/sources.json` with its `license`.

Rust workspace: `builder` fetches public sources and writes `dist/*.ipl`; `reader`
(library + `iplore` CLI) answers lookups. `reader` decodes LZMA with pure Rust
(`lzma-rust2`), so it builds for WebAssembly and wheels without a C toolchain; `builder`
encodes with liblzma. `bindings/*` are workspace members outside `default-members`.

The file stores only facts. Anything a client can compute from the address or from another
answered value is left out: address spellings, CIDR bounds, local time, granularity, risk
levels, `is_*` booleans, brand names, ASCII names, flag emoji. Reserved space (loopback,
private, link-local, CGNAT, documentation, multicast, 6to4, Teredo, ULA, …) is masked:
it answers nothing and its names are not stored.

## Bindings

`reader` stays the only place with lookup logic; bindings only move bytes and JSON.

Errors are two kinds everywhere, never a panic: an invalid address (`reader::Error::InvalidAddress`,
CLI exit 2, JS `TypeError`, Python `ValueError`) and a corrupt database
(`Error::Corrupt`, CLI exit 1, JS `DatabaseError`, Python `iplore.DatabaseError`). `Reader`
validates the header structure once at open (sections, offsets, block sizes, LZMA settings)
and caps every decompression, so lookups on untrusted files cannot panic or blow up memory.
The address grammar is `reader/tests/addresses.json`, shared with the Go reader.

| path | what |
| --- | --- |
| `bindings/wasm` | `cdylib`: `allocate`, `load`, `lookup`, `about`, `output`, `output_length`; they return a status (0 ok, 1 invalid address, 2 corrupt database, 3 not loaded, 4 already loaded), one database per instance |
| `bindings/js` | `iplore` npm package: TypeScript wrapper, `dist/iplore.wasm` (`wasm` profile, `wasm-opt -Oz`), tests |
| `bindings/python` | PyO3 abi3 wheel (`iplore.open(...)`), `.pyi` stubs, pytest |
| `bindings/data` | gitignored release databases the tests read |

```sh
cargo build --release -p reader
mkdir -p bindings/data && cd bindings/data
gh release download --repo tn3w/iplore --pattern 'iplore-*.ipl' --pattern SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS && cd ../..

rustup target add wasm32-unknown-unknown
cd bindings/js && npm install && npm run build
npm test && npm run test:deno && npm run test:bun && npm run test:workers

pip install pytest ./bindings/python && pytest bindings/python/tests
```

Tests assert known answers (1.1.1.1, Tor exit, reserved space, v6, v4-mapped, ports),
error cases, and that ~100 random addresses answer identically to the native CLI;
`test:workers` runs the wasm inside workerd (Miniflare). `IPLORE_DATA` and `IPLORE_CLI`
override the database directory and CLI path. `reader/tests/corrupt.rs` mutates
`bindings/data/iplore-country.ipl` (truncation, header lengths, flipped bytes) and
needs it present, otherwise it is skipped; CI downloads and checksums it first.

`.github/workflows/bindings.yml` builds and tests on every change. Every push to `master`
updates the `bindings` pre-release in place (wheels for Linux x86_64/aarch64, macOS,
Windows, `iplore.tgz` and `SHA256SUMS`; stale assets are removed); it is never marked latest,
so `releases/latest` stays the database. CI tests against one pinned database release whose
checksums it verifies. Nothing
goes to PyPI or npm, no tokens are stored. From source (needs Rust):
`pip install "git+https://github.com/tn3w/iplore#subdirectory=bindings/python"`.

### Edge workers

Cloudflare Workers and Vercel Edge forbid compiling WebAssembly at runtime, so import it
(`iplore/iplore.wasm`, on Vercel `iplore/iplore.wasm?module`) and pass it as second argument:

```ts
import { open } from "iplore";
import wasm from "iplore/iplore.wasm";
import country from "./iplore-country.ipl";  // bundled as ArrayBuffer

const database = await open(country, wasm);

export default {
  fetch(request: Request) {
    const address = request.headers.get("cf-connecting-ip");
    if (!address) return new Response("no client address", { status: 400 });
    return Response.json(database.lookup(address));
  },
};
```

`wrangler.toml` needs a rule so `.ipl` files bundle as data:

```toml
[[rules]]
type = "Data"
globs = ["**/*.ipl"]
fallthrough = true
```

Everything is held in memory: use `country`, `anonymizer` or `traffic` builds where memory
is capped (Workers 128 MB).

## Releases

`.github/workflows/database.yml` rebuilds every Sunday (or on demand). The `build` job
(read-only token; secrets only on the fetch step) checks canaries: 1.1.1.1, 8.8.8.8 and
9.9.9.9 have abuse risk below 0.4 and are not in `blocklist.netset`, whose entry count is
within 15% of the previous release. Only then the `publish` job writes `SHA256SUMS`,
attests build provenance, creates a draft `db-<date>` release, publishes it as latest and
deletes all but the newest three. Required repository secrets: `MAXMIND_LICENSE_KEY`,
`IPINFO_TOKEN`, `ABUSECH_AUTH_KEY`, `BGPTOOLS_USER_AGENT`. Downloads are limited to
`max_bytes` (optional in `sources.json`, default 2 GiB) and 4x that unpacked; sources are
fetched over https only; `Text::clean` drops control characters and caps strings at 128
characters.

| release asset | selection |
| --- | --- |
| `iplore-full.ipl` | `full` |
| `iplore-place.ipl` | `place` |
| `iplore-network.ipl` | `network` |
| `iplore-country.ipl` | `place.country.code` |
| `iplore-abuse.ipl` | `abuse.service+abuse.provider+abuse.risk` |
| `iplore-anonymizer.ipl` | `abuse.service` |
| `iplore-traffic.ipl` | `network.asn+network.operator.category+abuse.user_type` |
| `blocklist.netset` | `blocklist` |
| `SHA256SUMS` | checksums of all of the above |

## Quick start

```sh
cp .env.example .env            # optional keys, see Sources
cargo build --release
./target/release/builder fetch  # cached in inputs/, fresh files skipped
./target/release/builder full place network abuse place.country.code blocklist
./target/release/iplore dist/iplore-full.ipl 1.1.1.1
```

| command | does |
| --- | --- |
| `builder fetch` | download sources (`sources.json`), feeds (`feeds.json`), whois-referenced geofeeds |
| `builder <selection>...` | write `dist/iplore-<selection>.ipl`; `blocklist` writes `dist/blocklist.netset` |
| `builder bench-place` | geofeed holdout benchmark (every 10th row held out) |
| `builder bench-category` | agreement of domain/name/user rules with listed categories |
| `builder licenses` | regenerate `data/LICENSES` from the `license` of every source and feed |
| `builder check <a.ipl> <b.ipl>` | union property: common fields answer identically |
| `iplore <file> <address>` | JSON answer (v4, v6, v4-mapped, `[addr]:port`, `%zone`); exit 2 invalid address, 1 unreadable or corrupt file |
| `iplore <file> --about` | header: fields, vocabularies, tables, sections, sources |
| `iplore <file> --bench` | open time, cold/warm lookups, peak RSS |

## Answer

```json
{
  "place": {"lat": -33.8679, "lon": 151.2073, "accuracy": 100, "confidence": 60,
    "city": {"name": "Sydney", "geonames_id": 2147714, "population": 5638830,
      "district": null, "postal": "1001", "metro": null, "timezone": "Australia/Sydney"},
    "region": {"name": "New South Wales", "iso": "AU-NSW", "geonames_id": 2155400},
    "country": {"code": "AU", "name": "Australia", "continent": "OC", "currency": "AUD",
      "calling_code": "+61", "languages": "en-AU", "eu": false}},
  "network": {"asn": 13335, "handle": "CLOUDFLARENET", "prefix": 24, "rir": "apnic",
    "country": "AU", "year": 2011, "rpki": "valid", "users": 20792088,
    "mobile_code": null, "risk": 0.17,
    "operator": {"company": "Cloudflare, Inc.", "category": "cdn",
      "website": "cloudflare.com",
      "address": "101 Townsend St, San Francisco, CA 94107-1934", "country": "US",
      "abuse_email": "abuse@cloudflare.com", "since": 2010, "tier": 2, "cone": 1033}},
  "abuse": {"risk": null, "threat": null, "reports": null, "last_seen_days": null,
    "service": null, "evidence": null, "provider": null, "user_type": "hosting",
    "flags": ["anycast"]}
}
```

49 fields (was 102); missing = `null`. Field names come from `data/schema.json` (table columns,
links followed from `spine`).

| field | meaning |
| --- | --- |
| `place.lat/lon/accuracy` | point (1e-4°), radius in km |
| `place.confidence` | 0–100, agreement of sources |
| `network.prefix` | announced prefix length (CIDR = address masked to it) |
| `network.year/rir/country` | registry delegation of the block |
| `network.users` | APNIC estimated users of the ASN |
| `network.mobile_code` | `MCC-MNC` of the carrier matched by name (`310-160`) |
| `operator.website` | PeeringDB website, else IPinfo AS domain |
| `network.risk` | ASN-wide risk 0–1 |
| `abuse.risk` | address risk 0–1 |
| `abuse.reports` | independent reporting groups |
| `abuse.last_seen_days` | tightest listing window that hit |
| `abuse.user_type` | category of this range: named feed, else whois netname (`ADSL`, `GPRS`, `VPS`, …) |
| `abuse.flags` | `anycast`, `satellite` |

Removed as derivable: `address.*`, `network.cidr/start/end`, `place.time`,
`place.point.granularity`, `abuse.level`, `abuse.is_*`, `operator.brand`, `city.ascii`,
`city.postal_partial`, `country.flag/iso3/numeric/official/common`, carrier `user_type`/
`is_mobile`, operator `rir`. Merged: `place.point` into `place`, carrier into `network`,
operator street/city/state/postal into `operator.address`, district/metro into strings,
`mcc`+`mnc` into `mobile_code`, `operator.domain` into `operator.website`.

Removed for low information per byte (sampled over 5,000 addresses + section sizes):
`network.roas` (215 KB, 70% "1", `rpki` already says valid/invalid), `operator.scope`
and `operator.peering` (PeeringDB self-description, IXP count), `city.elevation`,
`city.type`, `region.type`, `country.capital`, `country.driving_side`.

## Selections

`+`-joined terms; a term matches a field at dotted-segment boundaries (`place`,
`abuse.risk`, `country`); `full` = all. `field=a,b` narrows a vocabulary field to those
values: `builder abuse.service=tor_exit_node` builds a 5 KB Tor-exit file. Builds without
`place.lat/lon/accuracy` snap place to /24 (v4) and /48 (v6) by address majority.

## Ratings

Feed risk is computed, not listed:

```
claim risk   = threat_risk[threat] × freshness[window] × quality[quality]
address risk = max(1 − Π_groups (1 − max claim risk in group), service floor)
service floor = service_risk[service] × evidence_weight[evidence] × quality
network risk = noisy-OR(ASN feeds, √(risk-weighted share of announced space))
```

| table | values |
| --- | --- |
| threat | botnet 0.9, malware 0.85, phishing 0.8, bruteforce 0.65, web_attack 0.6, abuse 0.55, spam 0.5, scanner 0.3 |
| freshness (days) | ≤3 1.0, 7 0.95, 14 0.9, 30 0.85, 60 0.75, 90 0.7, 120 0.65, 180 0.6, 365 0.5 |
| quality | high 1.0, normal 0.85, low 0.6, minimal 0.3 |
| service | tor 0.85, public proxy 0.75, residential proxy 0.7, VPN 0.5, private relay 0.15 |
| evidence | published/measured 1.0, reported 0.85, inferred 0.6 |

Trusted (operator-published CDN/crawler) ranges damp risk to ¼ and accept only
published/measured services. The strongest service claim wins by weakness, evidence,
service order; `user_type` comes from the strongest range claim (not weak, then named
provider, then narrowest). ASN baselines (tags, inferred
VPN/proxy brands, satellite operators) reach every address but carry no address risk.
Blocklist: own risk ≥ 0.40 outside trusted ranges (service floors make published VPN lists
of normal quality, proxies and Tor exits qualify; private relays at 0.15 do not).

## Pipeline

```
data/sources.json ─► fetch ─► inputs/ ─► parse ─► resolve ─► merge ─► write ─► dist/*.ipl
                                                                  └─► dist/blocklist.netset
```

| module | role |
| --- | --- |
| `fetch.rs` | env placeholders, host headers, dated listings, pages, lanes, retries, magic-byte unpacking, line filters, hostname resolution, whois geofeeds |
| `feeds.rs` | feeds + ipsum → rated claims |
| `geo.rs` | GeoNames, ISO regions, postal, place votes, geofeed vouching |
| `network.rs` | routes, RPKI, registry, operators, categories, carriers, whois holders |
| `abuse.rs` | claim folding, hosts, network risk, blocklist |
| `assemble.rs` | tables + spine merge, reserved masking |
| `write.rs` | schema → fields, selection rebuild, encoding |

Place: geofeeds > MaxMind GeoLite2 City > DB-IP City Lite; DB-IP leads only where MaxMind
is silent and otherwise votes once per MaxMind range (majority by address mass) to set
confidence. Network: RouteViews pfx2as (iptoasn fallback), VRPs, NRO registry, widest whois
holder for unannounced space.

Category per ASN (strongest of `network.json` → `strength` wins):

1. Primary: PeeringDB type, bgp.tools class, AS Rank IXP, and coverage — a category whose
   provider-named feed ranges (AWS, Cloudflare, T-Mobile geofeed, …) cover ≥ 50% of the
   ASN's announced space.
2. Tags (bgp.tools `dsl`/`mobile`/`vpsh`/…, risk-db): capabilities, not identity. Once a
   `dsl`/`mobile` tag is present, only eyeball tags count — ISPs carry `vpsh`/`cdn`,
   hosters never carry `dsl`/`mobile` (bgp.tools' `Eyeball` class also fires on VPN
   hosters, so it does not decide this).
3. Eyeball: APNIC users > 1,000 on a stub ASN, or ≥ 1M on any → residential, or
   cellular when the name says mobile/GPRS/LTE/celular/…; joins the vote.
4. Silent lists: domain (`.gov`, `.edu`, …) or name keywords, else eyeball.

Carrier `mobile_code`: cellular or eyeball networks matched by name to MCC-MNC lists in the
operator's country; the most-matched code wins (lowest on ties).

Range type (`abuse.user_type`) splits mixed operators the ASN category cannot: RIPE, APNIC
and AFRINIC inetnum netnames whose tokens hit exactly one `network.json` → `netnames` class
become weak claims (any named feed wins, narrowest range next), e.g. Orange FR (ASN
cellular) ADSL pools → residential, KPN/Telefónica DE APN pools → cellular, VodafoneZiggo
B2B → business. Classes: cellular, residential (incl. fixed wireless), business, hosting.

## File format

```
"IPLORE" 0x00 0x01 | header length:u32 LE | header (raw LZMA1 JSON) | sections
```

| encoding | block | content |
| --- | --- | --- |
| `keys` | 16,384 | sorted starts as varint gaps; v6 gap of upper 64 bits + low 64 |
| `ints` | 16,384 | width byte (1/2/4/8, bit 7 = zigzag delta) + fixed-width values |
| `strings` | 16,384 | one sorted pool, front-coded |

Every value: `0` = null, else `value + 1` (zigzag for signed, `scale`, vocabulary index,
flag bitmask, link row). Raw LZMA1 blocks, `[lc,lp,pb]` and delta chosen per section by
sample. Rows ranked by use or natural key. Hosts (single addresses differing from their
range) are checked before the spine.

## Integrations

`integrations/` holds one pure-Go, stdlib-only package (`github.com/tn3w/iplore/integrations`):
`lzma.go` (raw LZMA1), `reader.go` (`.ipl` decoder, six fields), `guard.go` (rules, headers,
client IP, reload on file change). The Caddy module (`caddy/`, own go.mod) and the
`iplore-server` sidecar (`iplore-server/main.go`, rules come from the query string) wrap it.

Rules (all three): `block_risk` (0 < x <= 1, >=), `block_service`, `block_country`,
`allow_country`, `block_category`, `allow_provider`. Matching ignores case. Rules fail closed:
the sidecar answers `400` and Caddy refuses to load on an unknown key, an unparseable, NaN,
zero, negative or above-1 `block_risk`, an empty list, malformed percent-encoding or a key
given twice. `allow_provider` skips the other rules only for records without an anonymizer
`service`; use it for crawler labels (`Googlebot`), never for hosting or VPN providers.

Client address: the sidecar trusts `X-Forwarded-For` (all header lines, rightmost untrusted
hop) only when the TCP peer is inside `-trusted` (default loopback); other peers are judged by
their own address. A malformed hop, an invalid peer or an empty address answers `403`; a
database read error answers `500`. The sidecar must see the proxy as a trusted peer, so
`-trusted` has to cover it. Caddy's `iplore` block takes the same list as `trusted_proxies`
(none: the peer is the client). Client-sent
`X-Iplore-*` and underscore variants (`X_Iplore_Country`) are stripped; nginx and Traefik
drop underscore headers, Caddy strips them in the module. Provider strings lose control
characters and are capped at 128 bytes. Reserved addresses and addresses without a record get
no headers and pass.

Reload: the database is re-read at most every 5 s after the file changes. A file that fails
the structural check (header, offsets, sections, key order) is rejected, the previous
database keeps serving and the error is logged once per distinct message.

Routing: the examples apply the strictest policy to every path and relax it only for the exact
routes `/open`, `/allow-country` and `/no-hosting` (case-sensitive, nginx and Traefik match the
normalized path). Anything else, including `/Open` or `/open/../x`, gets the strict policy.
Upstream paths are not normalized by nginx; keep relaxed routes to plain segments. Traefik
drops underscore headers, rejects encoded slashes and has no forwardAuth timeout, so
`respondingTimeouts` bounds a hung sidecar; nginx sets short `proxy_*_timeout` on the auth
locations. Upstreams get `X-Forwarded-For` from the proxy, `Forwarded` and `X-Real-IP` are
removed. nginx cannot strip unknown `X-Iplore-*` names (only the six it overwrites).
Containers run non-root, read-only, `cap_drop: ALL`, `no-new-privileges`, images pinned by
digest.

Setup per server: `integrations/caddy/Caddyfile`, `integrations/traefik/*.yml`,
`integrations/nginx/nginx.conf`.

| server | design | size |
| --- | --- | --- |
| Caddy | module `http.handlers.iplore`, built with xcaddy | caddy binary +65 KB |
| Traefik | `forwardAuth` to `iplore-server`, `authResponseHeaders` for the six `X-Iplore-*` | see below |
| nginx | `auth_request` to `iplore-server`, `iplore_headers.conf` | 6.6 MB static |

Traefik needs `trustForwardHeader: true` (otherwise it replaces `X-Forwarded-For` by the
connection address) together with entrypoint `forwardedHeaders.trustedIPs` (drops the header
from untrusted peers); `iplore-server -trusted` lists the same proxy CIDRs, nginx passes
`$http_x_forwarded_for, $realip_remote_addr` so the sidecar applies the same rule. A match
answers `403` from the sidecar, a `204` copies the headers, and headers missing from the
answer are removed from the request. The decoder runs native, cold and warm requests stay
below 25 ms with `iplore-full.ipl`. Caddyfile paths starting with `/` need the matcher `*`.

`integrations/test.sh` copies the release files from `bindings/data/` (or downloads them) to
`integrations/.scratch/` (ignored), runs `go vet`/`go test` for both modules, diffs the Go
decoder against `iplore` on 200 addresses for three databases, then starts all three servers
with `docker compose` and checks cold/warm latency below 100 ms, headers, `403`s, IPv6, forged
`X-Forwarded-For` (several lines, malformed hops), forged and underscore `X-Iplore-*`, path
case/encoding/dot-segment variants, sidecar rule errors, sidecar down or hung (never `200`)
and a truncated database during reload (old data keeps serving).
CI: `.github/workflows/integrations.yml`.

Publishing: `go install github.com/tn3w/iplore/integrations/iplore-server@latest` and
`xcaddy build --with github.com/tn3w/iplore/integrations/caddy` resolve once the repo is
public and the nested modules are tagged `integrations/v0.1.0` and `integrations/caddy/v0.1.0`
(`caddy/go.mod` requires `integrations v0.1.0`; its `replace` only serves local builds).

## Data files

| file | holds |
| --- | --- |
| `sources.json` | database fetches with `license` (+ `attribution`), host headers, geofeed fetch limits |
| `feeds.json` | 414 feeds: `license`, `scope`, `format`, `regex`, `hosts`, `geofeed`, `suffix`, `provider`, `user`, `service`, `evidence`, `threat`, `window`, `quality`, `group`, `flags`, `weak`, `trusted` |
| `schema.json` | vocabularies, tables and column kinds, snapping, file format, natural orders |
| `scoring.json` | ratings, trust, network risk, blocklist, inference brands, ipsum map |
| `network.json` | route/holder limits, whois per RIR, reserved registries, category sources, strength, coverage share, eyeball rule, netname classes |
| `place.json` | snap radii, confidence, votes, postal, region fixes, EU, US DMA labels |
| `text.json` | diacritic folding, placeholders, junk, street words, parser regexes |

## Results (2026-11-06)

| build | bytes | predecessor |
| --- | ---: | ---: |
| full | 19,190,020 | 19.2 MB |
| place | 6,373,655 | 6.3 MB |
| network | 6,224,263 | 7.4 MB |
| abuse.service+abuse.provider+abuse.risk | 5,264,624 | – |
| abuse.service=tor_exit_node | 10,484 | – |
| place.country.code | 469,727 | 378 KB |
| blocklist.netset | 7.2 MB, 418,245 CIDRs | 9.4 MB, 619k |

- Categories of the 1,500 largest ASNs by APNIC users: residential 1,049, cellular 316,
  hosting 70, transit 20, none 22 (before: transit 267, cellular 202); `mobile_code` on 29% of
  sampled addresses (was `mnc` 6%), `website` 88% (was 63%).

- Holdout city agreement (every 10th geofeed row held out): v4 81.6%, v6 81.8%.
- Reserved space (127.0.0.1, 10/8, 169.254/16, 100.64/10, 224/4, ::1, fe80::/10,
  fc00::/7, 2002::/16, …) answers nothing.
- Spot checks: 1.1.1.1 Cloudflare AS13335 anycast; 185.220.101.1 tor_exit_node;
  66.249.66.1 Googlebot crawler, no risk; 172.224.226.1 private_relay published;
  98.97.0.1 Starlink satellite.
- Union vs full (100k addresses): 0 mismatches for place, network, abuse;
  place.country.code 27 (/24 snapping).
- Reader: open 0.4–3.5 ms; cold lookup 0.2 µs–0.58 ms; warm 256k/s (full), 700k/s (place),
  3.3M/s (country), 7.8M/s (Tor); peak RSS 16–215 MB. Each lookup walks every link once
  (spine → network → operator, …) and reads all fields from the resolved rows.
- Every header carries the license list of all 450 sources and feeds (~5 KB).

## Sources

Keys in `.env` (never logged; missing key = source skipped):

| key | used for | without it |
| --- | --- | --- |
| `MAXMIND_LICENSE_KEY` | GeoLite2 City, the leading place source | v4 city agreement 81.6% → ~54% |
| `IPINFO_TOKEN` | IPinfo Lite AS domain | `operator.website` fallback lost (website 88% → 63% of addresses) |
| `ABUSECH_AUTH_KEY` | ThreatFox and URLhaus exports | ~3,000 malicious IPs lost |
| `BGPTOOLS_USER_AGENT` | contact UA bgp.tools requires (not a secret) | ASN classes and tag lists fail |

Measured and dropped (rebuild without the source, compare 100k addresses + feed overlap +
holdout): IP2Location DB11 (v4 city agreement better without: 79.3% → 81.6%), IP2Proxy
(website fallback only), MaxMind GeoLite2-ASN (no field changed), AbuseIPDB API (1% of its
IPs not already in keyless mirrors), AlienVault OTX (610 unique IPs per month), Cloudflare
Radar (ASN data duplicates PeeringDB), PeeringDB key (same data anonymously), ARIN bulk
whois (access not granted). Per-host auth headers live in `sources.json` → `host_headers`.

Feed candidates skipped (verified reachable 2026-11-06; revisit if size or role is solved):

| candidate | URL | why skipped |
| --- | --- | --- |
| FireHOL level1 | `iplists.firehol.org/files/firehol_level1.netset` | contains bogons (`0.0.0.0/8`, `10.x`); level4 (186k) too broad |
| bitwire inbound / outbound | `bitwire-it/ipblocklist` `inbound.txt` (67 MB, 1.4M IPs) / `outbound.txt` (99k) | aggregate of feeds already listed |
| romainmarcoux | `romainmarcoux/malicious-ip` `full-40k.txt`, `malicious-outgoing-ip` | arbitrary 40k cut of mixed sources |
| Data-Shield critical | `duggytuxy/Data-Shield_IPv4_Blocklist` `prod_critical_*.txt` | 120k IPs, overlaps `datashield` |
| 100k-entry proxy lists | `MuRongPIG/Proxy-Master`, `ErcinDedeoglu/proxies` (65k–100k each) | mostly dead, bloats host list |
| MISP `public-dns-v4` | `MISP/misp-warninglists` `lists/public-dns-v4` | 63k resolver hosts, no matching `user` class |
| MISP `hetzner` | `lists/hetzner` | 166k single IPs; `hetzner_ranges` has the 92 CIDRs |
| MISP `sinkholes`, `smtp-sending-ips`, `dynamic-dns` | `lists/*` | no fitting category / hostnames only |
| hagezi DoH | `hagezi/dns-blocklists` `ips/doh.txt` | public resolvers, no fitting category |
| O-X-L `ip/kind_{crawler,hosting,isp}`, `net/kind_isp` | `O-X-L/risk-db-lists` | 430k–1.4M entries, up to 20 MB |
| dataplane `proto41` | `dataplane.org/proto41.txt` | 6.6 MB, tunnel protocol not abuse by itself |
| Stanford ASdb | `asdb.stanford.edu/static-website/data/<date>_categorized_ases.csv` | "satellite" = satellite TV/cable; 55% of hosting ASNs also ISPs |
| bgp.tools `anycast`, `tor`, `ddosm`, `vpn` tags | `bgp.tools/tags/<slug>.txt` | capability tags, ASN-wide: `vpn` covers China Unicom, Cloudflare, Amazon; `ddosm` is not a CDN |
| stale FireHOL mirrors | `cybercure`, `graphiclineweb`, `iblocklist_malc0de`, `cleantalk_new_1d`, `vxvault` | source file older than 3 months |
| Snort, Talos, Bambenek, Dan.me.uk Tor | `snort.org/downloads/ip-block-list`, `talosintelligence.com/documents/ip-blacklist`, `faf.bambenekconsulting.com/feeds/c2-ipmasterlist.txt`, `dan.me.uk/torlist` | 403/404/rate-limited without a key or allowlisted UA |

MaxMind GeoLite2 City, DB-IP City Lite, IPinfo Lite, GeoNames, iso-codes, Natural Earth,
IANA special registries, CAIDA pfx2as/as2org/as-rel2/AS Rank, iptoasn, rpki-client VRPs,
NRO + RIR dumps, PeeringDB, bgp.tools, APNIC aspop, asn-abuse, MCC-MNC lists, operator
geofeeds and 414 feeds. `data/LICENSES` lists each one with its own license and terms URL
(generated by `builder licenses`); every built file carries the same list in its header.
