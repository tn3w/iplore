#!/bin/bash
set -u
shopt -s extglob
cd "$(dirname "$0")"

COMPOSE=${COMPOSE:-docker compose}
RELEASE=https://github.com/tn3w/iplore/releases/latest/download
CURL_DIGEST=3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93
CURL_IMAGE=curlimages/curl@sha256:$CURL_DIGEST
ROOT=$(cd .. && pwd)
DATABASE=.scratch/iplore-full.ipl
BACKUP=.scratch/full.backup
passed=0
failed=0

download() {
    mkdir -p .scratch
    for file in iplore-{country,full,anonymizer,traffic}.ipl; do
        [ -s ".scratch/$file" ] && continue
        if [ -s "$ROOT/bindings/data/$file" ]; then
            cp "$ROOT/bindings/data/$file" ".scratch/$file" || exit 1
        else
            curl -fsSL -o ".scratch/$file" "$RELEASE/$file" || exit 1
        fi
    done
}

report() {
    if [ "$1" = ok ]; then
        passed=$((passed + 1))
        echo "PASS $2"
    else
        failed=$((failed + 1))
        echo "FAIL $2"
    fi
}

decoder_tests() {
    cargo build --release -q -p reader --manifest-path "$ROOT/Cargo.toml" || exit 1
    gofmt -l . | grep -q . && report fail "gofmt"
    go vet ./... && go test -count=1 ./... && report ok "go unit tests" \
        || report fail "go unit tests"
    (cd caddy && go vet ./... && go test -count=1 ./...) && report ok "caddy unit tests" \
        || report fail "caddy unit tests"
    for database in full anonymizer traffic; do
        IPLORE_BIN="$ROOT/target/release/iplore" \
            IPLORE_DB="$PWD/.scratch/iplore-$database.ipl" \
            go test -count=1 -run Native -v . | grep -q -- "--- PASS" \
            && report ok "decoder matches native on 200 addresses: $database" \
            || report fail "decoder matches native on 200 addresses: $database"
    done
}

wait_for() {
    for _ in $(seq 120); do
        code=$(curl -s -o /dev/null -m 60 -w '%{http_code}' \
            -H "X-Forwarded-For: 1.1.1.1" "localhost:$1/open")
        [ "$code" = 200 ] && return
        sleep 1
    done
}

wait_all() {
    for port in 8081 8082 8083; do wait_for "$port"; done
}

expect() {
    local name=$1 port=$2 path=$3 forwarded=$4 status=$5
    shift 5
    local extra=()
    [ -n "$forwarded" ] && extra+=(-H "X-Forwarded-For: $forwarded")
    while [ "${1:-}" = -H ]; do extra+=(-H "$2"); shift 2; done
    local code
    code=$(curl -s --path-as-is -m 60 -o .scratch/body -w '%{http_code}' \
        "${extra[@]}" "localhost:$port$path")
    local problem=""
    [[ $code == $status ]] || problem="status $code, want $status"
    for pattern in "$@"; do
        if [ "${pattern:0:1}" = "!" ]; then
            grep -qi -- "${pattern:1}" .scratch/body && problem="unexpected ${pattern:1}"
        else
            grep -qi -- "$pattern" .scratch/body || problem="missing $pattern"
        fi
    done
    [ -z "$problem" ] && report ok "$name $path $forwarded ${extra[*]:2} -> $status" \
        || report fail "$name $path $forwarded ${extra[*]:2} -> $status ($problem)"
}

denied() {
    local name=$1 port=$2 path=$3 forwarded=$4
    shift 4
    expect "$name" "$port" "$path" "$forwarded" "[45]??" "$@" "!Hostname:"
}

scenarios() {
    local name=$1 port=$2
    expect "$name" "$port" / 80.187.64.1 200 "X-Iplore-Country: DE" "X-Iplore-Asn: 3320"
    expect "$name" "$port" / 1.1.1.1 403
    expect "$name" "$port" / 8.8.8.8 403
    expect "$name" "$port" / 185.220.101.1 403
    expect "$name" "$port" /anything/else 95.216.1.1 403
    expect "$name" "$port" / 66.249.66.1 200 "X-Iplore-Provider: Googlebot"
    expect "$name" "$port" / 157.55.39.1 200 "X-Iplore-Provider: Bingbot"
    expect "$name" "$port" / 1.1.1.1 403 -H "User-Agent: Googlebot/2.1"

    expect "$name" "$port" /open 1.1.1.1 200 "X-Iplore-Country: AU" \
        "X-Iplore-Asn: 13335" "X-Iplore-Category: cdn"
    expect "$name" "$port" /open/deep/path 1.1.1.1 200 "X-Iplore-Country: AU"
    expect "$name" "$port" /open 185.220.101.1 403
    expect "$name" "$port" /open 10.0.0.1 200 -H "X-Iplore-Country: XX" "!X-Iplore-"
    expect "$name" "$port" /open 2606:4700:4700::1111 200 "X-Iplore-Asn: 13335" \
        "X-Iplore-Country: US"
    expect "$name" "$port" /open "185.220.101.1, 1.1.1.1" 200 "X-Iplore-Country: AU"
    expect "$name" "$port" /open 1.1.1.1 200 -H "X-Iplore-Country: XX" \
        -H "X-Iplore-Provider: Googlebot" -H "X-Iplore-Risk: 0" "!: XX" "!Googlebot"
    expect "$name" "$port" /allow-country 8.8.8.8 200 "X-Iplore-Country: US"
    expect "$name" "$port" /allow-country 1.1.1.1 403
    expect "$name" "$port" /allow-country/x 1.1.1.1 403
    expect "$name" "$port" /no-hosting 95.216.1.1 403
    expect "$name" "$port" /no-hosting 1.1.1.1 200
    expect "$name" "$port" /no-hosting 157.55.39.1 200 "X-Iplore-Provider: Bingbot"
}

path_variants() {
    local name=$1 port=$2 path
    for path in /Open /OPEN /oPen/x /No-Hosting /NO-HOSTING/x /opening /open.txt \
        /no-hosting-x /x/../Open /open/../private /open/./../private \
        /open/%2e%2e/private /open%2f..%2fprivate /open/..%2fprivate /no-hosting/../x \
        //Open /./Open /%4Fpen/../x /open%5c..%5cprivate /open%00 /open%3bx; do
        denied "$name variant" "$port" "$path" 1.1.1.1
    done
    for path in /Allow-Country /ALLOW-COUNTRY/x /allow-country/../private \
        /allow-country%2f..%2fprivate; do
        denied "$name variant" "$port" "$path" 8.8.8.8
    done
}

header_tests() {
    local name=$1 port=$2
    expect "$name" "$port" /open 1.1.1.1 200 -H "X_iplore_country: XX" \
        -H "X_Iplore_Provider: Googlebot" -H "X-Iplore_Risk: 0" \
        -H "x_iplore_service: tor_exit_node" -H "X_IPLORE_ASN: 1" \
        "X-Iplore-Country: AU" "!iplore_" "!x_iplore" "!Googlebot" "!tor_exit_node"
    expect "$name" "$port" /open 1.1.1.1 200 -H "Forwarded: for=6.6.6.6" \
        -H "X-Real-IP: 6.6.6.6" "!6.6.6.6" "!Forwarded:" "!X-Real-Ip: 6"
}

forwarded_tests() {
    local name=$1 port=$2
    expect "$name" "$port" /open 185.220.101.1 200 -H "X-Forwarded-For: 1.1.1.1" \
        "X-Iplore-Country: AU"
    expect "$name" "$port" /open 1.1.1.1 403 -H "X-Forwarded-For: 185.220.101.1"
    denied "$name malformed" "$port" /open nope
    denied "$name malformed" "$port" /open "1.1.1.1, nope"
    denied "$name malformed" "$port" /open "1.1.1.1,,"
    denied "$name malformed" "$port" /open "unknown"
    denied "$name malformed" "$port" /open 1.1.1.1 -H "X-Forwarded-For: nope"
}

latency() {
    local name=$1 port=$2 address=$3
    for label in cold warm; do
        local seconds
        seconds=$(curl -s -m 60 -o /dev/null -w '%{time_total}' \
            -H "X-Forwarded-For: $address" "localhost:$port/")
        awk "BEGIN {exit !($seconds < 0.1)}" \
            && report ok "$name $label request $address ${seconds}s < 0.1s" \
            || report fail "$name $label request $address ${seconds}s >= 0.1s"
    done
}

sidecar_get() {
    local network format='{{range $key, $_ := .NetworkSettings.Networks}}{{$key}}{{end}}'
    network=$(docker inspect -f "$format" "$($COMPOSE ps -q sidecar)")
    docker run --rm --network "$network" "$CURL_IMAGE" -s -m 10 -o /dev/null \
        -w '%{http_code}' -X "$1" -H "X-Forwarded-For: 1.1.1.1" "http://sidecar:8080/$2"
}

sidecar_tests() {
    local query status want
    for query in "?unknown=1" "?block_country=AU&block_country=US" "?block_risk=NaN" \
        "?block_risk=-1" "?block_risk=0" "?block_risk=2" "?block_risk=" \
        "?block_country=" "?block_country=%zz" "?Block_Country=AU" "?block_risk=0.5&x"; do
        status=$(sidecar_get GET "$query")
        [ "$status" = 400 ] && report ok "sidecar $query -> 400" \
            || report fail "sidecar $query -> $status, want 400"
    done
    for want in "GET ?block_country=au 403" "GET ?block_country=us 204" "GET ? 204" \
        "HEAD ?block_country=AU 403" "POST ?block_country=us 405" "PUT ? 405"; do
        set -- $want
        status=$(sidecar_get "$1" "$2")
        [ "$status" = "$3" ] && report ok "sidecar $1 $2 -> $3" \
            || report fail "sidecar $1 $2 -> $status, want $3"
    done
}

outage_tests() {
    local name port
    $COMPOSE stop sidecar >/dev/null 2>&1
    for entry in nginx:8081 traefik:8083; do
        name=${entry%:*}
        port=${entry#*:}
        expect "$name sidecar down" "$port" /open 1.1.1.1 "5??" "!Hostname:"
        expect "$name sidecar down" "$port" / 80.187.64.1 "5??" "!Hostname:"
    done
    expect "caddy sidecar down" 8082 /open 1.1.1.1 200 "X-Iplore-Country: AU"
    $COMPOSE start sidecar >/dev/null 2>&1
    wait_all
    $COMPOSE pause sidecar >/dev/null 2>&1
    expect "nginx sidecar hung" 8081 /open 1.1.1.1 "5??" "!Hostname:"
    expect "traefik sidecar hung" 8083 /open 1.1.1.1 "@(5??|000)" "!Hostname:"
    $COMPOSE unpause sidecar >/dev/null 2>&1
    wait_all
}

reload_tests() {
    local logs
    cp "$DATABASE" "$BACKUP"
    trap 'mv -f "$BACKUP" "$DATABASE" 2>/dev/null' EXIT
    head -c 1000000 "$BACKUP" >"$DATABASE"
    for _ in 1 2 3; do
        sleep 6
        expect "truncated database" 8081 /open 1.1.1.1 200 "X-Iplore-Country: AU"
        expect "truncated database" 8082 /open 1.1.1.1 200 "X-Iplore-Country: AU"
        expect "truncated database" 8083 /open 1.1.1.1 200 "X-Iplore-Country: AU"
        expect "truncated database" 8081 / 1.1.1.1 403
    done
    for service in sidecar caddy; do
        logs=$($COMPOSE logs --no-log-prefix "$service" 2>&1 | grep -c "keeping previous")
        [ "$logs" = 1 ] && report ok "$service logged the reload failure once" \
            || report fail "$service logged the reload failure $logs times, want 1"
    done
    cp "$BACKUP" "$DATABASE"
    sleep 7
    expect "restored database" 8081 /open 80.187.64.1 200 "X-Iplore-Country: DE"
    rm -f "$BACKUP"
}

server_tests() {
    $COMPOSE down -v >/dev/null 2>&1
    $COMPOSE up -d --build >/dev/null 2>&1 || { report fail "compose up"; return; }
    wait_all
    latency nginx 8081 45.33.32.156
    latency caddy 8082 91.198.174.192
    latency traefik 8083 151.101.1.69
    for entry in nginx:8081 caddy:8082 traefik:8083; do
        scenarios "${entry%:*}" "${entry#*:}"
        path_variants "${entry%:*}" "${entry#*:}"
        header_tests "${entry%:*}" "${entry#*:}"
        forwarded_tests "${entry%:*}" "${entry#*:}"
    done
    expect nginx 8081 /open "6.6.6.6, 1.1.1.1" 200 "X-Forwarded-For: 1.1.1.1" "!6.6.6.6"
    sidecar_tests
    outage_tests
    reload_tests
    [ -n "${KEEP:-}" ] || $COMPOSE down -v >/dev/null 2>&1
}

download
decoder_tests
server_tests
echo
echo "passed $passed, failed $failed"
[ "$failed" -eq 0 ]
