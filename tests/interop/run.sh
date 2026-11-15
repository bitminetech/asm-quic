#!/bin/sh
# Run transport-interop pairs over quic-v1: the asm-quic node dials each
# implementation, and each implementation dials the asm-quic node. A pair
# passes when the dialer prints its handshake and ping times.
# Usage: tests/interop/run.sh ISA [IMPLEMENTATION ...]    (no names: all 12)
# Environment: RUNS=n runs each pair n times (default 1). BASELINE=1 also runs
# each implementation against itself, and the asm-quic node against itself.
# Each line: PASS or FAIL, implementation, direction, then for a pass the
# handshakePlusOneRTTMillis and pingRTTMilllis that the dialer printed.
# Needs the images from tests/interop/build-images.sh.
set -u
isa=$1
shift
asm=asm-quic-interop-$isa
runs=${RUNS:-1}
baseline=${BASELINE:-0}
all="go-v0.46 go-v0.47 go-v0.48 rust-v0.53 rust-v0.54 rust-v0.55 rust-v0.56 nim-v2.4 jvm-libp2p-v1.3 python-v0.x
c-v0.0.1 eth-p2p-z-v0.0.1"
[ "$baseline" = 1 ] && all="asm-quic $all"

pair() {    # dialer image, listener image -> 0, with timing set, when the dialer reported its times
    tmp=$(mktemp -d)
    cat > "$tmp/compose.yaml" <<YAML
name: interop
services:
  dialer:
    image: $1
    depends_on: [redis]
    environment: {transport: quic-v1, is_dialer: "true", ip: 0.0.0.0}
  listener:
    init: true
    image: $2
    depends_on: [redis]
    environment: {transport: quic-v1, is_dialer: "false", ip: 0.0.0.0}
  redis:
    image: redis:7-alpine
    environment: {REDIS_ARGS: --loglevel warning}
YAML
    out=$(timeout 180 docker compose -f "$tmp/compose.yaml" up --exit-code-from dialer --renew-anon-volumes 2>&1)
    docker compose -f "$tmp/compose.yaml" down -v >/dev/null 2>&1
    rm -rf "$tmp"
    result=$(echo "$out" | grep "dialer.*handshakePlusOneRTTMillis" | tail -1)
    if [ -n "$result" ]; then
        h=$(echo "$result" | sed -n 's/.*"handshakePlusOneRTTMillis": *\([0-9.eE+-]*\).*/\1/p')
        p=$(echo "$result" | sed -n 's/.*"pingRTTMilllis": *\([0-9.eE+-]*\).*/\1/p')
        timing="$h $p"
        return 0
    fi
    echo "$out" | grep -E "dialer|listener" | grep -v "Container\|Attaching" | tail -15
    return 1
}

pass=0 fail=0
for impl in $all; do
    if [ $# -gt 0 ] && [ "$impl" != asm-quic ]; then
        wanted=0
        for name in "$@"; do [ "$name" = "$impl" ] && wanted=1; done
        [ $wanted = 1 ] || continue
    fi
    dirs="asm-to-impl impl-to-asm"
    [ "$baseline" = 1 ] && dirs="$dirs impl-to-impl"
    [ "$impl" = asm-quic ] && dirs=impl-to-impl
    image=$impl
    [ "$impl" = asm-quic ] && image=$asm
    for dir in $dirs; do
        case $dir in
          asm-to-impl)  d=$asm;   l=$image ;;
          impl-to-asm)  d=$image; l=$asm ;;
          impl-to-impl) d=$image; l=$image ;;
        esac
        n=0
        while [ $n -lt "$runs" ]; do
            n=$((n + 1))
            if pair "$d" "$l"; then echo "PASS $impl $dir $timing"; pass=$((pass + 1));
            else echo "FAIL $impl $dir"; fail=$((fail + 1)); fi
        done
    done
done
echo "$pass pairs passed, $fail failed"
[ $fail = 0 ]
