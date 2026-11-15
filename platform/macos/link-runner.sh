#!/bin/sh
# Link the test runner and the shell loop test on a Mac against the library
# and the dependency objects that build.sh made.
# Usage: platform/macos/link-runner.sh ISA OUT_DIR    (ISA: x86_64 or arm64)
# The tests are C. They use the host Xcode clang and macOS SDK.
set -eu
isa=$1
out=$2
root=$(cd "$(dirname "$0")/../.." && pwd)

case "$isa" in
  x86_64) arch=x86_64 ;;
  arm64)  arch=arm64 ;;
  *) echo "unknown ISA: $isa" >&2; exit 2 ;;
esac

deps=""
for name in sha256 hmac aes x25519 p256 secp256k1 sha512 ed25519; do deps="$deps $out/crypto-$name.o"; done
clang -arch $arch -mmacosx-version-min=11.0 -std=c11 -O2 -Wall -Wextra -Werror \
    "$root/tests/runner/runner.c" -I"$root/platform/macos" "$root/tests/runner/abi_$isa.s" \
    "$out/libasm-quic.a" $deps -o "$out/runner"
clang -arch $arch -mmacosx-version-min=11.0 -std=c11 -O2 -Wall -Wextra -Werror \
    "$root/tests/shell/loop.c" "$out/libasm-quic.a" $deps -o "$out/loop"
