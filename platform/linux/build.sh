#!/bin/sh
# Build the asm-quic library, its dependency objects, the test runner, the
# shell loop test and the interop node for one Linux ISA.
# Usage: platform/linux/build.sh ISA OUT_DIR    (ISA: x86_64, arm64 or riscv64)
# Runs inside the image from platform/linux/Dockerfile, after platform/deps.sh.
set -eu
isa=$1
out=$2
root=$(cd "$(dirname "$0")/../.." && pwd)
crypto=$root/build/deps/asm-crypto

case "$isa" in
  x86_64)  target=x86_64-linux-gnu;  march="-march=x86-64" ;;
  arm64)   target=aarch64-linux-gnu; march="-march=armv8-a" ;;
  riscv64) target=riscv64-linux-gnu; march="-march=rv64gc -mabi=lp64d" ;;
  *) echo "unknown ISA: $isa" >&2; exit 2 ;;
esac

mkdir -p "$out"
clang --target=$target $march -I"$root/include" -I"$crypto/include" -I"$root/platform/linux" -I"$root/asm/core/$isa" \
    -c "$root/asm/core/$isa/quic.s" -o "$out/quic.o"
clang --target=$target $march -I"$root/include" -I"$root/platform/linux" \
    -c "$root/asm/shell/linux/$isa/shell.s" -o "$out/shell.o"
rm -f "$out/libasm-quic.a"
llvm-ar rcs "$out/libasm-quic.a" "$out/quic.o" "$out/shell.o"

# Dependency objects: the asm-crypto files the library calls.
deps=""
for name in sha256 hmac aes x25519 p256 secp256k1 sha512 ed25519; do
    clang --target=$target $march -I"$crypto/include" -I"$crypto/platform/linux" \
        -c "$crypto/asm/core/$isa/$name.s" -o "$out/crypto-$name.o"
    deps="$deps $out/crypto-$name.o"
done

# Tests (C), linked statically so QEMU user mode needs no target libraries.
clang --target=$target $march -std=c11 -O2 -Wall -Wextra -Werror -static -fuse-ld=lld \
    "$root/tests/runner/runner.c" -I"$root/platform/linux" "$root/tests/runner/abi_$isa.s" \
    "$out/libasm-quic.a" $deps -o "$out/runner"
clang --target=$target $march -std=c11 -O2 -Wall -Wextra -Werror -static -fuse-ld=lld \
    "$root/tests/shell/loop.c" "$out/libasm-quic.a" $deps -o "$out/loop"
clang --target=$target $march -std=c11 -O2 -Wall -Wextra -Werror -static -fuse-ld=lld \
    "$root/tests/interop/node.c" "$out/libasm-quic.a" $deps -o "$out/node"
