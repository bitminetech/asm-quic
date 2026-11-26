#!/bin/sh
# Pin the dependencies, fetch them into build/deps/, and name the functions
# this repo calls in them (ARCHITECTURE.md section 5).
# Runs inside the image from platform/linux/Dockerfile, from the repo root.
#
# The functions this repo calls in each dependency. platform/check.py rejects
# a call to any other function.
# uses asm-crypto: crypto_sha256 crypto_hmac_sha256 crypto_hkdf_extract crypto_hkdf_expand crypto_aes128_ctr crypto_aes128_gcm_ae crypto_aes128_gcm_ad crypto_x25519 crypto_p256_public_key crypto_p256_ecdh crypto_p256_sign crypto_p256_verify crypto_secp256k1_public_key crypto_secp256k1_sign crypto_secp256k1_verify crypto_ed25519_public_key crypto_ed25519_sign crypto_ed25519_verify
# uses libSystem (macOS shell, macOS 11.0 SDK): socket fcntl setsockopt bind getsockname sendto recvfrom poll close clock_gettime_nsec_np getentropy
# uses ws2_32, kernel32 and bcrypt (Windows shell, Windows 10): WSAStartup WSACleanup WSAIoctl WSAPoll socket ioctlsocket setsockopt bind getsockname sendto recvfrom closesocket Sleep QueryPerformanceCounter QueryPerformanceFrequency GetSystemTimeAsFileTime BCryptGenRandom

set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
fetch() {
    dir=$root/build/deps/$1
    if [ "$(git -C "$dir" rev-parse HEAD 2>/dev/null)" != "$2" ]; then
        rm -rf "$dir"
        git init -q "$dir"
        git -C "$dir" fetch -q --depth 1 "https://github.com/bitminetech/$1" "$2"
        git -C "$dir" checkout -q FETCH_HEAD
    fi
}
fetch asm-crypto a364b8c3c06b55607834f93cda7b7e315323b3b8
