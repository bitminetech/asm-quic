# asm-quic

QUIC version 1 with TLS 1.3 in the libp2p TLS profile, for an Ethereum consensus client, in assembly.

RFC 9000, RFC 9001 and RFC 9002 (NewReno), client and server, with the libp2p TLS certificate; libp2p protocols such as multistream-select run in the application, on the stream API.

Standard: [asm-standard@2a19d3f](https://github.com/bitminetech/asm-standard/blob/2a19d3f7fa737af1c01720b6e891703e53a682aa/ARCHITECTURE.md)

## Reference

| File | Covers |
|---|---|
| [docs/reference/node.md](docs/reference/node.md) | Node: config, state, step, events and actions, heap, random bytes, varints |
| [docs/reference/packet-protection.md](docs/reference/packet-protection.md) | Packet protection: Initial keys, AEAD, header protection, Retry tags |
| [docs/reference/certificates.md](docs/reference/certificates.md) | The libp2p TLS certificate |
| [docs/reference/tls.md](docs/reference/tls.md) | The TLS 1.3 handshake and key updates |
| [docs/reference/connections.md](docs/reference/connections.md) | Connections, connection IDs, closing |
| [docs/reference/recovery.md](docs/reference/recovery.md) | Loss detection and congestion control |
| [docs/reference/streams.md](docs/reference/streams.md) | Streams and flow control |
| [docs/reference/packets.md](docs/reference/packets.md) | Packets and frames, sent and received |
| [docs/reference/shell.md](docs/reference/shell.md) | Shell: UDP sockets, clock and random bytes |
| [include/quic.inc](include/quic.inc) | Constants and layouts |
| [include/state.inc](include/state.inc) | Layouts inside the state |

## Targets

| OS | ISAs |
|---|---|
| Linux | x86-64, ARM64, RISC-V |
| Windows | x86-64, ARM64 |
| macOS | x86-64, ARM64 |

## Dependencies

| Repo | Commit | Functions used |
|---|---|---|
| [asm-crypto](https://github.com/bitminetech/asm-crypto) | [`70753ee`](https://github.com/bitminetech/asm-crypto/tree/70753eea4f8a4e937b706d9308828c7ff3a14b40) | `crypto_sha256`, `crypto_hmac_sha256`, `crypto_hkdf_extract`, `crypto_hkdf_expand`, `crypto_aes128_ctr`, `crypto_aes128_gcm_ae`, `crypto_aes128_gcm_ad`, `crypto_x25519`, `crypto_p256_public_key`, `crypto_p256_ecdh`, `crypto_p256_sign`, `crypto_p256_verify`, `crypto_secp256k1_public_key`, `crypto_secp256k1_sign`, `crypto_secp256k1_verify`, `crypto_ed25519_public_key`, `crypto_ed25519_sign`, `crypto_ed25519_verify` |
| libSystem (macOS shell) | macOS 11.0 SDK | `socket`, `fcntl`, `setsockopt`, `bind`, `getsockname`, `sendto`, `recvfrom`, `poll`, `close`, `clock_gettime_nsec_np`, `getentropy` |
| ws2_32, kernel32 and bcrypt (Windows shell) | Windows 10 | `WSAStartup`, `WSACleanup`, `WSAIoctl`, `WSAPoll`, `socket`, `ioctlsocket`, `setsockopt`, `bind`, `getsockname`, `sendto`, `recvfrom`, `closesocket`, `Sleep`, `QueryPerformanceCounter`, `QueryPerformanceFrequency`, `GetSystemTimeAsFileTime`, `BCryptGenRandom` |

## Build tools

| Used for | Tool |
|---|---|
| Library | LLVM 23.1.5, official release (`clang`, `llvm-ar`, `lld`) |
| Windows tests | [llvm-mingw 20261104](https://github.com/mstorsjo/llvm-mingw/releases/tag/20261104) (LLVM 23.1.5) |
| macOS tests | The host Xcode clang, because they need the macOS SDK |
| Build image | [platform/linux/Dockerfile](platform/linux/Dockerfile) on `debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2` |
| Vector generator | Python 3 with the packages pinned in [tests/generator/requirements.txt](tests/generator/requirements.txt) |

## Tests

| Item | Location |
|---|---|
| Export and frame check | [platform/check.py](platform/check.py) |
| Vector generator | [tests/generator/](tests/generator/) |
| Test runner: vectors and 12 scenarios | [tests/runner/](tests/runner/) |
| Shell loop test | [tests/shell/](tests/shell/) |
| transport-interop of libp2p/test-plans, quic-v1 | [tests/interop/](tests/interop/) |

## Target profile

| ISA | Instructions |
|---|---|
| x86-64 | x86-64-v1 |
| ARM64 | Armv8.0-A |
| RISC-V | RV64GC |

| Item | Value |
|---|---|
| macOS objects | Marked for macOS 11.0 or later |
| Linux kernel | 3.17 or later, for `getrandom` |

## Environment boundaries

| OS | Call | Requirements |
|---|---|---|
| Linux | System calls `socket`, `setsockopt`, `bind`, `getsockname`, `sendto`, `recvfrom`, `ppoll`, `close`, `clock_gettime`, `getrandom` | Numbers and layouts from the kernel uapi headers of each ISA, as in Debian trixie |
| macOS | libSystem functions in the Dependencies table | macOS 11.0 or later |
| Windows | The ws2_32, kernel32 and bcrypt functions in the Dependencies table | Windows 10 or later |

## Stack

| Item | Value |
|---|---|
| Stack per call | At most 16384 bytes, callees included |
| Shell calls | The OS calls of the shell add their own native stack |

## Integration

| Item | Value |
|---|---|
| Startup | `quic_shell_clock` gives the seed for `quic_init`; `quic_shell_init` builds the shell context; `quic_shell_bind` opens UDP sockets |
| Event loop | The application owns it: it calls `quic_step` with a fresh tick and the events since the last step, and passes the events it did not handle again |
| Actions | After a step returns 0, `quic_shell_send` sends its SEND actions; the application handles the other actions |
| Wakeup | The application waits with `quic_shell_wait` until the WAKEUP time or a datagram, then reads with `quic_shell_receive` |
| Buffers | Scratch of `QUIC_SCRATCH_SIZE` bytes; action room of `QUIC_ACTIONS_MIN` bytes after the 24-byte header |
| Peer IDs | A DIAL names the peer ID to expect; CONNECTED gives the host key of the peer |
| libp2p protocols | The application runs multistream-select and its protocols on OPEN_STREAM, STREAM_WRITE, STREAM_CLOSE and the STREAM actions |
| Shutdown | `quic_shell_close` |
| Concurrency | One thread at a time for a state and its shell context |
