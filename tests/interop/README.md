# transport-interop

The asm-quic node runs the transport-interop test of [libp2p/test-plans](https://github.com/libp2p/test-plans/tree/12e2ff491db21115b8e775e0eb7ee51056d203fb/transport-interop) over quic-v1 against every implementation there that offers it. Each pair runs both ways: asm-quic dials the other implementation, and the other implementation dials asm-quic.

```bash
tests/runner/docker.sh ~/.cache/asm-quic/vectors
```

```bash
tests/interop/build-images.sh arm64 /path/to/work
```

```bash
tests/interop/run.sh arm64
```

| File | What it does |
|---|---|
| `node.c` | The asm-quic node of the test. Test code in C: it does Redis, multistream-select and the ping protocol; the library does QUIC and TLS, its shell the UDP socket. |
| `Dockerfile` | The image of the node, `asm-quic-interop-<ISA>`, from `build/linux-<ISA>/node`. For RISC-V, the node runs under QEMU user mode. |
| `build-images.sh` | `build-images.sh ISA WORK_DIR [IMAGE ...]`: builds the image of the node, checks out test-plans in WORK_DIR, and builds the images of the other implementations. |
| `run.sh` | `run.sh ISA [IMAGE ...]`: runs each pair with Docker Compose and a Redis container, and prints PASS with the two times of the dialer, or FAIL. A pair passes when the dialer prints its times. `RUNS=n` runs each pair n times; `BASELINE=1` also runs each implementation, and asm-quic, against itself. |

[.github/workflows/ci.yml](../../.github/workflows/ci.yml) runs the Linux x86-64 node against go-v0.48 and rust-v0.56, both ways.

## Implementations

| Image | Implementation |
|---|---|
| go-v0.46, go-v0.47, go-v0.48 | go-libp2p |
| rust-v0.53, rust-v0.54, rust-v0.55, rust-v0.56 | rust-libp2p |
| nim-v2.4 | nim-libp2p |
| jvm-libp2p-v1.3 | jvm-libp2p |
| python-v0.x | py-libp2p |
| c-v0.0.1 | c-libp2p |
| eth-p2p-z-v0.0.1 | eth-p2p-z (Zig) |

## The node

- Reads the settings of the test from its environment: `transport` (quic-v1), `is_dialer`, `ip`, `redis_addr`, `test_timeout_seconds`.
- Listener: binds a UDP socket, and publishes `/ip4/<ip>/udp/<port>/quic-v1/p2p/<id>` to Redis.
- Dialer: takes that address from Redis, dials it with the peer ID, opens a stream, agrees `/ipfs/ping/1.0.0` with multistream-select, pings (32 random bytes, echoed), and prints the result as JSON.

## Pins and fixes

| Item | Value |
|---|---|
| test-plans | `12e2ff491db21115b8e775e0eb7ee51056d203fb` |
| Redis | `redis:7-alpine` |
| c-v0.0.1 | Its Makefile moves `WjCryptLib-master`; GitHub now names the archive folder after its commit, so `build-images.sh` matches `WjCryptLib-*` |
| rust-v0.56 | rust-libp2p `70082df` needs a newer rustc than the pinned cargo-chef 0.1.68 image: `build-images.sh` builds with a cargo-chef image pinned by digest, on `debian:bookworm` |
| eth-p2p-z-v0.0.1 | Its Dockerfile fetches an x86-64 zig and test-plans pins `-Dcpu=x86_64`, which fail on an ARM64 host: `build-images.sh` uses the zig of the host ISA with `-Dcpu=baseline` |
