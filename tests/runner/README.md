# Test runner

`runner.c` runs the vector files of [tests/generator/](../generator/), then the scenarios: nodes in memory, with the runner as their shell. It delivers each datagram after 10 ms, and may drop every nth one. Keys, entropy and time are fixed, so every scenario is deterministic. It is test code in C; the library itself is pure assembly.

```bash
tests/runner/docker.sh ~/.cache/asm-quic/vectors
```

```bash
tests/runner/macos.sh ~/.cache/asm-quic/vectors
```

| File | What it does |
|---|---|
| `docker.sh` | Builds the Docker image, builds the library for all 7 targets into `build/`, and runs the runner and the [shell loop test](../shell/) for Linux x86-64, ARM64 and RISC-V. ISAs other than the host's run under QEMU user mode. |
| `macos.sh` | Links the runner and the shell loop test on a Mac against the library that `docker.sh` built, and runs both. |
| `tick_tables.py` | Writes the tick table of each function into its document, from the results of every target. |
| `abi_x86_64.s`, `abi_arm64.s`, `abi_riscv64.s` | `abi_call`, through which the runner calls every library function. Test code in assembly. |
| `quic.h` | The C view of the interface, for the tests. |

Name files or scenarios to run only those, for example `build/linux-arm64/runner VECTOR_DIR rfc9001.bin handshake`.

[.github/workflows/ci.yml](../../.github/workflows/ci.yml) runs everything on all 7 targets: Linux on GitHub's x64 and ARM64 runners (RISC-V under QEMU), Windows on `windows-2025` and `windows-11-arm`, and macOS on `macos-15-intel` and `macos-15`.

## Checks on every call

- Inputs sit at an offset with unused room after them, and must stay unchanged.
- Outputs have guard bytes after them.
- Outputs and scratch get exactly the size the function needs; one byte less must give `QUIC_BUFFER_TOO_SMALL`.
- A call must keep the registers, the stack pointer and the flags that its ABI keeps.
- A call must use at most 16384 bytes of stack; the runner prints the most each function used.

## Scenarios

| Scenario | What it checks |
|---|---|
| handshake | A dials B; each gets the host key of the other. A stream carries "hello" one way and "world" back, each with a FIN; then 1 MiB goes from A to B on a new stream. STREAM_ACKED gives each writer every byte it wrote. A closes with code 9: A hears LOCAL, B hears PEER with code 9. |
| loss | The same, with every 5th datagram dropped. |
| key_update | The same, with a key update every 40 packets each way. |
| key_update_loss | The key updates, with every 7th datagram dropped. |
| peer_id | A dial that names another peer ID fails with PEER_ID, and A never hears CONNECTED. |
| timeout | A dial to an address with no node fails with HANDSHAKE_TIMEOUT. |
| secp256k1 | secp256k1 host keys, as consensus clients use: the handshake, the host keys, and a stream. |
| reset | A resets a stream it wrote to; B resets one A opened; each hears the reset of the other, and a third stream still carries data. |
| idle | 3 s with no traffic closes both nodes with IDLE; with a 1 s keep-alive, 10 s pass with no close. |
| garbage | Garbage datagrams change nothing: a dial after them works. An unknown version in 1200 bytes gets one Version Negotiation packet. |
| errors | A short scratch or action list gives `QUIC_BUFFER_TOO_SMALL`; each malformed event or event list gives `QUIC_INVALID_EVENT` and leaves the state unchanged; bad configs give `QUIC_INVALID_CONFIG`; a short state gives `QUIC_BUFFER_TOO_SMALL`; a secp256k1 key of 0 or above the order gives `QUIC_INVALID_KEY`. |
| limits | A node with one connection slot keeps its first connection; a second dialer times out. |

## Transcript digests

- After its checks, each scenario prints a digest: FNV-1a 64 over every action of every node, in order.
- The `want` digests in `runner.c` are recorded on ARM64. Every ISA must give them: the cores follow one instruction sequence, so a difference is a port error.
