# Shell

## Contents

### Functions

- [`quic_shell_init`](#function-quic_shell_init): builds a shell context with no socket.
- [`quic_shell_bind`](#function-quic_shell_bind): opens a UDP socket.
- [`quic_shell_send`](#function-quic_shell_send): sends the SEND actions of a step.
- [`quic_shell_receive`](#function-quic_shell_receive): reads waiting datagrams.
- [`quic_shell_wait`](#function-quic_shell_wait): waits for a datagram or a time.
- [`quic_shell_clock`](#function-quic_shell_clock): reads the time and random bytes.
- [`quic_shell_close`](#function-quic_shell_close): closes every socket.
- [`quic_shell_sockaddr`](#function-quic_shell_sockaddr): builds a native socket address.
- [`quic_shell_address`](#function-quic_shell_address): reads a native socket address.
- [`quic_shell_fcntl`](#function-quic_shell_fcntl): calls fcntl.
- [`quic_shell_wsa_start`](#function-quic_shell_wsa_start): starts Winsock 2.2.
- [`quic_shell_no_connreset`](#function-quic_shell_no_connreset): turns off WSAECONNRESET on a UDP socket.
- [`quic_shell_now`](#function-quic_shell_now): reads the monotonic time.

### Types

- [`ShellContext`](#type-shellcontext): the UDP sockets of the shell.
- [`BindResult`](#type-bindresult): the output of `quic_shell_bind`.

### Constants

- `QUIC_OS_ERROR`: status 9: an OS call of the shell failed.
- `QUIC_SHELL_SIZE`: bytes of a ShellContext: 176.
- `QUIC_SH_MAX`: sockets a context holds: 4.
- `QUIC_RECEIVE_MAX`: the largest datagram the shell reads: 2048 bytes.

## Spec

- Document: [ARCHITECTURE.md](https://github.com/bitminetech/asm-standard/blob/2a19d3f7fa737af1c01720b6e891703e53a682aa/ARCHITECTURE.md) sections 2 and 6, asm-standard at commit 2a19d3f.
- Section: the shell of this library: UDP sockets, the clock and random bytes, for Linux (system calls), macOS (libSystem) and Windows (Winsock 2, kernel32, bcrypt).

## Function `quic_shell_init`

Builds a shell context with no socket.

### Signature

```
quic_shell_init(ctx) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `ctx` | resource context | [`ShellContext`](#type-shellcontext) |

### Returns

- `QUIC_OK`: The context is ready.
- `QUIC_BUFFER_TOO_SMALL`: The size field of the context is below `QUIC_SHELL_SIZE`.

### Limits

- Stack of its own: 8 bytes on Linux x86-64, 96 bytes on Linux ARM64, 112 bytes on Linux RISC-V, 8 bytes on macOS x86-64, 96 bytes on macOS ARM64, 8 bytes on Windows x86-64, 96 bytes on Windows ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L2.
- Symbol: `quic_shell_init` (`_quic_shell_init` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6); OS calls use the native convention.
- Argument order: `ctx`.

## Function `quic_shell_bind`

Opens a non-blocking UDP socket bound to an address.

### Signature

```
quic_shell_bind(ctx, addr, result) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `ctx` | resource context | [`ShellContext`](#type-shellcontext) |
| `addr` | input | [`Address`](node.md#type-address): port 0 picks a free port |
| `result` | output | [`BindResult`](#type-bindresult) |

### Returns

- `QUIC_OK`: `result` holds the socket ID and the local address.
- `QUIC_BUFFER_TOO_SMALL`: The context holds `QUIC_SH_MAX` sockets already.
- `QUIC_OS_ERROR`: An OS call failed; no socket is left open.

### Function does

- Makes an IPv6 socket IPv6 only.
- Asks for 4 MiB send and receive buffers; the OS may give less.
- Windows: starts Winsock 2.2 for the socket, and turns off WSAECONNRESET from ICMP port unreachable.

### Limits

- Stack of its own: 112 bytes on Linux x86-64, 144 bytes on Linux ARM64, 160 bytes on Linux RISC-V, 112 bytes on macOS x86-64, 144 bytes on macOS ARM64, 144 bytes on Windows x86-64, 144 bytes on Windows ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L2.
- Symbol: `quic_shell_bind` (`_quic_shell_bind` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6); OS calls use the native convention.
- Argument order: `ctx`, `addr`, `result`.

## Function `quic_shell_send`

Sends the SEND actions of a step.

### Signature

```
quic_shell_send(ctx, actions) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `ctx` | resource context | [`ShellContext`](#type-shellcontext) |
| `actions` | input | [`ByteList`](node.md#type-bytelist) of [`Action`](node.md#type-action) values |

### Returns

- `QUIC_OK`: Every SEND action went to the OS, or was dropped.

### Function does

- Sends each SEND action with sendto, without blocking.
- Skips the other kinds, and a SEND with an unknown socket ID.

### Effects

- A datagram the OS does not take is lost, as UDP allows.

### Limits

- Stack of its own: 96 bytes on Linux x86-64, 128 bytes on Linux ARM64, 144 bytes on Linux RISC-V, 96 bytes on macOS x86-64, 128 bytes on macOS ARM64, 144 bytes on Windows x86-64, 128 bytes on Windows ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L2.
- Symbol: `quic_shell_send` (`_quic_shell_send` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6); OS calls use the native convention.
- Argument order: `ctx`, `actions`.

## Function `quic_shell_receive`

Adds a DATAGRAM event for each datagram waiting on the sockets.

### Signature

```
quic_shell_receive(ctx, events) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `ctx` | resource context | [`ShellContext`](#type-shellcontext) |
| `events` | state | [`ByteList`](node.md#type-bytelist) of [`Event`](node.md#type-event) values |

### Returns

- `QUIC_OK`: The events hold what was waiting, while they had room.

### Function does

- Reads while the list has room for a datagram of `QUIC_RECEIVE_MAX` bytes.
- Moves to the next socket after an error or when nothing waits.

### Limits

- Stack of its own: 96 bytes on Linux x86-64, 144 bytes on Linux ARM64, 160 bytes on Linux RISC-V, 96 bytes on macOS x86-64, 144 bytes on macOS ARM64, 144 bytes on Windows x86-64, 144 bytes on Windows ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L2.
- Symbol: `quic_shell_receive` (`_quic_shell_receive` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6); OS calls use the native convention.
- Argument order: `ctx`, `events`.

## Function `quic_shell_wait`

Waits until a socket can be read or the monotonic time at until, at most 60 s.

### Signature

```
quic_shell_wait(ctx, until) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `ctx` | resource context | [`ShellContext`](#type-shellcontext) |
| `until` | input | u64: monotonic microseconds |

### Returns

- `QUIC_OK`: The wait ended.

### Function does

- Linux: ppoll, in microseconds.
- macOS: poll, rounded up to a millisecond.
- Windows: WSAPoll, rounded up to a millisecond; Sleep when no socket is open or WSAPoll fails.

### Limits

- Stack of its own: 128 bytes on Linux x86-64, 160 bytes on Linux ARM64, 176 bytes on Linux RISC-V, 96 bytes on macOS x86-64, 128 bytes on macOS ARM64, 176 bytes on Windows x86-64, 160 bytes on Windows ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L2.
- Symbol: `quic_shell_wait` (`_quic_shell_wait` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6); OS calls use the native convention.
- Argument order: `ctx`, `until`.

## Function `quic_shell_clock`

Reads the time and random bytes.

### Signature

```
quic_shell_clock(tick) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `tick` | output | [`Tick`](node.md#type-tick) |

### Returns

- `QUIC_OK`: The tick is filled.
- `QUIC_OS_ERROR`: An OS call failed.

### Function does

- Linux: clock_gettime CLOCK_MONOTONIC and CLOCK_REALTIME, and getrandom.
- macOS: clock_gettime_nsec_np CLOCK_MONOTONIC and CLOCK_REALTIME, and getentropy.
- Windows: QueryPerformanceCounter, GetSystemTimeAsFileTime and BCryptGenRandom.

### Limits

- Stack of its own: 80 bytes on Linux x86-64, 112 bytes on Linux ARM64, 128 bytes on Linux RISC-V, 64 bytes on macOS x86-64, 96 bytes on macOS ARM64, 96 bytes on Windows x86-64, 112 bytes on Windows ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L2.
- Symbol: `quic_shell_clock` (`_quic_shell_clock` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6); OS calls use the native convention.
- Argument order: `tick`.

## Function `quic_shell_close`

Closes every socket.

### Signature

```
quic_shell_close(ctx) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `ctx` | resource context | [`ShellContext`](#type-shellcontext) |

### Returns

- `QUIC_OK`: The context holds no socket.

### Function does

- Windows: ends the Winsock start of each socket.

### Limits

- Stack of its own: 64 bytes on Linux x86-64, 96 bytes on Linux ARM64, 112 bytes on Linux RISC-V, 64 bytes on macOS x86-64, 96 bytes on macOS ARM64, 96 bytes on Windows x86-64, 96 bytes on Windows ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L2.
- Symbol: `quic_shell_close` (`_quic_shell_close` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6); OS calls use the native convention.
- Argument order: `ctx`.

## Function `quic_shell_sockaddr`

Builds a native socket address.

### Signature

```
quic_shell_sockaddr(dst, addr) -> length
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | 32 bytes |
| `addr` | input | [`Address`](node.md#type-address) |

### Function does

- Writes sockaddr_in (16 bytes) or sockaddr_in6 (28 bytes) with the port big endian; macOS sets the length byte too.

### Limits

- Stack of its own: 8 bytes on Linux x86-64, 0 bytes on Linux ARM64, 0 bytes on Linux RISC-V, 8 bytes on macOS x86-64, 0 bytes on macOS ARM64, 8 bytes on Windows x86-64, 0 bytes on Windows ARM64 (x86-64 return address included).

### ABI

- Role: L0.
- Symbol: `quic_shell_sockaddr`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- It returns the length, not a status.
- Argument order: `dst`, `addr`.

## Function `quic_shell_address`

Reads a native socket address.

### Signature

```
quic_shell_address(dst, sockaddr)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | [`Address`](node.md#type-address) |
| `sockaddr` | input | sockaddr_in or sockaddr_in6 |

### Limits

- Stack of its own: 8 bytes on Linux x86-64, 0 bytes on Linux ARM64, 0 bytes on Linux RISC-V, 8 bytes on macOS x86-64, 0 bytes on macOS ARM64, 8 bytes on Windows x86-64, 0 bytes on Windows ARM64 (x86-64 return address included).

### ABI

- Role: L0.
- Symbol: `quic_shell_address`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `dst`, `sockaddr`.

## Function `quic_shell_fcntl`

Calls fcntl.

### Signature

```
quic_shell_fcntl(socket, command, value) -> result
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `socket` | input | u64 |
| `command` | input | u64 |
| `value` | input | u64 |

### Function does

- Passes `value` as the variadic third argument: on the stack on ARM64, with al 0 on x86-64.

### Limits

- Stack of its own: 16 bytes on macOS x86-64, 32 bytes on macOS ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L0.
- Symbol: `quic_shell_fcntl`, local to its object.
- OS: macOS.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6); OS calls use the native convention.
- It returns the int result of fcntl, not a status.
- Argument order: `socket`, `command`, `value`.

## Function `quic_shell_wsa_start`

Starts Winsock 2.2.

### Signature

```
quic_shell_wsa_start() -> result
```

### Function does

- Returns the WSAStartup result: 0 when Winsock started.

### Limits

- Stack of its own: 464 bytes on Windows x86-64, 432 bytes on Windows ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L0.
- Symbol: `quic_shell_wsa_start`, local to its object.
- OS: Windows.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6); OS calls use the native convention.

## Function `quic_shell_no_connreset`

Turns off WSAECONNRESET on a UDP socket.

### Signature

```
quic_shell_no_connreset(socket)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `socket` | input | u64 |

### Function does

- Calls WSAIoctl SIO_UDP_CONNRESET with FALSE.

### Limits

- Stack of its own: 96 bytes on Windows x86-64, 48 bytes on Windows ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L0.
- Symbol: `quic_shell_no_connreset`, local to its object.
- OS: Windows.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6); OS calls use the native convention.
- Argument order: `socket`.

## Function `quic_shell_now`

Reads the monotonic time.

### Signature

```
quic_shell_now() -> microseconds
```

### Function does

- Scales QueryPerformanceCounter by QueryPerformanceFrequency.

### Limits

- Stack of its own: 112 bytes on Windows x86-64, 112 bytes on Windows ARM64 (x86-64 return address included). OS calls add their own.

### ABI

- Role: L0.
- Symbol: `quic_shell_now`, local to its object.
- OS: Windows.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6); OS calls use the native convention.

## Type `ShellContext`

The UDP sockets of the shell.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes the caller gives: at least `QUIC_SHELL_SIZE` |
| 8 | `count` | u64 | Sockets open |
| 16 | `sockets` | 4 entries of 40 bytes | Each: the native socket (u64), then its local [`Address`](node.md#type-address) |

### Rules

- Size: `QUIC_SHELL_SIZE` (176) bytes.
- The socket ID of an entry is its index.
- The caller keeps it in place while sockets are open.


## Type `BindResult`

The output of `quic_shell_bind`.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `socket` | u64 | The socket ID for events and actions |
| 8 | `local` | [`Address`](node.md#type-address) | The local address |


## Test vectors

- Shell loop test
  - File: [tests/shell/loop.c](../../tests/shell/loop.c): two nodes in one process over 127.0.0.1, on every target.
- transport-interop of libp2p/test-plans
  - File: [tests/interop/](../../tests/interop/): the Linux shell.

## Results

<!-- CI generates the tick table for each function here. -->

### `quic_shell_init`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_shell_bind`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_shell_send`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_shell_receive`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_shell_wait`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_shell_clock`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_shell_close`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_shell_sockaddr`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_shell_address`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_shell_fcntl`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  | ✅ |  |
| ARM64 |  |  | ✅ |  |
| RISC-V |  |  |  |  |

### `quic_shell_wsa_start`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  | ✅ |  |  |
| ARM64 |  | ✅ |  |  |
| RISC-V |  |  |  |  |

### `quic_shell_no_connreset`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  | ✅ |  |  |
| ARM64 |  | ✅ |  |  |
| RISC-V |  |  |  |  |

### `quic_shell_now`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  | ✅ |  |  |
| ARM64 |  | ✅ |  |  |
| RISC-V |  |  |  |  |
