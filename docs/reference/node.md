# Node

## Contents

### Functions

- [`quic_state_size`](#function-quic_state_size): gives the bytes of the state of a config.
- [`quic_init`](#function-quic_init): builds a node with no connections.
- [`quic_step`](#function-quic_step): runs the node for one step.
- [`quic_layout`](#function-quic_layout): checks a config and lays out its state.
- [`quic_check_addr`](#function-quic_check_addr): checks an address.
- [`quic_check_event`](#function-quic_check_event): checks one event.
- [`quic_event`](#function-quic_event): hands an event to the function of its kind.
- [`quic_on_dial`](#function-quic_on_dial): starts a client connection.
- [`quic_on_close`](#function-quic_on_close): closes a connection for the application.
- [`quic_connections`](#function-quic_connections): runs every connection for the step.
- [`quic_conn_timers`](#function-quic_conn_timers): runs the timers of a connection.
- [`quic_conn_tell`](#function-quic_conn_tell): tells the application what happened on a connection.
- [`quic_conn_deadline`](#function-quic_conn_deadline): adds the deadlines of a connection to the wakeup.
- [`quic_copy`](#function-quic_copy): copies bytes.
- [`quic_zero`](#function-quic_zero): zeroes bytes.
- [`quic_equal`](#function-quic_equal): compares bytes in constant time.
- [`quic_heap_alloc`](#function-quic_heap_alloc): allocates a heap block.
- [`quic_heap_free`](#function-quic_heap_free): frees a heap block.
- [`quic_heap_room`](#function-quic_heap_room): gives the bytes a heap block holds.
- [`quic_random`](#function-quic_random): draws random bytes.
- [`quic_reseed`](#function-quic_reseed): mixes entropy into the random bytes generator.
- [`quic_action`](#function-quic_action): adds an action.
- [`quic_room`](#function-quic_room): gives the action bytes left.
- [`quic_wake_at`](#function-quic_wake_at): brings the wakeup forward.
- [`quic_slot`](#function-quic_slot): finds the slot of a handle.
- [`quic_conn`](#function-quic_conn): finds the connection of a handle.
- [`quic_stream`](#function-quic_stream): finds the stream of a handle.
- [`quic_handle`](#function-quic_handle): gives the handle of a slot.
- [`quic_conn_handle`](#function-quic_conn_handle): gives the handle of a connection.
- [`quic_stream_handle`](#function-quic_stream_handle): gives the handle of a stream.
- [`quic_conn_index`](#function-quic_conn_index): gives the slot index of a connection.
- [`quic_conn_at`](#function-quic_conn_at): gives the connection slot of an index.
- [`quic_stream_at`](#function-quic_stream_at): gives the stream slot of an index.
- [`quic_stream_index`](#function-quic_stream_index): gives the slot index of a stream.
- [`quic_alloc_slot`](#function-quic_alloc_slot): takes a free slot.
- [`quic_vlen`](#function-quic_vlen): gives the length of a varint.
- [`quic_vput`](#function-quic_vput): writes a varint.
- [`quic_vput2`](#function-quic_vput2): writes a 2-byte varint.
- [`quic_vget`](#function-quic_vget): reads a varint.
- [`quic_put16`](#function-quic_put16): writes 2 bytes big endian.
- [`quic_put24`](#function-quic_put24): writes 3 bytes big endian.
- [`quic_get24`](#function-quic_get24): reads 3 bytes big endian.

### Types

- [`Config`](#type-config): the input of `quic_init`.
- [`Tick`](#type-tick): the time and entropy of a step.
- [`Address`](#type-address): an IPv4 or IPv6 address and UDP port.
- [`ByteList`](#type-bytelist): a counted list of bytes (ARCHITECTURE.md section 6).
- [`StepResult`](#type-stepresult): the output of `quic_step`.
- [`Handle`](#type-handle): a connection or stream of the node.
- [`Event`](#type-event): an input of `quic_step`: a size, a kind, then the fields of the kind.
- [`DatagramEvent`](#type-datagramevent): kind DATAGRAM: a UDP datagram arrived.
- [`DialEvent`](#type-dialevent): kind DIAL: connect to a peer.
- [`OpenStreamEvent`](#type-openstreamevent): kind OPEN_STREAM: open a bidirectional stream.
- [`StreamWriteEvent`](#type-streamwriteevent): kind STREAM_WRITE: bytes for a stream.
- [`StreamCloseEvent`](#type-streamcloseevent): kind STREAM_CLOSE: no more bytes on a stream; a FIN follows the queue.
- [`StreamResetEvent`](#type-streamresetevent): kind STREAM_RESET: reset a stream both ways.
- [`CloseEvent`](#type-closeevent): kind CLOSE: close a connection.
- [`Action`](#type-action): an output of `quic_step`: a size, a kind, then the fields of the kind.
- [`SendAction`](#type-sendaction): kind SEND: a UDP datagram to send.
- [`WakeupAction`](#type-wakeupaction): kind WAKEUP: when the next step is due.
- [`ConnectedAction`](#type-connectedaction): kind CONNECTED: a connection is up.
- [`DialFailedAction`](#type-dialfailedaction): kind DIAL_FAILED: a DIAL ended without a connection.
- [`ClosedAction`](#type-closedaction): kind CLOSED: a connection is over.
- [`StreamOpenedAction`](#type-streamopenedaction): kind STREAM_OPENED: a stream is open.
- [`StreamDataAction`](#type-streamdataaction): kind STREAM_DATA: bytes of a stream, in order.
- [`StreamFinAction`](#type-streamfinaction): kind STREAM_FIN: the peer sends no more on a stream.
- [`StreamResetAction`](#type-streamresetaction): kind STREAM_RESET: the peer reset a stream, or stopped our side.

### Constants

- `QUIC_OK`: status 0: success.
- `QUIC_BUFFER_TOO_SMALL`: status 1: an output or scratch is too small.
- `QUIC_INVALID_ARGUMENT`: status 2: a value breaks a rule of its type.
- `QUIC_INVALID_PACKET`: status 3: a packet is too short or malformed.
- `QUIC_DECRYPT_FAILED`: status 4: the AEAD tag of a packet does not match.
- `QUIC_INVALID_CERT`: status 5: a certificate breaks a rule of the libp2p TLS spec.
- `QUIC_INVALID_CONFIG`: status 6: a config breaks a rule of its type.
- `QUIC_INVALID_EVENT`: status 7: an event breaks a rule of its kind.
- `QUIC_INVALID_KEY`: status 8: a host private key is out of range.
- `QUIC_VERSION`: the version of the Config and state layouts: 1.
- `QUIC_CFG_ACCEPT`: flag 1: accept connections from peers.
- `QUIC_SCRATCH_SIZE`: bytes of the scratch of `quic_step`: 14336.
- `QUIC_ACTIONS_MIN`: action bytes a step needs after the header: 2048.
- `QUIC_ERR_LOCAL`: reason 1: the application closed it.
- `QUIC_ERR_PEER`: reason 2: the peer closed it.
- `QUIC_ERR_IDLE`: reason 3: no packet within the idle timeout.
- `QUIC_ERR_HANDSHAKE_TIMEOUT`: reason 4: the handshake did not end in time.
- `QUIC_ERR_PROTOCOL`: reason 5: the peer broke a rule; the error is the code we sent.
- `QUIC_ERR_PEER_ID`: reason 6: the peer is not the one the DIAL named.
- `QUIC_ERR_VERSION`: reason 7: the peer speaks no version we do.
- `QUIC_ERR_LIMIT`: reason 8: no room for the connection.
- `QUIC_ERR_RESET`: reason 9: a stateless reset.

## Spec

- Document: [ARCHITECTURE.md](https://github.com/bitminetech/asm-standard/blob/2a19d3f7fa737af1c01720b6e891703e53a682aa/ARCHITECTURE.md) section 6, asm-standard at commit 2a19d3f.
- Document: [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) section 16.
- Section: the state, the step, its events and actions, and variable-length integers.

## Function `quic_state_size`

Gives the bytes of the state that `quic_init` builds for a config.

### Signature

```
quic_state_size(config, size) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `config` | input | [`Config`](#type-config) |
| `size` | output | u64 |

### Returns

- `QUIC_OK`: `size` holds the bytes.
- `QUIC_INVALID_CONFIG`: The config breaks a rule of its type.

### Function does

- Adds the fixed fields, the connection table, the stream table and the heap, at a multiple of 64.

### Function never

- Writes outside `size` and its own stack.
- Makes an OS call.

### Limits

- Stack: 104 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V, callees included, the most the test runner measured.

### ABI

- Role: L2.
- Symbol: `quic_state_size` (`_quic_state_size` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `config`, `size`.

## Function `quic_init`

Builds a node with no connections.

### Signature

```
quic_init(config, state) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `config` | input | [`Config`](#type-config) |
| `state` | output | u64 size, then the state |

### Returns

- `QUIC_OK`: The state is ready.
- `QUIC_INVALID_CONFIG`: The config breaks a rule of its type.
- `QUIC_BUFFER_TOO_SMALL`: The size field of the state is below what `quic_state_size` gives.
- `QUIC_INVALID_KEY`: A secp256k1 host key is 0 or not below the group order.

### Function does

- Lays out the tables and the heap as one free block.
- Keys the random bytes generator with the seed of the config.
- Derives the host public key and its PublicKey protobuf.
- Draws a P-256 certificate key and builds our certificate.

### Function never

- Writes outside the state and its own stack.
- Makes an OS call.

### Limits

- Stack: 3672 bytes on x86-64 (return address included), 3712 bytes on ARM64, 3824 bytes on RISC-V, callees included, the most the test runner measured.

### ABI

- Role: L2.
- Symbol: `quic_init` (`_quic_init` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `config`, `state`.

## Function `quic_step`

Runs the node for one step: events, timers, what the application hears, datagrams out, and the next wakeup.

### Signature

```
quic_step(state, tick, events, scratch, actions, result) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `state` | state | the state of `quic_init` |
| `tick` | input | [`Tick`](#type-tick) |
| `events` | input | [`ByteList`](node.md#type-bytelist) of [`Event`](#type-event) values |
| `scratch` | scratch | u64 size, then at least `QUIC_SCRATCH_SIZE` bytes |
| `actions` | output | [`ByteList`](node.md#type-bytelist) of [`Action`](#type-action) values |
| `result` | output | [`StepResult`](#type-stepresult) |

### Returns

- `QUIC_OK`: The step ran; `actions` and `result` are written.
- `QUIC_BUFFER_TOO_SMALL`: The scratch is below `QUIC_SCRATCH_SIZE`, or `actions` below 24 + `QUIC_ACTIONS_MIN` bytes.
- `QUIC_INVALID_EVENT`: The events ByteList is malformed, or an event breaks a rule of its kind.

### Caller must

- Keep the tick time monotonic; a time below the last one counts as the last one.
- Give the events not handled again, first, in the next step.

### Function does

- Checks every event before it changes anything; a failed check changes nothing.
- Takes the events in order while 256 action bytes are left.
- Runs the timers of each connection, then tells the application what happened, then sends datagrams.
- Ends the actions with one WAKEUP: the earliest deadline, at most 60 s ahead, or now when events are left.

### Function never

- Writes outside the state, the scratch, `actions`, `result` and its own stack.
- Makes an OS call.

### Effects

- The SEND actions are datagrams to send; the others are for the application.

### Limits

- Stack: 3208 bytes on x86-64 (return address included), 3328 bytes on ARM64, 3568 bytes on RISC-V, callees included, the most the test runner measured.

### ABI

- Role: L2.
- Symbol: `quic_step` (`_quic_step` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `state`, `tick`, `events`, `scratch`, `actions`, `result`.

## Function `quic_layout`

Checks a config and lays out its state.

### Signature

```
quic_layout(config) -> (size, streams, heap)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `config` | input | [`Config`](#type-config) |

### Function does

- Returns the state size, or 0 when the config breaks a rule.
- Returns the offsets of the stream table and of the heap too.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_layout`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- It returns three values: x0, x1, x2 on ARM64; rax, rdx, rcx on x86-64; a0, a1, a2 on RISC-V.
- Argument order: `config`.

## Function `quic_check_addr`

Checks an address.

### Signature

```
quic_check_addr(addr) -> valid
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `addr` | input | [`Address`](#type-address) |

### Function does

- Returns 1 for family 4 or 6 and a port below 65536.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_check_addr`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `addr`.

## Function `quic_check_event`

Checks one event.

### Signature

```
quic_check_event(event, room) -> valid
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `event` | input | [`Event`](#type-event) |
| `room` | input | u64: the bytes left in the list |

### Function does

- Returns 1 when the size is a multiple of 8 within `room`, the kind is known, and the fields keep the rules of the kind.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_check_event`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `event`, `room`.

## Function `quic_event`

Hands an event to the function of its kind.

### Signature

```
quic_event(event)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `event` | input | [`Event`](#type-event) |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 16 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_event`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `event`.

## Function `quic_on_dial`

Starts a client connection.

### Signature

```
quic_on_dial(event)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `event` | input | [`DialEvent`](#type-dialevent) |

### Function does

- Draws a first Destination Connection ID of 8 bytes.
- Derives its Initial keys and sends a ClientHello.
- Adds DIAL_FAILED with `QUIC_ERR_LIMIT` when no slot or heap is free.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_dial`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `event`.

## Function `quic_on_close`

Closes a connection for the application.

### Signature

```
quic_on_close(event)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `event` | input | [`CloseEvent`](#type-closeevent) |

### Function does

- Starts closing with the application code (RFC 9000 section 10.2).
- Ignores a stale handle or a connection already closing.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_close`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `event`.

## Function `quic_connections`

Runs every connection for the step.

### Signature

```
quic_connections()
```

### Function does

- Runs the timers, tells the application, sends datagrams and sets the wakeup of each connection in use.
- Frees a connection that is over once the application heard it.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_connections`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.

## Function `quic_conn_timers`

Runs the timers of a connection.

### Signature

```
quic_conn_timers()
```

### Function does

- Ends closing or draining.
- Ends a handshake past its deadline with `QUIC_ERR_HANDSHAKE_TIMEOUT`.
- Ends an idle connection with `QUIC_ERR_IDLE`, silently.
- Runs the loss detection timer.
- Asks for a PING when the keep-alive is due.
- Drops the previous receive keys when their time is up.
- Starts a key update when one is due.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_conn_timers`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.

## Function `quic_conn_tell`

Tells the application what happened on a connection.

### Signature

```
quic_conn_tell()
```

### Function does

- Adds CONNECTED, then the stream actions, then CLOSED or DIAL_FAILED, while the action room allows.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_conn_tell`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.

## Function `quic_conn_deadline`

Adds the deadlines of a connection to the wakeup.

### Signature

```
quic_conn_deadline()
```

### Function does

- Takes the loss detection timer, the idle timeout, the end of closing, the keep-alive, the end of the previous keys, a delayed ACK and the handshake deadline.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 16 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_conn_deadline`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.

## Function `quic_copy`

Copies bytes.

### Signature

```
quic_copy(dst, src, n) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | `n` bytes, below `src` or apart from it |
| `src` | input | `n` bytes |
| `n` | input | u64 |

### Function does

- Returns dst + n.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_copy`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `dst`, `src`, `n`.

## Function `quic_zero`

Zeroes bytes.

### Signature

```
quic_zero(dst, n) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | `n` bytes |
| `n` | input | u64 |

### Function does

- Returns dst + n.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_zero`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `dst`, `n`.

## Function `quic_equal`

Compares bytes in constant time.

### Signature

```
quic_equal(a, b, n) -> equal
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `a` | input | `n` bytes |
| `b` | input | `n` bytes |
| `n` | input | u64 |

### Function does

- Reads all n bytes, and returns 1 when they are equal, else 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_equal`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `a`, `b`, `n`.

## Function `quic_heap_alloc`

Allocates a heap block of at least n bytes after its header: a buddy allocator over the heap of the state.

### Signature

```
quic_heap_alloc(n) -> offset
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `n` | input | u64 |

### Function does

- Returns the state offset of the block, or 0 when the heap cannot hold it.
- A block of order k is 2^k bytes, its first 16 bytes the header.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_heap_alloc`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9.
- Argument order: `n`.

## Function `quic_heap_free`

Frees a heap block.

### Signature

```
quic_heap_free(offset)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `offset` | input | u64: a block of `quic_heap_alloc`, or 0 |

### Function does

- Joins the block with its free buddies.
- Does nothing for offset 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_heap_free`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9.
- Argument order: `offset`.

## Function `quic_heap_room`

Gives the bytes a heap block holds.

### Signature

```
quic_heap_room(offset) -> bytes
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `offset` | input | u64: a block of `quic_heap_alloc` |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_heap_room`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9.
- Argument order: `offset`.

## Function `quic_random`

Draws random bytes from the generator of the state: SHA-256(key || counter) for each 32 bytes, the counter one higher each time.

### Signature

```
quic_random(dst, n)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | `n` bytes |
| `n` | input | u64 |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 192 bytes on x86-64 (return address included), 192 bytes on ARM64, 208 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_random`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9.
- Argument order: `dst`, `n`.

## Function `quic_reseed`

Mixes entropy into the random bytes generator.

### Signature

```
quic_reseed(entropy)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `entropy` | input | 32 bytes |

### Function does

- Makes the key SHA-256(key || entropy).

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 192 bytes on x86-64 (return address included), 192 bytes on ARM64, 208 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_reseed`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9.
- Argument order: `entropy`.

## Function `quic_action`

Adds an action.

### Signature

```
quic_action(kind, size) -> action
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `kind` | input | u64 |
| `size` | input | u64: a multiple of 8 |

### Function does

- Returns the new action, zeroed, with its size and kind; 0 when the list has no room.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_action`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `kind`, `size`.

## Function `quic_room`

Gives the action bytes left.

### Signature

```
quic_room() -> bytes
```

### Function does

- Leaves out the reserve the step keeps for its WAKEUP.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_room`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.

## Function `quic_wake_at`

Brings the wakeup forward.

### Signature

```
quic_wake_at(time)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `time` | input | u64: monotonic microseconds, or NONE |

### Function does

- Keeps the earlier of the wakeup and `time`.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_wake_at`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10.
- Argument order: `time`.

## Function `quic_slot`

Finds the slot of a handle.

### Signature

```
quic_slot(table, count, stride, handle) -> slot
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `table` | input | u64: the state field of the table offset |
| `count` | input | u64: the state field of the slot count |
| `stride` | input | u64: bytes of a slot |
| `handle` | input | u64: a [`Handle`](#type-handle) |

### Function does

- Returns the slot when the index is below the count, the generation matches and the slot is in use, else 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_slot`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9.
- Argument order: `table`, `count`, `stride`, `handle`.

## Function `quic_conn`

Finds the connection of a handle.

### Signature

```
quic_conn(handle) -> conn
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `handle` | input | u64: a [`Handle`](#type-handle) |

### Function does

- Returns the connection slot, or 0 for a stale handle.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 16 bytes on x86-64 (return address included), 96 bytes on ARM64, 16 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_conn`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9.
- Argument order: `handle`.

## Function `quic_stream`

Finds the stream of a handle.

### Signature

```
quic_stream(handle) -> stream
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `handle` | input | u64: a [`Handle`](#type-handle) |

### Function does

- Returns the stream slot, or 0 for a stale handle.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 16 bytes on x86-64 (return address included), 96 bytes on ARM64, 16 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9.
- Argument order: `handle`.

## Function `quic_handle`

Gives the handle of a slot.

### Signature

```
quic_handle(table, stride, slot) -> handle
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `table` | input | u64: the state field of the table offset |
| `stride` | input | u64: bytes of a slot |
| `slot` | input | a slot |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_handle`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9.
- Argument order: `table`, `stride`, `slot`.

## Function `quic_conn_handle`

Gives the handle of a connection.

### Signature

```
quic_conn_handle(conn) -> handle
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `conn` | input | a connection slot |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 16 bytes on x86-64 (return address included), 96 bytes on ARM64, 16 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_conn_handle`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9.
- Argument order: `conn`.

## Function `quic_stream_handle`

Gives the handle of a stream.

### Signature

```
quic_stream_handle(stream) -> handle
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `stream` | input | a stream slot |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 16 bytes on x86-64 (return address included), 96 bytes on ARM64, 16 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_handle`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9.
- Argument order: `stream`.

## Function `quic_conn_index`

Gives the slot index of a connection.

### Signature

```
quic_conn_index(conn) -> index
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `conn` | input | a connection slot |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_conn_index`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9.
- Argument order: `conn`.

## Function `quic_conn_at`

Gives the connection slot of an index.

### Signature

```
quic_conn_at(index) -> conn
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `index` | input | u64 |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_conn_at`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9.
- Argument order: `index`.

## Function `quic_stream_at`

Gives the stream slot of an index.

### Signature

```
quic_stream_at(index) -> stream
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `index` | input | u64 |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_at`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9.
- Argument order: `index`.

## Function `quic_stream_index`

Gives the slot index of a stream.

### Signature

```
quic_stream_index(stream) -> index
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `stream` | input | a stream slot |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_stream_index`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9.
- Argument order: `stream`.

## Function `quic_alloc_slot`

Takes a free slot.

### Signature

```
quic_alloc_slot(table, count, stride) -> slot
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `table` | input | u64: the state field of the table offset |
| `count` | input | u64: the state field of the slot count |
| `stride` | input | u64: bytes of a slot |

### Function does

- Zeroes the slot after its generation, makes the generation one higher and marks it in use.
- Returns 0 when every slot is in use.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_alloc_slot`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9.
- Argument order: `table`, `count`, `stride`.

## Function `quic_vlen`

Gives the bytes of the shortest variable-length integer of v: 1, 2, 4 or 8 (RFC 9000 section 16).

### Signature

```
quic_vlen(v) -> bytes
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `v` | input | u64, below 2^62 |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_vlen`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `v`.

## Function `quic_vput`

Writes the shortest variable-length integer of v (RFC 9000 section 16).

### Signature

```
quic_vput(dst, v) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | 1 to 8 bytes |
| `v` | input | u64, below 2^62 |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_vput`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `dst`, `v`.

## Function `quic_vput2`

Writes a 2-byte varint.

### Signature

```
quic_vput2(dst, v) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | 2 bytes |
| `v` | input | u64, below 16384 |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_vput2`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `dst`, `v`.

## Function `quic_vget`

Reads a variable-length integer (RFC 9000 section 16).

### Signature

```
quic_vget(p, end) -> (next, value)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the varint |
| `end` | input | the end of the data |

### Function does

- Returns the position after it and its value, or 0 when it does not end by `end`.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_vget`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- It returns two values: x0, rax or a0, then x1, rdx or a1.
- Argument order: `p`, `end`.

## Function `quic_put16`

Writes 2 bytes big endian.

### Signature

```
quic_put16(dst, v) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | 2 bytes |
| `v` | input | u64 |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_put16`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `dst`, `v`.

## Function `quic_put24`

Writes 3 bytes big endian.

### Signature

```
quic_put24(dst, v) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | 3 bytes |
| `v` | input | u64 |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_put24`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `dst`, `v`.

## Function `quic_get24`

Reads 3 bytes big endian.

### Signature

```
quic_get24(p) -> value
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | 3 bytes |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_get24`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `p`.

## Type `Config`

The input of `quic_init`.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value: at least 192 |
| 8 | `version` | u64 | `QUIC_VERSION` |
| 16 | `key_type` | u64 | `QUIC_KEY_ED25519` or `QUIC_KEY_SECP256K1` |
| 24 | `key` | 32 bytes | The host private key |
| 56 | `conns` | u64 | Connection slots: 1 to 65535 |
| 64 | `streams` | u64 | Stream slots: 1 to 2^20 |
| 72 | `heap` | u64 | Heap bytes: a power of two from 2^16 to 2^40 |
| 80 | `idle` | u64 | max_idle_timeout in ms, below 2^40; 0: no limit of ours |
| 88 | `handshake` | u64 | The handshake must end within this, in ms: 1 to 2^40 - 1 |
| 96 | `keep_alive` | u64 | A PING after this quiet time, in ms, below 2^40; 0: none |
| 104 | `max_data` | u64 | initial_max_data, below 2^60 |
| 112 | `stream_data` | u64 | initial_max_stream_data_bidi_local and _remote, below 2^60 |
| 120 | `max_streams` | u64 | initial_max_streams_bidi, below 2^60 |
| 128 | `stream_queue` | u64 | Bytes a stream may hold unacknowledged: at least 1 |
| 136 | `flags` | u64 | `QUIC_CFG_ACCEPT` or 0 |
| 144 | `sent` | u64 | Sent packet records of a connection: 16 to 65536 |
| 152 | `seed` | 32 bytes | Random bytes for the first keys |
| 184 | `key_update` | u64 | Packets we send in one key phase, below 2^23; 0: 1000000 |


## Type `Tick`

The time and entropy of a step.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `now` | u64 | Monotonic time in microseconds |
| 8 | `unix` | u64 | Unix time in seconds |
| 16 | `entropy` | 32 bytes | Random bytes, mixed into the generator |


## Type `Address`

An IPv4 or IPv6 address and UDP port.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `family` | u64 | 4 or 6 |
| 8 | `port` | u64 | Below 65536 |
| 16 | `ip` | 16 bytes | Network order; IPv4 in the first 4 |


## Type `ByteList`

A counted list of bytes (ARCHITECTURE.md section 6).

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value |
| 8 | `offset` | u64 | Where the bytes start: at least 24 |
| 16 | `count` | u64 | Bytes in the list |

### Rules

- The bytes lie inside `size`.


## Type `StepResult`

The output of `quic_step`.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `handled` | u64 | Events handled, from the first |


## Type `Handle`

A connection or stream of the node.

### Rules

- Bits 0 to 31: the slot index; bits 32 to 63: the generation of the slot.
- A handle goes stale when its slot is freed; events with a stale handle do nothing.
- Handle 0 names nothing.


## Type `Event`

An input of `quic_step`: a size, a kind, then the fields of the kind.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value, a multiple of 8 |
| 8 | `kind` | u64 | The kind |

### Rules

- Kinds: DATAGRAM 1, DIAL 2, OPEN_STREAM 3, STREAM_WRITE 4, STREAM_CLOSE 5, STREAM_RESET 6, CLOSE 7.


## Type `DatagramEvent`

Kind DATAGRAM: a UDP datagram arrived.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value, a multiple of 8 |
| 8 | `kind` | u64 | The kind |
| 16 | `socket` | u64 | The socket ID it came on |
| 24 | `addr` | [`Address`](#type-address) | Where it came from |
| 56 | `count` | u64 | Bytes of the datagram, below 65536 |
| 64 | `data` | count bytes | The datagram |


## Type `DialEvent`

Kind DIAL: connect to a peer.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value, a multiple of 8 |
| 8 | `kind` | u64 | The kind |
| 16 | `tag` | u64 | Comes back in CONNECTED or DIAL_FAILED |
| 24 | `socket` | u64 | The socket ID to use |
| 32 | `addr` | [`Address`](#type-address) | The peer |
| 64 | `peer_len` | u64 | Bytes of the peer ID: at most 48 |
| 72 | `peer` | 48 bytes | The peer ID to expect, a multihash |

### Rules

- Size: 120 bytes.
- A peer whose host key gives another peer ID fails with `QUIC_ERR_PEER_ID`.


## Type `OpenStreamEvent`

Kind OPEN_STREAM: open a bidirectional stream.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value, a multiple of 8 |
| 8 | `kind` | u64 | The kind |
| 16 | `conn` | u64 | The connection handle |
| 24 | `tag` | u64 | Comes back in STREAM_OPENED |

### Rules

- Size: 32 bytes.
- STREAM_OPENED answers it; its stream handle is 0 when no slot was free or the connection is gone.


## Type `StreamWriteEvent`

Kind STREAM_WRITE: bytes for a stream.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value, a multiple of 8 |
| 8 | `kind` | u64 | The kind |
| 16 | `stream` | u64 | The stream handle |
| 24 | `count` | u64 | Bytes to send |
| 32 | `data` | count bytes | The bytes |

### Rules

- A stream whose queue would pass `stream_queue`, or whose bytes the heap cannot hold, is reset with code 0.
- A stream the application closed or reset ignores it.


## Type `StreamCloseEvent`

Kind STREAM_CLOSE: no more bytes on a stream; a FIN follows the queue.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value, a multiple of 8 |
| 8 | `kind` | u64 | The kind |
| 16 | `stream` | u64 | The stream handle |

### Rules

- Size: 24 bytes.


## Type `StreamResetEvent`

Kind STREAM_RESET: reset a stream both ways.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value, a multiple of 8 |
| 8 | `kind` | u64 | The kind |
| 16 | `stream` | u64 | The stream handle |
| 24 | `code` | u64 | The application error code, below 2^62 |

### Rules

- Size: 32 bytes.
- RESET_STREAM and STOP_SENDING go out with the code.


## Type `CloseEvent`

Kind CLOSE: close a connection.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value, a multiple of 8 |
| 8 | `kind` | u64 | The kind |
| 16 | `conn` | u64 | The connection handle |
| 24 | `code` | u64 | The application error code, below 2^62 |

### Rules

- Size: 32 bytes.
- CLOSED with `QUIC_ERR_LOCAL` follows.


## Type `Action`

An output of `quic_step`: a size, a kind, then the fields of the kind.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value, a multiple of 8 |
| 8 | `kind` | u64 | The kind |

### Rules

- Kinds: SEND 1, WAKEUP 2, CONNECTED 3, DIAL_FAILED 4, CLOSED 5, STREAM_OPENED 6, STREAM_DATA 7, STREAM_FIN 8, STREAM_RESET 9.
- For each connection: CONNECTED first, then its stream actions, then CLOSED.
- For each stream: STREAM_OPENED first, then STREAM_DATA in order, then STREAM_FIN or STREAM_RESET.


## Type `SendAction`

Kind SEND: a UDP datagram to send.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value, a multiple of 8 |
| 8 | `kind` | u64 | The kind |
| 16 | `socket` | u64 | The socket ID |
| 24 | `addr` | [`Address`](#type-address) | The peer |
| 56 | `count` | u64 | Bytes of the datagram |
| 64 | `data` | count bytes | The datagram |

### Rules

- A datagram that is lost is sent again by the protocol, so the shell may drop it.


## Type `WakeupAction`

Kind WAKEUP: when the next step is due.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value, a multiple of 8 |
| 8 | `kind` | u64 | The kind |
| 16 | `time` | u64 | Monotonic microseconds |

### Rules

- Size: 24 bytes.
- Every step ends with exactly one.


## Type `ConnectedAction`

Kind CONNECTED: a connection is up.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value, a multiple of 8 |
| 8 | `kind` | u64 | The kind |
| 16 | `conn` | u64 | The connection handle |
| 24 | `tag` | u64 | The tag of the DIAL; 0 inbound |
| 32 | `direction` | u64 | 0 inbound, 1 outbound |
| 40 | `socket` | u64 | The socket ID |
| 48 | `addr` | [`Address`](#type-address) | The peer |
| 80 | `key_len` | u64 | Bytes of the key |
| 88 | `key` | 128 bytes | The PublicKey protobuf of the peer host key |

### Rules

- Size: 216 bytes.


## Type `DialFailedAction`

Kind DIAL_FAILED: a DIAL ended without a connection.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value, a multiple of 8 |
| 8 | `kind` | u64 | The kind |
| 24 | `tag` | u64 | The tag of the DIAL |
| 32 | `reason` | u64 | A `QUIC_ERR_*` value |
| 40 | `error` | u64 | The QUIC error code |

### Rules

- Size: 48 bytes.


## Type `ClosedAction`

Kind CLOSED: a connection is over.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value, a multiple of 8 |
| 8 | `kind` | u64 | The kind |
| 16 | `conn` | u64 | The connection handle |
| 24 | `tag` | u64 | The tag of the DIAL; 0 inbound |
| 32 | `reason` | u64 | A `QUIC_ERR_*` value |
| 40 | `error` | u64 | The QUIC error code |

### Rules

- Size: 48 bytes.


## Type `StreamOpenedAction`

Kind STREAM_OPENED: a stream is open.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value, a multiple of 8 |
| 8 | `kind` | u64 | The kind |
| 16 | `stream` | u64 | The stream handle; 0 when OPEN_STREAM failed |
| 24 | `conn` | u64 | The connection handle |
| 32 | `tag` | u64 | The tag of OPEN_STREAM; 0 for a stream of the peer |

### Rules

- Size: 40 bytes.


## Type `StreamDataAction`

Kind STREAM_DATA: bytes of a stream, in order.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value, a multiple of 8 |
| 8 | `kind` | u64 | The kind |
| 16 | `stream` | u64 | The stream handle |
| 24 | `count` | u64 | Bytes |
| 32 | `data` | count bytes | The bytes |


## Type `StreamFinAction`

Kind STREAM_FIN: the peer sends no more on a stream.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value, a multiple of 8 |
| 8 | `kind` | u64 | The kind |
| 16 | `stream` | u64 | The stream handle |

### Rules

- Size: 24 bytes.


## Type `StreamResetAction`

Kind STREAM_RESET: the peer reset a stream, or stopped our side.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes of the value, a multiple of 8 |
| 8 | `kind` | u64 | The kind |
| 16 | `stream` | u64 | The stream handle |
| 24 | `code` | u64 | The application error code |

### Rules

- Size: 32 bytes.


## Test vectors

- Scenarios
  - File: [tests/runner/runner.c](../../tests/runner/runner.c): 12 scenarios; their digests must be equal on every ISA.

## Results

<!-- CI generates the tick table for each function here. -->

### `quic_state_size`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_init`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_step`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_layout`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_check_addr`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_check_event`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_event`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_on_dial`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_on_close`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_connections`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_conn_timers`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_conn_tell`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_conn_deadline`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_copy`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_zero`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_equal`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_heap_alloc`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_heap_free`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_heap_room`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_random`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_reseed`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_action`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_room`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_wake_at`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_slot`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_conn`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_stream`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_handle`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_conn_handle`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_stream_handle`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_conn_index`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_conn_at`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_stream_at`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_stream_index`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_alloc_slot`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_vlen`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_vput`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_vput2`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_vget`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_put16`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_put24`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |

### `quic_get24`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 |  |  |  |  |
| ARM64 |  |  |  |  |
| RISC-V |  |  |  |  |
