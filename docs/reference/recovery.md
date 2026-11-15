# Loss detection and congestion control

## Contents

### Functions

- [`quic_recv_pn`](#function-quic_recv_pn): records a received packet number.
- [`quic_range_insert`](#function-quic_range_insert): inserts a range of one packet number.
- [`quic_range_remove`](#function-quic_range_remove): removes a received range.
- [`quic_ring_free`](#function-quic_ring_free): tells whether the ring of sent packets has room.
- [`quic_record_at`](#function-quic_record_at): gives a record of the ring.
- [`quic_record_sent`](#function-quic_record_sent): records a sent packet.
- [`quic_record_gone`](#function-quic_record_gone): retires a sent packet record.
- [`quic_ring_tidy`](#function-quic_ring_tidy): drops retired records from the ring.
- [`quic_drop_space_records`](#function-quic_drop_space_records): drops the records of a space whose keys are gone.
- [`quic_ref_acked`](#function-quic_ref_acked): handles a frame of an acknowledged packet.
- [`quic_ref_lost`](#function-quic_ref_lost): handles a frame of a lost packet.
- [`quic_ref_stream`](#function-quic_ref_stream): finds the stream of a frame ref.
- [`quic_on_ack`](#function-quic_on_ack): handles an ACK frame.
- [`quic_rtt_sample`](#function-quic_rtt_sample): takes an RTT sample.
- [`quic_detect_loss`](#function-quic_detect_loss): detects lost packets.
- [`quic_cc_acked`](#function-quic_cc_acked): grows the congestion window.
- [`quic_cc_lost`](#function-quic_cc_lost): reacts to a lost packet.
- [`quic_set_loss_timer`](#function-quic_set_loss_timer): sets the loss detection timer.
- [`quic_on_loss_timer`](#function-quic_on_loss_timer): handles the loss detection timer.
- [`quic_crypto_unacked`](#function-quic_crypto_unacked): finds the first unacknowledged CRYPTO offset.

## Spec

- Document: [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002).
- Section: 5 (RTT), 6 (loss detection), 7 (NewReno congestion control).

## Function `quic_recv_pn`

Records a received packet number.

### Signature

```
quic_recv_pn(space, pn) -> seen
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `space` | input | the space record |
| `pn` | input | u64 |

### Function does

- Returns 1 when pn was received before.
- Else adds it to the ranges of the space, largest first, and returns 0.
- Drops the smallest range when the ranges are full.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_recv_pn`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `space`, `pn`.

## Function `quic_range_insert`

Inserts a range of one packet number.

### Signature

```
quic_range_insert(space, index, pn)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `space` | input | the space record |
| `index` | input | u64 |
| `pn` | input | u64 |

### Function does

- Inserts [pn, pn] at index; the last range goes when the ranges are full.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_range_insert`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `space`, `index`, `pn`.

## Function `quic_range_remove`

Removes a received range.

### Signature

```
quic_range_remove(space, index)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `space` | input | the space record |
| `index` | input | u64 |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_range_remove`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `space`, `index`.

## Function `quic_ring_free`

Tells whether the ring of sent packets has room.

### Signature

```
quic_ring_free() -> free
```

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_ring_free`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1.

## Function `quic_record_at`

Gives a record of the ring.

### Signature

```
quic_record_at(i) -> record
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `i` | input | u64: places after the oldest |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_record_at`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `i`.

## Function `quic_record_sent`

Records a sent packet.

### Signature

```
quic_record_sent(space, pn, size, flags, frames, n)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |
| `pn` | input | u64 |
| `size` | input | u64: bytes |
| `flags` | input | u64: ack-eliciting, in flight |
| `frames` | input | `n` frame refs |
| `n` | input | u64 |

### Caller must

- Check `quic_ring_free` first.

### Function does

- Adds a live record sent now.
- Updates the bytes in flight, the ack-eliciting count and the loss timer.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_record_sent`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `space`, `pn`, `size`, `flags`, `frames`, `n`.

## Function `quic_record_gone`

Retires a sent packet record.

### Signature

```
quic_record_gone(record, acked)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `record` | input | a sent packet record |
| `acked` | input | u64: 1 acknowledged, 0 lost |

### Function does

- Updates the bytes in flight and the ack-eliciting count.
- Hands each frame ref to `quic_ref_acked` or `quic_ref_lost`.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_record_gone`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `record`, `acked`.

## Function `quic_ring_tidy`

Drops retired records from the ring.

### Signature

```
quic_ring_tidy()
```

### Function does

- Drops the oldest records that are no longer live.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_ring_tidy`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.

## Function `quic_drop_space_records`

Drops the records of a space whose keys are gone.

### Signature

```
quic_drop_space_records(space)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |

### Function does

- Retires every live record of the space as neither acknowledged nor lost.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_drop_space_records`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `space`.

## Function `quic_ref_acked`

Handles a frame of an acknowledged packet.

### Signature

```
quic_ref_acked(ref, space)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `ref` | input | a frame ref of a record: 16 bytes |
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_ref_acked`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `ref`, `space`.

## Function `quic_ref_lost`

Handles a frame of a lost packet.

### Signature

```
quic_ref_lost(ref, space)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `ref` | input | a frame ref of a record: 16 bytes |
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |

### Function does

- Asks for the frame to go out again.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_ref_lost`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `ref`, `space`.

## Function `quic_ref_stream`

Finds the stream of a frame ref.

### Signature

```
quic_ref_stream() -> stream
```

### Function does

- Returns the live stream of the ref when its generation matches, or 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_ref_stream`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the ref in x20, rbp, s2.

## Function `quic_on_ack`

Handles an ACK frame (RFC 9002 sections 5, 6 and 7).

### Signature

```
quic_on_ack(space, ranges, n, ack_delay)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |
| `ranges` | input | `n` pairs: smallest, largest; largest first |
| `n` | input | u64 |
| `ack_delay` | input | u64: microseconds |

### Function does

- Retires the records the ranges cover as acknowledged.
- Takes an RTT sample when the largest is new and an ack-eliciting packet is among them.
- Runs loss detection, then sets the timer.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 128 bytes on x86-64 (return address included), 128 bytes on ARM64, 144 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_ack`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `space`, `ranges`, `n`, `ack_delay`.

## Function `quic_rtt_sample`

Takes an RTT sample (RFC 9002 section 5.3).

### Signature

```
quic_rtt_sample(latest, ack_delay)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `latest` | input | u64: microseconds |
| `ack_delay` | input | u64: microseconds |

### Function does

- Caps ack_delay by max_ack_delay once the handshake is confirmed.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_rtt_sample`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `latest`, `ack_delay`.

## Function `quic_detect_loss`

Detects lost packets of a space (RFC 9002 section 6.1).

### Signature

```
quic_detect_loss(space)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |

### Function does

- Declares lost a record below the largest acknowledged when 3 later packets are acknowledged, or when it was sent 9/8 RTT ago.
- Sets the loss time from the others.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_detect_loss`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `space`.

## Function `quic_cc_acked`

Grows the congestion window for an acknowledged packet: slow start or congestion avoidance (RFC 9002 section 7).

### Signature

```
quic_cc_acked(sent_time, size)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `sent_time` | input | u64: microseconds |
| `size` | input | u64: bytes |

### Function does

- Does nothing inside recovery.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_cc_acked`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the connection in x19, rbx, s1.
- Argument order: `sent_time`, `size`.

## Function `quic_cc_lost`

Reacts to a lost packet.

### Signature

```
quic_cc_lost(sent_time)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `sent_time` | input | u64: microseconds |

### Function does

- Starts a congestion event when the packet was sent after the last recovery began.
- Halves ssthresh and the window, to at least 2 datagrams.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_cc_lost`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `sent_time`.

## Function `quic_set_loss_timer`

Sets the loss detection timer (RFC 9002 section 6.2).

### Signature

```
quic_set_loss_timer()
```

### Function does

- Takes the earliest loss time of a space.
- Else the probe timeout of the earliest space with ack-eliciting packets in flight; the Application space only once the handshake is confirmed.
- A client still in its handshake keeps a probe armed (RFC 9002 section 6.2.2.1).

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_set_loss_timer`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.

## Function `quic_on_loss_timer`

Handles the loss detection timer (RFC 9002 section 6.2.4).

### Signature

```
quic_on_loss_timer()
```

### Function does

- Runs loss detection in the space of the earliest loss time.
- Else asks the space of the earliest probe for an ack-eliciting probe, with its unacknowledged CRYPTO data again, and doubles the backoff.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_on_loss_timer`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.

## Function `quic_crypto_unacked`

Finds the first unacknowledged CRYPTO offset.

### Signature

```
quic_crypto_unacked(space) -> offset
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `space` | input | u64: 0 Initial, 1 Handshake, 2 Application |

### Function does

- Returns the smallest CRYPTO offset in a live record of the space, or the sent offset when there is none.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_crypto_unacked`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9; the scratch in x28, r14, s10; the connection in x19, rbx, s1.
- Argument order: `space`.

## Test vectors

- Scenarios
  - File: [tests/runner/runner.c](../../tests/runner/runner.c): loss and key_update_loss drop datagrams.

## Results

<!-- CI generates the tick table for each function here. -->
