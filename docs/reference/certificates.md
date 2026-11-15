# Certificates

## Contents

### Functions

- [`quic_cert_verify`](#function-quic_cert_verify): checks a peer certificate.
- [`quic_cert_check`](#function-quic_cert_check): runs the checks of the libp2p TLS spec on a certificate.
- [`quic_der_next`](#function-quic_der_next): reads one DER element.
- [`quic_der_take`](#function-quic_der_take): reads one DER element of a given tag.
- [`quic_bytes_is`](#function-quic_bytes_is): compares two byte strings.
- [`quic_der_digits`](#function-quic_der_digits): reads ASCII digits.
- [`quic_der_time`](#function-quic_der_time): reads a certificate time.
- [`quic_der_int_get`](#function-quic_der_int_get): reads a DER INTEGER as 32 bytes.
- [`quic_der_sig_get`](#function-quic_der_sig_get): reads a DER ECDSA signature.
- [`quic_der_int_put`](#function-quic_der_int_put): writes a DER INTEGER.
- [`quic_der_sig_put`](#function-quic_der_sig_put): writes a DER ECDSA signature.
- [`quic_low_s`](#function-quic_low_s): normalises a secp256k1 signature.
- [`quic_cert_alg`](#function-quic_cert_alg): reads a signature AlgorithmIdentifier.
- [`quic_cert_spki`](#function-quic_cert_spki): reads the SubjectPublicKeyInfo of a certificate.
- [`quic_cert_exts`](#function-quic_cert_exts): reads the extensions of a certificate.
- [`quic_ext_understood`](#function-quic_ext_understood): tells whether a critical extension may be present.
- [`quic_pb_key`](#function-quic_pb_key): reads a PublicKey protobuf.
- [`quic_cert_selfsig`](#function-quic_cert_selfsig): checks the signature of a certificate with its own key.
- [`quic_host_verify`](#function-quic_host_verify): checks the host key signature of the libp2p extension.
- [`quic_der_wrap`](#function-quic_der_wrap): writes one DER element.
- [`quic_cert_build`](#function-quic_cert_build): builds our certificate.

### Types

- [`CertInfo`](#type-certinfo): what a checked certificate holds.

### Constants

- `QUIC_CERT_SCRATCH`: bytes of the scratch of `quic_cert_verify`: 2632.
- `QUIC_CERT_MAX`: the longest certificate a peer may send: 2048 bytes.
- `QUIC_CERT_P256`: kind 1: a P-256 key, ecdsa_secp256r1_sha256.
- `QUIC_CERT_ED25519`: kind 2: an Ed25519 key, ed25519.
- `QUIC_KEY_ED25519`: host key type 1.
- `QUIC_KEY_SECP256K1`: host key type 2.
- `QUIC_KEY_ECDSA`: host key type 3, checked only.

## Spec

- Document: [tls/tls.md](https://github.com/libp2p/specs/blob/c750236de43cd8b246a824b377dfdb26bae686db/tls/tls.md), libp2p/specs at commit c750236.
- Section: the certificate and its libp2p extension; DER as in RFC 5280.

## Function `quic_cert_verify`

Checks a peer certificate against the libp2p TLS spec at a Unix time.

### Signature

```
quic_cert_verify(cert, now, scratch, info) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `cert` | input | [`ByteList`](node.md#type-bytelist): the DER certificate |
| `now` | input | u64: Unix time in seconds |
| `scratch` | scratch | u64 size, then the work area |
| `info` | output | [`CertInfo`](#type-certinfo) |

### Returns

- `QUIC_OK`: The certificate meets the spec; `info` holds its key and host key.
- `QUIC_BUFFER_TOO_SMALL`: The scratch is below `QUIC_CERT_SCRATCH` bytes, or `info` below 224 bytes.
- `QUIC_INVALID_CERT`: A check of `quic_cert_check` fails.

### Function never

- Writes outside the scratch, `info` and its own stack.
- Makes an OS call.

### Limits

- Stack: 2128 bytes on x86-64 (return address included), 2208 bytes on ARM64, 2336 bytes on RISC-V, callees included, the most the test runner measured.

### ABI

- Role: L2.
- Symbol: `quic_cert_verify` (`_quic_cert_verify` on macOS).
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `cert`, `now`, `scratch`, `info`.

## Function `quic_cert_check`

Runs the checks of the libp2p TLS spec on a certificate.

### Signature

```
quic_cert_check(cert, len, now, info, work) -> status
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `cert` | input | `len` bytes of DER |
| `len` | input | u64 |
| `now` | input | u64: Unix time in seconds |
| `info` | output | [`CertInfo`](#type-certinfo) |
| `work` | scratch | 2624 bytes at a multiple of 8 |

### Returns

- `QUIC_OK`: Every check passes; `info` is filled.
- `QUIC_INVALID_CERT`: A check fails.

### Function does

- Checks for one Certificate with nothing after it.
- Checks that `now` lies inside the validity period.
- Checks for a P-256 or Ed25519 key that verifies the signature of the certificate.
- Checks that no unique ID is present.
- Checks for exactly one libp2p extension and no other critical extension.
- Checks the host key signature of the extension (`quic_host_verify`).

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_cert_check`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `cert`, `len`, `now`, `info`, `work`.

## Function `quic_der_next`

Reads one DER element with a one-byte tag and a length of at most 0xFFFF.

### Signature

```
quic_der_next(p, end, tlv) -> found
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the element |
| `end` | input | the end of the data |
| `tlv` | output | three u64: the tag, the start and the end of the content |

### Function does

- Returns 1 when the element ends by `end`, else 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_der_next`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `p`, `end`, `tlv`.

## Function `quic_der_take`

Reads one DER element of a given tag.

### Signature

```
quic_der_take(p, end, tlv, tag) -> end
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the element |
| `end` | input | the end of the data |
| `tlv` | output | three u64: the tag, the start and the end of the content |
| `tag` | input | u64 |

### Function does

- Returns the end of the element, or 0 when it is not one with that tag.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_der_take`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `p`, `end`, `tlv`, `tag`.

## Function `quic_bytes_is`

Compares two byte strings.

### Signature

```
quic_bytes_is(p, n, q, m) -> equal
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | `n` bytes |
| `n` | input | u64 |
| `q` | input | `m` bytes |
| `m` | input | u64 |

### Function does

- Returns 1 when n equals m and the bytes are equal, else 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_bytes_is`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `p`, `n`, `q`, `m`.

## Function `quic_der_digits`

Reads ASCII digits.

### Signature

```
quic_der_digits(p, n) -> number
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | `n` bytes |
| `n` | input | u64 |

### Function does

- Returns the number the digits give, or -1 when a byte is not a digit.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_der_digits`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `p`, `n`.

## Function `quic_der_time`

Reads a UTCTime or a GeneralizedTime as a Unix time in seconds (RFC 5280 section 4.1.2.5).

### Signature

```
quic_der_time(tag, p, n) -> time
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `tag` | input | u64: 0x17 or 0x18 |
| `p` | input | `n` bytes |
| `n` | input | u64 |

### Function does

- Takes UTCTime YYMMDDHHMMSSZ with years 1950 to 2049.
- Takes GeneralizedTime YYYYMMDDHHMMSSZ.
- Returns a signed time, or NONE when the time is malformed.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_der_time`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `tag`, `p`, `n`.

## Function `quic_der_int_get`

Reads a DER INTEGER as 32 bytes.

### Signature

```
quic_der_int_get(dst, p, end) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | 32 bytes big endian |
| `p` | input | the INTEGER |
| `end` | input | the end of the data |

### Function does

- Returns the position after the INTEGER, or 0 when it is not a positive INTEGER of at most 32 bytes of value.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_der_int_get`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `dst`, `p`, `end`.

## Function `quic_der_sig_get`

Reads a DER ECDSA signature.

### Signature

```
quic_der_sig_get(sig, p, n) -> found
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `sig` | output | 64 bytes: r then s, big endian |
| `p` | input | `n` bytes |
| `n` | input | u64 |

### Function does

- Returns 1 when the bytes are a SEQUENCE of two positive INTEGERs of at most 127 bytes, else 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_der_sig_get`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `sig`, `p`, `n`.

## Function `quic_der_int_put`

Writes a DER INTEGER.

### Signature

```
quic_der_int_put(dst, src) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | at most 35 bytes |
| `src` | input | 32 bytes big endian |

### Function does

- Writes the shortest positive INTEGER and returns `dst` after it.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_der_int_put`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `dst`, `src`.

## Function `quic_der_sig_put`

Writes a DER ECDSA signature.

### Signature

```
quic_der_sig_put(dst, sig) -> length
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | at most 72 bytes |
| `sig` | input | 64 bytes: r then s, big endian |

### Function does

- Writes the SEQUENCE of r and s and returns its length.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_der_sig_put`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `dst`, `sig`.

## Function `quic_low_s`

Replaces a secp256k1 s above n / 2 with n - s.

### Signature

```
quic_low_s(s)
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `s` | input and output | 32 bytes big endian |

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_low_s`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `s`.

## Function `quic_cert_alg`

Reads a signature AlgorithmIdentifier.

### Signature

```
quic_cert_alg(p, end) -> kind
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the AlgorithmIdentifier content |
| `end` | input | its end |

### Function does

- Returns `QUIC_CERT_P256` for ecdsa-with-SHA256 with no parameters, `QUIC_CERT_ED25519` for Ed25519, else 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_cert_alg`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the context of the check in x24, r13, s6.
- Argument order: `p`, `end`.

## Function `quic_cert_spki`

Reads the SubjectPublicKeyInfo of a certificate.

### Signature

```
quic_cert_spki(p, end) -> found
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the SubjectPublicKeyInfo content |
| `end` | input | its end |

### Function does

- Takes a P-256 key: id-ecPublicKey, prime256v1, 65 bytes from 0x04.
- Takes an Ed25519 key of 32 bytes.
- Returns 1 with the kind and key in the context, else 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_cert_spki`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the context of the check in x24, r13, s6.
- Argument order: `p`, `end`.

## Function `quic_cert_exts`

Reads the extensions of a certificate.

### Signature

```
quic_cert_exts(p, end) -> found
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | the Extensions content |
| `end` | input | its end |

### Function does

- Returns 1 when the content is a SEQUENCE of Extension elements with one libp2p extension (1.3.6.1.4.1.53594.1.1) and no other critical extension that is not understood, else 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_cert_exts`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the context of the check in x24, r13, s6.
- Argument order: `p`, `end`.

## Function `quic_ext_understood`

Tells whether a critical extension may be present.

### Signature

```
quic_ext_understood(oid, n) -> understood
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `oid` | input | `n` bytes |
| `n` | input | u64 |

### Function does

- Returns 1 for the extensions that the x509 parser of go-libp2p handles: 2.5.29.14, 15, 17, 19, 35 and 37.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_ext_understood`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `oid`, `n`.

## Function `quic_pb_key`

Reads a PublicKey protobuf.

### Signature

```
quic_pb_key(p, n) -> found
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `p` | input | `n` bytes |
| `n` | input | u64 |

### Function does

- Returns 1 when the bytes hold Type (field 1, a varint below 128) and Data (field 2, below 128 bytes), each once; they go to the context.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 8 bytes on x86-64 (return address included), 0 bytes on ARM64, 0 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_pb_key`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the context of the check in x24, r13, s6.
- Argument order: `p`, `n`.

## Function `quic_cert_selfsig`

Checks the signature of a certificate with its own key.

### Signature

```
quic_cert_selfsig() -> valid
```

### Function does

- Verifies ECDSA P-256 over the SHA-256 of tbsCertificate, or Ed25519 over tbsCertificate.
- Returns 1 when it verifies, else 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_cert_selfsig`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the work area in x23, r12, s5; the context of the check in x24, r13, s6.

## Function `quic_host_verify`

Checks the host key signature of the libp2p extension.

### Signature

```
quic_host_verify() -> valid
```

### Function does

- Takes a SignedKey whose PublicKey is Ed25519, Secp256k1 or ECDSA P-256.
- Verifies its signature of "libp2p-tls-handshake:" || the SubjectPublicKeyInfo.
- Uses Ed25519 over the message, or ECDSA in DER over its SHA-256.
- Takes a secp256k1 s above n / 2 as n - s.
- Returns 1 when it verifies, else 0.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_host_verify`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the work area in x23, r12, s5; the context of the check in x24, r13, s6.

## Function `quic_der_wrap`

Writes one DER element.

### Signature

```
quic_der_wrap(dst, tag, src, n) -> next
```

### Arguments

| Name | Role | Type |
|---|---|---|
| `dst` | output | n + 4 bytes at most |
| `tag` | input | u64 |
| `src` | input | `n` bytes, apart from `dst` |
| `n` | input | u64, below 65536 |

### Function does

- Writes the tag, the length and the bytes, and returns `dst` after them.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 96 bytes on x86-64 (return address included), 96 bytes on ARM64, 112 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_der_wrap`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Argument order: `dst`, `tag`, `src`, `n`.

## Function `quic_cert_build`

Builds our self-signed certificate in the state (libp2p TLS spec).

### Signature

```
quic_cert_build()
```

### Function does

- Uses the template of the test vectors of the spec: version 3, ecdsa-with-SHA256, issuer and subject O=libp2p.io serialNumber=1, valid from 1975 to 4096.
- Takes a random serial number.
- Takes the P-256 key of the state.
- Adds the libp2p extension: the host key protobuf and its signature of "libp2p-tls-handshake:" || the SubjectPublicKeyInfo.
- Signs with Ed25519, or with secp256k1 ECDSA over SHA-256 in DER.

### Function never

- Makes an OS call.

### Limits

- Stack of its own: 1504 bytes on x86-64 (return address included), 1504 bytes on ARM64, 1520 bytes on RISC-V.

### ABI

- Role: L0.
- Symbol: `quic_cert_build`, local to its object.
- Convention: the core ABI for each ISA (ARCHITECTURE.md section 6).
- Registers it reads, on ARM64, x86-64, RISC-V: the state in x27, r15, s9.

## Type `CertInfo`

What a checked certificate holds.

### Layout

| Offset | Field | Type | Meaning |
|---|---|---|---|
| 0 | `size` | u64 | Bytes the caller gives: at least 224 |
| 8 | `kind` | u64 | `QUIC_CERT_P256` or `QUIC_CERT_ED25519` |
| 16 | `key` | 72 bytes | The key of the certificate: 65 bytes 0x04, x, y, or 32 bytes; then zeros |
| 88 | `host_len` | u64 | Bytes of the host key |
| 96 | `host` | 128 bytes | The PublicKey protobuf of the host key |


## Test vectors

- libp2p TLS spec
  - File: libp2p-tls.bin, the 4 certificates of the spec, from [tests/generator/vectors.py](../../tests/generator/vectors.py).
- Generated certificates
  - File: cert-generated.bin, from [tests/generator/vectors.py](../../tests/generator/vectors.py).
  - Expected results: the checks of the spec written out in the generator.

## Results

<!-- CI generates the tick table for each function here. -->

### `quic_cert_verify`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_cert_check`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_der_next`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_der_take`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_bytes_is`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_der_digits`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_der_time`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_der_int_get`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_der_sig_get`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_der_int_put`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_der_sig_put`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_low_s`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_cert_alg`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_cert_spki`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_cert_exts`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_ext_understood`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_pb_key`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_cert_selfsig`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_host_verify`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_der_wrap`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |

### `quic_cert_build`

| ISA | Linux | Windows | macOS | `equal` |
|---|---|---|---|---|
| x86-64 | ✅ | ✅ | ✅ |  |
| ARM64 | ✅ | ✅ | ✅ |  |
| RISC-V | ✅ |  |  |  |
