/*
 * asm-quic for ARM64 (AAPCS64): QUIC version 1 with TLS 1.3 in the libp2p
 * TLS profile, for an Ethereum consensus client.
 * Requirements: docs/reference/. Layouts: include/quic.inc.
 *
 * One object: this file includes the other parts of the core. Hashes,
 * ciphers and keys go through asm-crypto.
 */
.set ISA_ARM64, 1
.include "crypto.inc"
.include "hmac.inc"
.include "aes.inc"
.include "quic.inc"
.include "state.inc"
.include "platform.inc"
.include "frame.inc"

/* ---------------------------------------------------------------- Byte helpers */

/* quic_copy(dst, src, n) -> dst + n. dst is below src, or the regions do not overlap. */
LOCAL_FUNCTION quic_copy
    UNWIND_END_PROLOGUE
1:  cmp     x2, #8
    b.lo    2f
    ldr     x3, [x1], #8
    str     x3, [x0], #8
    sub     x2, x2, #8
    b       1b
2:  cbz     x2, 3f
    ldrb    w3, [x1], #1
    strb    w3, [x0], #1
    sub     x2, x2, #1
    b       2b
3:  ret
END_FUNCTION quic_copy

/* quic_zero(dst, n) -> dst + n. */
LOCAL_FUNCTION quic_zero
    UNWIND_END_PROLOGUE
1:  cmp     x1, #8
    b.lo    2f
    str     xzr, [x0], #8
    sub     x1, x1, #8
    b       1b
2:  cbz     x1, 3f
    strb    wzr, [x0], #1
    sub     x1, x1, #1
    b       2b
3:  ret
END_FUNCTION quic_zero

/* quic_equal(a, b, n) -> 1 when the n bytes at a and b are equal, else 0. Reads all n bytes. */
LOCAL_FUNCTION quic_equal
    UNWIND_END_PROLOGUE
    mov     x4, #0
1:  cbz     x2, 2f
    ldrb    w3, [x0], #1
    ldrb    w5, [x1], #1
    eor     w3, w3, w5
    orr     x4, x4, x3
    sub     x2, x2, #1
    b       1b
2:  cmp     x4, #0
    cset    x0, eq
    ret
END_FUNCTION quic_equal

.include "util.s"
.include "keys.s"
.include "cert.s"
.include "tls.s"
.include "conn.s"
.include "recovery.s"
.include "stream.s"
.include "recv.s"
.include "send.s"
.include "node.s"
