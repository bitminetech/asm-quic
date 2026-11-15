/*
 * asm-quic for RISC-V (RISC-V ELF psABI, LP64D): QUIC version 1 with TLS 1.3
 * in the libp2p TLS profile, for an Ethereum consensus client.
 * Requirements: docs/reference/. Layouts: include/quic.inc, include/state.inc.
 *
 * One object: this file includes the other parts of the core. Hashes,
 * ciphers and keys go through asm-crypto. Baseline RV64GC instructions
 * only. The functions and their steps follow the ARM64 core one for one;
 * frame.inc maps its registers. 8-byte loads and stores only touch 8-byte
 * aligned addresses.
 */
.set ISA_RISCV64, 1
.include "crypto.inc"
.include "hmac.inc"
.include "aes.inc"
.include "quic.inc"
.include "state.inc"
.include "platform.inc"
.include "frame.inc"

/* ---------------------------------------------------------------- Byte helpers */

/*
 * quic_copy(dst, src, n) -> dst + n. dst is below src, or the regions do not
 * overlap. 8 bytes at a time when dst and src are both 8-byte aligned.
 */
LOCAL_FUNCTION quic_copy
    UNWIND_END_PROLOGUE
    or      a3, a0, a1
    andi    a3, a3, 7
    bnez    a3, 2f
    li      a4, 8
1:  bltu    a2, a4, 2f
    ld      a5, 0(a1)
    sd      a5, 0(a0)
    addi    a0, a0, 8
    addi    a1, a1, 8
    addi    a2, a2, -8
    j       1b
2:  beqz    a2, 3f
    lbu     a5, 0(a1)
    sb      a5, 0(a0)
    addi    a0, a0, 1
    addi    a1, a1, 1
    addi    a2, a2, -1
    j       2b
3:  ret
END_FUNCTION quic_copy

/* quic_zero(dst, n) -> dst + n. */
LOCAL_FUNCTION quic_zero
    UNWIND_END_PROLOGUE
    andi    a2, a0, 7
    bnez    a2, 2f
    li      a3, 8
1:  bltu    a1, a3, 2f
    sd      zero, 0(a0)
    addi    a0, a0, 8
    addi    a1, a1, -8
    j       1b
2:  beqz    a1, 3f
    sb      zero, 0(a0)
    addi    a0, a0, 1
    addi    a1, a1, -1
    j       2b
3:  ret
END_FUNCTION quic_zero

/* quic_equal(a, b, n) -> 1 when the n bytes at a and b are equal, else 0. */
LOCAL_FUNCTION quic_equal
    UNWIND_END_PROLOGUE
    li      a4, 0
1:  beqz    a2, 2f
    lbu     a3, 0(a0)
    lbu     a5, 0(a1)
    xor     a3, a3, a5
    or      a4, a4, a3
    addi    a0, a0, 1
    addi    a1, a1, 1
    addi    a2, a2, -1
    j       1b
2:  seqz    a0, a4
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
