/*
 * asm-quic for x86-64 (System V AMD64 psABI), AT&T syntax: QUIC version 1
 * with TLS 1.3 in the libp2p TLS profile, for an Ethereum consensus client.
 * Requirements: docs/reference/. Layouts: include/quic.inc, include/state.inc.
 *
 * One object: this file includes the other parts of the core. Hashes,
 * ciphers and keys go through asm-crypto. Baseline x86-64 instructions only.
 * The functions and their steps follow the ARM64 core one for one; frame.inc
 * maps its registers. Every call may change rax, rcx, rdx, rsi, rdi, r8-r11
 * and the xmm registers. Arguments: rdi, rsi, rdx, rcx, r8, r9, then r10 for
 * a seventh of a local function; results in rax, then rdx.
 */
.set ISA_X86_64, 1
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
    mov     %rdx, %rcx
    rep movsb
    mov     %rdi, %rax
    ret
END_FUNCTION quic_copy

/* quic_zero(dst, n) -> dst + n. */
LOCAL_FUNCTION quic_zero
    UNWIND_END_PROLOGUE
    mov     %rsi, %rcx
    xor     %eax, %eax
    rep stosb
    mov     %rdi, %rax
    ret
END_FUNCTION quic_zero

/* quic_equal(a, b, n) -> 1 when the n bytes at a and b are equal, else 0. */
LOCAL_FUNCTION quic_equal
    UNWIND_END_PROLOGUE
    xor     %r8d, %r8d
1:  test    %rdx, %rdx
    jz      2f
    movzbl  (%rdi), %ecx
    xorb    (%rsi), %cl
    or      %rcx, %r8
    inc     %rdi
    inc     %rsi
    dec     %rdx
    jmp     1b
2:  xor     %eax, %eax
    test    %r8, %r8
    sete    %al
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
