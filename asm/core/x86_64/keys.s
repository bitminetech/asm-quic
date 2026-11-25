/*
 * Packet protection of QUIC version 1 (RFC 9001 section 5): the HKDF-Expand-Label
 * of TLS 1.3, the Initial keys, AEAD_AES_128_GCM payload protection, AES header
 * protection, packet number decoding and the Retry integrity tag.
 */

/* ---------------------------------------------------------------- Key derivation */

/*
 * quic_expand_label(secret, label, label_len, context, context_len, length, out):
 * out = HKDF-Expand-Label(secret, label, context, length) of RFC 8446 section 7.1,
 * with the 32-byte secret as the PRK and "tls13 " before the label. out in r10.
 * label_len, context_len and length are at most 32, 32 and 64.
 * rbx secret, rbp label, r12 label_len, r13 context, X23 context_len, X24 length,
 * X25 out, X26 the HkdfLabel.
 */
.set EL_PRK, 0                          /* ByteList: 24 + 32 */
.set EL_INFO, 56                        /* ByteList: 24 + 80 */
.set EL_LENGTH, 160
.set EL_SCRATCH, 168                    /* HkdfScratch: 208 bytes */
.set EL_OKM, 376                        /* ByteList: 24 + 64 */
.set EL_FRAME, 464
LOCAL_FUNCTION quic_expand_label
    ENTER   0, EL_FRAME
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     %rcx, %r13
    mov     %r8, X23(%rsp)
    mov     %r9, X24(%rsp)
    mov     %r10, X25(%rsp)
    mov     $32, %eax
    BYTELIST %rsp, (32 + EL_PRK), 56, %rax
    mov     (%rbx), %rax
    mov     8(%rbx), %rcx
    mov     %rax, (32 + EL_PRK + 24)(%rsp)
    mov     %rcx, (32 + EL_PRK + 32)(%rsp)
    mov     16(%rbx), %rax
    mov     24(%rbx), %rcx
    mov     %rax, (32 + EL_PRK + 40)(%rsp)
    mov     %rcx, (32 + EL_PRK + 48)(%rsp)
    lea     (32 + EL_INFO + 24)(%rsp), %rax /* the HkdfLabel */
    mov     %rax, X26(%rsp)
    mov     X24(%rsp), %rcx
    mov     %ecx, %edx
    shr     $8, %edx
    movb    %dl, (%rax)
    movb    %cl, 1(%rax)
    lea     6(%r12), %edx
    movb    %dl, 2(%rax)
    movabs  $0x0000203331736C74, %rdx       /* "tls13 " */
    mov     %rdx, 3(%rax)
    lea     9(%rax), %rdi
    mov     %rbp, %rsi
    mov     %r12, %rdx
    call    quic_copy
    mov     X23(%rsp), %rcx
    movb    %cl, (%rax)
    lea     1(%rax), %rdi
    mov     %r13, %rsi
    mov     X23(%rsp), %rdx
    call    quic_copy
    sub     X26(%rsp), %rax
    BYTELIST %rsp, (32 + EL_INFO), 104, %rax
    mov     X24(%rsp), %rax
    mov     %rax, (32 + EL_LENGTH)(%rsp)
    movq    $208, (32 + EL_SCRATCH)(%rsp)
    movq    $88, (32 + EL_OKM)(%rsp)
    lea     (32 + EL_PRK)(%rsp), %rdi
    lea     (32 + EL_INFO)(%rsp), %rsi
    lea     (32 + EL_LENGTH)(%rsp), %rdx
    lea     (32 + EL_SCRATCH)(%rsp), %rcx
    lea     (32 + EL_OKM)(%rsp), %r8
    CALL_GLOBAL crypto_hkdf_expand
    mov     X25(%rsp), %rdi
    lea     (32 + EL_OKM + 24)(%rsp), %rsi
    mov     X24(%rsp), %rdx
    call    quic_copy
    LEAVE   0, EL_FRAME
END_FUNCTION quic_expand_label

/*
 * quic_derive_keys(secret, keys): the AEAD key, IV and header protection key of a
 * 32-byte traffic secret (RFC 9001 section 5.1), as PacketKeys.
 */
LOCAL_FUNCTION quic_derive_keys
    ENTER   0
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rbx, %rdi
    lea     504f(%rip), %rsi
    mov     $8, %edx
    xor     %ecx, %ecx
    xor     %r8d, %r8d
    mov     $16, %r9d
    lea     QUIC_KEYS_KEY(%rbp), %r10
    call    quic_expand_label
    mov     %rbx, %rdi
    lea     505f(%rip), %rsi
    mov     $7, %edx
    xor     %ecx, %ecx
    xor     %r8d, %r8d
    mov     $12, %r9d
    lea     QUIC_KEYS_IV(%rbp), %r10
    call    quic_expand_label
    movl    $0, (QUIC_KEYS_IV + 12)(%rbp)
    mov     %rbx, %rdi
    lea     506f(%rip), %rsi
    mov     $7, %edx
    xor     %ecx, %ecx
    xor     %r8d, %r8d
    mov     $16, %r9d
    lea     QUIC_KEYS_HP(%rbp), %r10
    call    quic_expand_label
    LEAVE   0
END_FUNCTION quic_derive_keys

/*
 * quic_initial_keys(dcid, keys) -> status: the client and server Initial keys of
 * a Destination Connection ID (RFC 9001 section 5.2).
 */
.set IK_SALT, 0                         /* ByteList: 24 + 20, then 4 */
.set IK_IKM, 48                         /* ByteList: 24 + 20, then 4 */
.set IK_PRK, 96                         /* the initial secret */
.set IK_SECRET, 128
.set IK_SCRATCH, 160                    /* HmacScratch: 128 bytes */
.set IK_FRAME, 288
FUNCTION quic_initial_keys
    ENTER   0
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     QUIC_CID_LENGTH(%rbx), %r12
    mov     $QUIC_INVALID_ARGUMENT, %eax
    cmp     $QUIC_CID_MAX, %r12
    ja      9f
    mov     %rbp, %rdi
    mov     %rbx, %rsi
    call    quic_initial_derive
    mov     $QUIC_OK, %eax
9:  LEAVE   0
END_FUNCTION quic_initial_keys

/* quic_initial_derive(keys, dcid): the Initial keys of a checked ConnectionId. */
LOCAL_FUNCTION quic_initial_derive
    ENTER   0, IK_FRAME
    mov     %rdi, %rbp
    mov     %rsi, %rbx
    mov     QUIC_CID_LENGTH(%rbx), %r12
    mov     $20, %eax
    BYTELIST %rsp, (32 + IK_SALT), 48, %rax
    lea     (32 + IK_SALT + 24)(%rsp), %rdi
    lea     501f(%rip), %rsi
    mov     $20, %edx
    call    quic_copy
    BYTELIST %rsp, (32 + IK_IKM), 48, %r12
    lea     (32 + IK_IKM + 24)(%rsp), %rdi
    lea     QUIC_CID_ID(%rbx), %rsi
    mov     %r12, %rdx
    call    quic_copy
    movq    $128, (32 + IK_SCRATCH)(%rsp)
    lea     (32 + IK_SALT)(%rsp), %rdi
    lea     (32 + IK_IKM)(%rsp), %rsi
    lea     (32 + IK_SCRATCH)(%rsp), %rdx
    lea     (32 + IK_PRK)(%rsp), %rcx
    CALL_GLOBAL crypto_hkdf_extract
    lea     (32 + IK_PRK)(%rsp), %rdi
    lea     502f(%rip), %rsi
    mov     $9, %edx
    xor     %ecx, %ecx
    xor     %r8d, %r8d
    mov     $32, %r9d
    lea     (32 + IK_SECRET)(%rsp), %r10
    call    quic_expand_label
    lea     (32 + IK_SECRET)(%rsp), %rdi
    lea     QUIC_INITIAL_CLIENT(%rbp), %rsi
    call    quic_derive_keys
    lea     (32 + IK_PRK)(%rsp), %rdi
    lea     503f(%rip), %rsi
    mov     $9, %edx
    xor     %ecx, %ecx
    xor     %r8d, %r8d
    mov     $32, %r9d
    lea     (32 + IK_SECRET)(%rsp), %r10
    call    quic_expand_label
    lea     (32 + IK_SECRET)(%rsp), %rdi
    lea     QUIC_INITIAL_SERVER(%rbp), %rsi
    call    quic_derive_keys
    LEAVE   0, IK_FRAME
END_FUNCTION quic_initial_derive

/* ---------------------------------------------------------------- Packet protection */

/*
 * quic_nonce(dst, keys, pn): the 12-byte AEAD nonce, the IV XOR the packet number
 * as a big-endian number at the end (RFC 9001 section 5.3), then 4 zero bytes. A leaf.
 */
LOCAL_FUNCTION quic_nonce
    UNWIND_END_PROLOGUE
    mov     QUIC_KEYS_IV(%rsi), %rax
    movl    (QUIC_KEYS_IV + 8)(%rsi), %ecx
    mov     %rdx, %r8
    bswap   %r8
    mov     %r8, %r9
    shl     $32, %r9
    xor     %r9, %rax
    shr     $32, %r8
    xor     %r8d, %ecx
    mov     %rax, (%rdi)
    movl    %ecx, 8(%rdi)
    movl    $0, 12(%rdi)
    ret
END_FUNCTION quic_nonce

/*
 * quic_hp_mask(hp, sample, mask): the 16 bytes AES-ECB(hp, sample) at mask, for
 * header protection (RFC 9001 section 5.4.3). sample may be at any address.
 */
.set HM_IN, 0                           /* ByteList: 24 + 16 zero bytes */
.set HM_OUT, 40                         /* ByteList: 24 + 16 */
.set HM_COUNTER, 80
.set HM_FRAME, 96
LOCAL_FUNCTION quic_hp_mask
    ENTER   0, HM_FRAME
    mov     %rdi, %rbx
    mov     %rdx, %rbp
    mov     (%rsi), %rax
    mov     8(%rsi), %rcx
    mov     %rax, (32 + HM_COUNTER)(%rsp)
    mov     %rcx, (32 + HM_COUNTER + 8)(%rsp)
    mov     $16, %eax
    BYTELIST %rsp, (32 + HM_IN), 40, %rax
    movq    $0, (32 + HM_IN + 24)(%rsp)
    movq    $0, (32 + HM_IN + 32)(%rsp)
    movq    $40, (32 + HM_OUT)(%rsp)
    mov     %rbx, %rdi
    lea     (32 + HM_COUNTER)(%rsp), %rsi
    lea     (32 + HM_IN)(%rsp), %rdx
    lea     (32 + HM_OUT)(%rsp), %rcx
    CALL_GLOBAL crypto_aes128_ctr
    mov     (32 + HM_OUT + 24)(%rsp), %rax
    mov     (32 + HM_OUT + 32)(%rsp), %rcx
    mov     %rax, (%rbp)
    mov     %rcx, 8(%rbp)
    LEAVE   0, HM_FRAME
END_FUNCTION quic_hp_mask

/*
 * quic_pn_decode(truncated, bits, largest) -> the packet number closest to
 * largest + 1 that ends in the truncated bits (RFC 9000 appendix A.3).
 * largest is NONE before the first packet of a space. A leaf.
 */
LOCAL_FUNCTION quic_pn_decode
    UNWIND_END_PROLOGUE
    lea     1(%rdx), %r8                    /* expected */
    mov     %rsi, %rcx
    mov     $1, %r9d
    shl     %cl, %r9                        /* window */
    mov     %r9, %r10
    shr     $1, %r10                        /* half window */
    lea     -1(%r9), %r11
    not     %r11
    and     %r8, %r11
    or      %rdi, %r11                      /* candidate */
    mov     %r8, %rax
    sub     %r10, %rax
    cmp     %rax, %r11
    jg      1f
    movabs  $(1 << 62), %rax
    sub     %r9, %rax
    cmp     %rax, %r11
    jge     1f
    lea     (%r11,%r9), %rax
    ret
1:  lea     (%r8,%r10), %rax
    cmp     %rax, %r11
    jle     2f
    cmp     %r9, %r11
    jl      2f
    mov     %r11, %rax
    sub     %r9, %rax
    ret
2:  mov     %r11, %rax
    ret
END_FUNCTION quic_pn_decode

/*
 * The work area of quic_seal and quic_open: W_SIZE bytes at a multiple of 8.
 */
.set W_AAD, 0                           /* ByteList: 24 + 256 */
.set W_IN, 280                          /* ByteList: 24 + 1520 */
.set W_OUT, 1824                        /* ByteList: 24 + 1520 */
.set W_NONCE, 3368
.set W_MASK, 3384
.set W_SIZE, 3400
.set W_HEADER_MAX, 256
.set W_SEALED_MAX, 1520

/*
 * quic_mask_header(buf, pn_offset, pn_len, mask): XORs the header protection mask
 * into the first byte (4 bits of a long header, 5 of a short one) and the packet
 * number bytes. A leaf.
 */
LOCAL_FUNCTION quic_mask_header
    UNWIND_END_PROLOGUE
    movzbl  (%rdi), %eax
    movzbl  (%rcx), %r8d
    mov     $0x1F, %r9d
    test    $0x80, %al
    jz      1f
    mov     $0x0F, %r9d
1:  and     %r9d, %r8d
    xor     %r8d, %eax
    movb    %al, (%rdi)
    lea     (%rdi,%rsi), %r10
    xor     %r11d, %r11d
2:  cmp     %rdx, %r11
    jae     3f
    movzbl  1(%rcx,%r11), %eax
    xorb    %al, (%r10,%r11)
    inc     %r11
    jmp     2b
3:  ret
END_FUNCTION quic_mask_header

/*
 * quic_seal(keys, buf, header_len, payload_len, pn, work) -> header_len +
 * payload_len + 16. buf holds the header, its packet number last, then the
 * frames: writes C || T after the header, then protects the header (RFC 9001
 * sections 5.3 and 5.4). The caller checks header_len <= W_HEADER_MAX,
 * payload_len + 16 <= W_SEALED_MAX, and payload_len + the packet number length >= 4.
 * rbx keys, rbp buf, r12 header_len, r13 payload_len, X23 pn, X24 work,
 * X25 pn length, X26 pn offset.
 */
LOCAL_FUNCTION quic_seal
    ENTER   0
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     %rcx, %r13
    mov     %r8, X23(%rsp)
    mov     %r9, X24(%rsp)
    BYTELIST %r9, W_AAD, 280, %r12
    lea     (W_AAD + 24)(%r9), %rdi
    mov     %rbp, %rsi
    mov     %r12, %rdx
    call    quic_copy
    mov     X24(%rsp), %rax
    BYTELIST %rax, W_IN, 1544, %r13
    lea     (W_IN + 24)(%rax), %rdi
    lea     (%rbp,%r12), %rsi
    mov     %r13, %rdx
    call    quic_copy
    mov     X24(%rsp), %rax
    movq    $1544, W_OUT(%rax)
    lea     W_NONCE(%rax), %rdi
    mov     %rbx, %rsi
    mov     X23(%rsp), %rdx
    call    quic_nonce
    mov     X24(%rsp), %rax
    lea     QUIC_KEYS_KEY(%rbx), %rdi
    lea     W_NONCE(%rax), %rsi
    lea     W_IN(%rax), %rdx
    lea     W_AAD(%rax), %rcx
    lea     W_OUT(%rax), %r8
    CALL_GLOBAL crypto_aes128_gcm_ae
    mov     X24(%rsp), %rax
    lea     (%rbp,%r12), %rdi
    lea     (W_OUT + 24)(%rax), %rsi
    lea     16(%r13), %rdx
    call    quic_copy
    movzbl  (%rbp), %eax
    and     $3, %eax
    inc     %eax
    mov     %rax, X25(%rsp)
    mov     %r12, %rcx
    sub     %rax, %rcx
    mov     %rcx, X26(%rsp)
    lea     QUIC_KEYS_HP(%rbx), %rdi
    lea     4(%rbp,%rcx), %rsi
    mov     X24(%rsp), %rdx
    add     $W_MASK, %rdx
    call    quic_hp_mask
    mov     %rbp, %rdi
    mov     X26(%rsp), %rsi
    mov     X25(%rsp), %rdx
    mov     X24(%rsp), %rcx
    add     $W_MASK, %rcx
    call    quic_mask_header
    lea     16(%r12,%r13), %rax
    LEAVE   0
END_FUNCTION quic_seal

/*
 * quic_unprotect(keys, buf, pn_offset, total, work) -> status.
 * Removes the header protection of the packet of total bytes at buf in place:
 * its first byte and its packet number. Gives QUIC_INVALID_PACKET, with buf
 * unchanged, when the packet is too short for the sample.
 * rbx keys, rbp buf, r12 pn offset, r13 total, X24 work, X26 pn length.
 */
LOCAL_FUNCTION quic_unprotect
    ENTER   0
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     %rcx, %r13
    mov     %r8, X24(%rsp)
    mov     $QUIC_INVALID_PACKET, %eax
    lea     20(%r12), %rcx
    cmp     %r13, %rcx
    ja      9f
    lea     QUIC_KEYS_HP(%rbx), %rdi
    lea     4(%rbp,%r12), %rsi
    mov     X24(%rsp), %rdx
    add     $W_MASK, %rdx
    call    quic_hp_mask
    movzbl  (%rbp), %eax                    /* the first byte without protection */
    mov     X24(%rsp), %rcx
    movzbl  W_MASK(%rcx), %ecx
    mov     $0x1F, %edx
    test    $0x80, %al
    jz      1f
    mov     $0x0F, %edx
1:  and     %edx, %ecx
    xor     %ecx, %eax
    and     $3, %eax
    inc     %eax
    mov     %rax, X26(%rsp)
    mov     %rbp, %rdi
    mov     %r12, %rsi
    mov     %rax, %rdx
    mov     X24(%rsp), %rcx
    add     $W_MASK, %rcx
    call    quic_mask_header
    mov     $QUIC_OK, %eax
9:  LEAVE   0
END_FUNCTION quic_unprotect

/*
 * quic_open(keys, buf, pn_offset, total, largest, work, result) -> status; result
 * in r10. The packet of total bytes at buf, its header protection removed by
 * quic_unprotect: decodes the packet number with largest, and decrypts the
 * payload in place after the header. result: the packet number, the header
 * length and the payload length, three u64.
 * Gives QUIC_INVALID_PACKET when the packet is too short for the sample or the
 * tag, or its header or sealed payload is too long for the work area, and
 * QUIC_DECRYPT_FAILED when the tag does not match. buf changes only on QUIC_OK.
 * rbx keys, rbp buf, r12 pn offset then header length, r13 total then sealed
 * length, X23 largest then pn, X24 work, X25 result, X26 pn length.
 */
LOCAL_FUNCTION quic_open
    ENTER   0
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     %rcx, %r13
    mov     %r8, X23(%rsp)
    mov     %r9, X24(%rsp)
    mov     %r10, X25(%rsp)
    mov     $QUIC_INVALID_PACKET, %eax
    lea     20(%r12), %rcx
    cmp     %r13, %rcx
    ja      9f
    movzbl  (%rbp), %eax                    /* the packet number length, from the first byte */
    and     $3, %eax
    inc     %eax
    mov     %rax, X26(%rsp)
    xor     %edi, %edi                      /* the truncated packet number */
    lea     (%rbp,%r12), %rsi
    mov     X26(%rsp), %rcx
2:  shl     $8, %rdi
    movzbl  (%rsi), %eax
    or      %rax, %rdi
    inc     %rsi
    dec     %rcx
    jnz     2b
    mov     X26(%rsp), %rsi
    shl     $3, %rsi
    mov     X23(%rsp), %rdx
    call    quic_pn_decode
    mov     %rax, X23(%rsp)
    add     X26(%rsp), %r12                 /* the header length */
    sub     %r12, %r13                      /* the sealed length */
    mov     $QUIC_INVALID_PACKET, %eax
    cmp     $16, %r13
    jb      9f
    cmp     $W_HEADER_MAX, %r12
    ja      9f
    cmp     $W_SEALED_MAX, %r13
    ja      9f
    mov     X24(%rsp), %rax
    BYTELIST %rax, W_AAD, 280, %r12
    lea     (W_AAD + 24)(%rax), %rdi
    mov     %rbp, %rsi
    mov     %r12, %rdx
    call    quic_copy
    mov     X24(%rsp), %rax
    BYTELIST %rax, W_IN, 1544, %r13
    lea     (W_IN + 24)(%rax), %rdi
    lea     (%rbp,%r12), %rsi
    mov     %r13, %rdx
    call    quic_copy
    mov     X24(%rsp), %rax
    movq    $1544, W_OUT(%rax)
    lea     W_NONCE(%rax), %rdi
    mov     %rbx, %rsi
    mov     X23(%rsp), %rdx
    call    quic_nonce
    mov     X24(%rsp), %rax
    lea     QUIC_KEYS_KEY(%rbx), %rdi
    lea     W_NONCE(%rax), %rsi
    lea     W_IN(%rax), %rdx
    lea     W_AAD(%rax), %rcx
    lea     W_OUT(%rax), %r8
    CALL_GLOBAL crypto_aes128_gcm_ad
    mov     %rax, %rcx
    mov     $QUIC_DECRYPT_FAILED, %eax
    test    %rcx, %rcx
    jnz     9f
    sub     $16, %r13
    lea     (%rbp,%r12), %rdi
    mov     X24(%rsp), %rsi
    add     $(W_OUT + 24), %rsi
    mov     %r13, %rdx
    call    quic_copy
    mov     X25(%rsp), %rax
    mov     X23(%rsp), %rcx
    mov     %rcx, (%rax)
    mov     %r12, 8(%rax)
    mov     %r13, 16(%rax)
    mov     $QUIC_OK, %eax
9:  LEAVE   0
END_FUNCTION quic_open

/* ---------------------------------------------------------------- Entry points for vectors */

/*
 * The scratch of quic_packet_seal and quic_packet_open: the size, the packet
 * at 8 (W_HEADER_MAX + W_SEALED_MAX bytes), then the work area.
 */
.set PS_BUF, 8
.set PS_WORK, PS_BUF + W_HEADER_MAX + W_SEALED_MAX
.set PS_RESULT, PS_WORK + W_SIZE        /* 24 bytes */
.set PS_NEED, PS_RESULT + 24
.if PS_NEED > QUIC_PACKET_SCRATCH
.error "QUIC_PACKET_SCRATCH is below the scratch layout of quic_packet_seal"
.endif

/* quic_packet_seal(keys, packet, scratch, sealed) -> status. X23 header bytes, X24 payload bytes, X26 the size. */
FUNCTION quic_packet_seal
    ENTER   0
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     %rcx, %r13
    mov     $QUIC_BUFFER_TOO_SMALL, %eax
    cmpq    $QUIC_PACKET_SCRATCH, (%r12)
    jb      9f
    mov     $QUIC_INVALID_ARGUMENT, %eax
    mov     QUIC_PP_SIZE(%rbp), %r8
    mov     QUIC_PP_HEADER_COUNT(%rbp), %r9
    mov     QUIC_PP_PAYLOAD_COUNT(%rbp), %r10
    mov     QUIC_PP_HEADER_OFF(%rbp), %rcx
    cmp     $QUIC_PP_FIXED, %rcx
    jb      9f
    cmp     %r8, %rcx
    ja      9f
    mov     %r8, %rdx
    sub     %rcx, %rdx
    cmp     %rdx, %r9
    ja      9f
    lea     (%rbp,%rcx), %r11               /* the header */
    mov     QUIC_PP_PAYLOAD_OFF(%rbp), %rcx
    cmp     $QUIC_PP_FIXED, %rcx
    jb      9f
    cmp     %r8, %rcx
    ja      9f
    mov     %r8, %rdx
    sub     %rcx, %rdx
    cmp     %rdx, %r10
    ja      9f
    test    %r9, %r9
    jz      9f
    cmp     $W_HEADER_MAX, %r9
    ja      9f
    cmp     $(W_SEALED_MAX - 16), %r10
    ja      9f
    movzbl  (%r11), %ecx
    and     $3, %ecx
    inc     %ecx
    cmp     %r9, %rcx
    ja      9f
    add     %r10, %rcx
    cmp     $4, %rcx
    jb      9f
    lea     (QUIC_BL_FIXED + 16)(%r9,%r10), %rdx
    mov     $QUIC_BUFFER_TOO_SMALL, %eax
    cmp     %rdx, (%r13)
    jb      9f
    mov     %r9, X23(%rsp)
    mov     %r10, X24(%rsp)
    lea     PS_BUF(%r12), %rdi
    mov     %r11, %rsi
    mov     %r9, %rdx
    call    quic_copy
    mov     QUIC_PP_PAYLOAD_OFF(%rbp), %rsi
    add     %rbp, %rsi
    mov     %rax, %rdi
    mov     X24(%rsp), %rdx
    call    quic_copy
    mov     %rbx, %rdi
    lea     PS_BUF(%r12), %rsi
    mov     X23(%rsp), %rdx
    mov     X24(%rsp), %rcx
    mov     QUIC_PP_NUMBER(%rbp), %r8
    lea     PS_WORK(%r12), %r9
    call    quic_seal
    mov     %rax, X26(%rsp)
    movq    $QUIC_BL_FIXED, QUIC_BL_OFFSET(%r13)
    mov     %rax, QUIC_BL_COUNT(%r13)
    lea     QUIC_BL_FIXED(%r13), %rdi
    lea     PS_BUF(%r12), %rsi
    mov     X26(%rsp), %rdx
    call    quic_copy
    mov     $QUIC_OK, %eax
9:  LEAVE   0
END_FUNCTION quic_packet_seal

/* quic_packet_open(keys, request, scratch, opened) -> status. X23 header bytes, X24 payload bytes, X25 payload offset. */
FUNCTION quic_packet_open
    ENTER   0
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     %rcx, %r13
    mov     $QUIC_BUFFER_TOO_SMALL, %eax
    cmpq    $QUIC_PACKET_SCRATCH, (%r12)
    jb      9f
    mov     $QUIC_INVALID_ARGUMENT, %eax
    mov     QUIC_OR_SIZE(%rbp), %r8
    mov     QUIC_OR_PACKET_COUNT(%rbp), %r9
    mov     QUIC_OR_PACKET_OFF(%rbp), %rcx
    cmp     $QUIC_OR_FIXED, %rcx
    jb      9f
    cmp     %r8, %rcx
    ja      9f
    mov     %r8, %rdx
    sub     %rcx, %rdx
    cmp     %rdx, %r9
    ja      9f
    lea     (%rbp,%rcx), %rsi               /* the packet */
    mov     $QUIC_INVALID_PACKET, %eax
    cmp     $(W_HEADER_MAX + W_SEALED_MAX), %r9
    ja      9f
    lea     (QUIC_OP_FIXED + 8)(%r9), %rdx
    mov     $QUIC_BUFFER_TOO_SMALL, %eax
    cmp     %rdx, (%r13)
    jb      9f
    mov     %r9, X23(%rsp)
    lea     PS_BUF(%r12), %rdi
    mov     %r9, %rdx
    call    quic_copy
    mov     QUIC_OR_PN_OFFSET(%rbp), %rdx
    mov     X23(%rsp), %rcx
    mov     $QUIC_INVALID_PACKET, %eax
    cmp     %rcx, %rdx
    jae     9f
    mov     %rbx, %rdi
    lea     PS_BUF(%r12), %rsi
    lea     PS_WORK(%r12), %r8
    call    quic_unprotect
    test    %rax, %rax
    jnz     9f
    mov     %rbx, %rdi
    lea     PS_BUF(%r12), %rsi
    mov     QUIC_OR_PN_OFFSET(%rbp), %rdx
    mov     X23(%rsp), %rcx
    mov     QUIC_OR_LARGEST(%rbp), %r8
    lea     PS_WORK(%r12), %r9
    lea     PS_RESULT(%r12), %r10
    call    quic_open
    test    %rax, %rax
    jnz     9f
    mov     PS_RESULT(%r12), %rax
    mov     %rax, QUIC_OP_NUMBER(%r13)
    mov     (PS_RESULT + 8)(%r12), %rax     /* header length */
    mov     %rax, X23(%rsp)
    mov     (PS_RESULT + 16)(%r12), %rcx    /* payload length */
    mov     %rcx, X24(%rsp)
    movq    $QUIC_OP_FIXED, QUIC_OP_HEADER_OFF(%r13)
    mov     %rax, QUIC_OP_HEADER_COUNT(%r13)
    lea     7(%rax), %rdx
    and     $-8, %rdx
    add     $QUIC_OP_FIXED, %rdx
    mov     %rdx, X25(%rsp)
    mov     %rdx, QUIC_OP_PAYLOAD_OFF(%r13)
    mov     %rcx, QUIC_OP_PAYLOAD_COUNT(%r13)
    lea     QUIC_OP_FIXED(%r13), %rdi
    lea     PS_BUF(%r12), %rsi
    mov     X23(%rsp), %rdx
    call    quic_copy
    mov     X25(%rsp), %rdi
    add     %r13, %rdi
    lea     PS_BUF(%r12), %rsi
    add     X23(%rsp), %rsi
    mov     X24(%rsp), %rdx
    call    quic_copy
    mov     $QUIC_OK, %eax
9:  LEAVE   0
END_FUNCTION quic_packet_open

/*
 * quic_retry_tag(odcid, retry, scratch, tag) -> status: the Retry Integrity Tag
 * of a Retry packet without its tag (RFC 9001 section 5.8). The scratch holds
 * the pseudo-packet: its size, then a ByteList. X23 the ODCID length, X24 the
 * Retry length.
 */
.set RT_PLAIN, 0                        /* ByteList: empty */
.set RT_SEALED, 24                      /* ByteList: 24 + 16 */
.set RT_NONCE, 64
.set RT_FRAME, 80
FUNCTION quic_retry_tag
    ENTER   0, RT_FRAME
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     %rcx, %r13
    mov     $QUIC_INVALID_ARGUMENT, %eax
    mov     QUIC_CID_LENGTH(%rbx), %r8
    cmp     $QUIC_CID_MAX, %r8
    ja      9f
    mov     QUIC_BL_COUNT(%rbp), %r9
    cmp     $QUIC_MAX_PACKET, %r9
    ja      9f
    lea     1(%r8,%r9), %r10                /* the pseudo-packet length */
    lea     (8 + QUIC_BL_FIXED)(%r10), %rdx
    mov     $QUIC_BUFFER_TOO_SMALL, %eax
    cmp     %rdx, (%r12)
    jb      9f
    mov     %r8, X23(%rsp)
    mov     %r9, X24(%rsp)
    mov     (%r12), %rcx
    sub     $8, %rcx
    mov     %r10, (8 + 16)(%r12)
    mov     %rcx, 8(%r12)
    movq    $QUIC_BL_FIXED, (8 + 8)(%r12)
    movb    %r8b, (8 + QUIC_BL_FIXED)(%r12)
    lea     (8 + QUIC_BL_FIXED + 1)(%r12), %rdi
    lea     QUIC_CID_ID(%rbx), %rsi
    mov     %r8, %rdx
    call    quic_copy
    mov     QUIC_BL_OFFSET(%rbp), %rsi
    add     %rbp, %rsi
    mov     %rax, %rdi
    mov     X24(%rsp), %rdx
    call    quic_copy
    xor     %eax, %eax
    BYTELIST %rsp, (32 + RT_PLAIN), 24, %rax
    movq    $40, (32 + RT_SEALED)(%rsp)
    lea     508f(%rip), %rax
    mov     (%rax), %rcx
    movl    8(%rax), %edx
    mov     %rcx, (32 + RT_NONCE)(%rsp)
    mov     %rdx, (32 + RT_NONCE + 8)(%rsp)
    lea     507f(%rip), %rdi
    lea     (32 + RT_NONCE)(%rsp), %rsi
    lea     (32 + RT_PLAIN)(%rsp), %rdx
    lea     8(%r12), %rcx
    lea     (32 + RT_SEALED)(%rsp), %r8
    CALL_GLOBAL crypto_aes128_gcm_ae
    mov     (32 + RT_SEALED + 24)(%rsp), %rax
    mov     (32 + RT_SEALED + 32)(%rsp), %rcx
    mov     %rax, (%r13)
    mov     %rcx, 8(%r13)
    mov     $QUIC_OK, %eax
9:  LEAVE   0, RT_FRAME
END_FUNCTION quic_retry_tag

/* ---------------------------------------------------------------- Constants of RFC 9001 */

    .p2align 3
/* initial_salt of QUIC version 1 (RFC 9001 section 5.2). */
501:
    .byte   0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17
    .byte   0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
502:
    .ascii  "client in"
503:
    .ascii  "server in"
504:
    .ascii  "quic key"
505:
    .ascii  "quic iv"
506:
    .ascii  "quic hp"
    .p2align 3
/* The Retry key and nonce of QUIC version 1 (RFC 9001 section 5.8). */
507:
    .byte   0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a
    .byte   0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e
508:
    .byte   0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2
    .byte   0x23, 0x98, 0x25, 0xbb, 0, 0, 0, 0
    .p2align 2
