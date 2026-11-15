/*
 * Packet protection of QUIC version 1 (RFC 9001 section 5): the HKDF-Expand-Label
 * of TLS 1.3, the Initial keys, AEAD_AES_128_GCM payload protection, AES header
 * protection, packet number decoding and the Retry integrity tag.
 */

/* ---------------------------------------------------------------- Key derivation */

/*
 * quic_expand_label(secret, label, label_len, context, context_len, length, out):
 * out = HKDF-Expand-Label(secret, label, context, length) of RFC 8446 section 7.1,
 * with the 32-byte secret as the PRK and "tls13 " before the label.
 * label_len, context_len and length are at most 32, 32 and 64.
 * x19 secret, x20 label, x21 label_len, x22 context, x23 context_len, x24 length, x25 out.
 */
.set EL_PRK, 0                          /* ByteList: 24 + 32 */
.set EL_INFO, 56                        /* ByteList: 24 + 80 */
.set EL_LENGTH, 160
.set EL_SCRATCH, 168                    /* HkdfScratch: 208 bytes */
.set EL_OKM, 376                        /* ByteList: 24 + 64 */
.set EL_FRAME, 464
LOCAL_FUNCTION quic_expand_label
    ENTER   0, EL_FRAME
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x22, x3
    mov     x23, x4
    mov     x24, x5
    mov     x25, x6
    mov     x10, #32
    BYTELIST sp, EL_PRK, 56, x10
    ldp     x9, x10, [x19]
    stp     x9, x10, [sp, #EL_PRK + 24]
    ldp     x9, x10, [x19, #16]
    stp     x9, x10, [sp, #EL_PRK + 40]
    add     x26, sp, #EL_INFO + 24          /* the HkdfLabel */
    lsr     x9, x24, #8
    strb    w9, [x26]
    strb    w24, [x26, #1]
    add     x9, x21, #6
    strb    w9, [x26, #2]
    MOV64   x9, 0x0000203331736C74          /* "tls13 " */
    stur    x9, [x26, #3]
    add     x0, x26, #9
    mov     x1, x20
    mov     x2, x21
    bl      quic_copy
    strb    w23, [x0], #1
    mov     x1, x22
    mov     x2, x23
    bl      quic_copy
    sub     x9, x0, x26
    BYTELIST sp, EL_INFO, 104, x9
    str     x24, [sp, #EL_LENGTH]
    mov     x9, #208
    str     x9, [sp, #EL_SCRATCH]
    mov     x9, #88
    str     x9, [sp, #EL_OKM]
    add     x0, sp, #EL_PRK
    add     x1, sp, #EL_INFO
    add     x2, sp, #EL_LENGTH
    add     x3, sp, #EL_SCRATCH
    add     x4, sp, #EL_OKM
    CALL_GLOBAL crypto_hkdf_expand
    mov     x0, x25
    add     x1, sp, #EL_OKM + 24
    mov     x2, x24
    bl      quic_copy
    LEAVE   0, EL_FRAME
END_FUNCTION quic_expand_label

/*
 * quic_derive_keys(secret, keys): the AEAD key, IV and header protection key of a
 * 32-byte traffic secret (RFC 9001 section 5.1), as PacketKeys.
 */
LOCAL_FUNCTION quic_derive_keys
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    mov     x0, x19
    adr     x1, 504f
    mov     x2, #8
    mov     x3, #0
    mov     x4, #0
    mov     x5, #16
    add     x6, x20, #QUIC_KEYS_KEY
    bl      quic_expand_label
    mov     x0, x19
    adr     x1, 505f
    mov     x2, #7
    mov     x3, #0
    mov     x4, #0
    mov     x5, #12
    add     x6, x20, #QUIC_KEYS_IV
    bl      quic_expand_label
    str     wzr, [x20, #QUIC_KEYS_IV + 12]
    mov     x0, x19
    adr     x1, 506f
    mov     x2, #7
    mov     x3, #0
    mov     x4, #0
    mov     x5, #16
    add     x6, x20, #QUIC_KEYS_HP
    bl      quic_expand_label
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
    mov     x19, x0
    mov     x20, x1
    ldr     x21, [x19, #QUIC_CID_LENGTH]
    mov     x0, #QUIC_INVALID_ARGUMENT
    cmp     x21, #QUIC_CID_MAX
    b.hi    9f
    mov     x0, x20
    mov     x1, x19
    bl      quic_initial_derive
    mov     x0, #QUIC_OK
9:  LEAVE   0
END_FUNCTION quic_initial_keys

/* quic_initial_derive(keys, dcid): the Initial keys of a checked ConnectionId. */
LOCAL_FUNCTION quic_initial_derive
    ENTER   0, IK_FRAME
    mov     x20, x0
    mov     x19, x1
    ldr     x21, [x19, #QUIC_CID_LENGTH]
    mov     x10, #20
    BYTELIST sp, IK_SALT, 48, x10
    add     x0, sp, #IK_SALT + 24
    adr     x1, 501f
    mov     x2, #20
    bl      quic_copy
    BYTELIST sp, IK_IKM, 48, x21
    add     x0, sp, #IK_IKM + 24
    add     x1, x19, #QUIC_CID_ID
    mov     x2, x21
    bl      quic_copy
    mov     x9, #128
    str     x9, [sp, #IK_SCRATCH]
    add     x0, sp, #IK_SALT
    add     x1, sp, #IK_IKM
    add     x2, sp, #IK_SCRATCH
    add     x3, sp, #IK_PRK
    CALL_GLOBAL crypto_hkdf_extract
    add     x0, sp, #IK_PRK
    adr     x1, 502f
    mov     x2, #9
    mov     x3, #0
    mov     x4, #0
    mov     x5, #32
    add     x6, sp, #IK_SECRET
    bl      quic_expand_label
    add     x0, sp, #IK_SECRET
    add     x1, x20, #QUIC_INITIAL_CLIENT
    bl      quic_derive_keys
    add     x0, sp, #IK_PRK
    adr     x1, 503f
    mov     x2, #9
    mov     x3, #0
    mov     x4, #0
    mov     x5, #32
    add     x6, sp, #IK_SECRET
    bl      quic_expand_label
    add     x0, sp, #IK_SECRET
    add     x1, x20, #QUIC_INITIAL_SERVER
    bl      quic_derive_keys
    LEAVE   0, IK_FRAME
END_FUNCTION quic_initial_derive

/* ---------------------------------------------------------------- Packet protection */

/*
 * quic_nonce(dst, keys, pn): the 12-byte AEAD nonce, the IV XOR the packet number
 * as a big-endian number at the end (RFC 9001 section 5.3), then 4 zero bytes. A leaf.
 */
LOCAL_FUNCTION quic_nonce
    UNWIND_END_PROLOGUE
    ldr     x3, [x1, #QUIC_KEYS_IV]
    ldr     w4, [x1, #QUIC_KEYS_IV + 8]
    rev     x5, x2
    eor     x3, x3, x5, lsl #32
    lsr     x6, x5, #32
    eor     w4, w4, w6
    str     x3, [x0]
    str     w4, [x0, #8]
    str     wzr, [x0, #12]
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
    mov     x19, x0
    mov     x20, x2
    ldr     x9, [x1]
    ldr     x10, [x1, #8]
    stp     x9, x10, [sp, #HM_COUNTER]
    mov     x10, #16
    BYTELIST sp, HM_IN, 40, x10
    stp     xzr, xzr, [sp, #HM_IN + 24]
    mov     x9, #40
    str     x9, [sp, #HM_OUT]
    mov     x0, x19
    add     x1, sp, #HM_COUNTER
    add     x2, sp, #HM_IN
    add     x3, sp, #HM_OUT
    CALL_GLOBAL crypto_aes128_ctr
    ldp     x9, x10, [sp, #HM_OUT + 24]
    stp     x9, x10, [x20]
    LEAVE   0, HM_FRAME
END_FUNCTION quic_hp_mask

/*
 * quic_pn_decode(truncated, bits, largest) -> the packet number closest to
 * largest + 1 that ends in the truncated bits (RFC 9000 appendix A.3).
 * largest is NONE before the first packet of a space. A leaf.
 */
LOCAL_FUNCTION quic_pn_decode
    UNWIND_END_PROLOGUE
    add     x3, x2, #1                      /* expected */
    mov     x4, #1
    lsl     x4, x4, x1                      /* window */
    lsr     x5, x4, #1                      /* half window */
    sub     x6, x4, #1
    bic     x7, x3, x6
    orr     x7, x7, x0                      /* candidate */
    sub     x8, x3, x5
    cmp     x7, x8
    b.gt    1f
    mov     x9, #1
    lsl     x9, x9, #62
    sub     x9, x9, x4
    cmp     x7, x9
    b.ge    1f
    add     x0, x7, x4
    ret
1:  add     x8, x3, x5
    cmp     x7, x8
    b.le    2f
    cmp     x7, x4
    b.lt    2f
    sub     x0, x7, x4
    ret
2:  mov     x0, x7
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
    ldrb    w9, [x0]
    ldrb    w10, [x3]
    tst     w9, #0x80
    mov     w11, #0x0F
    mov     w12, #0x1F
    csel    w11, w11, w12, ne
    and     w10, w10, w11
    eor     w9, w9, w10
    strb    w9, [x0]
    add     x4, x0, x1
    mov     x5, #0
1:  cmp     x5, x2
    b.hs    2f
    add     x6, x3, x5
    ldrb    w7, [x6, #1]
    ldrb    w8, [x4, x5]
    eor     w8, w8, w7
    strb    w8, [x4, x5]
    add     x5, x5, #1
    b       1b
2:  ret
END_FUNCTION quic_mask_header

/*
 * quic_seal(keys, buf, header_len, payload_len, pn, work) -> header_len +
 * payload_len + 16. buf holds the header, its packet number last, then the
 * frames: writes C || T after the header, then protects the header (RFC 9001
 * sections 5.3 and 5.4). The caller checks header_len <= W_HEADER_MAX,
 * payload_len + 16 <= W_SEALED_MAX, and payload_len + the packet number length >= 4.
 * x19 keys, x20 buf, x21 header_len, x22 payload_len, x23 pn, x24 work, x25 pn length, x26 pn offset.
 */
LOCAL_FUNCTION quic_seal
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x22, x3
    mov     x23, x4
    mov     x24, x5
    BYTELIST x24, W_AAD, 280, x21
    add     x0, x24, #W_AAD + 24
    mov     x1, x20
    mov     x2, x21
    bl      quic_copy
    BYTELIST x24, W_IN, 1544, x22
    add     x0, x24, #W_IN + 24
    add     x1, x20, x21
    mov     x2, x22
    bl      quic_copy
    mov     x9, #1544
    str     x9, [x24, #W_OUT]
    add     x0, x24, #W_NONCE
    mov     x1, x19
    mov     x2, x23
    bl      quic_nonce
    add     x0, x19, #QUIC_KEYS_KEY
    add     x1, x24, #W_NONCE
    add     x2, x24, #W_IN
    add     x3, x24, #W_AAD
    add     x4, x24, #W_OUT
    CALL_GLOBAL crypto_aes128_gcm_ae
    add     x0, x20, x21
    add     x1, x24, #W_OUT + 24
    add     x2, x22, #16
    bl      quic_copy
    ldrb    w9, [x20]
    and     x9, x9, #3
    add     x25, x9, #1
    sub     x26, x21, x25
    add     x0, x19, #QUIC_KEYS_HP
    add     x1, x20, x26
    add     x1, x1, #4
    add     x2, x24, #W_MASK
    bl      quic_hp_mask
    mov     x0, x20
    mov     x1, x26
    mov     x2, x25
    add     x3, x24, #W_MASK
    bl      quic_mask_header
    add     x0, x21, x22
    add     x0, x0, #16
    LEAVE   0
END_FUNCTION quic_seal

/*
 * quic_open(keys, buf, pn_offset, total, largest, work, result) -> status.
 * Removes the header protection of the packet of total bytes at buf in place,
 * decodes the packet number with largest, and decrypts the payload in place
 * after the header. result: the packet number, the header length and the
 * payload length, three u64.
 * Gives QUIC_INVALID_PACKET when the packet is too short for the sample or the
 * tag, or its header or sealed payload is too long for the work area, and
 * QUIC_DECRYPT_FAILED when the tag does not match. buf may change either way.
 * x19 keys, x20 buf, x21 pn offset then header length, x22 total then sealed length,
 * x23 largest then pn, x24 work, x25 result, x26 pn length.
 */
LOCAL_FUNCTION quic_open
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x22, x3
    mov     x23, x4
    mov     x24, x5
    mov     x25, x6
    mov     x0, #QUIC_INVALID_PACKET
    add     x9, x21, #20
    cmp     x9, x22
    b.hi    9f
    add     x0, x19, #QUIC_KEYS_HP
    add     x1, x20, x21
    add     x1, x1, #4
    add     x2, x24, #W_MASK
    bl      quic_hp_mask
    ldrb    w9, [x20]                       /* the first byte without protection */
    ldrb    w10, [x24, #W_MASK]
    tst     w9, #0x80
    mov     w11, #0x0F
    mov     w12, #0x1F
    csel    w11, w11, w12, ne
    and     w10, w10, w11
    eor     w9, w9, w10
    and     x9, x9, #3
    add     x26, x9, #1
    mov     x0, x20
    mov     x1, x21
    mov     x2, x26
    add     x3, x24, #W_MASK
    bl      quic_mask_header
    mov     x0, #0                          /* the truncated packet number */
    add     x9, x20, x21
    mov     x10, x26
1:  ldrb    w11, [x9], #1
    orr     x0, x11, x0, lsl #8
    subs    x10, x10, #1
    b.ne    1b
    lsl     x1, x26, #3
    mov     x2, x23
    bl      quic_pn_decode
    mov     x23, x0
    add     x21, x21, x26                   /* the header length */
    sub     x22, x22, x21                   /* the sealed length */
    mov     x0, #QUIC_INVALID_PACKET
    cmp     x22, #16
    b.lo    9f
    cmp     x21, #W_HEADER_MAX
    b.hi    9f
    cmp     x22, #W_SEALED_MAX
    b.hi    9f
    BYTELIST x24, W_AAD, 280, x21
    add     x0, x24, #W_AAD + 24
    mov     x1, x20
    mov     x2, x21
    bl      quic_copy
    BYTELIST x24, W_IN, 1544, x22
    add     x0, x24, #W_IN + 24
    add     x1, x20, x21
    mov     x2, x22
    bl      quic_copy
    mov     x9, #1544
    str     x9, [x24, #W_OUT]
    add     x0, x24, #W_NONCE
    mov     x1, x19
    mov     x2, x23
    bl      quic_nonce
    add     x0, x19, #QUIC_KEYS_KEY
    add     x1, x24, #W_NONCE
    add     x2, x24, #W_IN
    add     x3, x24, #W_AAD
    add     x4, x24, #W_OUT
    CALL_GLOBAL crypto_aes128_gcm_ad
    mov     x9, x0
    mov     x0, #QUIC_DECRYPT_FAILED
    cbnz    x9, 9f
    sub     x22, x22, #16
    add     x0, x20, x21
    add     x1, x24, #W_OUT + 24
    mov     x2, x22
    bl      quic_copy
    str     x23, [x25]
    str     x21, [x25, #8]
    str     x22, [x25, #16]
    mov     x0, #QUIC_OK
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

/* quic_packet_seal(keys, packet, scratch, sealed) -> status. */
FUNCTION quic_packet_seal
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x22, x3
    ldr     x9, [x21]
    MOV64   x10, QUIC_PACKET_SCRATCH
    mov     x0, #QUIC_BUFFER_TOO_SMALL
    cmp     x9, x10
    b.lo    9f
    mov     x0, #QUIC_INVALID_ARGUMENT
    ldr     x26, [x20, #QUIC_PP_SIZE]
    ldr     x23, [x20, #QUIC_PP_HEADER_COUNT]
    ldr     x24, [x20, #QUIC_PP_PAYLOAD_COUNT]
    ldr     x9, [x20, #QUIC_PP_HEADER_OFF]
    cmp     x9, #QUIC_PP_FIXED
    b.lo    9f
    cmp     x9, x26
    b.hi    9f
    sub     x10, x26, x9
    cmp     x23, x10
    b.hi    9f
    add     x25, x20, x9                    /* the header */
    ldr     x9, [x20, #QUIC_PP_PAYLOAD_OFF]
    cmp     x9, #QUIC_PP_FIXED
    b.lo    9f
    cmp     x9, x26
    b.hi    9f
    sub     x10, x26, x9
    cmp     x24, x10
    b.hi    9f
    cbz     x23, 9f
    cmp     x23, #W_HEADER_MAX
    b.hi    9f
    cmp     x24, #(W_SEALED_MAX - 16)
    b.hi    9f
    ldrb    w9, [x25]
    and     x9, x9, #3
    add     x9, x9, #1
    cmp     x9, x23
    b.hi    9f
    add     x9, x9, x24
    cmp     x9, #4
    b.lo    9f
    ldr     x9, [x22]
    add     x10, x23, x24
    add     x10, x10, #(QUIC_BL_FIXED + 16)
    mov     x0, #QUIC_BUFFER_TOO_SMALL
    cmp     x9, x10
    b.lo    9f
    add     x0, x21, #PS_BUF
    mov     x1, x25
    mov     x2, x23
    bl      quic_copy
    ldr     x1, [x20, #QUIC_PP_PAYLOAD_OFF]
    add     x1, x20, x1
    mov     x2, x24
    bl      quic_copy
    mov     x0, x19
    add     x1, x21, #PS_BUF
    mov     x2, x23
    mov     x3, x24
    ldr     x4, [x20, #QUIC_PP_NUMBER]
    add     x5, x21, #PS_WORK
    bl      quic_seal
    mov     x26, x0
    mov     x9, #QUIC_BL_FIXED
    str     x9, [x22, #QUIC_BL_OFFSET]
    str     x26, [x22, #QUIC_BL_COUNT]
    add     x0, x22, #QUIC_BL_FIXED
    add     x1, x21, #PS_BUF
    mov     x2, x26
    bl      quic_copy
    mov     x0, #QUIC_OK
9:  LEAVE   0
END_FUNCTION quic_packet_seal

/* quic_packet_open(keys, request, scratch, opened) -> status. */
FUNCTION quic_packet_open
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x22, x3
    ldr     x9, [x21]
    MOV64   x10, QUIC_PACKET_SCRATCH
    mov     x0, #QUIC_BUFFER_TOO_SMALL
    cmp     x9, x10
    b.lo    9f
    mov     x0, #QUIC_INVALID_ARGUMENT
    ldr     x26, [x20, #QUIC_OR_SIZE]
    ldr     x23, [x20, #QUIC_OR_PACKET_COUNT]
    ldr     x9, [x20, #QUIC_OR_PACKET_OFF]
    cmp     x9, #QUIC_OR_FIXED
    b.lo    9f
    cmp     x9, x26
    b.hi    9f
    sub     x10, x26, x9
    cmp     x23, x10
    b.hi    9f
    add     x24, x20, x9                    /* the packet */
    mov     x0, #QUIC_INVALID_PACKET
    cmp     x23, #(W_HEADER_MAX + W_SEALED_MAX)
    b.hi    9f
    ldr     x9, [x22]
    add     x10, x23, #(QUIC_OP_FIXED + 8)
    mov     x0, #QUIC_BUFFER_TOO_SMALL
    cmp     x9, x10
    b.lo    9f
    add     x0, x21, #PS_BUF
    mov     x1, x24
    mov     x2, x23
    bl      quic_copy
    mov     x0, x19
    add     x1, x21, #PS_BUF
    ldr     x2, [x20, #QUIC_OR_PN_OFFSET]
    mov     x3, x23
    ldr     x4, [x20, #QUIC_OR_LARGEST]
    add     x5, x21, #PS_WORK
    add     x6, x21, #PS_WORK
    add     x6, x6, #W_SIZE                 /* PS_RESULT */
    cmp     x2, x23
    mov     x0, #QUIC_INVALID_PACKET
    b.hs    9f
    mov     x0, x19
    bl      quic_open
    cbnz    x0, 9f
    ldr     x9, [x21, #PS_RESULT]
    str     x9, [x22, #QUIC_OP_NUMBER]
    ldr     x23, [x21, #PS_RESULT + 8]      /* header length */
    ldr     x24, [x21, #PS_RESULT + 16]     /* payload length */
    mov     x9, #QUIC_OP_FIXED
    str     x9, [x22, #QUIC_OP_HEADER_OFF]
    str     x23, [x22, #QUIC_OP_HEADER_COUNT]
    add     x25, x23, #7
    and     x25, x25, #~7
    add     x25, x25, #QUIC_OP_FIXED
    str     x25, [x22, #QUIC_OP_PAYLOAD_OFF]
    str     x24, [x22, #QUIC_OP_PAYLOAD_COUNT]
    add     x0, x22, #QUIC_OP_FIXED
    add     x1, x21, #PS_BUF
    mov     x2, x23
    bl      quic_copy
    add     x0, x22, x25
    add     x1, x21, #PS_BUF
    add     x1, x1, x23
    mov     x2, x24
    bl      quic_copy
    mov     x0, #QUIC_OK
9:  LEAVE   0
END_FUNCTION quic_packet_open

/*
 * quic_retry_tag(odcid, retry, scratch, tag) -> status: the Retry Integrity Tag
 * of a Retry packet without its tag (RFC 9001 section 5.8). The scratch holds
 * the pseudo-packet: its size, then a ByteList.
 */
.set RT_PLAIN, 0                        /* ByteList: empty */
.set RT_SEALED, 24                      /* ByteList: 24 + 16 */
.set RT_NONCE, 64
.set RT_FRAME, 80
FUNCTION quic_retry_tag
    ENTER   0, RT_FRAME
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x22, x3
    mov     x0, #QUIC_INVALID_ARGUMENT
    ldr     x23, [x19, #QUIC_CID_LENGTH]
    cmp     x23, #QUIC_CID_MAX
    b.hi    9f
    ldr     x24, [x20, #QUIC_BL_COUNT]
    cmp     x24, #QUIC_MAX_PACKET
    b.hi    9f
    add     x25, x24, x23
    add     x25, x25, #1                    /* the pseudo-packet length */
    ldr     x9, [x21]
    add     x10, x25, #(8 + QUIC_BL_FIXED)
    mov     x0, #QUIC_BUFFER_TOO_SMALL
    cmp     x9, x10
    b.lo    9f
    sub     x10, x9, #8
    BYTELIST x21, 8, 0, x25
    str     x10, [x21, #8]
    strb    w23, [x21, #(8 + QUIC_BL_FIXED)]
    add     x0, x21, #(8 + QUIC_BL_FIXED + 1)
    add     x1, x19, #QUIC_CID_ID
    mov     x2, x23
    bl      quic_copy
    ldr     x1, [x20, #QUIC_BL_OFFSET]
    add     x1, x20, x1
    mov     x2, x24
    bl      quic_copy
    mov     x10, #0
    BYTELIST sp, RT_PLAIN, 24, x10
    mov     x9, #40
    str     x9, [sp, #RT_SEALED]
    adr     x9, 508f
    ldr     x10, [x9]
    ldr     w11, [x9, #8]
    str     x10, [sp, #RT_NONCE]
    str     x11, [sp, #RT_NONCE + 8]
    adr     x0, 507f
    add     x1, sp, #RT_NONCE
    add     x2, sp, #RT_PLAIN
    add     x3, x21, #8
    add     x4, sp, #RT_SEALED
    CALL_GLOBAL crypto_aes128_gcm_ae
    ldp     x9, x10, [sp, #RT_SEALED + 24]
    str     x9, [x22]
    str     x10, [x22, #8]
    mov     x0, #QUIC_OK
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
