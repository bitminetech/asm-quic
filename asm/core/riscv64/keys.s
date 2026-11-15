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
 * s1 secret, s2 label, s3 label_len, s4 context, s5 context_len, s6 length, s7 out, s8 the HkdfLabel.
 */
.set EL_PRK, 0                          /* ByteList: 24 + 32 */
.set EL_INFO, 56                        /* ByteList: 24 + 80 */
.set EL_LENGTH, 160
.set EL_SCRATCH, 168                    /* HkdfScratch: 208 bytes */
.set EL_OKM, 376                        /* ByteList: 24 + 64 */
.set EL_FRAME, 464
LOCAL_FUNCTION quic_expand_label
    ENTER   0, EL_FRAME
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    mv      s4, a3
    mv      s5, a4
    mv      s6, a5
    mv      s7, a6
    li      t0, 32
    BYTELIST sp, (FL + EL_PRK), 56, t0
    addi    a0, sp, (FL + EL_PRK + 24)
    mv      a1, s1
    li      a2, 32
    call    quic_copy
    addi    s8, sp, (FL + EL_INFO + 24)     # the HkdfLabel
    srli    t0, s6, 8
    sb      t0, 0(s8)
    sb      s6, 1(s8)
    addi    t0, s3, 6
    sb      t0, 2(s8)
    li      t0, 0x74                        # "tls13 "
    sb      t0, 3(s8)
    li      t0, 0x6C
    sb      t0, 4(s8)
    li      t0, 0x73
    sb      t0, 5(s8)
    li      t0, 0x31
    sb      t0, 6(s8)
    li      t0, 0x33
    sb      t0, 7(s8)
    li      t0, 0x20
    sb      t0, 8(s8)
    addi    a0, s8, 9
    mv      a1, s2
    mv      a2, s3
    call    quic_copy
    sb      s5, 0(a0)
    addi    a0, a0, 1
    mv      a1, s4
    mv      a2, s5
    call    quic_copy
    sub     t0, a0, s8
    BYTELIST sp, (FL + EL_INFO), 104, t0
    sd      s6, (FL + EL_LENGTH)(sp)
    li      t0, 208
    sd      t0, (FL + EL_SCRATCH)(sp)
    li      t0, 88
    sd      t0, (FL + EL_OKM)(sp)
    addi    a0, sp, (FL + EL_PRK)
    addi    a1, sp, (FL + EL_INFO)
    addi    a2, sp, (FL + EL_LENGTH)
    addi    a3, sp, (FL + EL_SCRATCH)
    addi    a4, sp, (FL + EL_OKM)
    CALL_GLOBAL crypto_hkdf_expand
    mv      a0, s7
    addi    a1, sp, (FL + EL_OKM + 24)
    mv      a2, s6
    call    quic_copy
    LEAVE   0, EL_FRAME
END_FUNCTION quic_expand_label

/*
 * quic_derive_keys(secret, keys): the AEAD key, IV and header protection key of a
 * 32-byte traffic secret (RFC 9001 section 5.1), as PacketKeys.
 */
LOCAL_FUNCTION quic_derive_keys
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    mv      a0, s1
    lla     a1, 504f
    li      a2, 8
    li      a3, 0
    li      a4, 0
    li      a5, 16
    addi    a6, s2, QUIC_KEYS_KEY
    call    quic_expand_label
    mv      a0, s1
    lla     a1, 505f
    li      a2, 7
    li      a3, 0
    li      a4, 0
    li      a5, 12
    addi    a6, s2, QUIC_KEYS_IV
    call    quic_expand_label
    sw      zero, (QUIC_KEYS_IV + 12)(s2)
    mv      a0, s1
    lla     a1, 506f
    li      a2, 7
    li      a3, 0
    li      a4, 0
    li      a5, 16
    addi    a6, s2, QUIC_KEYS_HP
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
    mv      s1, a0
    mv      s2, a1
    ld      s3, QUIC_CID_LENGTH(s1)
    li      a0, QUIC_INVALID_ARGUMENT
    li      t0, QUIC_CID_MAX
    bltu    t0, s3, 9f
    mv      a0, s2
    mv      a1, s1
    call    quic_initial_derive
    li      a0, QUIC_OK
9:  LEAVE   0
END_FUNCTION quic_initial_keys

/* quic_initial_derive(keys, dcid): the Initial keys of a checked ConnectionId. */
LOCAL_FUNCTION quic_initial_derive
    ENTER   0, IK_FRAME
    mv      s2, a0
    mv      s1, a1
    ld      s3, QUIC_CID_LENGTH(s1)
    li      t0, 20
    BYTELIST sp, (FL + IK_SALT), 48, t0
    addi    a0, sp, (FL + IK_SALT + 24)
    lla     a1, 501f
    li      a2, 20
    call    quic_copy
    BYTELIST sp, (FL + IK_IKM), 48, s3
    addi    a0, sp, (FL + IK_IKM + 24)
    addi    a1, s1, QUIC_CID_ID
    mv      a2, s3
    call    quic_copy
    li      t0, 128
    sd      t0, (FL + IK_SCRATCH)(sp)
    addi    a0, sp, (FL + IK_SALT)
    addi    a1, sp, (FL + IK_IKM)
    addi    a2, sp, (FL + IK_SCRATCH)
    addi    a3, sp, (FL + IK_PRK)
    CALL_GLOBAL crypto_hkdf_extract
    addi    a0, sp, (FL + IK_PRK)
    lla     a1, 502f
    li      a2, 9
    li      a3, 0
    li      a4, 0
    li      a5, 32
    addi    a6, sp, (FL + IK_SECRET)
    call    quic_expand_label
    addi    a0, sp, (FL + IK_SECRET)
    addi    a1, s2, QUIC_INITIAL_CLIENT
    call    quic_derive_keys
    addi    a0, sp, (FL + IK_PRK)
    lla     a1, 503f
    li      a2, 9
    li      a3, 0
    li      a4, 0
    li      a5, 32
    addi    a6, sp, (FL + IK_SECRET)
    call    quic_expand_label
    addi    a0, sp, (FL + IK_SECRET)
    addi    a1, s2, QUIC_INITIAL_SERVER
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
    ld      a3, QUIC_KEYS_IV(a1)
    lwu     a4, (QUIC_KEYS_IV + 8)(a1)
    sd      a3, 0(a0)
    sw      a4, 8(a0)
    sw      zero, 12(a0)
    li      a3, 0                           # byte i of the packet number, most significant first
    li      a4, 56
1:  addi    a5, a0, 4
    add     a5, a5, a3
    lbu     a6, 0(a5)
    srl     a7, a2, a4
    xor     a6, a6, a7
    sb      a6, 0(a5)
    addi    a3, a3, 1
    addi    a4, a4, -8
    bgez    a4, 1b
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
    mv      s1, a0
    mv      s2, a2
    addi    a0, sp, (FL + HM_COUNTER)
    li      a2, 16
    call    quic_copy
    li      t0, 16
    BYTELIST sp, (FL + HM_IN), 40, t0
    sd      zero, (FL + HM_IN + 24)(sp)
    sd      zero, (FL + HM_IN + 32)(sp)
    li      t0, 40
    sd      t0, (FL + HM_OUT)(sp)
    mv      a0, s1
    addi    a1, sp, (FL + HM_COUNTER)
    addi    a2, sp, (FL + HM_IN)
    addi    a3, sp, (FL + HM_OUT)
    CALL_GLOBAL crypto_aes128_ctr
    ld      t0, (FL + HM_OUT + 24)(sp)
    ld      t1, (FL + HM_OUT + 32)(sp)
    sd      t0, 0(s2)
    sd      t1, 8(s2)
    LEAVE   0, HM_FRAME
END_FUNCTION quic_hp_mask

/*
 * quic_pn_decode(truncated, bits, largest) -> the packet number closest to
 * largest + 1 that ends in the truncated bits (RFC 9000 appendix A.3).
 * largest is NONE before the first packet of a space. A leaf.
 */
LOCAL_FUNCTION quic_pn_decode
    UNWIND_END_PROLOGUE
    addi    a3, a2, 1                       # expected
    li      a4, 1
    sll     a4, a4, a1                      # window
    srli    a5, a4, 1                       # half window
    addi    a6, a4, -1
    not     a6, a6
    and     a6, a3, a6
    or      a6, a6, a0                      # candidate
    sub     a7, a3, a5
    blt     a7, a6, 1f
    li      t0, 1
    slli    t0, t0, 62
    sub     t0, t0, a4
    bge     a6, t0, 1f
    add     a0, a6, a4
    ret
1:  add     a7, a3, a5
    bge     a7, a6, 2f
    blt     a6, a4, 2f
    sub     a0, a6, a4
    ret
2:  mv      a0, a6
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
    lbu     t0, 0(a0)
    lbu     t1, 0(a3)
    andi    t2, t0, 0x80
    li      t3, 0x1F
    beqz    t2, 1f
    li      t3, 0x0F
1:  and     t1, t1, t3
    xor     t0, t0, t1
    sb      t0, 0(a0)
    add     a4, a0, a1
    li      a5, 0
2:  bgeu    a5, a2, 3f
    add     a6, a3, a5
    lbu     t1, 1(a6)
    add     a6, a4, a5
    lbu     t0, 0(a6)
    xor     t0, t0, t1
    sb      t0, 0(a6)
    addi    a5, a5, 1
    j       2b
3:  ret
END_FUNCTION quic_mask_header

/*
 * quic_seal(keys, buf, header_len, payload_len, pn, work) -> header_len +
 * payload_len + 16. buf holds the header, its packet number last, then the
 * frames: writes C || T after the header, then protects the header (RFC 9001
 * sections 5.3 and 5.4). The caller checks header_len <= W_HEADER_MAX,
 * payload_len + 16 <= W_SEALED_MAX, and payload_len + the packet number length >= 4.
 * s1 keys, s2 buf, s3 header_len, s4 payload_len, s5 pn, s6 work, s7 pn length, s8 pn offset.
 */
LOCAL_FUNCTION quic_seal
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    mv      s4, a3
    mv      s5, a4
    mv      s6, a5
    BYTELIST s6, W_AAD, 280, s3
    addi    a0, s6, (W_AAD + 24)
    mv      a1, s2
    mv      a2, s3
    call    quic_copy
    BYTELIST s6, W_IN, 1544, s4
    addi    a0, s6, (W_IN + 24)
    add     a1, s2, s3
    mv      a2, s4
    call    quic_copy
    li      t0, 1544
    li      t1, W_OUT
    add     t1, s6, t1
    sd      t0, 0(t1)
    li      t1, W_NONCE
    add     a0, s6, t1
    mv      a1, s1
    mv      a2, s5
    call    quic_nonce
    addi    a0, s1, QUIC_KEYS_KEY
    li      t1, W_NONCE
    add     a1, s6, t1
    addi    a2, s6, W_IN
    addi    a3, s6, W_AAD
    li      t1, W_OUT
    add     a4, s6, t1
    CALL_GLOBAL crypto_aes128_gcm_ae
    add     a0, s2, s3
    li      t1, (W_OUT + 24)
    add     a1, s6, t1
    addi    a2, s4, 16
    call    quic_copy
    lbu     t0, 0(s2)
    andi    t0, t0, 3
    addi    s7, t0, 1
    sub     s8, s3, s7
    addi    a0, s1, QUIC_KEYS_HP
    add     a1, s2, s8
    addi    a1, a1, 4
    li      t1, W_MASK
    add     a2, s6, t1
    call    quic_hp_mask
    mv      a0, s2
    mv      a1, s8
    mv      a2, s7
    li      t1, W_MASK
    add     a3, s6, t1
    call    quic_mask_header
    add     a0, s3, s4
    addi    a0, a0, 16
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
 * s1 keys, s2 buf, s3 pn offset then header length, s4 total then sealed length,
 * s5 largest then pn, s6 work, s7 result, s8 pn length.
 */
LOCAL_FUNCTION quic_open
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    mv      s4, a3
    mv      s5, a4
    mv      s6, a5
    mv      s7, a6
    li      a0, QUIC_INVALID_PACKET
    addi    t0, s3, 20
    bltu    s4, t0, 9f
    addi    a0, s1, QUIC_KEYS_HP
    add     a1, s2, s3
    addi    a1, a1, 4
    li      t1, W_MASK
    add     a2, s6, t1
    call    quic_hp_mask
    lbu     t0, 0(s2)                       # the first byte without protection
    li      t1, W_MASK
    add     t1, s6, t1
    lbu     t1, 0(t1)
    andi    t2, t0, 0x80
    li      t3, 0x1F
    beqz    t2, 1f
    li      t3, 0x0F
1:  and     t1, t1, t3
    xor     t0, t0, t1
    andi    t0, t0, 3
    addi    s8, t0, 1
    mv      a0, s2
    mv      a1, s3
    mv      a2, s8
    li      t1, W_MASK
    add     a3, s6, t1
    call    quic_mask_header
    li      a0, 0                           # the truncated packet number
    add     t0, s2, s3
    mv      t1, s8
2:  lbu     t2, 0(t0)
    slli    a0, a0, 8
    or      a0, a0, t2
    addi    t0, t0, 1
    addi    t1, t1, -1
    bnez    t1, 2b
    slli    a1, s8, 3
    mv      a2, s5
    call    quic_pn_decode
    mv      s5, a0
    add     s3, s3, s8                      # the header length
    sub     s4, s4, s3                      # the sealed length
    li      a0, QUIC_INVALID_PACKET
    li      t0, 16
    bltu    s4, t0, 9f
    li      t0, W_HEADER_MAX
    bltu    t0, s3, 9f
    li      t0, W_SEALED_MAX
    bltu    t0, s4, 9f
    BYTELIST s6, W_AAD, 280, s3
    addi    a0, s6, (W_AAD + 24)
    mv      a1, s2
    mv      a2, s3
    call    quic_copy
    BYTELIST s6, W_IN, 1544, s4
    addi    a0, s6, (W_IN + 24)
    add     a1, s2, s3
    mv      a2, s4
    call    quic_copy
    li      t0, 1544
    li      t1, W_OUT
    add     t1, s6, t1
    sd      t0, 0(t1)
    li      t1, W_NONCE
    add     a0, s6, t1
    mv      a1, s1
    mv      a2, s5
    call    quic_nonce
    addi    a0, s1, QUIC_KEYS_KEY
    li      t1, W_NONCE
    add     a1, s6, t1
    addi    a2, s6, W_IN
    addi    a3, s6, W_AAD
    li      t1, W_OUT
    add     a4, s6, t1
    CALL_GLOBAL crypto_aes128_gcm_ad
    mv      t0, a0
    li      a0, QUIC_DECRYPT_FAILED
    bnez    t0, 9f
    addi    s4, s4, -16
    add     a0, s2, s3
    li      t1, (W_OUT + 24)
    add     a1, s6, t1
    mv      a2, s4
    call    quic_copy
    sd      s5, 0(s7)
    sd      s3, 8(s7)
    sd      s4, 16(s7)
    li      a0, QUIC_OK
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

/* quic_packet_seal(keys, packet, scratch, sealed) -> status. s5 header count, s6 payload count, s7 header, s8 size. */
FUNCTION quic_packet_seal
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    mv      s4, a3
    ld      t0, 0(s3)
    li      t1, QUIC_PACKET_SCRATCH
    li      a0, QUIC_BUFFER_TOO_SMALL
    bltu    t0, t1, 9f
    li      a0, QUIC_INVALID_ARGUMENT
    ld      s8, QUIC_PP_SIZE(s2)
    ld      s5, QUIC_PP_HEADER_COUNT(s2)
    ld      s6, QUIC_PP_PAYLOAD_COUNT(s2)
    ld      t0, QUIC_PP_HEADER_OFF(s2)
    li      t1, QUIC_PP_FIXED
    bltu    t0, t1, 9f
    bltu    s8, t0, 9f
    sub     t2, s8, t0
    bltu    t2, s5, 9f
    add     s7, s2, t0                      # the header
    ld      t0, QUIC_PP_PAYLOAD_OFF(s2)
    bltu    t0, t1, 9f
    bltu    s8, t0, 9f
    sub     t2, s8, t0
    bltu    t2, s6, 9f
    beqz    s5, 9f
    li      t1, W_HEADER_MAX
    bltu    t1, s5, 9f
    li      t1, (W_SEALED_MAX - 16)
    bltu    t1, s6, 9f
    lbu     t0, 0(s7)
    andi    t0, t0, 3
    addi    t0, t0, 1
    bltu    s5, t0, 9f
    add     t0, t0, s6
    li      t1, 4
    bltu    t0, t1, 9f
    ld      t0, 0(s4)
    add     t1, s5, s6
    addi    t1, t1, (QUIC_BL_FIXED + 16)
    li      a0, QUIC_BUFFER_TOO_SMALL
    bltu    t0, t1, 9f
    addi    a0, s3, PS_BUF
    mv      a1, s7
    mv      a2, s5
    call    quic_copy
    ld      a1, QUIC_PP_PAYLOAD_OFF(s2)
    add     a1, s2, a1
    mv      a2, s6
    call    quic_copy
    mv      a0, s1
    addi    a1, s3, PS_BUF
    mv      a2, s5
    mv      a3, s6
    ld      a4, QUIC_PP_NUMBER(s2)
    li      t0, PS_WORK
    add     a5, s3, t0
    call    quic_seal
    mv      s8, a0
    li      t0, QUIC_BL_FIXED
    sd      t0, QUIC_BL_OFFSET(s4)
    sd      s8, QUIC_BL_COUNT(s4)
    addi    a0, s4, QUIC_BL_FIXED
    addi    a1, s3, PS_BUF
    mv      a2, s8
    call    quic_copy
    li      a0, QUIC_OK
9:  LEAVE   0
END_FUNCTION quic_packet_seal

/* quic_packet_open(keys, request, scratch, opened) -> status. s5 count, s6 the packet, s7 payload offset, s8 size. */
FUNCTION quic_packet_open
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    mv      s4, a3
    ld      t0, 0(s3)
    li      t1, QUIC_PACKET_SCRATCH
    li      a0, QUIC_BUFFER_TOO_SMALL
    bltu    t0, t1, 9f
    li      a0, QUIC_INVALID_ARGUMENT
    ld      s8, QUIC_OR_SIZE(s2)
    ld      s5, QUIC_OR_PACKET_COUNT(s2)
    ld      t0, QUIC_OR_PACKET_OFF(s2)
    li      t1, QUIC_OR_FIXED
    bltu    t0, t1, 9f
    bltu    s8, t0, 9f
    sub     t2, s8, t0
    bltu    t2, s5, 9f
    add     s6, s2, t0                      # the packet
    li      a0, QUIC_INVALID_PACKET
    li      t1, (W_HEADER_MAX + W_SEALED_MAX)
    bltu    t1, s5, 9f
    ld      t0, 0(s4)
    addi    t1, s5, (QUIC_OP_FIXED + 8)
    li      a0, QUIC_BUFFER_TOO_SMALL
    bltu    t0, t1, 9f
    addi    a0, s3, PS_BUF
    mv      a1, s6
    mv      a2, s5
    call    quic_copy
    ld      a2, QUIC_OR_PN_OFFSET(s2)
    li      a0, QUIC_INVALID_PACKET
    bgeu    a2, s5, 9f
    mv      a0, s1
    addi    a1, s3, PS_BUF
    mv      a3, s5
    ld      a4, QUIC_OR_LARGEST(s2)
    li      t0, PS_WORK
    add     a5, s3, t0
    li      t0, PS_RESULT
    add     a6, s3, t0
    call    quic_open
    bnez    a0, 9f
    li      t0, PS_RESULT
    add     t0, s3, t0
    ld      t1, 0(t0)
    sd      t1, QUIC_OP_NUMBER(s4)
    ld      s5, 8(t0)                       # header length
    ld      s6, 16(t0)                      # payload length
    li      t1, QUIC_OP_FIXED
    sd      t1, QUIC_OP_HEADER_OFF(s4)
    sd      s5, QUIC_OP_HEADER_COUNT(s4)
    addi    s7, s5, 7
    andi    s7, s7, -8
    addi    s7, s7, QUIC_OP_FIXED
    sd      s7, QUIC_OP_PAYLOAD_OFF(s4)
    sd      s6, QUIC_OP_PAYLOAD_COUNT(s4)
    addi    a0, s4, QUIC_OP_FIXED
    addi    a1, s3, PS_BUF
    mv      a2, s5
    call    quic_copy
    add     a0, s4, s7
    addi    a1, s3, PS_BUF
    add     a1, a1, s5
    mv      a2, s6
    call    quic_copy
    li      a0, QUIC_OK
9:  LEAVE   0
END_FUNCTION quic_packet_open

/*
 * quic_retry_tag(odcid, retry, scratch, tag) -> status: the Retry Integrity Tag
 * of a Retry packet without its tag (RFC 9001 section 5.8). The scratch holds
 * the pseudo-packet: its size, then a ByteList.
 * s5 odcid length, s6 retry count, s7 the pseudo-packet length.
 */
.set RT_PLAIN, 0                        /* ByteList: empty */
.set RT_SEALED, 24                      /* ByteList: 24 + 16 */
.set RT_NONCE, 64
.set RT_FRAME, 80
FUNCTION quic_retry_tag
    ENTER   0, RT_FRAME
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    mv      s4, a3
    li      a0, QUIC_INVALID_ARGUMENT
    ld      s5, QUIC_CID_LENGTH(s1)
    li      t0, QUIC_CID_MAX
    bltu    t0, s5, 9f
    ld      s6, QUIC_BL_COUNT(s2)
    li      t0, QUIC_MAX_PACKET
    bltu    t0, s6, 9f
    add     s7, s6, s5
    addi    s7, s7, 1                       # the pseudo-packet length
    ld      t0, 0(s3)
    addi    t1, s7, (8 + QUIC_BL_FIXED)
    li      a0, QUIC_BUFFER_TOO_SMALL
    bltu    t0, t1, 9f
    addi    t1, t0, -8
    sd      t1, 8(s3)
    li      t2, QUIC_BL_FIXED
    sd      t2, 16(s3)
    sd      s7, 24(s3)
    sb      s5, (8 + QUIC_BL_FIXED)(s3)
    addi    a0, s3, (8 + QUIC_BL_FIXED + 1)
    addi    a1, s1, QUIC_CID_ID
    mv      a2, s5
    call    quic_copy
    ld      a1, QUIC_BL_OFFSET(s2)
    add     a1, s2, a1
    mv      a2, s6
    call    quic_copy
    li      t0, 0
    BYTELIST sp, (FL + RT_PLAIN), 24, t0
    li      t0, 40
    sd      t0, (FL + RT_SEALED)(sp)
    addi    a0, sp, (FL + RT_NONCE)
    lla     a1, 508f
    li      a2, 12
    call    quic_copy
    sw      zero, (FL + RT_NONCE + 12)(sp)
    lla     a0, 507f
    addi    a1, sp, (FL + RT_NONCE)
    addi    a2, sp, (FL + RT_PLAIN)
    addi    a3, s3, 8
    addi    a4, sp, (FL + RT_SEALED)
    CALL_GLOBAL crypto_aes128_gcm_ae
    ld      t0, (FL + RT_SEALED + 24)(sp)
    ld      t1, (FL + RT_SEALED + 32)(sp)
    sd      t0, 0(s4)
    sd      t1, 8(s4)
    li      a0, QUIC_OK
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
