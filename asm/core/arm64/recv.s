/*
 * Receiving (RFC 9000 sections 5, 12, 17 and 19): datagrams, packet headers,
 * finding or making the connection, opening packets with the key phases,
 * Version Negotiation and Retry for a client, and the frames.
 */

.set ERR_FRAME_ENCODING, 0x07
.set ERR_CID_LIMIT, 0x09
.set ERR_NONE, 0x00

/* ---------------------------------------------------------------- Keys */

/*
 * quic_initial_install(dcid): the Initial keys of the connection from a
 * ConnectionId, for its role. x19 the connection.
 */
.set II_KEYS, 0                         /* InitialKeys, 96 bytes */
.set II_FRAME, 96
LOCAL_FUNCTION quic_initial_install
    ENTER   0, II_FRAME
    mov     x1, x0
    add     x0, sp, #II_KEYS
    bl      quic_initial_derive
    add     x20, x19, #C_SPACES             /* the Initial space */
    ldr     x9, [x19, #C_ROLE]
    add     x21, sp, #(II_KEYS + QUIC_INITIAL_CLIENT)
    add     x22, sp, #(II_KEYS + QUIC_INITIAL_SERVER)
    cmp     x9, #0
    csel    x1, x22, x21, eq                /* receive: the peer's keys */
    add     x0, x20, #SP_RX_KEYS
    mov     x2, #QUIC_KEYS_SIZE
    bl      quic_copy
    ldr     x9, [x19, #C_ROLE]
    cmp     x9, #0
    csel    x1, x21, x22, eq
    add     x0, x20, #SP_TX_KEYS
    mov     x2, #QUIC_KEYS_SIZE
    bl      quic_copy
    ldr     x9, [x20, #SP_FLAGS]
    orr     x9, x9, #(SPF_RX | SPF_TX)
    str     x9, [x20, #SP_FLAGS]
    LEAVE   0, II_FRAME
END_FUNCTION quic_initial_install

/* quic_cid_put(cid, p, n): the ConnectionId cid = the n bytes at p (n at most 20). */
LOCAL_FUNCTION quic_cid_put
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    add     x0, x19, #QUIC_CID_ID
    mov     x1, #24
    bl      quic_zero
    str     x21, [x19, #QUIC_CID_LENGTH]
    add     x0, x19, #QUIC_CID_ID
    mov     x1, x20
    mov     x2, x21
    bl      quic_copy
    LEAVE   0
END_FUNCTION quic_cid_put

/* ---------------------------------------------------------------- Datagrams */

/*
 * quic_on_datagram(event): each packet of the datagram in turn (RFC 9000
 * section 12.2): long headers until a short one, which takes the rest.
 * x20 position, x21 end, x22 the datagram size, x23 the event, x24 the
 * connection of the first packet (for the amplification count),
 * x25 the packet start, x26 the connection.
 */
.set DG_DCID, 0                         /* pointer */
.set DG_DCID_LEN, 8
.set DG_SCID, 16
.set DG_SCID_LEN, 24
.set DG_TYPE, 32
.set DG_VERSION, 40
.set DG_PN_OFF, 48
.set DG_END, 56
.set DG_TOKEN, 64
.set DG_TOKEN_LEN, 72
.set DG_FRAME, 80
LOCAL_FUNCTION quic_on_datagram
    ENTER   0, DG_FRAME
    mov     x23, x0
    add     x20, x23, #QUIC_EV_DATA
    ldr     x22, [x23, #QUIC_EV_COUNT]
    add     x21, x20, x22
    mov     x24, #0
1:  cmp     x20, x21
    b.hs    9f
    mov     x25, x20
    ldrb    w9, [x20]
    tbz     w9, #7, 50f
    /* A long header: the version, the connection IDs. */
    sub     x10, x21, x20
    cmp     x10, #7
    b.lo    9f
    ldrb    w10, [x20, #1]
    ldrb    w11, [x20, #2]
    ldrb    w12, [x20, #3]
    ldrb    w13, [x20, #4]
    lsl     w10, w10, #24
    orr     w10, w10, w11, lsl #16
    orr     w10, w10, w12, lsl #8
    orr     w10, w10, w13
    str     x10, [sp, #DG_VERSION]
    ldrb    w11, [x20, #5]
    cmp     x11, #QUIC_CID_MAX
    b.hi    9f
    add     x12, x20, #6
    str     x12, [sp, #DG_DCID]
    str     x11, [sp, #DG_DCID_LEN]
    add     x12, x12, x11
    cmp     x12, x21
    b.hs    9f
    ldrb    w13, [x12], #1
    cmp     x13, #QUIC_CID_MAX
    b.hi    9f
    str     x12, [sp, #DG_SCID]
    str     x13, [sp, #DG_SCID_LEN]
    add     x12, x12, x13
    cmp     x12, x21
    b.hi    9f
    ldr     x10, [sp, #DG_VERSION]
    cbz     x10, 40f                        /* Version Negotiation */
    cmp     x10, #1
    b.ne    45f
    ubfx    x9, x9, #4, #2
    str     x9, [sp, #DG_TYPE]
    cmp     x9, #3
    b.eq    42f                             /* Retry */
    str     xzr, [sp, #DG_TOKEN_LEN]
    cbnz    x9, 2f
    mov     x0, x12                         /* Initial: the token */
    mov     x1, x21
    bl      quic_vget
    cbz     x0, 9f
    sub     x10, x21, x0
    cmp     x1, x10
    b.hi    9f
    str     x0, [sp, #DG_TOKEN]
    str     x1, [sp, #DG_TOKEN_LEN]
    add     x12, x0, x1
2:  mov     x0, x12                         /* Length */
    mov     x1, x21
    bl      quic_vget
    cbz     x0, 9f
    sub     x10, x21, x0
    cmp     x1, x10
    b.hi    9f
    str     x0, [sp, #DG_PN_OFF]
    add     x10, x0, x1
    str     x10, [sp, #DG_END]
    ldr     x9, [sp, #DG_TYPE]
    cmp     x9, #1
    b.eq    48f                             /* 0-RTT: dropped */
    /* The connection. */
    ldr     x0, [sp, #DG_DCID]
    ldr     x1, [sp, #DG_DCID_LEN]
    bl      quic_conn_find
    cbnz    x0, 3f
    ldr     x9, [sp, #DG_TYPE]
    cbnz    x9, 48f
    ldr     x0, [sp, #DG_DCID]
    ldr     x1, [sp, #DG_DCID_LEN]
    ldr     x2, [x23, #QUIC_EV_SOCKET]
    add     x3, x23, #QUIC_EV_ADDR
    bl      quic_conn_find_odcid
    cbnz    x0, 3f
    mov     x0, sp
    bl      quic_accept
    cbz     x0, 9f
3:  mov     x26, x0
    cbnz    x24, 31f
    mov     x24, x26
31: mov     x19, x26
    ldr     x9, [x19, #C_ROLE]              /* a client takes the server's connection ID from its first packet */
    cbnz    x9, 32f
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_GOT_PACKET
    b.ne    32f
    ldr     x9, [sp, #DG_TYPE]
    cmp     x9, #2
    b.hi    32f
    add     x0, x19, #C_RCID
    ldr     x1, [sp, #DG_SCID]
    ldr     x2, [sp, #DG_SCID_LEN]
    bl      quic_cid_put
    add     x0, x19, #C_ISCID
    ldr     x1, [sp, #DG_SCID]
    ldr     x2, [sp, #DG_SCID_LEN]
    bl      quic_cid_put
32: ldr     x9, [sp, #DG_TYPE]
    mov     x1, #SPACE_INITIAL
    cmp     x9, #2
    mov     x10, #SPACE_HANDSHAKE
    csel    x1, x10, x1, eq
    mov     x0, x19
    mov     x2, x25
    ldr     x3, [sp, #DG_PN_OFF]
    sub     x3, x3, x25
    ldr     x4, [sp, #DG_END]
    sub     x4, x4, x25
    bl      quic_packet_in
    ldr     x20, [sp, #DG_END]
    b       1b
    /* A short header: our connection ID of 8 bytes, then the rest of the datagram. */
50: sub     x10, x21, x20
    cmp     x10, #(1 + 8 + 20)
    b.lo    9f
    add     x0, x20, #1
    mov     x1, #8
    bl      quic_conn_find
    cbz     x0, 9f
    mov     x26, x0
    cbnz    x24, 51f
    mov     x24, x26
51: mov     x19, x26
    mov     x0, x19
    mov     x1, #SPACE_APP
    mov     x2, x20
    mov     x3, #9
    sub     x4, x21, x20
    bl      quic_packet_in
    b       9f
40: ldr     x0, [sp, #DG_DCID]              /* Version Negotiation, for a client */
    ldr     x1, [sp, #DG_DCID_LEN]
    bl      quic_conn_find
    cbz     x0, 9f
    mov     x19, x0
    mov     x0, x12
    mov     x1, x21
    bl      quic_on_vn
    b       9f
42: ldr     x0, [sp, #DG_DCID]              /* Retry, for a client */
    ldr     x1, [sp, #DG_DCID_LEN]
    bl      quic_conn_find
    cbz     x0, 9f
    mov     x19, x0
    mov     x0, x25
    sub     x1, x21, x25
    ldr     x2, [sp, #DG_SCID]
    ldr     x3, [sp, #DG_SCID_LEN]
    bl      quic_on_retry
    b       9f
45: ldr     x9, [x27, #(ST_CONFIG + QUIC_CFG_FLAGS)]   /* another version: Version Negotiation from a server */
    tst     x9, #QUIC_CFG_ACCEPT
    b.eq    9f
    cmp     x22, #1200
    b.lo    9f
    ldr     x0, [sp, #DG_DCID]
    ldr     x1, [sp, #DG_DCID_LEN]
    bl      quic_conn_find
    cbnz    x0, 9f
    add     x0, sp, #DG_DCID
    bl      quic_send_vn
    b       9f
48: ldr     x20, [sp, #DG_END]              /* skip the packet */
    b       1b
9:  cbz     x24, 99f
    ldr     x9, [x24, #C_RX_BYTES]
    add     x9, x9, x22
    str     x9, [x24, #C_RX_BYTES]
99: LEAVE   0, DG_FRAME
END_FUNCTION quic_on_datagram

/*
 * quic_accept(header) -> a new server connection for the first Initial of a
 * client, or 0: the server accepts, the datagram is at least 1200 bytes, the
 * Destination Connection ID is at least 8 bytes, and a slot is free.
 * header: the DG_* fields. x23 the event.
 */
LOCAL_FUNCTION quic_accept
    ENTER   0
    mov     x20, x0
    ldr     x9, [x27, #(ST_CONFIG + QUIC_CFG_FLAGS)]
    tst     x9, #QUIC_CFG_ACCEPT
    b.eq    8f
    ldr     x9, [x23, #QUIC_EV_COUNT]
    cmp     x9, #1200
    b.lo    8f
    ldr     x9, [x20, #DG_DCID_LEN]
    cmp     x9, #8
    b.lo    8f
    mov     x0, #1
    bl      quic_conn_new
    cbz     x0, 8f
    mov     x19, x0
    ldr     x9, [x23, #QUIC_EV_SOCKET]
    str     x9, [x19, #C_SOCKET]
    add     x0, x19, #C_ADDR
    add     x1, x23, #QUIC_EV_ADDR
    mov     x2, #QUIC_ADDR_SIZE
    bl      quic_copy
    add     x0, x19, #C_ODCID
    ldr     x1, [x20, #DG_DCID]
    ldr     x2, [x20, #DG_DCID_LEN]
    bl      quic_cid_put
    add     x0, x19, #C_RCID
    ldr     x1, [x20, #DG_SCID]
    ldr     x2, [x20, #DG_SCID_LEN]
    bl      quic_cid_put
    add     x0, x19, #C_ISCID
    ldr     x1, [x20, #DG_SCID]
    ldr     x2, [x20, #DG_SCID_LEN]
    bl      quic_cid_put
    add     x0, x19, #C_ODCID
    bl      quic_initial_install
    ldr     x9, [x19, #C_TLS]
    add     x9, x27, x9
    mov     x10, #TS_WAIT_CH
    str     x10, [x9, #T_STAGE]
    bl      quic_idle_reset
    mov     x0, x19
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_accept

/*
 * quic_send_vn(header): a Version Negotiation packet back to a client that
 * offered another version (RFC 9000 section 6.1): the connection IDs swapped,
 * version 1 the only one listed. header: the DG_* fields. x23 the event.
 */
LOCAL_FUNCTION quic_send_vn
    ENTER   0
    mov     x20, x0
    ldr     x9, [x20, #DG_DCID_LEN]
    ldr     x10, [x20, #DG_SCID_LEN]
    add     x21, x9, x10
    add     x21, x21, #11                   /* first byte, version, two lengths, one version */
    add     x1, x21, #(QUIC_ACT_DATA + 7)
    and     x1, x1, #~7
    mov     x0, #QUIC_ACTION_SEND
    bl      quic_action
    cbz     x0, 9f
    mov     x22, x0
    ldr     x9, [x23, #QUIC_EV_SOCKET]
    str     x9, [x22, #QUIC_ACT_SOCKET]
    add     x0, x22, #QUIC_ACT_ADDR
    add     x1, x23, #QUIC_EV_ADDR
    mov     x2, #QUIC_ADDR_SIZE
    bl      quic_copy
    str     x21, [x22, #QUIC_ACT_COUNT]
    add     x24, x22, #QUIC_ACT_DATA
    mov     x0, x24
    mov     x1, #1
    bl      quic_random
    ldrb    w9, [x24]
    orr     w9, w9, #0x80
    strb    w9, [x24]
    str     wzr, [x24, #1]
    ldr     x2, [x20, #DG_SCID_LEN]
    strb    w2, [x24, #5]
    add     x0, x24, #6
    ldr     x1, [x20, #DG_SCID]
    bl      quic_copy
    ldr     x2, [x20, #DG_DCID_LEN]
    strb    w2, [x0], #1
    ldr     x1, [x20, #DG_DCID]
    bl      quic_copy
    strb    wzr, [x0]
    strb    wzr, [x0, #1]
    strb    wzr, [x0, #2]
    mov     w9, #1
    strb    w9, [x0, #3]
9:  LEAVE   0
END_FUNCTION quic_send_vn

/*
 * quic_on_vn(p, end): Version Negotiation for a client before any packet of
 * the server: when it does not list version 1, the dial fails with
 * QUIC_ERR_VERSION (RFC 9000 section 6.2). x19 the connection.
 */
LOCAL_FUNCTION quic_on_vn
    ENTER   0
    mov     x20, x0
    mov     x21, x1
    ldr     x9, [x19, #C_ROLE]
    cbnz    x9, 9f
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_GOT_PACKET
    b.ne    9f
    ldr     x9, [x19, #C_STATE]
    cmp     x9, #CS_HANDSHAKE
    b.ne    9f
1:  sub     x9, x21, x20
    cmp     x9, #4
    b.lo    2f
    ldr     w10, [x20], #4
    rev     w10, w10
    cmp     w10, #1
    b.eq    9f                              /* lists ours: ignored */
    b       1b
2:  mov     x9, #QUIC_ERR_VERSION
    str     x9, [x19, #C_REASON]
    mov     x0, x19
    mov     x1, #0
    bl      quic_conn_drain
    str     xzr, [x19, #C_CLOSE_AT]         /* nothing to wait for */
9:  LEAVE   0
END_FUNCTION quic_on_vn

/*
 * quic_on_retry(packet, n, scid, scid_len): a Retry for a client before any
 * other packet of the server, once (RFC 9000 section 17.2.5): with a valid
 * integrity tag, the server's connection ID and the token are taken, the
 * Initial keys change, and the ClientHello goes again in new Initial packets.
 * x19 the connection.
 * x20 packet, x21 n, x22 scid, x23 scid length.
 */
.set RY_TAG, 0
.set RY_PLAIN, 16                       /* ByteList: empty */
.set RY_SEALED, 40                      /* ByteList: 24 + 16 */
.set RY_NONCE, 80
.set RY_FRAME, 96
LOCAL_FUNCTION quic_on_retry
    ENTER   0, RY_FRAME
    mov     x20, x0
    mov     x21, x1
    mov     x22, x2
    mov     x23, x3
    ldr     x9, [x19, #C_ROLE]
    cbnz    x9, 9f
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #(CF_GOT_PACKET | CF_RETRIED)
    b.ne    9f
    add     x9, x22, x23                    /* the token: after the SCID, up to the tag */
    add     x10, x20, x21
    sub     x10, x10, #16
    cmp     x9, x10
    b.hs    9f                              /* no token */
    sub     x9, x21, #16
    cmp     x9, #W_SEALED_MAX
    b.hi    9f
    /* The pseudo-packet in the packet buffer of the scratch: ODCID, then the Retry without its tag. */
    add     x24, x28, #SC_PKT_BUF
    sub     x25, x21, #16
    ldr     x2, [x19, #(C_ODCID + QUIC_CID_LENGTH)]
    add     x26, x25, x2
    add     x26, x26, #1
    BYTELIST x24, 0, 1776, x26
    strb    w2, [x24, #QUIC_BL_FIXED]
    add     x0, x24, #(QUIC_BL_FIXED + 1)
    add     x1, x19, #(C_ODCID + QUIC_CID_ID)
    bl      quic_copy
    mov     x1, x20
    mov     x2, x25
    bl      quic_copy
    mov     x10, #0
    BYTELIST sp, RY_PLAIN, 24, x10
    mov     x9, #40
    str     x9, [sp, #RY_SEALED]
    adr     x9, 508b                        /* the Retry nonce and key, in keys.s */
    ldr     x10, [x9]
    ldr     w11, [x9, #8]
    str     x10, [sp, #RY_NONCE]
    str     x11, [sp, #(RY_NONCE + 8)]
    adr     x0, 507b
    add     x1, sp, #RY_NONCE
    add     x2, sp, #RY_PLAIN
    mov     x3, x24
    add     x4, sp, #RY_SEALED
    CALL_GLOBAL crypto_aes128_gcm_ae
    add     x0, sp, #(RY_SEALED + 24)
    add     x1, x20, x25
    mov     x2, #16
    bl      quic_equal
    cbz     x0, 9f
    /* Valid: the new connection ID, the token, new Initial keys. */
    ldr     x9, [x19, #C_FLAGS]
    orr     x9, x9, #CF_RETRIED
    str     x9, [x19, #C_FLAGS]
    add     x0, x19, #C_RSCID
    mov     x1, x22
    mov     x2, x23
    bl      quic_cid_put
    add     x0, x19, #C_RCID
    mov     x1, x22
    mov     x2, x23
    bl      quic_cid_put
    add     x24, x22, x23                   /* the token */
    add     x25, x20, x21
    sub     x25, x25, #16
    sub     x25, x25, x24
    mov     x0, x25
    bl      quic_heap_alloc
    cbz     x0, 9f
    str     x0, [x19, #C_TOKEN]
    str     x25, [x19, #C_TOKEN_LEN]
    add     x0, x27, x0
    mov     x1, x24
    mov     x2, x25
    bl      quic_copy
    add     x0, x19, #C_RCID
    bl      quic_initial_install
    mov     x0, #SPACE_INITIAL              /* the Initial packets sent are gone; the ClientHello goes again */
    bl      quic_drop_space_records
    mov     x0, x19
    mov     x1, #SPACE_INITIAL
    bl      quic_space
    str     xzr, [x0, #SP_CTX_SENT]
    str     xzr, [x19, #C_PTO_COUNT]
    bl      quic_set_loss_timer
9:  LEAVE   0, RY_FRAME
END_FUNCTION quic_on_retry

/* ---------------------------------------------------------------- Packets */

/*
 * quic_packet_in(conn, space, packet, pn_offset, n): one packet of a
 * datagram: opened with the keys of its space (the next or the previous key
 * phase for a 1-RTT packet), checked, its packet number recorded, and its
 * frames handled. A packet that does not open is dropped; a 1-RTT one may be
 * a stateless reset.
 * x19 conn, x20 space, x21 packet, x22 pn offset, x23 n, x24 the space record.
 */
LOCAL_FUNCTION quic_packet_in
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x22, x3
    mov     x23, x4
    mov     x0, x19
    mov     x1, x20
    bl      quic_space
    mov     x24, x0
    ldr     x9, [x19, #C_STATE]
    cmp     x9, #CS_DRAINING
    b.hs    9f
    ldr     x9, [x24, #SP_FLAGS]
    tst     x9, #SPF_RX
    b.eq    9f
    tst     x9, #SPF_DISCARDED
    b.ne    9f
    cmp     x23, #(W_HEADER_MAX + W_SEALED_MAX)
    b.hi    9f
    add     x0, x24, #SP_RX_KEYS
    bl      quic_try_open
    cbz     x0, 5f
    cmp     x20, #SPACE_APP                 /* 1-RTT: another key phase? */
    b.ne    4f
    ldrb    w9, [x28, #SC_PKT_BUF]
    ubfx    x9, x9, #2, #1
    ldr     x10, [x19, #C_KEY_PHASE]
    cmp     x9, x10
    b.eq    4f
    add     x0, x19, #C_NEXT_RX
    bl      quic_try_open
    cbnz    x0, 2f
    ldr     x9, [x28, #(SC_PKT_RESULT)]     /* the next phase must be newer than the current one */
    ldr     x10, [x19, #C_PHASE_PN]
    cmn     x10, #1
    b.eq    1f
    cmp     x9, x10
    b.ls    2f
1:  bl      quic_key_update                 /* the peer moved to the next key phase */
    bl      quic_phase_start
    ldr     x9, [x28, #SC_PKT_RESULT]
    str     x9, [x19, #C_PHASE_PN]
    b       5f
2:  ldr     x9, [x19, #C_PREV_UNTIL]        /* a late packet of the previous phase */
    ldr     x10, [x27, #ST_NOW]
    cmn     x9, #1
    b.eq    4f
    cmp     x10, x9
    b.hs    4f
    add     x0, x19, #C_PREV_RX
    bl      quic_try_open
    cbz     x0, 5f
4:  cmp     x20, #SPACE_APP                 /* a stateless reset? (RFC 9000 section 10.3.1) */
    b.ne    9f
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_RESET_TOKEN
    b.eq    9f
    add     x0, x21, x23
    sub     x0, x0, #16
    add     x1, x19, #C_RCID_TOKEN
    mov     x2, #16
    bl      quic_equal
    cbz     x0, 9f
    mov     x9, #QUIC_ERR_RESET
    str     x9, [x19, #C_REASON]
    mov     x0, x19
    mov     x1, #0
    bl      quic_conn_drain
    b       9f
5:  /* Opened: the reserved bits, duplicates, then the frames. */
    ldrb    w9, [x28, #SC_PKT_BUF]
    mov     w10, #0x0C
    mov     w11, #0x18
    tst     w9, #0x80
    csel    w10, w10, w11, ne
    tst     w9, w10
    b.eq    6f
    mov     x0, x19
    mov     x1, #ERR_PROTOCOL
    mov     x2, #QUIC_ERR_PROTOCOL
    bl      quic_conn_close
    b       9f
6:  ldr     x9, [x19, #C_STATE]
    cmp     x9, #CS_CLOSING
    b.ne    61f
    ldr     x9, [x19, #C_FLAGS]             /* closing: answer with CONNECTION_CLOSE again */
    orr     x9, x9, #CF_CLOSE_FRAME
    str     x9, [x19, #C_FLAGS]
    b       9f
61: ldr     x22, [x28, #SC_PKT_RESULT]      /* the packet number */
    mov     x0, x24
    mov     x1, x22
    bl      quic_recv_pn
    cbnz    x0, 9f
    ldr     x9, [x24, #SP_LARGEST_RECV]
    cmn     x9, #1
    b.eq    7f
    cmp     x22, x9
    b.ls    71f
7:  str     x22, [x24, #SP_LARGEST_RECV]
    ldr     x9, [x27, #ST_NOW]
    str     x9, [x24, #SP_RECV_TIME]
71: ldr     x9, [x19, #C_FLAGS]
    orr     x9, x9, #CF_GOT_PACKET
    bic     x9, x9, #CF_ELICIT_SENT
    str     x9, [x19, #C_FLAGS]
    ldr     x9, [x28, #(SC_PKT_RESULT + 8)]
    add     x0, x28, #SC_PKT_BUF
    add     x0, x0, x9
    ldr     x1, [x28, #(SC_PKT_RESULT + 16)]
    mov     x2, x20
    bl      quic_frames
    cbz     x0, 72f
    cmn     x0, #1
    b.eq    9f                              /* CONNECTION_CLOSE: draining */
    mov     x1, x0
    mov     x0, x19
    mov     x2, #QUIC_ERR_PROTOCOL
    bl      quic_conn_close
    b       9f
72: tbz     x1, #0, 74f                     /* ack-eliciting: an ACK is due */
    ldr     x9, [x24, #SP_ACK_COUNT]
    add     x9, x9, #1
    str     x9, [x24, #SP_ACK_COUNT]
    cmp     x20, #SPACE_APP
    b.ne    73f
    cmp     x9, #2
    b.hs    73f
    ldr     x9, [x27, #ST_NOW]
    mov     x10, #25000                     /* our max_ack_delay */
    add     x9, x9, x10
    ldr     x10, [x24, #SP_ACK_AT]
    cmp     x9, x10
    csel    x10, x9, x10, lo
    str     x10, [x24, #SP_ACK_AT]
    b       74f
73: ldr     x9, [x24, #SP_FLAGS]
    orr     x9, x9, #SPF_ACK_NOW
    str     x9, [x24, #SP_FLAGS]
74: bl      quic_idle_reset
    ldr     x9, [x19, #C_ROLE]              /* a server: a Handshake packet validates the address and ends Initial */
    cbz     x9, 9f
    cmp     x20, #SPACE_HANDSHAKE
    b.ne    9f
    ldr     x9, [x19, #C_FLAGS]
    orr     x9, x9, #CF_VALIDATED
    str     x9, [x19, #C_FLAGS]
    mov     x0, #SPACE_INITIAL
    bl      quic_discard_space
9:  LEAVE   0
END_FUNCTION quic_packet_in

/*
 * quic_try_open(keys) -> 0 when the packet at x21 (x23 bytes, the packet
 * number at x22) opens with the keys: it is copied to the packet buffer of the
 * scratch and opened there, the result in SC_PKT_RESULT. Else the error;
 * the buffer then holds the first byte without header protection.
 * x24 the space record.
 */
LOCAL_FUNCTION quic_try_open
    ENTER   0
    mov     x25, x0
    add     x0, x28, #SC_PKT_BUF
    mov     x1, x21
    mov     x2, x23
    bl      quic_copy
    mov     x0, x25
    add     x1, x28, #SC_PKT_BUF
    mov     x2, x22
    mov     x3, x23
    ldr     x4, [x24, #SP_LARGEST_RECV]
    add     x5, x28, #SC_PKT_WORK
    add     x6, x28, #SC_PKT_RESULT
    bl      quic_open
    LEAVE   0
END_FUNCTION quic_try_open

/* ---------------------------------------------------------------- Frames */

/*
 * quic_frames(p, n, space) -> x0 0, -1 after a CONNECTION_CLOSE, or the error
 * code; x1 bit 0 when the packet is ack-eliciting. The frames of a packet in
 * order (RFC 9000 section 19); Initial and Handshake packets carry PADDING,
 * PING, ACK, CRYPTO and CONNECTION_CLOSE only (section 12.4).
 * x19 the connection, x20 position, x21 end, x22 space, x23 ack-eliciting, x24 type.
 */
LOCAL_FUNCTION quic_frames
    ENTER   0
    mov     x20, x0
    add     x21, x0, x1
    mov     x22, x2
    mov     x23, #0
    cbz     x1, 80f                         /* a packet with no frames */
1:  cmp     x20, x21
    b.hs    90f
    mov     x0, x20
    mov     x1, x21
    bl      quic_vget
    cbz     x0, 81f
    mov     x20, x0
    mov     x24, x1
    cmp     x24, #0x00
    b.eq    1b                              /* PADDING */
    cmp     x22, #SPACE_APP
    b.eq    2f
    cmp     x24, #0x01
    b.eq    2f
    cmp     x24, #0x02
    b.eq    2f
    cmp     x24, #0x03
    b.eq    2f
    cmp     x24, #0x06
    b.eq    2f
    cmp     x24, #0x1C
    b.eq    2f
    b       80f
2:  cmp     x24, #0x02
    b.eq    20f
    cmp     x24, #0x03
    b.eq    20f
    cmp     x24, #0x1C
    b.eq    28f
    cmp     x24, #0x1D
    b.eq    28f
    orr     x23, x23, #1                    /* every other frame is ack-eliciting */
    cmp     x24, #0x01
    b.eq    1b
    cmp     x24, #0x04
    b.eq    21f
    cmp     x24, #0x05
    b.eq    22f
    cmp     x24, #0x06
    b.eq    23f
    cmp     x24, #0x07
    b.eq    24f
    cmp     x24, #0x08
    b.lo    81f
    cmp     x24, #0x0F
    b.ls    25f
    cmp     x24, #0x10
    b.eq    30f
    cmp     x24, #0x11
    b.eq    31f
    cmp     x24, #0x12
    b.eq    32f
    cmp     x24, #0x13
    b.eq    33f
    cmp     x24, #0x14
    b.eq    33f
    cmp     x24, #0x15
    b.eq    34f
    cmp     x24, #0x16
    b.eq    33f
    cmp     x24, #0x17
    b.eq    33f
    cmp     x24, #0x18
    b.eq    35f
    cmp     x24, #0x19
    b.eq    36f
    cmp     x24, #0x1A
    b.eq    37f
    cmp     x24, #0x1B
    b.eq    38f
    cmp     x24, #0x1E
    b.eq    39f
    b       81f
20: mov     x0, x20                         /* ACK */
    mov     x1, x21
    mov     x2, x22
    mov     x3, x24
    bl      quic_frame_ack
    b       60f
21: mov     x0, x20                         /* RESET_STREAM */
    mov     x1, x21
    bl      quic_v3
    cbz     x0, 81f
    mov     x20, x0
    ldp     x0, x1, [x28, #SC_FRAME]
    ldr     x2, [x28, #(SC_FRAME + 16)]
    bl      quic_on_reset_stream
    b       61f
22: mov     x0, x20                         /* STOP_SENDING */
    mov     x1, x21
    bl      quic_v2
    cbz     x0, 81f
    mov     x20, x0
    ldp     x0, x1, [x28, #SC_FRAME]
    bl      quic_on_stop_sending
    b       61f
23: mov     x0, x20                         /* CRYPTO */
    mov     x1, x21
    bl      quic_v2
    cbz     x0, 81f
    ldr     x9, [x28, #(SC_FRAME + 8)]
    sub     x10, x21, x0
    cmp     x9, x10
    b.hi    81f
    add     x20, x0, x9
    mov     x2, x0
    mov     x0, x22
    ldr     x1, [x28, #SC_FRAME]
    mov     x3, x9
    bl      quic_on_crypto
    b       61f
24: ldr     x9, [x19, #C_ROLE]              /* NEW_TOKEN: for a client, not used */
    cbnz    x9, 80f
    mov     x0, x20
    mov     x1, x21
    bl      quic_vget
    cbz     x0, 81f
    sub     x10, x21, x0
    cmp     x1, x10
    b.hi    81f
    cbz     x1, 81f
    add     x20, x0, x1
    b       1b
25: mov     x0, x20                         /* STREAM */
    mov     x1, x21
    mov     x2, x24
    bl      quic_frame_stream
    b       60f
30: mov     x0, x20                         /* MAX_DATA */
    mov     x1, x21
    bl      quic_vget
    cbz     x0, 81f
    mov     x20, x0
    ldr     x9, [x19, #C_TX_MAX]
    cmp     x1, x9
    csel    x9, x1, x9, hi
    str     x9, [x19, #C_TX_MAX]
    b       1b
31: mov     x0, x20                         /* MAX_STREAM_DATA */
    mov     x1, x21
    bl      quic_v2
    cbz     x0, 81f
    mov     x20, x0
    ldp     x0, x1, [x28, #SC_FRAME]
    bl      quic_on_max_stream_data
    b       61f
32: mov     x0, x20                         /* MAX_STREAMS (bidirectional) */
    mov     x1, x21
    bl      quic_vget
    cbz     x0, 81f
    mov     x20, x0
    mov     x9, #1
    lsl     x9, x9, #60
    cmp     x1, x9
    b.hi    81f
    ldr     x9, [x19, #C_P_STREAMS]
    cmp     x1, x9
    b.ls    1b
    str     x1, [x19, #C_P_STREAMS]
    bl      quic_assign_ids
    b       1b
33: mov     x0, x20                         /* MAX_STREAMS (uni), DATA_BLOCKED, STREAMS_BLOCKED: one varint */
    mov     x1, x21
    bl      quic_vget
    cbz     x0, 81f
    mov     x20, x0
    b       1b
34: mov     x0, x20                         /* STREAM_DATA_BLOCKED: two varints */
    mov     x1, x21
    bl      quic_v2
    cbz     x0, 81f
    mov     x20, x0
    b       1b
35: mov     x0, x20                         /* NEW_CONNECTION_ID */
    mov     x1, x21
    bl      quic_frame_new_cid
    b       60f
36: mov     x0, x20                         /* RETIRE_CONNECTION_ID: we gave only sequence 0 */
    mov     x1, x21
    bl      quic_vget
    cbz     x0, 81f
    mov     x20, x0
    cbnz    x1, 80f
    b       1b
37: sub     x9, x21, x20                    /* PATH_CHALLENGE */
    cmp     x9, #8
    b.lo    81f
    ldr     x9, [x20], #8
    str     x9, [x19, #C_CHALLENGE]
    ldr     x9, [x19, #C_FLAGS]
    orr     x9, x9, #CF_CHALLENGE
    str     x9, [x19, #C_FLAGS]
    b       1b
38: sub     x9, x21, x20                    /* PATH_RESPONSE: we send no challenge */
    cmp     x9, #8
    b.lo    81f
    add     x20, x20, #8
    b       1b
39: ldr     x9, [x19, #C_ROLE]              /* HANDSHAKE_DONE: for a client */
    cbnz    x9, 80f
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_CONFIRMED
    b.ne    1b
    bl      quic_confirm
    b       1b
28: mov     x0, x20                         /* CONNECTION_CLOSE */
    mov     x1, x21
    mov     x2, x24
    bl      quic_frame_close
    cbz     x0, 81f
    mov     x0, #-1
    b       99f
60: cbz     x0, 81f                         /* x0 the position, x1 the error */
    cbnz    x1, 98f
    mov     x20, x0
    b       1b
61: cbnz    x0, 97f                         /* x0 the error */
    b       1b
80: mov     x0, #ERR_PROTOCOL
    b       99f
81: mov     x0, #ERR_FRAME_ENCODING
    b       99f
90: mov     x0, #0
    b       99f
97: b       99f
98: mov     x0, x1
99: mov     x1, x23
    LEAVE   0
END_FUNCTION quic_frames

/* quic_v2(p, end) -> the position after two varints, their values at SC_FRAME, or 0. */
LOCAL_FUNCTION quic_v2
    ENTER   0
    mov     x19, x1
    bl      quic_vget
    cbz     x0, 9f
    str     x1, [x28, #SC_FRAME]
    mov     x1, x19
    bl      quic_vget
    cbz     x0, 9f
    str     x1, [x28, #(SC_FRAME + 8)]
9:  LEAVE   0
END_FUNCTION quic_v2

/* quic_v3(p, end) -> the position after three varints, their values at SC_FRAME, or 0. */
LOCAL_FUNCTION quic_v3
    ENTER   0
    mov     x19, x1
    bl      quic_v2
    cbz     x0, 9f
    mov     x1, x19
    bl      quic_vget
    cbz     x0, 9f
    str     x1, [x28, #(SC_FRAME + 16)]
9:  LEAVE   0
END_FUNCTION quic_v3

/*
 * quic_frame_ack(p, end, space, type) -> x0 the position after the ACK frame
 * or 0; x1 0 or the error. Its ranges go to the area SC_OUT (at most 64; the
 * rest are not read for loss) and to quic_on_ack. An ACK of a packet number
 * never sent is a PROTOCOL_VIOLATION.
 * x19 the connection, x20 position, x21 end, x22 space, x23 ranges, x24 count, x25 smallest so far, x26 n kept.
 */
LOCAL_FUNCTION quic_frame_ack
    ENTER   0
    mov     x20, x0
    mov     x21, x1
    mov     x22, x2
    stp     x3, xzr, [x28, #(SC_FRAME + 32)]
    SCR     x23, SC_OUT
    mov     x0, x20
    mov     x1, x21
    bl      quic_v3                         /* largest, delay, range count */
    cbz     x0, 8f
    mov     x20, x0
    ldr     x9, [x28, #SC_FRAME]            /* the largest: below the next packet number */
    mov     x0, x19
    mov     x1, x22
    bl      quic_space
    ldr     x10, [x0, #SP_NEXT_PN]
    ldr     x9, [x28, #SC_FRAME]
    cmp     x9, x10
    b.hs    7f
    ldr     x24, [x28, #(SC_FRAME + 16)]
    ldr     x9, [x28, #(SC_FRAME + 8)]      /* the delay, in microseconds */
    ldr     x10, [x19, #C_P_ACK_EXP]
    lsl     x9, x9, x10
    str     x9, [x28, #(SC_FRAME + 24)]
    mov     x0, x20                         /* the first range */
    mov     x1, x21
    bl      quic_vget
    cbz     x0, 8f
    mov     x20, x0
    ldr     x9, [x28, #SC_FRAME]
    cmp     x1, x9
    b.hi    6f
    sub     x25, x9, x1
    stp     x25, x9, [x23]
    mov     x26, #1
1:  cbz     x24, 3f
    mov     x0, x20
    mov     x1, x21
    bl      quic_v2                         /* gap, length */
    cbz     x0, 8f
    mov     x20, x0
    ldp     x9, x10, [x28, #SC_FRAME]
    add     x11, x9, #2
    cmp     x11, x25
    b.hi    6f
    sub     x12, x25, x11                   /* the largest of this range */
    cmp     x10, x12
    b.hi    6f
    sub     x25, x12, x10
    cmp     x26, #64
    b.hs    2f
    add     x13, x23, x26, lsl #4
    stp     x25, x12, [x13]
    add     x26, x26, #1
2:  sub     x24, x24, #1
    b       1b
3:  ldr     x9, [x28, #(SC_FRAME + 32)]
    cmp     x9, #0x03
    b.ne    4f
    mov     x0, x20                         /* ECN counts */
    mov     x1, x21
    bl      quic_v3
    cbz     x0, 8f
    mov     x20, x0
4:  mov     x0, x22
    mov     x1, x23
    mov     x2, x26
    ldr     x3, [x28, #(SC_FRAME + 24)]
    bl      quic_on_ack
    mov     x0, x20
    mov     x1, #0
    b       9f
6:  mov     x0, x20
    mov     x1, #ERR_FRAME_ENCODING
    b       9f
7:  mov     x0, x20
    mov     x1, #ERR_PROTOCOL
    b       9f
8:  mov     x0, #0
    mov     x1, #0
9:  LEAVE   0
END_FUNCTION quic_frame_ack

/*
 * quic_frame_stream(p, end, type) -> x0 the position after the STREAM frame
 * or 0; x1 0 or the error.
 * x20 position, x21 end, x22 type, x23 id, x24 offset.
 */
LOCAL_FUNCTION quic_frame_stream
    ENTER   0
    mov     x20, x0
    mov     x21, x1
    mov     x22, x2
    mov     x1, x21
    bl      quic_vget
    cbz     x0, 8f
    mov     x20, x0
    mov     x23, x1
    mov     x24, #0
    tbz     x22, #2, 1f
    mov     x1, x21
    bl      quic_vget
    cbz     x0, 8f
    mov     x20, x0
    mov     x24, x1
1:  sub     x3, x21, x20                    /* no LEN: to the end of the packet */
    tbz     x22, #1, 2f
    mov     x0, x20
    mov     x1, x21
    bl      quic_vget
    cbz     x0, 8f
    mov     x20, x0
    sub     x9, x21, x20
    cmp     x1, x9
    b.hi    8f
    mov     x3, x1
2:  add     x25, x20, x3
    mov     x0, x23
    mov     x1, x24
    mov     x2, x20
    and     x4, x22, #1
    bl      quic_on_stream_frame
    mov     x1, x0
    mov     x0, x25
    b       9f
8:  mov     x0, #0
    mov     x1, #0
9:  LEAVE   0
END_FUNCTION quic_frame_stream

/*
 * quic_frame_close(p, end, type) -> the position after the CONNECTION_CLOSE
 * frame, or 0: the connection drains; the application hears the code.
 */
LOCAL_FUNCTION quic_frame_close
    ENTER   0
    mov     x20, x1
    mov     x21, x2
    bl      quic_vget                       /* the error code */
    cbz     x0, 8f
    mov     x22, x1
    cmp     x21, #0x1C
    b.ne    1f
    mov     x1, x20                         /* the frame type */
    bl      quic_vget
    cbz     x0, 8f
1:  mov     x1, x20                         /* the reason */
    bl      quic_vget
    cbz     x0, 8f
    sub     x9, x20, x0
    cmp     x1, x9
    b.hi    8f
    add     x23, x0, x1
    mov     x9, #QUIC_ERR_PEER
    str     x9, [x19, #C_REASON]
    mov     x0, x19
    mov     x1, x22
    bl      quic_conn_drain
    mov     x0, x23
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_frame_close

/*
 * quic_frame_new_cid(p, end) -> x0 the position after the NEW_CONNECTION_ID
 * frame, or 0; x1 0 or the error. We hold the peer's connection ID in use and
 * one spare (active_connection_id_limit 2); retire_prior_to moves us to the
 * spare and retires the old one.
 * x20 end, x21 seq, x22 retire_prior_to, x23 the ID, x24 its length, x25 the token.
 */
LOCAL_FUNCTION quic_frame_new_cid
    ENTER   0
    mov     x20, x1
    bl      quic_v2
    cbz     x0, 8f
    ldp     x21, x22, [x28, #SC_FRAME]
    cmp     x22, x21
    b.hi    7f
    cmp     x0, x20
    b.hs    8f
    ldrb    w24, [x0], #1
    cbz     x24, 7f
    cmp     x24, #QUIC_CID_MAX
    b.hi    7f
    mov     x23, x0
    add     x25, x23, x24
    add     x26, x25, #16
    cmp     x26, x20
    b.hi    8f
    ldr     x9, [x19, #(C_RCID + QUIC_CID_LENGTH)]
    cbz     x9, 6f                          /* the peer uses an empty ID */
    ldr     x9, [x19, #C_RCID_SEQ]
    cmp     x21, x9
    b.eq    5f                              /* known */
    ldr     x10, [x19, #C_NCID_SEQ]
    cmp     x21, x10
    b.eq    5f
    ldr     x9, [x19, #C_RETIRE_PRIOR]
    cmp     x22, x9
    csel    x9, x22, x9, hi
    str     x9, [x19, #C_RETIRE_PRIOR]
    cmp     x21, x9
    b.hs    1f
    str     x21, [x19, #C_RETIRE_SEQ]       /* retired already */
    b       4f
1:  ldr     x10, [x19, #C_NCID_SEQ]         /* the spare */
    cmn     x10, #1
    b.eq    2f
    cmp     x10, x9
    b.hs    3f
    str     x10, [x19, #C_RETIRE_SEQ]       /* the spare is retired: replace it */
2:  add     x0, x19, #C_NCID
    mov     x1, x23
    mov     x2, x24
    bl      quic_cid_put
    str     x21, [x19, #C_NCID_SEQ]
    ldp     x9, x10, [x25]
    add     x11, x19, #C_NCID_TOKEN
    stp     x9, x10, [x11]
    b       4f
3:  ldr     x9, [x19, #C_RCID_SEQ]          /* one more than the limit */
    ldr     x10, [x19, #C_RETIRE_PRIOR]
    cmp     x9, x10
    b.hs    71f
4:  ldr     x9, [x19, #C_RCID_SEQ]          /* move off a retired ID in use */
    ldr     x10, [x19, #C_RETIRE_PRIOR]
    cmp     x9, x10
    b.hs    5f
    ldr     x11, [x19, #C_NCID_SEQ]
    cmn     x11, #1
    b.eq    5f
    cmp     x11, x10
    b.lo    5f
    str     x9, [x19, #C_RETIRE_SEQ]
    add     x0, x19, #C_RCID
    add     x1, x19, #C_NCID
    mov     x2, #(QUIC_CID_SIZE + 8 + 16)
    bl      quic_copy
    mov     x9, #NONE
    str     x9, [x19, #C_NCID_SEQ]
    ldr     x9, [x19, #C_FLAGS]
    orr     x9, x9, #CF_RESET_TOKEN
    str     x9, [x19, #C_FLAGS]
5:  mov     x0, x26
    mov     x1, #0
    b       9f
6:  mov     x0, x26
    mov     x1, #ERR_PROTOCOL
    b       9f
7:  mov     x0, x26
    mov     x1, #ERR_FRAME_ENCODING
    b       9f
71: mov     x0, x26
    mov     x1, #ERR_CID_LIMIT
    b       9f
8:  mov     x0, #0
    mov     x1, #0
9:  LEAVE   0
END_FUNCTION quic_frame_new_cid

/*
 * quic_on_crypto(space, offset, data, len) -> 0 or the error code: CRYPTO
 * data joins the receive block of the space (at most 4 separate ranges, the
 * block CRYPTO_ROOM bytes), then TLS takes the messages that are complete.
 * x19 the connection, x20 the space record, x21 offset, x22 data, x23 len,
 * x24 the block, x25 space.
 */
LOCAL_FUNCTION quic_on_crypto
    ENTER   0
    mov     x25, x0
    mov     x21, x1
    mov     x22, x2
    mov     x23, x3
    mov     x0, x19
    mov     x1, x25
    bl      quic_space
    mov     x20, x0
    ldr     x24, [x20, #SP_CRX]
    cbnz    x24, 1f
    mov     x0, #CRYPTO_ROOM
    bl      quic_heap_alloc
    cbz     x0, 7f
    mov     x24, x0
    str     x24, [x20, #SP_CRX]
    str     xzr, [x20, #SP_CRX_BASE]
    str     xzr, [x20, #SP_CRX_DONE]
    str     xzr, [x20, #SP_CRX_NR]
1:  ldr     x9, [x20, #SP_CRX_BASE]
    add     x10, x21, x23
    cmp     x10, x9
    b.ls    8f                              /* taken already */
    cmp     x21, x9
    b.hs    2f
    sub     x11, x9, x21
    add     x22, x22, x11
    sub     x23, x23, x11
    mov     x21, x9
2:  sub     x21, x21, x9                    /* block offsets */
    add     x26, x21, x23
    cmp     x26, #CRYPTO_ROOM
    b.hi    6f
    cbz     x23, 8f
    ldr     x9, [x20, #SP_CRX_NR]           /* a fifth separate range does not fit */
    and     x9, x9, #0xFF
    cmp     x9, #4
    b.lo    3f
    mov     x0, x20
    mov     x1, x21
    mov     x2, x26
    bl      quic_crx_touches
    cbz     x0, 6f
3:  add     x0, x27, x24
    add     x0, x0, x21
    mov     x1, x22
    mov     x2, x23
    bl      quic_copy
    mov     x0, x20
    mov     x1, x21
    mov     x2, x26
    add     x3, x20, #SP_CRX_NR
    mov     x4, #4
    bl      quic_ranges_add
    mov     x0, x25
    bl      quic_tls_feed
    b       9f
6:  mov     x0, #ERR_CRYPTO_BUFFER
    b       9f
7:  mov     x0, #ERR_INTERNAL
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_on_crypto

/* quic_crx_touches(space, start, end) -> 1 when [start, end) touches a received CRYPTO range. A leaf. */
LOCAL_FUNCTION quic_crx_touches
    UNWIND_END_PROLOGUE
    ldr     x3, [x0, #SP_CRX_NR]
    and     x3, x3, #0xFF
    add     x4, x0, #SP_CRX_RANGES
1:  cbz     x3, 8f
    ldp     x5, x6, [x4], #16
    sub     x3, x3, #1
    cmp     x2, x5
    b.lo    1b
    cmp     x1, x6
    b.hi    1b
    mov     x0, #1
    ret
8:  mov     x0, #0
    ret
END_FUNCTION quic_crx_touches
