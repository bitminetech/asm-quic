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
 * ConnectionId, for its role. s1 the connection.
 */
.set II_KEYS, 0                         /* InitialKeys, 96 bytes */
.set II_FRAME, 96
LOCAL_FUNCTION quic_initial_install
    ENTER   0, II_FRAME
    mv      a1, a0
    addi    a0, sp, (FL + II_KEYS)
    call    quic_initial_derive
    addi    s2, s1, C_SPACES                # the Initial space
    ld      t0, C_ROLE(s1)
    addi    s3, sp, (FL + II_KEYS + QUIC_INITIAL_CLIENT)
    addi    s4, sp, (FL + II_KEYS + QUIC_INITIAL_SERVER)
    mv      a1, s3                          # receive: the peer's keys
    bnez    t0, 1f
    mv      a1, s4
1:  addi    a0, s2, SP_RX_KEYS
    li      a2, QUIC_KEYS_SIZE
    call    quic_copy
    ld      t0, C_ROLE(s1)
    mv      a1, s4
    bnez    t0, 2f
    mv      a1, s3
2:  addi    a0, s2, SP_TX_KEYS
    li      a2, QUIC_KEYS_SIZE
    call    quic_copy
    ld      t0, SP_FLAGS(s2)
    ori     t0, t0, (SPF_RX | SPF_TX)
    sd      t0, SP_FLAGS(s2)
    LEAVE   0, II_FRAME
END_FUNCTION quic_initial_install

/* quic_cid_put(cid, p, n): the ConnectionId cid = the n bytes at p (n at most 20). */
LOCAL_FUNCTION quic_cid_put
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    addi    a0, s1, QUIC_CID_ID
    li      a1, 24
    call    quic_zero
    sd      s3, QUIC_CID_LENGTH(s1)
    addi    a0, s1, QUIC_CID_ID
    mv      a1, s2
    mv      a2, s3
    call    quic_copy
    LEAVE   0
END_FUNCTION quic_cid_put

/* ---------------------------------------------------------------- Datagrams */

/*
 * quic_on_datagram(event): each packet of the datagram in turn (RFC 9000
 * section 12.2): long headers until a short one, which takes the rest.
 * s2 position, s3 end, s4 the datagram size, s5 the event, s6 the
 * connection of the first packet (for the amplification count),
 * s7 the packet start, s8 the connection.
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
    mv      s5, a0
    addi    s2, s5, QUIC_EV_DATA
    ld      s4, QUIC_EV_COUNT(s5)
    add     s3, s2, s4
    li      s6, 0
1:  bgeu    s2, s3, 9f
    mv      s7, s2
    lbu     t0, 0(s2)
    andi    t1, t0, 0x80
    beqz    t1, 50f
    /* A long header: the version, the connection IDs. */
    sub     t1, s3, s2
    li      t2, 7
    bltu    t1, t2, 9f
    lbu     t1, 1(s2)
    lbu     t2, 2(s2)
    lbu     t3, 3(s2)
    lbu     t4, 4(s2)
    slli    t1, t1, 24
    slli    t2, t2, 16
    or      t1, t1, t2
    slli    t3, t3, 8
    or      t1, t1, t3
    or      t1, t1, t4
    sd      t1, (FL + DG_VERSION)(sp)
    lbu     t2, 5(s2)
    li      t3, QUIC_CID_MAX
    bltu    t3, t2, 9f
    addi    t3, s2, 6
    sd      t3, (FL + DG_DCID)(sp)
    sd      t2, (FL + DG_DCID_LEN)(sp)
    add     t3, t3, t2
    bgeu    t3, s3, 9f
    lbu     t4, 0(t3)
    addi    t3, t3, 1
    li      t5, QUIC_CID_MAX
    bltu    t5, t4, 9f
    sd      t3, (FL + DG_SCID)(sp)
    sd      t4, (FL + DG_SCID_LEN)(sp)
    add     t3, t3, t4
    bltu    s3, t3, 9f
    ld      t1, (FL + DG_VERSION)(sp)
    beqz    t1, 40f                         # Version Negotiation
    li      t2, 1
    bne     t1, t2, 45f
    srli    t0, t0, 4
    andi    t0, t0, 3
    sd      t0, (FL + DG_TYPE)(sp)
    li      t2, 3
    beq     t0, t2, 42f                     # Retry
    sd      zero, (FL + DG_TOKEN_LEN)(sp)
    bnez    t0, 2f
    mv      a0, t3                          # Initial: the token
    mv      a1, s3
    call    quic_vget
    beqz    a0, 9f
    sub     t1, s3, a0
    bltu    t1, a1, 9f
    sd      a0, (FL + DG_TOKEN)(sp)
    sd      a1, (FL + DG_TOKEN_LEN)(sp)
    add     t3, a0, a1
2:  mv      a0, t3                          # Length
    mv      a1, s3
    call    quic_vget
    beqz    a0, 9f
    sub     t1, s3, a0
    bltu    t1, a1, 9f
    sd      a0, (FL + DG_PN_OFF)(sp)
    add     t1, a0, a1
    sd      t1, (FL + DG_END)(sp)
    ld      t0, (FL + DG_TYPE)(sp)
    li      t2, 1
    beq     t0, t2, 48f                     # 0-RTT: dropped
    /* The connection. */
    ld      a0, (FL + DG_DCID)(sp)
    ld      a1, (FL + DG_DCID_LEN)(sp)
    call    quic_conn_find
    bnez    a0, 3f
    ld      t0, (FL + DG_TYPE)(sp)
    bnez    t0, 48f
    ld      a0, (FL + DG_DCID)(sp)
    ld      a1, (FL + DG_DCID_LEN)(sp)
    ld      a2, QUIC_EV_SOCKET(s5)
    addi    a3, s5, QUIC_EV_ADDR
    call    quic_conn_find_odcid
    bnez    a0, 3f
    addi    a0, sp, (FL + DG_DCID)
    call    quic_accept
    beqz    a0, 9f
3:  mv      s8, a0
    bnez    s6, 31f
    mv      s6, s8
31: mv      s1, s8
    ld      t0, C_ROLE(s1)                  # a client takes the server's connection ID from its first packet
    bnez    t0, 32f
    ld      t0, C_FLAGS(s1)
    ANDV    t0, CF_GOT_PACKET
    bnez    t0, 32f
    ld      t0, (FL + DG_TYPE)(sp)
    li      t1, 2
    bltu    t1, t0, 32f
    addi    a0, s1, C_RCID
    ld      a1, (FL + DG_SCID)(sp)
    ld      a2, (FL + DG_SCID_LEN)(sp)
    call    quic_cid_put
    addi    a0, s1, C_ISCID
    ld      a1, (FL + DG_SCID)(sp)
    ld      a2, (FL + DG_SCID_LEN)(sp)
    call    quic_cid_put
32: ld      t0, (FL + DG_TYPE)(sp)
    li      a1, SPACE_INITIAL
    li      t1, 2
    bne     t0, t1, 33f
    li      a1, SPACE_HANDSHAKE
33: mv      a0, s1
    mv      a2, s7
    ld      a3, (FL + DG_PN_OFF)(sp)
    sub     a3, a3, s7
    ld      a4, (FL + DG_END)(sp)
    sub     a4, a4, s7
    call    quic_packet_in
    ld      s2, (FL + DG_END)(sp)
    j       1b
    /* A short header: our connection ID of 8 bytes, then the rest of the datagram. */
50: sub     t1, s3, s2
    li      t2, (1 + 8 + 20)
    bltu    t1, t2, 9f
    addi    a0, s2, 1
    li      a1, 8
    call    quic_conn_find
    beqz    a0, 9f
    mv      s8, a0
    bnez    s6, 51f
    mv      s6, s8
51: mv      s1, s8
    mv      a0, s1
    li      a1, SPACE_APP
    mv      a2, s2
    li      a3, 9
    sub     a4, s3, s2
    call    quic_packet_in
    j       9f
40: sd      t3, (FL + DG_END)(sp)           # Version Negotiation, for a client: the versions start here
    ld      a0, (FL + DG_DCID)(sp)
    ld      a1, (FL + DG_DCID_LEN)(sp)
    call    quic_conn_find
    beqz    a0, 9f
    mv      s1, a0
    ld      a0, (FL + DG_END)(sp)
    mv      a1, s3
    call    quic_on_vn
    j       9f
42: ld      a0, (FL + DG_DCID)(sp)          # Retry, for a client
    ld      a1, (FL + DG_DCID_LEN)(sp)
    call    quic_conn_find
    beqz    a0, 9f
    mv      s1, a0
    mv      a0, s7
    sub     a1, s3, s7
    ld      a2, (FL + DG_SCID)(sp)
    ld      a3, (FL + DG_SCID_LEN)(sp)
    call    quic_on_retry
    j       9f
45: CFG     t0, QUIC_CFG_FLAGS              # another version: Version Negotiation from a server
    andi    t0, t0, QUIC_CFG_ACCEPT
    beqz    t0, 9f
    li      t1, 1200
    bltu    s4, t1, 9f
    ld      a0, (FL + DG_DCID)(sp)
    ld      a1, (FL + DG_DCID_LEN)(sp)
    call    quic_conn_find
    bnez    a0, 9f
    addi    a0, sp, (FL + DG_DCID)
    call    quic_send_vn
    j       9f
48: ld      s2, (FL + DG_END)(sp)           # skip the packet
    j       1b
9:  beqz    s6, 99f
    LDX     t0, s6, C_RX_BYTES
    add     t0, t0, s4
    SDX     t0, s6, C_RX_BYTES
99: LEAVE   0, DG_FRAME
END_FUNCTION quic_on_datagram

/*
 * quic_accept(header) -> a new server connection for the first Initial of a
 * client, or 0: the server accepts, the datagram is at least 1200 bytes, the
 * Destination Connection ID is at least 8 bytes, and a slot is free.
 * header: the DG_* fields. s5 the event.
 */
LOCAL_FUNCTION quic_accept
    ENTER   0
    mv      s2, a0
    CFG     t0, QUIC_CFG_FLAGS
    andi    t0, t0, QUIC_CFG_ACCEPT
    beqz    t0, 8f
    ld      t0, QUIC_EV_COUNT(s5)
    li      t1, 1200
    bltu    t0, t1, 8f
    ld      t0, DG_DCID_LEN(s2)
    li      t1, 8
    bltu    t0, t1, 8f
    li      a0, 1
    call    quic_conn_new
    beqz    a0, 8f
    mv      s1, a0
    ld      t0, QUIC_EV_SOCKET(s5)
    sd      t0, C_SOCKET(s1)
    addi    a0, s1, C_ADDR
    addi    a1, s5, QUIC_EV_ADDR
    li      a2, QUIC_ADDR_SIZE
    call    quic_copy
    addi    a0, s1, C_ODCID
    ld      a1, DG_DCID(s2)
    ld      a2, DG_DCID_LEN(s2)
    call    quic_cid_put
    addi    a0, s1, C_RCID
    ld      a1, DG_SCID(s2)
    ld      a2, DG_SCID_LEN(s2)
    call    quic_cid_put
    addi    a0, s1, C_ISCID
    ld      a1, DG_SCID(s2)
    ld      a2, DG_SCID_LEN(s2)
    call    quic_cid_put
    addi    a0, s1, C_ODCID
    call    quic_initial_install
    LDX     t0, s1, C_TLS
    add     t0, s9, t0
    li      t1, TS_WAIT_CH
    sd      t1, T_STAGE(t0)
    call    quic_idle_reset
    mv      a0, s1
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_accept

/*
 * quic_send_vn(header): a Version Negotiation packet back to a client that
 * offered another version (RFC 9000 section 6.1): the connection IDs swapped,
 * version 1 the only one listed. header: the DG_* fields. s5 the event.
 */
LOCAL_FUNCTION quic_send_vn
    ENTER   0
    mv      s2, a0
    ld      t0, DG_DCID_LEN(s2)
    ld      t1, DG_SCID_LEN(s2)
    add     s3, t0, t1
    addi    s3, s3, 11                      # first byte, version, two lengths, one version
    addi    a1, s3, (QUIC_ACT_DATA + 7)
    andi    a1, a1, -8
    li      a0, QUIC_ACTION_SEND
    call    quic_action
    beqz    a0, 9f
    mv      s4, a0
    ld      t0, QUIC_EV_SOCKET(s5)
    sd      t0, QUIC_ACT_SOCKET(s4)
    addi    a0, s4, QUIC_ACT_ADDR
    addi    a1, s5, QUIC_EV_ADDR
    li      a2, QUIC_ADDR_SIZE
    call    quic_copy
    sd      s3, QUIC_ACT_COUNT(s4)
    addi    s6, s4, QUIC_ACT_DATA
    mv      a0, s6
    li      a1, 1
    call    quic_random
    lbu     t0, 0(s6)
    ori     t0, t0, 0x80
    sb      t0, 0(s6)
    sb      zero, 1(s6)
    sb      zero, 2(s6)
    sb      zero, 3(s6)
    sb      zero, 4(s6)
    ld      a2, DG_SCID_LEN(s2)
    sb      a2, 5(s6)
    addi    a0, s6, 6
    ld      a1, DG_SCID(s2)
    call    quic_copy
    ld      a2, DG_DCID_LEN(s2)
    sb      a2, 0(a0)
    addi    a0, a0, 1
    ld      a1, DG_DCID(s2)
    call    quic_copy
    sb      zero, 0(a0)
    sb      zero, 1(a0)
    sb      zero, 2(a0)
    li      t0, 1
    sb      t0, 3(a0)
9:  LEAVE   0
END_FUNCTION quic_send_vn

/*
 * quic_on_vn(p, end): Version Negotiation for a client before any packet of
 * the server: when it does not list version 1, the dial fails with
 * QUIC_ERR_VERSION (RFC 9000 section 6.2). s1 the connection.
 */
LOCAL_FUNCTION quic_on_vn
    ENTER   0
    mv      s2, a0
    mv      s3, a1
    ld      t0, C_ROLE(s1)
    bnez    t0, 9f
    ld      t0, C_FLAGS(s1)
    ANDV    t0, CF_GOT_PACKET
    bnez    t0, 9f
    ld      t0, C_STATE(s1)
    li      t1, CS_HANDSHAKE
    bne     t0, t1, 9f
1:  sub     t0, s3, s2
    li      t1, 4
    bltu    t0, t1, 2f
    lbu     t0, 0(s2)
    lbu     t1, 1(s2)
    lbu     t2, 2(s2)
    lbu     t3, 3(s2)
    addi    s2, s2, 4
    or      t0, t0, t1
    or      t0, t0, t2
    bnez    t0, 1b
    li      t1, 1
    beq     t3, t1, 9f                      # lists ours: ignored
    j       1b
2:  li      t0, QUIC_ERR_VERSION
    sd      t0, C_REASON(s1)
    mv      a0, s1
    li      a1, 0
    call    quic_conn_drain
    SDX     zero, s1, C_CLOSE_AT            # nothing to wait for
9:  LEAVE   0
END_FUNCTION quic_on_vn

/*
 * quic_on_retry(packet, n, scid, scid_len): a Retry for a client before any
 * other packet of the server, once (RFC 9000 section 17.2.5): with a valid
 * integrity tag, the server's connection ID and the token are taken, the
 * Initial keys change, and the ClientHello goes again in new Initial packets.
 * s1 the connection.
 * s2 packet, s3 n, s4 scid, s5 scid length.
 */
.set RY_TAG, 0
.set RY_PLAIN, 16                       /* ByteList: empty */
.set RY_SEALED, 40                      /* ByteList: 24 + 16 */
.set RY_NONCE, 80
.set RY_FRAME, 96
LOCAL_FUNCTION quic_on_retry
    ENTER   0, RY_FRAME
    mv      s2, a0
    mv      s3, a1
    mv      s4, a2
    mv      s5, a3
    ld      t0, C_ROLE(s1)
    bnez    t0, 9f
    ld      t0, C_FLAGS(s1)
    ANDV    t0, (CF_GOT_PACKET | CF_RETRIED)
    bnez    t0, 9f
    add     t0, s4, s5                      # the token: after the SCID, up to the tag
    add     t1, s2, s3
    addi    t1, t1, -16
    bgeu    t0, t1, 9f                      # no token
    addi    t0, s3, -16
    li      t1, W_SEALED_MAX
    bltu    t1, t0, 9f
    /* The pseudo-packet in the packet buffer of the scratch: ODCID, then the Retry without its tag. */
    addi    s6, s10, SC_PKT_BUF
    addi    s7, s3, -16
    ld      a2, (C_ODCID + QUIC_CID_LENGTH)(s1)
    add     s8, s7, a2
    addi    s8, s8, 1
    BYTELIST s6, 0, 1776, s8
    sb      a2, QUIC_BL_FIXED(s6)
    addi    a0, s6, (QUIC_BL_FIXED + 1)
    addi    a1, s1, (C_ODCID + QUIC_CID_ID)
    call    quic_copy
    mv      a1, s2
    mv      a2, s7
    call    quic_copy
    li      t1, 0
    BYTELIST sp, (FL + RY_PLAIN), 24, t1
    li      t0, 40
    sd      t0, (FL + RY_SEALED)(sp)
    sd      zero, (FL + RY_NONCE + 8)(sp)
    addi    a0, sp, (FL + RY_NONCE)
    lla     a1, 508b                        # the Retry nonce and key, in keys.s
    li      a2, 12
    call    quic_copy
    lla     a0, 507b
    addi    a1, sp, (FL + RY_NONCE)
    addi    a2, sp, (FL + RY_PLAIN)
    mv      a3, s6
    addi    a4, sp, (FL + RY_SEALED)
    CALL_GLOBAL crypto_aes128_gcm_ae
    addi    a0, sp, (FL + RY_SEALED + 24)
    add     a1, s2, s7
    li      a2, 16
    call    quic_equal
    beqz    a0, 9f
    /* Valid: the new connection ID, the token, new Initial keys. */
    ld      t0, C_FLAGS(s1)
    ORV     t0, CF_RETRIED
    sd      t0, C_FLAGS(s1)
    addi    a0, s1, C_RSCID
    mv      a1, s4
    mv      a2, s5
    call    quic_cid_put
    addi    a0, s1, C_RCID
    mv      a1, s4
    mv      a2, s5
    call    quic_cid_put
    add     s6, s4, s5                      # the token
    add     s7, s2, s3
    addi    s7, s7, -16
    sub     s7, s7, s6
    mv      a0, s7
    call    quic_heap_alloc
    beqz    a0, 9f
    sd      a0, C_TOKEN(s1)
    sd      s7, C_TOKEN_LEN(s1)
    add     a0, s9, a0
    mv      a1, s6
    mv      a2, s7
    call    quic_copy
    addi    a0, s1, C_RCID
    call    quic_initial_install
    li      a0, SPACE_INITIAL               # the Initial packets sent are gone; the ClientHello goes again
    call    quic_drop_space_records
    mv      a0, s1
    li      a1, SPACE_INITIAL
    call    quic_space
    sd      zero, SP_CTX_SENT(a0)
    SDX     zero, s1, C_PTO_COUNT
    call    quic_set_loss_timer
9:  LEAVE   0, RY_FRAME
END_FUNCTION quic_on_retry

/* ---------------------------------------------------------------- Packets */

/*
 * quic_packet_in(conn, space, packet, pn_offset, n): one packet of a
 * datagram: opened with the keys of its space (the next or the previous key
 * phase for a 1-RTT packet), checked, its packet number recorded, and its
 * frames handled. A packet that does not open is dropped; a 1-RTT one may be
 * a stateless reset.
 * s1 conn, s2 space, s3 packet, s4 pn offset, s5 n, s6 the space record.
 */
LOCAL_FUNCTION quic_packet_in
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    mv      s4, a3
    mv      s5, a4
    mv      a0, s1
    mv      a1, s2
    call    quic_space
    mv      s6, a0
    ld      t0, C_STATE(s1)
    li      t1, CS_DRAINING
    bgeu    t0, t1, 9f
    ld      t0, SP_FLAGS(s6)
    andi    t1, t0, SPF_RX
    beqz    t1, 9f
    andi    t1, t0, SPF_DISCARDED
    bnez    t1, 9f
    li      t0, (W_HEADER_MAX + W_SEALED_MAX)
    bltu    t0, s5, 9f
    addi    a0, s6, SP_RX_KEYS
    call    quic_try_open
    beqz    a0, 5f
    li      t0, SPACE_APP                   # 1-RTT: another key phase?
    bne     s2, t0, 4f
    lbu     t0, SC_PKT_BUF(s10)
    srli    t0, t0, 2
    andi    t0, t0, 1
    LDX     t1, s1, C_KEY_PHASE
    beq     t0, t1, 4f
    ADDX    a0, s1, C_NEXT_RX
    call    quic_try_open
    bnez    a0, 2f
    ld      t0, SC_PKT_RESULT(s10)          # the next phase must be newer than the current one
    LDX     t1, s1, C_PHASE_PN
    li      t2, -1
    beq     t1, t2, 1f
    bgeu    t1, t0, 2f
1:  call    quic_key_update                 # the peer moved to the next key phase
    call    quic_phase_start
    ld      t0, SC_PKT_RESULT(s10)
    SDX     t0, s1, C_PHASE_PN
    j       5f
2:  LDX     t0, s1, C_PREV_UNTIL            # a late packet of the previous phase
    ld      t1, ST_NOW(s9)
    li      t2, -1
    beq     t0, t2, 4f
    bgeu    t1, t0, 4f
    ADDX    a0, s1, C_PREV_RX
    call    quic_try_open
    beqz    a0, 5f
4:  li      t0, SPACE_APP                   # a stateless reset? (RFC 9000 section 10.3.1)
    bne     s2, t0, 9f
    ld      t0, C_FLAGS(s1)
    ANDV    t0, CF_RESET_TOKEN
    beqz    t0, 9f
    add     a0, s3, s5
    addi    a0, a0, -16
    addi    a1, s1, C_RCID_TOKEN
    li      a2, 16
    call    quic_equal
    beqz    a0, 9f
    li      t0, QUIC_ERR_RESET
    sd      t0, C_REASON(s1)
    mv      a0, s1
    li      a1, 0
    call    quic_conn_drain
    j       9f
5:  /* Opened: the reserved bits, duplicates, then the frames. */
    lbu     t0, SC_PKT_BUF(s10)
    li      t1, 0x18
    andi    t2, t0, 0x80
    beqz    t2, 51f
    li      t1, 0x0C
51: and     t0, t0, t1
    beqz    t0, 6f
    mv      a0, s1
    li      a1, ERR_PROTOCOL
    li      a2, QUIC_ERR_PROTOCOL
    call    quic_conn_close
    j       9f
6:  ld      t0, C_STATE(s1)
    li      t1, CS_CLOSING
    bne     t0, t1, 61f
    ld      t0, C_FLAGS(s1)                 # closing: answer with CONNECTION_CLOSE again
    ori     t0, t0, CF_CLOSE_FRAME
    sd      t0, C_FLAGS(s1)
    j       9f
61: ld      s4, SC_PKT_RESULT(s10)          # the packet number
    mv      a0, s6
    mv      a1, s4
    call    quic_recv_pn
    bnez    a0, 9f
    ld      t0, SP_LARGEST_RECV(s6)
    li      t1, -1
    beq     t0, t1, 7f
    bgeu    t0, s4, 71f
7:  sd      s4, SP_LARGEST_RECV(s6)
    ld      t0, ST_NOW(s9)
    sd      t0, SP_RECV_TIME(s6)
71: ld      t0, C_FLAGS(s1)
    ORV     t0, CF_GOT_PACKET
    BICV    t0, CF_ELICIT_SENT
    sd      t0, C_FLAGS(s1)
    ld      t0, (SC_PKT_RESULT + 8)(s10)
    addi    a0, s10, SC_PKT_BUF
    add     a0, a0, t0
    ld      a1, (SC_PKT_RESULT + 16)(s10)
    mv      a2, s2
    call    quic_frames
    beqz    a0, 72f
    li      t0, -1
    beq     a0, t0, 9f                      # CONNECTION_CLOSE: draining
    mv      a1, a0
    mv      a0, s1
    li      a2, QUIC_ERR_PROTOCOL
    call    quic_conn_close
    j       9f
72: andi    t0, a1, 1                       # ack-eliciting: an ACK is due
    beqz    t0, 74f
    ld      t0, SP_ACK_COUNT(s6)
    addi    t0, t0, 1
    sd      t0, SP_ACK_COUNT(s6)
    li      t1, SPACE_APP
    bne     s2, t1, 73f
    li      t1, 2
    bgeu    t0, t1, 73f
    ld      t0, ST_NOW(s9)
    li      t1, 25000                       # our max_ack_delay
    add     t0, t0, t1
    ld      t1, SP_ACK_AT(s6)
    bgeu    t0, t1, 75f
    mv      t1, t0
75: sd      t1, SP_ACK_AT(s6)
    j       74f
73: ld      t0, SP_FLAGS(s6)
    ori     t0, t0, SPF_ACK_NOW
    sd      t0, SP_FLAGS(s6)
74: call    quic_idle_reset
    ld      t0, C_ROLE(s1)                  # a server: a Handshake packet validates the address and ends Initial
    beqz    t0, 9f
    li      t1, SPACE_HANDSHAKE
    bne     s2, t1, 9f
    ld      t0, C_FLAGS(s1)
    ori     t0, t0, CF_VALIDATED
    sd      t0, C_FLAGS(s1)
    li      a0, SPACE_INITIAL
    call    quic_discard_space
9:  LEAVE   0
END_FUNCTION quic_packet_in

/*
 * quic_try_open(keys) -> 0 when the packet at s3 (s5 bytes, the packet
 * number at s4) opens with the keys: it is copied to the packet buffer of the
 * scratch and opened there (quic_unprotect, then quic_open), the result in
 * SC_PKT_RESULT. Else the error; when quic_unprotect gave QUIC_OK, the buffer
 * then holds the packet without header protection.
 * s6 the space record.
 */
LOCAL_FUNCTION quic_try_open
    ENTER   0
    mv      s7, a0
    addi    a0, s10, SC_PKT_BUF
    mv      a1, s3
    mv      a2, s5
    call    quic_copy
    mv      a0, s7
    addi    a1, s10, SC_PKT_BUF
    mv      a2, s4
    mv      a3, s5
    SCR     a4, SC_PKT_WORK
    call    quic_unprotect
    bnez    a0, 9f
    mv      a0, s7
    addi    a1, s10, SC_PKT_BUF
    mv      a2, s4
    mv      a3, s5
    ld      a4, SP_LARGEST_RECV(s6)
    SCR     a5, SC_PKT_WORK
    addi    a6, s10, SC_PKT_RESULT
    call    quic_open
9:  LEAVE   0
END_FUNCTION quic_try_open

/* ---------------------------------------------------------------- Frames */

/*
 * quic_frames(p, n, space) -> a0 0, -1 after a CONNECTION_CLOSE, or the error
 * code; a1 bit 0 when the packet is ack-eliciting. The frames of a packet in
 * order (RFC 9000 section 19); Initial and Handshake packets carry PADDING,
 * PING, ACK, CRYPTO and CONNECTION_CLOSE only (section 12.4).
 * s1 the connection, s2 position, s3 end, s4 space, s5 ack-eliciting, s6 type.
 */
LOCAL_FUNCTION quic_frames
    ENTER   0
    mv      s2, a0
    add     s3, a0, a1
    mv      s4, a2
    li      s5, 0
    beqz    a1, 80f                         # a packet with no frames
1:  bgeu    s2, s3, 90f
    mv      a0, s2
    mv      a1, s3
    call    quic_vget
    beqz    a0, 81f
    mv      s2, a0
    mv      s6, a1
    beqz    s6, 1b                          # PADDING
    li      t0, SPACE_APP
    beq     s4, t0, 2f
    li      t0, 0x01
    beq     s6, t0, 2f
    li      t0, 0x02
    beq     s6, t0, 2f
    li      t0, 0x03
    beq     s6, t0, 2f
    li      t0, 0x06
    beq     s6, t0, 2f
    li      t0, 0x1C
    beq     s6, t0, 2f
    j       80f
2:  li      t0, 0x02
    beq     s6, t0, 20f
    li      t0, 0x03
    beq     s6, t0, 20f
    li      t0, 0x1C
    beq     s6, t0, 28f
    li      t0, 0x1D
    beq     s6, t0, 28f
    ori     s5, s5, 1                       # every other frame is ack-eliciting
    li      t0, 0x01
    beq     s6, t0, 1b
    li      t0, 0x04
    beq     s6, t0, 21f
    li      t0, 0x05
    beq     s6, t0, 22f
    li      t0, 0x06
    beq     s6, t0, 23f
    li      t0, 0x07
    beq     s6, t0, 24f
    li      t0, 0x08
    bltu    s6, t0, 81f
    li      t0, 0x0F
    bgeu    t0, s6, 25f
    li      t0, 0x10
    beq     s6, t0, 30f
    li      t0, 0x11
    beq     s6, t0, 31f
    li      t0, 0x12
    beq     s6, t0, 32f
    li      t0, 0x13
    beq     s6, t0, 33f
    li      t0, 0x14
    beq     s6, t0, 33f
    li      t0, 0x15
    beq     s6, t0, 34f
    li      t0, 0x16
    beq     s6, t0, 33f
    li      t0, 0x17
    beq     s6, t0, 33f
    li      t0, 0x18
    beq     s6, t0, 35f
    li      t0, 0x19
    beq     s6, t0, 36f
    li      t0, 0x1A
    beq     s6, t0, 37f
    li      t0, 0x1B
    beq     s6, t0, 38f
    li      t0, 0x1E
    beq     s6, t0, 39f
    j       81f
20: mv      a0, s2                          # ACK
    mv      a1, s3
    mv      a2, s4
    mv      a3, s6
    call    quic_frame_ack
    j       60f
21: mv      a0, s2                          # RESET_STREAM
    mv      a1, s3
    call    quic_v3
    beqz    a0, 81f
    mv      s2, a0
    ld      a0, SC_FRAME(s10)
    ld      a1, (SC_FRAME + 8)(s10)
    ld      a2, (SC_FRAME + 16)(s10)
    call    quic_on_reset_stream
    j       61f
22: mv      a0, s2                          # STOP_SENDING
    mv      a1, s3
    call    quic_v2
    beqz    a0, 81f
    mv      s2, a0
    ld      a0, SC_FRAME(s10)
    ld      a1, (SC_FRAME + 8)(s10)
    call    quic_on_stop_sending
    j       61f
23: mv      a0, s2                          # CRYPTO
    mv      a1, s3
    call    quic_v2
    beqz    a0, 81f
    ld      t0, (SC_FRAME + 8)(s10)
    sub     t1, s3, a0
    bltu    t1, t0, 81f
    add     s2, a0, t0
    mv      a2, a0
    mv      a0, s4
    ld      a1, SC_FRAME(s10)
    mv      a3, t0
    call    quic_on_crypto
    j       61f
24: ld      t0, C_ROLE(s1)                  # NEW_TOKEN: for a client, not used
    bnez    t0, 80f
    mv      a0, s2
    mv      a1, s3
    call    quic_vget
    beqz    a0, 81f
    sub     t1, s3, a0
    bltu    t1, a1, 81f
    beqz    a1, 81f
    add     s2, a0, a1
    j       1b
25: mv      a0, s2                          # STREAM
    mv      a1, s3
    mv      a2, s6
    call    quic_frame_stream
    j       60f
30: mv      a0, s2                          # MAX_DATA
    mv      a1, s3
    call    quic_vget
    beqz    a0, 81f
    mv      s2, a0
    LDX     t0, s1, C_TX_MAX
    bgeu    t0, a1, 1b
    SDX     a1, s1, C_TX_MAX
    j       1b
31: mv      a0, s2                          # MAX_STREAM_DATA
    mv      a1, s3
    call    quic_v2
    beqz    a0, 81f
    mv      s2, a0
    ld      a0, SC_FRAME(s10)
    ld      a1, (SC_FRAME + 8)(s10)
    call    quic_on_max_stream_data
    j       61f
32: mv      a0, s2                          # MAX_STREAMS (bidirectional)
    mv      a1, s3
    call    quic_vget
    beqz    a0, 81f
    mv      s2, a0
    li      t0, 1
    slli    t0, t0, 60
    bltu    t0, a1, 81f
    LDX     t0, s1, C_P_STREAMS
    bgeu    t0, a1, 1b
    SDX     a1, s1, C_P_STREAMS
    call    quic_assign_ids
    j       1b
33: mv      a0, s2                          # MAX_STREAMS (uni), DATA_BLOCKED, STREAMS_BLOCKED: one varint
    mv      a1, s3
    call    quic_vget
    beqz    a0, 81f
    mv      s2, a0
    j       1b
34: mv      a0, s2                          # STREAM_DATA_BLOCKED: two varints
    mv      a1, s3
    call    quic_v2
    beqz    a0, 81f
    mv      s2, a0
    j       1b
35: mv      a0, s2                          # NEW_CONNECTION_ID
    mv      a1, s3
    call    quic_frame_new_cid
    j       60f
36: mv      a0, s2                          # RETIRE_CONNECTION_ID: we gave only sequence 0
    mv      a1, s3
    call    quic_vget
    beqz    a0, 81f
    mv      s2, a0
    bnez    a1, 80f
    j       1b
37: sub     t0, s3, s2                      # PATH_CHALLENGE
    li      t1, 8
    bltu    t0, t1, 81f
    ADDX    a0, s1, C_CHALLENGE
    mv      a1, s2
    li      a2, 8
    call    quic_copy
    addi    s2, s2, 8
    ld      t0, C_FLAGS(s1)
    ORV     t0, CF_CHALLENGE
    sd      t0, C_FLAGS(s1)
    j       1b
38: sub     t0, s3, s2                      # PATH_RESPONSE: we send no challenge
    li      t1, 8
    bltu    t0, t1, 81f
    addi    s2, s2, 8
    j       1b
39: ld      t0, C_ROLE(s1)                  # HANDSHAKE_DONE: for a client
    bnez    t0, 80f
    ld      t0, C_FLAGS(s1)
    andi    t0, t0, CF_CONFIRMED
    bnez    t0, 1b
    call    quic_confirm
    j       1b
28: mv      a0, s2                          # CONNECTION_CLOSE
    mv      a1, s3
    mv      a2, s6
    call    quic_frame_close
    beqz    a0, 81f
    li      a0, -1
    j       99f
60: beqz    a0, 81f                         # a0 the position, a1 the error
    bnez    a1, 98f
    mv      s2, a0
    j       1b
61: bnez    a0, 97f                         # a0 the error
    j       1b
80: li      a0, ERR_PROTOCOL
    j       99f
81: li      a0, ERR_FRAME_ENCODING
    j       99f
90: li      a0, 0
    j       99f
97: j       99f
98: mv      a0, a1
99: mv      a1, s5
    LEAVE   0
END_FUNCTION quic_frames

/* quic_v2(p, end) -> the position after two varints, their values at SC_FRAME, or 0. */
LOCAL_FUNCTION quic_v2
    ENTER   0
    mv      s1, a1
    call    quic_vget
    beqz    a0, 9f
    sd      a1, SC_FRAME(s10)
    mv      a1, s1
    call    quic_vget
    beqz    a0, 9f
    sd      a1, (SC_FRAME + 8)(s10)
9:  LEAVE   0
END_FUNCTION quic_v2

/* quic_v3(p, end) -> the position after three varints, their values at SC_FRAME, or 0. */
LOCAL_FUNCTION quic_v3
    ENTER   0
    mv      s1, a1
    call    quic_v2
    beqz    a0, 9f
    mv      a1, s1
    call    quic_vget
    beqz    a0, 9f
    sd      a1, (SC_FRAME + 16)(s10)
9:  LEAVE   0
END_FUNCTION quic_v3

/*
 * quic_frame_ack(p, end, space, type) -> a0 the position after the ACK frame
 * or 0; a1 0 or the error. Its ranges go to the area SC_OUT (at most 64; the
 * rest are not read for loss) and to quic_on_ack. An ACK of a packet number
 * never sent is a PROTOCOL_VIOLATION.
 * s1 the connection, s2 position, s3 end, s4 space, s5 ranges, s6 count, s7 smallest so far, s8 n kept.
 */
LOCAL_FUNCTION quic_frame_ack
    ENTER   0
    mv      s2, a0
    mv      s3, a1
    mv      s4, a2
    sd      a3, (SC_FRAME + 32)(s10)
    sd      zero, (SC_FRAME + 40)(s10)
    SCR     s5, SC_OUT
    mv      a0, s2
    mv      a1, s3
    call    quic_v3                         # largest, delay, range count
    beqz    a0, 8f
    mv      s2, a0
    mv      a0, s1                          # the largest: below the next packet number
    mv      a1, s4
    call    quic_space
    ld      t1, SP_NEXT_PN(a0)
    ld      t0, SC_FRAME(s10)
    bgeu    t0, t1, 7f
    ld      s6, (SC_FRAME + 16)(s10)
    ld      t0, (SC_FRAME + 8)(s10)         # the delay, in microseconds
    LDX     t1, s1, C_P_ACK_EXP
    sll     t0, t0, t1
    sd      t0, (SC_FRAME + 24)(s10)
    mv      a0, s2                          # the first range
    mv      a1, s3
    call    quic_vget
    beqz    a0, 8f
    mv      s2, a0
    ld      t0, SC_FRAME(s10)
    bltu    t0, a1, 6f
    sub     s7, t0, a1
    sd      s7, 0(s5)
    sd      t0, 8(s5)
    li      s8, 1
1:  beqz    s6, 3f
    mv      a0, s2
    mv      a1, s3
    call    quic_v2                         # gap, length
    beqz    a0, 8f
    mv      s2, a0
    ld      t0, SC_FRAME(s10)
    ld      t1, (SC_FRAME + 8)(s10)
    addi    t2, t0, 2
    bltu    s7, t2, 6f
    sub     t3, s7, t2                      # the largest of this range
    bltu    t3, t1, 6f
    sub     s7, t3, t1
    li      t4, 64
    bgeu    s8, t4, 2f
    slli    t4, s8, 4
    add     t4, s5, t4
    sd      s7, 0(t4)
    sd      t3, 8(t4)
    addi    s8, s8, 1
2:  addi    s6, s6, -1
    j       1b
3:  ld      t0, (SC_FRAME + 32)(s10)
    li      t1, 0x03
    bne     t0, t1, 4f
    mv      a0, s2                          # ECN counts
    mv      a1, s3
    call    quic_v3
    beqz    a0, 8f
    mv      s2, a0
4:  mv      a0, s4
    mv      a1, s5
    mv      a2, s8
    ld      a3, (SC_FRAME + 24)(s10)
    call    quic_on_ack
    mv      a0, s2
    li      a1, 0
    j       9f
6:  mv      a0, s2
    li      a1, ERR_FRAME_ENCODING
    j       9f
7:  mv      a0, s2
    li      a1, ERR_PROTOCOL
    j       9f
8:  li      a0, 0
    li      a1, 0
9:  LEAVE   0
END_FUNCTION quic_frame_ack

/*
 * quic_frame_stream(p, end, type) -> a0 the position after the STREAM frame
 * or 0; a1 0 or the error.
 * s2 position, s3 end, s4 type, s5 id, s6 offset, s7 the frame end.
 */
LOCAL_FUNCTION quic_frame_stream
    ENTER   0
    mv      s2, a0
    mv      s3, a1
    mv      s4, a2
    mv      a1, s3
    call    quic_vget
    beqz    a0, 8f
    mv      s2, a0
    mv      s5, a1
    li      s6, 0
    andi    t0, s4, 4
    beqz    t0, 1f
    mv      a1, s3
    call    quic_vget
    beqz    a0, 8f
    mv      s2, a0
    mv      s6, a1
1:  sub     a3, s3, s2                      # no LEN: to the end of the packet
    andi    t0, s4, 2
    beqz    t0, 2f
    mv      a0, s2
    mv      a1, s3
    call    quic_vget
    beqz    a0, 8f
    mv      s2, a0
    sub     t0, s3, s2
    bltu    t0, a1, 8f
    mv      a3, a1
2:  add     s7, s2, a3
    mv      a0, s5
    mv      a1, s6
    mv      a2, s2
    andi    a4, s4, 1
    call    quic_on_stream_frame
    mv      a1, a0
    mv      a0, s7
    j       9f
8:  li      a0, 0
    li      a1, 0
9:  LEAVE   0
END_FUNCTION quic_frame_stream

/*
 * quic_frame_close(p, end, type) -> the position after the CONNECTION_CLOSE
 * frame, or 0: the connection drains; the application hears the code.
 */
LOCAL_FUNCTION quic_frame_close
    ENTER   0
    mv      s2, a1
    mv      s3, a2
    call    quic_vget                       # the error code
    beqz    a0, 8f
    mv      s4, a1
    li      t0, 0x1C
    bne     s3, t0, 1f
    mv      a1, s2                          # the frame type
    call    quic_vget
    beqz    a0, 8f
1:  mv      a1, s2                          # the reason
    call    quic_vget
    beqz    a0, 8f
    sub     t0, s2, a0
    bltu    t0, a1, 8f
    add     s5, a0, a1
    li      t0, QUIC_ERR_PEER
    sd      t0, C_REASON(s1)
    mv      a0, s1
    mv      a1, s4
    call    quic_conn_drain
    mv      a0, s5
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_frame_close

/*
 * quic_frame_new_cid(p, end) -> a0 the position after the NEW_CONNECTION_ID
 * frame, or 0; a1 0 or the error. We hold the peer's connection ID in use and
 * one spare (active_connection_id_limit 2); retire_prior_to moves us to the
 * spare and retires the old one.
 * s2 end, s3 seq, s4 retire_prior_to, s5 the ID, s6 its length, s7 the token, s8 the frame end.
 */
LOCAL_FUNCTION quic_frame_new_cid
    ENTER   0
    mv      s2, a1
    call    quic_v2
    beqz    a0, 8f
    ld      s3, SC_FRAME(s10)
    ld      s4, (SC_FRAME + 8)(s10)
    bltu    s3, s4, 7f
    bgeu    a0, s2, 8f
    lbu     s6, 0(a0)
    addi    a0, a0, 1
    beqz    s6, 7f
    li      t0, QUIC_CID_MAX
    bltu    t0, s6, 7f
    mv      s5, a0
    add     s7, s5, s6
    addi    s8, s7, 16
    bltu    s2, s8, 8f
    ld      t0, (C_RCID + QUIC_CID_LENGTH)(s1)
    beqz    t0, 6f                          # the peer uses an empty ID
    ld      t0, C_RCID_SEQ(s1)
    beq     s3, t0, 5f                      # known
    ld      t1, C_NCID_SEQ(s1)
    beq     s3, t1, 5f
    ld      t0, C_RETIRE_PRIOR(s1)
    bgeu    t0, s4, 11f
    mv      t0, s4
11: sd      t0, C_RETIRE_PRIOR(s1)
    bgeu    s3, t0, 1f
    sd      s3, C_RETIRE_SEQ(s1)            # retired already
    j       4f
1:  ld      t1, C_NCID_SEQ(s1)              # the spare
    li      t2, -1
    beq     t1, t2, 2f
    bgeu    t1, t0, 3f
    sd      t1, C_RETIRE_SEQ(s1)            # the spare is retired: replace it
2:  addi    a0, s1, C_NCID
    mv      a1, s5
    mv      a2, s6
    call    quic_cid_put
    sd      s3, C_NCID_SEQ(s1)
    addi    a0, s1, C_NCID_TOKEN
    mv      a1, s7
    li      a2, 16
    call    quic_copy
    j       4f
3:  ld      t0, C_RCID_SEQ(s1)              # one more than the limit
    ld      t1, C_RETIRE_PRIOR(s1)
    bgeu    t0, t1, 71f
4:  ld      t0, C_RCID_SEQ(s1)              # move off a retired ID in use
    ld      t1, C_RETIRE_PRIOR(s1)
    bgeu    t0, t1, 5f
    ld      t2, C_NCID_SEQ(s1)
    li      t3, -1
    beq     t2, t3, 5f
    bltu    t2, t1, 5f
    sd      t0, C_RETIRE_SEQ(s1)
    addi    a0, s1, C_RCID
    addi    a1, s1, C_NCID
    li      a2, (QUIC_CID_SIZE + 8 + 16)
    call    quic_copy
    li      t0, NONE
    sd      t0, C_NCID_SEQ(s1)
    ld      t0, C_FLAGS(s1)
    ORV     t0, CF_RESET_TOKEN
    sd      t0, C_FLAGS(s1)
5:  mv      a0, s8
    li      a1, 0
    j       9f
6:  mv      a0, s8
    li      a1, ERR_PROTOCOL
    j       9f
7:  mv      a0, s8
    li      a1, ERR_FRAME_ENCODING
    j       9f
71: mv      a0, s8
    li      a1, ERR_CID_LIMIT
    j       9f
8:  li      a0, 0
    li      a1, 0
9:  LEAVE   0
END_FUNCTION quic_frame_new_cid

/*
 * quic_on_crypto(space, offset, data, len) -> 0 or the error code: CRYPTO
 * data joins the receive block of the space (at most 4 separate ranges, the
 * block CRYPTO_ROOM bytes), then TLS takes the messages that are complete.
 * s1 the connection, s2 the space record, s3 offset, s4 data, s5 len,
 * s6 the block, s7 space, s8 end.
 */
LOCAL_FUNCTION quic_on_crypto
    ENTER   0
    mv      s7, a0
    mv      s3, a1
    mv      s4, a2
    mv      s5, a3
    mv      a0, s1
    mv      a1, s7
    call    quic_space
    mv      s2, a0
    ld      s6, SP_CRX(s2)
    bnez    s6, 1f
    li      a0, CRYPTO_ROOM
    call    quic_heap_alloc
    beqz    a0, 7f
    mv      s6, a0
    sd      s6, SP_CRX(s2)
    sd      zero, SP_CRX_BASE(s2)
    sd      zero, SP_CRX_DONE(s2)
    sd      zero, SP_CRX_NR(s2)
1:  ld      t0, SP_CRX_BASE(s2)
    add     t1, s3, s5
    bgeu    t0, t1, 8f                      # taken already
    bgeu    s3, t0, 2f
    sub     t2, t0, s3
    add     s4, s4, t2
    sub     s5, s5, t2
    mv      s3, t0
2:  sub     s3, s3, t0                      # block offsets
    add     s8, s3, s5
    li      t1, CRYPTO_ROOM
    bltu    t1, s8, 6f
    beqz    s5, 8f
    ld      t0, SP_CRX_NR(s2)               # a fifth separate range does not fit
    andi    t0, t0, 0xFF
    li      t1, 4
    bltu    t0, t1, 3f
    mv      a0, s2
    mv      a1, s3
    mv      a2, s8
    call    quic_crx_touches
    beqz    a0, 6f
3:  add     a0, s9, s6
    add     a0, a0, s3
    mv      a1, s4
    mv      a2, s5
    call    quic_copy
    mv      a0, s2
    mv      a1, s3
    mv      a2, s8
    addi    a3, s2, SP_CRX_NR
    li      a4, 4
    call    quic_ranges_add
    mv      a0, s7
    call    quic_tls_feed
    j       9f
6:  li      a0, ERR_CRYPTO_BUFFER
    j       9f
7:  li      a0, ERR_INTERNAL
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_on_crypto

/* quic_crx_touches(space, start, end) -> 1 when [start, end) touches a received CRYPTO range. A leaf. */
LOCAL_FUNCTION quic_crx_touches
    UNWIND_END_PROLOGUE
    ld      a3, SP_CRX_NR(a0)
    andi    a3, a3, 0xFF
    addi    a4, a0, SP_CRX_RANGES
1:  beqz    a3, 8f
    ld      a5, 0(a4)
    ld      a6, 8(a4)
    addi    a4, a4, 16
    addi    a3, a3, -1
    bltu    a2, a5, 1b
    bltu    a6, a1, 1b
    li      a0, 1
    ret
8:  li      a0, 0
    ret
END_FUNCTION quic_crx_touches
