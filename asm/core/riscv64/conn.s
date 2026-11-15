/*
 * Connections: slots, connection IDs, the start of each role, closing and
 * draining (RFC 9000 section 10), and dropping the keys of a space (RFC 9001
 * section 4.9).
 */

.set INITIAL_RTT, 333000                /* RFC 9002 section 6.2.2, microseconds */
.set MAX_DATAGRAM, 1200                 /* the datagrams we send */
.set INITIAL_WINDOW, 12000              /* 10 datagrams (RFC 9002 section 7.2) */
.set MINIMUM_WINDOW, 2400               /* 2 datagrams */

/*
 * quic_conn_new(role) -> a new connection, or 0 when no slot or heap is free:
 * its fields at their start values, a connection ID of its own (the slot
 * index, 16 bits of the generation, 4 random bytes), the ring of sent
 * packets and the TLS block. s1 the connection.
 */
LOCAL_FUNCTION quic_conn_new
    ENTER   0
    mv      s2, a0
    li      a0, ST_CONN_OFF
    li      a1, ST_CONN_COUNT
    li      a2, C_SIZE
    call    quic_alloc_slot
    beqz    a0, 9f
    mv      s1, a0
    li      t0, CS_HANDSHAKE
    sd      t0, C_STATE(s1)
    sd      s2, C_ROLE(s1)
    li      t0, NONE
    sd      t0, C_NCID_SEQ(s1)
    sd      t0, C_RETIRE_SEQ(s1)
    sd      t0, (C_RSCID + QUIC_CID_LENGTH)(s1)
    SDX     t0, s1, C_PHASE_PN
    SDX     t0, s1, C_PREV_UNTIL
    SDX     t0, s1, C_STREAM_HEAD
    SDX     t0, s1, C_RTT_FIRST
    SDX     t0, s1, C_LOSS_AT
    SDX     t0, s1, C_IDLE_AT
    SDX     t0, s1, C_CLOSE_AT
    SDX     t0, s1, C_PING_AT
    SDX     t0, s1, C_SSTHRESH
    addi    t1, s1, C_SPACES
    li      t2, 3
1:  sd      t0, SP_LARGEST_ACKED(t1)
    sd      t0, SP_LARGEST_RECV(t1)
    sd      t0, SP_ACK_AT(t1)
    sd      t0, SP_LOSS_TIME(t1)
    sd      t0, SP_LAST_ELICIT(t1)
    addi    t1, t1, SP_SIZE
    addi    t2, t2, -1
    bnez    t2, 1b
    li      t0, INITIAL_WINDOW
    SDX     t0, s1, C_CWND
    li      t0, INITIAL_RTT
    SDX     t0, s1, C_RTT_SMOOTH
    srli    t0, t0, 1
    SDX     t0, s1, C_RTT_VAR
    li      t0, 25000
    SDX     t0, s1, C_P_ACK_DELAY
    li      t0, 3
    SDX     t0, s1, C_P_ACK_EXP
    ld      t0, ST_NOW(s9)
    SDX     t0, s1, C_START
    CFG     t0, QUIC_CFG_MAX_DATA
    SDX     t0, s1, C_RX_MAX
    CFG     t0, QUIC_CFG_MAX_STREAMS
    SDX     t0, s1, C_PEER_MAX
    CFG     t0, QUIC_CFG_IDLE
    li      t1, 1000
    mul     t0, t0, t1
    SDX     t0, s1, C_IDLE_US
    /* Our connection ID. */
    mv      a0, s1
    call    quic_conn_index
    sh      a0, C_LCID(s1)
    lwu     t0, C_GEN(s1)
    sh      t0, (C_LCID + 2)(s1)
    addi    a0, s1, (C_LCID + 4)
    li      a1, 4
    call    quic_random
    /* The ring of sent packets. */
    CFG     t0, QUIC_CFG_SENT
    li      t1, SR_SIZE
    mul     a0, t0, t1
    call    quic_heap_alloc
    beqz    a0, 8f
    SDX     a0, s1, C_SENT
    call    quic_heap_room
    srli    a0, a0, 7                       # SR_SIZE is 128
    SDX     a0, s1, C_SENT_CAP
    /* The TLS block. */
    li      a0, T_SIZE
    call    quic_heap_alloc
    beqz    a0, 8f
    SDX     a0, s1, C_TLS
    add     s2, s9, a0
    mv      a0, s2
    li      a1, T_LIST
    call    quic_zero
    li      t0, (QUIC_BL_FIXED + TRANSCRIPT_ROOM)
    sd      t0, (T_LIST + QUIC_BL_SIZE)(s2)
    li      t0, QUIC_BL_FIXED
    sd      t0, (T_LIST + QUIC_BL_OFFSET)(s2)
    sd      zero, (T_LIST + QUIC_BL_COUNT)(s2)
    mv      a0, s1
    j       9f
8:  mv      a0, s1
    call    quic_conn_free
    li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_conn_new

/* quic_conn_free(conn): its heap blocks and streams go, and the slot is free. */
LOCAL_FUNCTION quic_conn_free
    ENTER   0
    mv      s1, a0
    LDX     a0, s1, C_TLS
    call    quic_heap_free
    LDX     a0, s1, C_SENT
    call    quic_heap_free
    ld      a0, C_TOKEN(s1)
    call    quic_heap_free
    addi    s2, s1, C_SPACES
    li      s3, 3
1:  ld      a0, SP_CTX(s2)
    call    quic_heap_free
    ld      a0, SP_CRX(s2)
    call    quic_heap_free
    sd      zero, SP_CTX(s2)
    sd      zero, SP_CRX(s2)
    addi    s2, s2, SP_SIZE
    addi    s3, s3, -1
    bnez    s3, 1b
2:  LDX     a0, s1, C_STREAM_HEAD           # every stream of the connection
    li      t0, -1
    beq     a0, t0, 3f
    call    quic_stream_at
    call    quic_stream_free
    j       2b
3:  SDX     zero, s1, C_TLS
    SDX     zero, s1, C_SENT
    sd      zero, C_TOKEN(s1)
    sw      zero, C_USED(s1)
    LEAVE   0
END_FUNCTION quic_conn_free

/* quic_space(conn, space) -> the space record. A leaf. */
LOCAL_FUNCTION quic_space
    UNWIND_END_PROLOGUE
    li      a2, SP_SIZE
    mul     a2, a1, a2
    add     a0, a0, a2
    addi    a0, a0, C_SPACES
    ret
END_FUNCTION quic_space

/*
 * quic_conn_find(dcid, n) -> the connection whose own connection ID is the n
 * bytes at dcid, or 0. Our IDs are 8 bytes: the slot index first.
 */
LOCAL_FUNCTION quic_conn_find
    ENTER   0
    mv      s1, a0
    li      t0, 8
    bne     a1, t0, 8f
    lbu     t0, 0(s1)
    lbu     t1, 1(s1)
    slli    t1, t1, 8
    or      t0, t0, t1
    ld      t1, ST_CONN_COUNT(s9)
    bgeu    t0, t1, 8f
    mv      a0, t0
    call    quic_conn_at
    mv      s2, a0
    lwu     t0, C_USED(s2)
    beqz    t0, 8f
    addi    a0, s2, C_LCID
    mv      a1, s1
    li      a2, 8
    call    quic_equal
    beqz    a0, 8f
    ld      t0, C_STATE(s2)
    li      t1, CS_DONE
    beq     t0, t1, 8f
    mv      a0, s2
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_conn_find

/*
 * quic_conn_find_odcid(dcid, n, socket, addr) -> the server connection still in
 * its handshake that the client began with this DCID from this address, or 0.
 * s1 dcid, s2 n, s3 socket, s4 addr, s5 index, s6 the connection.
 */
LOCAL_FUNCTION quic_conn_find_odcid
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    mv      s4, a3
    li      s5, 0
1:  ld      t0, ST_CONN_COUNT(s9)
    bgeu    s5, t0, 8f
    mv      a0, s5
    call    quic_conn_at
    mv      s6, a0
    addi    s5, s5, 1
    lwu     t0, C_USED(s6)
    beqz    t0, 1b
    ld      t0, C_ROLE(s6)
    beqz    t0, 1b
    ld      t0, C_STATE(s6)
    li      t1, CS_HANDSHAKE
    bne     t0, t1, 1b
    ld      t0, C_SOCKET(s6)
    bne     t0, s3, 1b
    mv      a0, s1
    mv      a1, s2
    addi    a2, s6, C_ODCID
    call    quic_cid_is
    beqz    a0, 1b
    addi    a0, s6, C_ADDR
    mv      a1, s4
    li      a2, QUIC_ADDR_SIZE
    call    quic_equal
    beqz    a0, 1b
    mv      a0, s6
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_conn_find_odcid

/*
 * quic_pto_period(conn, space) -> the probe timeout of RFC 9002 section 6.2.1:
 * smoothed_rtt + max(4 * rttvar, 1 ms), plus max_ack_delay in the Application
 * space, doubled for each PTO in a row. A leaf; a5 points into the fields
 * above offset 2047.
 */
LOCAL_FUNCTION quic_pto_period
    UNWIND_END_PROLOGUE
    addi    a5, a0, 2047
    ld      a2, (C_RTT_VAR - 2047)(a5)
    slli    a2, a2, 2
    li      a3, 1000
    bltu    a3, a2, 1f
    mv      a2, a3
1:  ld      a3, (C_RTT_SMOOTH - 2047)(a5)
    add     a2, a2, a3
    li      a4, SPACE_APP
    bne     a1, a4, 2f
    ld      a3, (C_P_ACK_DELAY - 2047)(a5)
    add     a2, a2, a3
2:  ld      a3, (C_PTO_COUNT - 2047)(a5)
    li      a4, 16
    bltu    a3, a4, 3f
    mv      a3, a4
3:  sll     a0, a2, a3
    ret
END_FUNCTION quic_pto_period

/*
 * quic_conn_close(conn, error, reason): we close: CONNECTION_CLOSE with the
 * error code goes out (RFC 9000 section 10.2), then the connection stays in
 * the closing state for three probe timeouts. reason is the QUIC_ERR_* the
 * application hears. A connection already closing or draining stays as it is.
 */
LOCAL_FUNCTION quic_conn_close
    ENTER   0
    mv      s1, a0
    ld      t0, C_STATE(s1)
    li      t1, CS_CLOSING
    bgeu    t0, t1, 9f
    sd      a1, C_ERROR(s1)
    ld      t0, C_REASON(s1)
    bnez    t0, 1f                          # a reason set before, such as PEER_ID, stays
    sd      a2, C_REASON(s1)
1:  li      t0, CS_CLOSING
    sd      t0, C_STATE(s1)
    ld      t0, C_FLAGS(s1)
    ORV     t0, (CF_CLOSE_FRAME | CF_GONE)
    sd      t0, C_FLAGS(s1)
    mv      a0, s1
    call    quic_close_timer
9:  LEAVE   0
END_FUNCTION quic_conn_close

/*
 * quic_conn_drain(conn, error): the peer closed, or a stateless reset came: the
 * connection drains for three probe timeouts and sends nothing (RFC 9000
 * section 10.2.2).
 */
LOCAL_FUNCTION quic_conn_drain
    ENTER   0
    mv      s1, a0
    ld      t0, C_STATE(s1)
    li      t1, CS_DRAINING
    bgeu    t0, t1, 9f
    li      t1, CS_CLOSING
    beq     t0, t1, 1f
    sd      a1, C_ERROR(s1)
1:  li      t0, CS_DRAINING
    sd      t0, C_STATE(s1)
    ld      t0, C_FLAGS(s1)
    ORV     t0, CF_GONE
    BICV    t0, CF_CLOSE_FRAME
    sd      t0, C_FLAGS(s1)
    mv      a0, s1
    call    quic_close_timer
9:  LEAVE   0
END_FUNCTION quic_conn_drain

/* quic_close_timer(conn): the end of closing or draining: now + 3 PTO. */
LOCAL_FUNCTION quic_close_timer
    ENTER   0
    mv      s1, a0
    li      a1, SPACE_APP
    SDX     zero, s1, C_PTO_COUNT
    call    quic_pto_period
    slli    t0, a0, 1
    add     a0, a0, t0
    ld      t0, ST_NOW(s9)
    add     a0, a0, t0
    SDX     a0, s1, C_CLOSE_AT
    li      t0, NONE
    SDX     t0, s1, C_LOSS_AT
    SDX     t0, s1, C_PING_AT
    LEAVE   0
END_FUNCTION quic_close_timer

/*
 * quic_discard_space(space): the keys of the space go (RFC 9001 section 4.9):
 * its packets leave bytes in flight, its CRYPTO buffers are freed, and the
 * probe count starts again (RFC 9002 section 6.2.2). s1 the connection.
 */
LOCAL_FUNCTION quic_discard_space
    ENTER   0
    mv      s2, a0
    mv      a0, s1
    mv      a1, s2
    call    quic_space
    mv      s3, a0
    ld      t0, SP_FLAGS(s3)
    andi    t0, t0, SPF_DISCARDED
    bnez    t0, 9f
    li      t0, SPF_DISCARDED
    sd      t0, SP_FLAGS(s3)
    mv      a0, s2
    call    quic_drop_space_records
    ld      a0, SP_CTX(s3)
    call    quic_heap_free
    ld      a0, SP_CRX(s3)
    call    quic_heap_free
    sd      zero, SP_CTX(s3)
    sd      zero, SP_CRX(s3)
    sd      zero, SP_CTX_LEN(s3)
    sd      zero, SP_CTX_SENT(s3)
    sd      zero, SP_ACK_COUNT(s3)
    li      t0, NONE
    sd      t0, SP_ACK_AT(s3)
    sd      t0, SP_LOSS_TIME(s3)
    sd      t0, SP_LAST_ELICIT(s3)
    SDX     zero, s1, C_PTO_COUNT
    mv      a0, s1
    call    quic_set_loss_timer
9:  LEAVE   0
END_FUNCTION quic_discard_space

/*
 * quic_confirm(): the handshake is confirmed: the Handshake keys go and the TLS
 * block is freed. s1 the connection.
 */
LOCAL_FUNCTION quic_confirm
    ENTER   0
    ld      t0, C_FLAGS(s1)
    ori     t0, t0, CF_CONFIRMED
    sd      t0, C_FLAGS(s1)
    li      a0, SPACE_HANDSHAKE
    call    quic_discard_space
    LDX     a0, s1, C_TLS
    call    quic_heap_free
    SDX     zero, s1, C_TLS
    LEAVE   0
END_FUNCTION quic_confirm

/*
 * quic_idle_reset(): the idle timer starts again (RFC 9000 section 10.1): the
 * smaller of our and the peer's max_idle_timeout, at least 3 PTO; none when
 * both are 0. s1 the connection.
 */
LOCAL_FUNCTION quic_idle_reset
    ENTER   0
    LDX     s2, s1, C_IDLE_US
    LDX     t0, s1, C_P_IDLE
    li      t1, 1000
    mul     t0, t0, t1
    beqz    s2, 1f
    beqz    t0, 2f
    bgeu    t0, s2, 2f
    mv      s2, t0
    j       2f
1:  mv      s2, t0
2:  li      t0, NONE
    beqz    s2, 3f
    mv      a0, s1
    li      a1, SPACE_APP
    call    quic_pto_period
    slli    t1, a0, 1
    add     a0, a0, t1
    bgeu    s2, a0, 4f
    mv      s2, a0
4:  ld      t0, ST_NOW(s9)
    add     t0, t0, s2
3:  SDX     t0, s1, C_IDLE_AT
    /* The keep-alive PING. */
    CFG     t0, QUIC_CFG_KEEP_ALIVE
    li      t1, NONE
    beqz    t0, 5f
    li      t2, 1000
    mul     t0, t0, t2
    ld      t1, ST_NOW(s9)
    add     t1, t1, t0
5:  SDX     t1, s1, C_PING_AT
    LEAVE   0
END_FUNCTION quic_idle_reset
