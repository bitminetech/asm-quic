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
 * packets and the TLS block. x19 the connection.
 */
LOCAL_FUNCTION quic_conn_new
    ENTER   0
    mov     x20, x0
    mov     x0, #ST_CONN_OFF
    mov     x1, #ST_CONN_COUNT
    mov     x2, #C_SIZE
    bl      quic_alloc_slot
    cbz     x0, 9f
    mov     x19, x0
    mov     x9, #CS_HANDSHAKE
    str     x9, [x19, #C_STATE]
    str     x20, [x19, #C_ROLE]
    mov     x9, #NONE
    str     x9, [x19, #C_NCID_SEQ]
    str     x9, [x19, #C_RETIRE_SEQ]
    str     x9, [x19, #(C_RSCID + QUIC_CID_LENGTH)]
    str     x9, [x19, #C_PHASE_PN]
    str     x9, [x19, #C_PREV_UNTIL]
    str     x9, [x19, #C_STREAM_HEAD]
    str     x9, [x19, #C_RTT_FIRST]
    str     x9, [x19, #C_LOSS_AT]
    str     x9, [x19, #C_IDLE_AT]
    str     x9, [x19, #C_CLOSE_AT]
    str     x9, [x19, #C_PING_AT]
    str     x9, [x19, #C_SSTHRESH]
    add     x10, x19, #C_SPACES
    mov     x11, #3
1:  str     x9, [x10, #SP_LARGEST_ACKED]
    str     x9, [x10, #SP_LARGEST_RECV]
    str     x9, [x10, #SP_ACK_AT]
    str     x9, [x10, #SP_LOSS_TIME]
    str     x9, [x10, #SP_LAST_ELICIT]
    add     x10, x10, #SP_SIZE
    subs    x11, x11, #1
    b.ne    1b
    MOV64   x9, INITIAL_WINDOW
    str     x9, [x19, #C_CWND]
    MOV64   x9, INITIAL_RTT
    str     x9, [x19, #C_RTT_SMOOTH]
    lsr     x9, x9, #1
    str     x9, [x19, #C_RTT_VAR]
    mov     x9, #25000
    str     x9, [x19, #C_P_ACK_DELAY]
    mov     x9, #3
    str     x9, [x19, #C_P_ACK_EXP]
    ldr     x9, [x27, #ST_NOW]
    str     x9, [x19, #C_START]
    ldr     x9, [x27, #(ST_CONFIG + QUIC_CFG_MAX_DATA)]
    str     x9, [x19, #C_RX_MAX]
    ldr     x9, [x27, #(ST_CONFIG + QUIC_CFG_MAX_STREAMS)]
    str     x9, [x19, #C_PEER_MAX]
    ldr     x9, [x27, #(ST_CONFIG + QUIC_CFG_IDLE)]
    mov     x10, #1000
    mul     x9, x9, x10
    str     x9, [x19, #C_IDLE_US]
    /* Our connection ID. */
    mov     x0, x19
    bl      quic_conn_index
    strh    w0, [x19, #C_LCID]
    ldr     w9, [x19, #C_GEN]
    strh    w9, [x19, #(C_LCID + 2)]
    add     x0, x19, #(C_LCID + 4)
    mov     x1, #4
    bl      quic_random
    /* The ring of sent packets. */
    ldr     x9, [x27, #(ST_CONFIG + QUIC_CFG_SENT)]
    mov     x10, #SR_SIZE
    mul     x0, x9, x10
    bl      quic_heap_alloc
    cbz     x0, 8f
    str     x0, [x19, #C_SENT]
    bl      quic_heap_room
    lsr     x0, x0, #7                      /* SR_SIZE is 128 */
    str     x0, [x19, #C_SENT_CAP]
    /* The TLS block. */
    MOV64   x0, T_SIZE
    bl      quic_heap_alloc
    cbz     x0, 8f
    str     x0, [x19, #C_TLS]
    add     x20, x27, x0
    mov     x0, x20
    mov     x1, #T_LIST
    bl      quic_zero
    MOV64   x9, (QUIC_BL_FIXED + TRANSCRIPT_ROOM)
    str     x9, [x20, #(T_LIST + QUIC_BL_SIZE)]
    mov     x9, #QUIC_BL_FIXED
    str     x9, [x20, #(T_LIST + QUIC_BL_OFFSET)]
    str     xzr, [x20, #(T_LIST + QUIC_BL_COUNT)]
    mov     x0, x19
    b       9f
8:  mov     x0, x19
    bl      quic_conn_free
    mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_conn_new

/* quic_conn_free(conn): its heap blocks and streams go, and the slot is free. */
LOCAL_FUNCTION quic_conn_free
    ENTER   0
    mov     x19, x0
    ldr     x0, [x19, #C_TLS]
    bl      quic_heap_free
    ldr     x0, [x19, #C_SENT]
    bl      quic_heap_free
    ldr     x0, [x19, #C_TOKEN]
    bl      quic_heap_free
    add     x20, x19, #C_SPACES
    mov     x21, #3
1:  ldr     x0, [x20, #SP_CTX]
    bl      quic_heap_free
    ldr     x0, [x20, #SP_CRX]
    bl      quic_heap_free
    str     xzr, [x20, #SP_CTX]
    str     xzr, [x20, #SP_CRX]
    add     x20, x20, #SP_SIZE
    subs    x21, x21, #1
    b.ne    1b
2:  ldr     x0, [x19, #C_STREAM_HEAD]       /* every stream of the connection */
    cmn     x0, #1
    b.eq    3f
    bl      quic_stream_at
    bl      quic_stream_free
    b       2b
3:  str     xzr, [x19, #C_TLS]
    str     xzr, [x19, #C_SENT]
    str     xzr, [x19, #C_TOKEN]
    str     wzr, [x19, #C_USED]
    LEAVE   0
END_FUNCTION quic_conn_free

/* quic_space(conn, space) -> the space record. A leaf. */
LOCAL_FUNCTION quic_space
    UNWIND_END_PROLOGUE
    mov     x2, #SP_SIZE
    madd    x0, x1, x2, x0
    add     x0, x0, #C_SPACES
    ret
END_FUNCTION quic_space

/*
 * quic_conn_find(dcid, n) -> the connection whose own connection ID is the n
 * bytes at dcid, or 0. Our IDs are 8 bytes: the slot index first.
 */
LOCAL_FUNCTION quic_conn_find
    ENTER   0
    mov     x19, x0
    cmp     x1, #8
    b.ne    8f
    ldrh    w9, [x19]
    ldr     x10, [x27, #ST_CONN_COUNT]
    cmp     x9, x10
    b.hs    8f
    mov     x0, x9
    bl      quic_conn_at
    ldr     w9, [x0, #C_USED]
    cbz     w9, 8f
    ldr     x9, [x0, #C_LCID]
    ldr     x10, [x19]
    cmp     x9, x10
    b.ne    8f
    ldr     x9, [x0, #C_STATE]
    cmp     x9, #CS_DONE
    b.eq    8f
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_conn_find

/*
 * quic_conn_find_odcid(dcid, n, socket, addr) -> the server connection still in
 * its handshake that the client began with this DCID from this address, or 0.
 * x19 dcid, x20 n, x21 socket, x22 addr, x23 index, x24 the connection.
 */
LOCAL_FUNCTION quic_conn_find_odcid
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x22, x3
    mov     x23, #0
1:  ldr     x9, [x27, #ST_CONN_COUNT]
    cmp     x23, x9
    b.hs    8f
    mov     x0, x23
    bl      quic_conn_at
    mov     x24, x0
    add     x23, x23, #1
    ldr     w9, [x24, #C_USED]
    cbz     w9, 1b
    ldr     x9, [x24, #C_ROLE]
    cbz     x9, 1b
    ldr     x9, [x24, #C_STATE]
    cmp     x9, #CS_HANDSHAKE
    b.ne    1b
    ldr     x9, [x24, #C_SOCKET]
    cmp     x9, x21
    b.ne    1b
    mov     x0, x19
    mov     x1, x20
    add     x2, x24, #C_ODCID
    bl      quic_cid_is
    cbz     x0, 1b
    add     x0, x24, #C_ADDR
    mov     x1, x22
    mov     x2, #QUIC_ADDR_SIZE
    bl      quic_equal
    cbz     x0, 1b
    mov     x0, x24
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_conn_find_odcid

/*
 * quic_pto_period(conn, space) -> the probe timeout of RFC 9002 section 6.2.1:
 * smoothed_rtt + max(4 * rttvar, 1 ms), plus max_ack_delay in the Application
 * space, doubled for each PTO in a row. A leaf.
 */
LOCAL_FUNCTION quic_pto_period
    UNWIND_END_PROLOGUE
    ldr     x2, [x0, #C_RTT_VAR]
    lsl     x2, x2, #2
    mov     x3, #1000
    cmp     x2, x3
    csel    x2, x2, x3, hi
    ldr     x3, [x0, #C_RTT_SMOOTH]
    add     x2, x2, x3
    cmp     x1, #SPACE_APP
    b.ne    1f
    ldr     x3, [x0, #C_P_ACK_DELAY]
    add     x2, x2, x3
1:  ldr     x3, [x0, #C_PTO_COUNT]
    cmp     x3, #16
    mov     x4, #16
    csel    x3, x3, x4, lo
    lsl     x0, x2, x3
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
    mov     x19, x0
    ldr     x9, [x19, #C_STATE]
    cmp     x9, #CS_CLOSING
    b.hs    9f
    str     x1, [x19, #C_ERROR]
    ldr     x9, [x19, #C_REASON]
    cbnz    x9, 1f                          /* a reason set before, such as PEER_ID, stays */
    str     x2, [x19, #C_REASON]
1:  mov     x9, #CS_CLOSING
    str     x9, [x19, #C_STATE]
    ldr     x9, [x19, #C_FLAGS]
    mov     x10, #(CF_CLOSE_FRAME | CF_GONE)
    orr     x9, x9, x10
    str     x9, [x19, #C_FLAGS]
    mov     x0, x19
    bl      quic_close_timer
9:  LEAVE   0
END_FUNCTION quic_conn_close

/*
 * quic_conn_drain(conn, error): the peer closed, or a stateless reset came: the
 * connection drains for three probe timeouts and sends nothing (RFC 9000
 * section 10.2.2).
 */
LOCAL_FUNCTION quic_conn_drain
    ENTER   0
    mov     x19, x0
    ldr     x9, [x19, #C_STATE]
    cmp     x9, #CS_DRAINING
    b.hs    9f
    cmp     x9, #CS_CLOSING
    b.eq    1f
    str     x1, [x19, #C_ERROR]
1:  mov     x9, #CS_DRAINING
    str     x9, [x19, #C_STATE]
    ldr     x9, [x19, #C_FLAGS]
    orr     x9, x9, #CF_GONE
    bic     x9, x9, #CF_CLOSE_FRAME
    str     x9, [x19, #C_FLAGS]
    mov     x0, x19
    bl      quic_close_timer
9:  LEAVE   0
END_FUNCTION quic_conn_drain

/* quic_close_timer(conn): the end of closing or draining: now + 3 PTO. */
LOCAL_FUNCTION quic_close_timer
    ENTER   0
    mov     x19, x0
    mov     x1, #SPACE_APP
    str     xzr, [x19, #C_PTO_COUNT]
    bl      quic_pto_period
    add     x0, x0, x0, lsl #1
    ldr     x9, [x27, #ST_NOW]
    add     x0, x0, x9
    str     x0, [x19, #C_CLOSE_AT]
    mov     x9, #NONE
    str     x9, [x19, #C_LOSS_AT]
    str     x9, [x19, #C_PING_AT]
    LEAVE   0
END_FUNCTION quic_close_timer

/*
 * quic_discard_space(space): the keys of the space go (RFC 9001 section 4.9):
 * its packets leave bytes in flight, its CRYPTO buffers are freed, and the
 * probe count starts again (RFC 9002 section 6.2.2). x19 the connection.
 */
LOCAL_FUNCTION quic_discard_space
    ENTER   0
    mov     x20, x0
    mov     x0, x19
    mov     x1, x20
    bl      quic_space
    mov     x21, x0
    ldr     x9, [x21, #SP_FLAGS]
    tst     x9, #SPF_DISCARDED
    b.ne    9f
    mov     x9, #SPF_DISCARDED
    str     x9, [x21, #SP_FLAGS]
    mov     x0, x20
    bl      quic_drop_space_records
    ldr     x0, [x21, #SP_CTX]
    bl      quic_heap_free
    ldr     x0, [x21, #SP_CRX]
    bl      quic_heap_free
    str     xzr, [x21, #SP_CTX]
    str     xzr, [x21, #SP_CRX]
    str     xzr, [x21, #SP_CTX_LEN]
    str     xzr, [x21, #SP_CTX_SENT]
    str     xzr, [x21, #SP_ACK_COUNT]
    mov     x9, #NONE
    str     x9, [x21, #SP_ACK_AT]
    str     x9, [x21, #SP_LOSS_TIME]
    str     x9, [x21, #SP_LAST_ELICIT]
    str     xzr, [x19, #C_PTO_COUNT]
    mov     x0, x19
    bl      quic_set_loss_timer
9:  LEAVE   0
END_FUNCTION quic_discard_space

/*
 * quic_confirm(): the handshake is confirmed: the Handshake keys go and the TLS
 * block is freed. x19 the connection.
 */
LOCAL_FUNCTION quic_confirm
    ENTER   0
    ldr     x9, [x19, #C_FLAGS]
    orr     x9, x9, #CF_CONFIRMED
    str     x9, [x19, #C_FLAGS]
    mov     x0, #SPACE_HANDSHAKE
    bl      quic_discard_space
    ldr     x0, [x19, #C_TLS]
    bl      quic_heap_free
    str     xzr, [x19, #C_TLS]
    LEAVE   0
END_FUNCTION quic_confirm

/*
 * quic_idle_reset(): the idle timer starts again (RFC 9000 section 10.1): the
 * smaller of our and the peer's max_idle_timeout, at least 3 PTO; none when
 * both are 0. x19 the connection.
 */
LOCAL_FUNCTION quic_idle_reset
    ENTER   0
    ldr     x20, [x19, #C_IDLE_US]
    ldr     x9, [x19, #C_P_IDLE]
    mov     x10, #1000
    mul     x9, x9, x10
    cbz     x20, 1f
    cbz     x9, 2f
    cmp     x9, x20
    csel    x20, x9, x20, lo
    b       2f
1:  mov     x20, x9
2:  mov     x9, #NONE
    cbz     x20, 3f
    mov     x0, x19
    mov     x1, #SPACE_APP
    bl      quic_pto_period
    add     x0, x0, x0, lsl #1
    cmp     x20, x0
    csel    x20, x20, x0, hs
    ldr     x9, [x27, #ST_NOW]
    add     x9, x9, x20
3:  str     x9, [x19, #C_IDLE_AT]
    /* The keep-alive PING. */
    ldr     x9, [x27, #(ST_CONFIG + QUIC_CFG_KEEP_ALIVE)]
    mov     x10, #NONE
    cbz     x9, 4f
    mov     x11, #1000
    mul     x9, x9, x11
    ldr     x10, [x27, #ST_NOW]
    add     x10, x10, x9
4:  str     x10, [x19, #C_PING_AT]
    LEAVE   0
END_FUNCTION quic_idle_reset
