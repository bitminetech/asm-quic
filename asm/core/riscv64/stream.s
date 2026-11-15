/*
 * Bidirectional streams (RFC 9000 sections 2, 3 and 4): slots, the send queue
 * with its acknowledged and lost ranges, the receive segments, flow control,
 * and what the application hears. s1 the connection, where a function uses it.
 */

.set ERR_FLOW_CONTROL, 0x03
.set ERR_STREAM_LIMIT, 0x04
.set ERR_STREAM_STATE, 0x05
.set ERR_FINAL_SIZE, 0x06

/* ---------------------------------------------------------------- Slots */

/*
 * quic_stream_new(id, local) -> a new stream of the connection with the ID (or
 * NONE), linked first in its list; 0 when no slot is free. s1 the connection.
 */
LOCAL_FUNCTION quic_stream_new
    ENTER   0
    mv      s2, a0
    mv      s3, a1
    li      a0, ST_STREAM_OFF
    li      a1, ST_STREAM_COUNT
    li      a2, S_SIZE
    call    quic_alloc_slot
    beqz    a0, 9f
    mv      s4, a0
    mv      a0, s1
    call    quic_conn_index
    sd      a0, S_CONN(s4)
    lwu     t0, C_GEN(s1)
    sd      t0, S_CONN_GEN(s4)
    sd      s2, S_ID(s4)
    li      t0, SF_TELL_OPEN
    beqz    s3, 1f
    ori     t0, t0, SF_LOCAL
1:  sd      t0, S_FLAGS(s4)
    li      t0, NONE
    sd      t0, S_RX_FINAL(s4)
    CFG     t0, QUIC_CFG_STREAM_DATA
    sd      t0, S_RX_MAX(s4)
    LDX     t0, s1, C_P_SD_LOCAL            # the peer's limit for streams it opened
    beqz    s3, 2f
    LDX     t0, s1, C_P_SD_REMOTE           # and for streams we opened
2:  sd      t0, S_TX_MAX(s4)
    LDX     t0, s1, C_STREAM_HEAD
    sd      t0, S_NEXT(s4)
    mv      a0, s4
    call    quic_stream_index
    SDX     a0, s1, C_STREAM_HEAD
    mv      a0, s4
9:  LEAVE   0
END_FUNCTION quic_stream_new

/*
 * quic_stream_free(stream): its chunks and segments go, it leaves the list of
 * its connection, and the slot is free.
 */
LOCAL_FUNCTION quic_stream_free
    ENTER   0
    mv      s2, a0
    ld      a0, S_CONN(s2)
    call    quic_conn_at
    mv      s3, a0
1:  ld      a0, S_Q_HEAD(s2)
    beqz    a0, 2f
    add     t0, s9, a0
    ld      t0, Q_NEXT(t0)
    sd      t0, S_Q_HEAD(s2)
    call    quic_heap_free
    j       1b
2:  ld      a0, S_RX_HEAD(s2)
    beqz    a0, 3f
    add     t0, s9, a0
    ld      t0, R_NEXT(t0)
    sd      t0, S_RX_HEAD(s2)
    call    quic_heap_free
    j       2b
3:  mv      a0, s2                          # unlink
    call    quic_stream_index
    mv      s4, a0
    LDX     t0, s3, C_STREAM_HEAD
    bne     t0, s4, 4f
    ld      t1, S_NEXT(s2)
    SDX     t1, s3, C_STREAM_HEAD
    j       6f
4:  li      t1, -1
    beq     t0, t1, 6f
    mv      a0, t0
    call    quic_stream_at
    ld      t0, S_NEXT(a0)
    bne     t0, s4, 4b
    ld      t1, S_NEXT(s2)
    sd      t1, S_NEXT(a0)
6:  sw      zero, S_USED(s2)
    LEAVE   0
END_FUNCTION quic_stream_free

/* quic_stream_find(id) -> the stream of the connection with the ID, or 0. s1 the connection. */
LOCAL_FUNCTION quic_stream_find
    ENTER   0
    mv      s2, a0
    LDX     s3, s1, C_STREAM_HEAD
1:  li      t0, -1
    beq     s3, t0, 8f
    mv      a0, s3
    call    quic_stream_at
    ld      t0, S_ID(a0)
    beq     t0, s2, 9f
    ld      s3, S_NEXT(a0)
    j       1b
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_stream_find

/*
 * quic_assign_ids(): our streams that wait get IDs while the peer's
 * MAX_STREAMS allows: 4n for a client, 4n + 1 for a server. s1 the connection.
 */
LOCAL_FUNCTION quic_assign_ids
    ENTER   0
10: LDX     s2, s1, C_STREAM_HEAD
    li      s3, NONE                        # the oldest waiting stream is last in the list
1:  li      t0, -1
    beq     s2, t0, 2f
    mv      a0, s2
    call    quic_stream_at
    ld      t0, S_ID(a0)
    li      t1, -1
    bne     t0, t1, 11f
    mv      s3, s2
11: ld      s2, S_NEXT(a0)
    j       1b
2:  li      t0, -1
    beq     s3, t0, 9f
    LDX     t0, s1, C_LOCAL_OPEN
    LDX     t1, s1, C_P_STREAMS
    bgeu    t0, t1, 9f
    mv      a0, s3
    call    quic_stream_at
    LDX     t0, s1, C_LOCAL_OPEN
    ld      t1, C_ROLE(s1)
    slli    t2, t0, 2
    or      t2, t2, t1
    sd      t2, S_ID(a0)
    addi    t0, t0, 1
    SDX     t0, s1, C_LOCAL_OPEN
    j       10b
9:  LEAVE   0
END_FUNCTION quic_assign_ids

/* ---------------------------------------------------------------- Events of the application */

/*
 * quic_on_open_stream(event): a new stream of ours on the connection; its ID
 * comes when MAX_STREAMS allows. STREAM_OPENED tells the application its
 * handle; a handle 0 means no slot was free or the connection is gone.
 */
LOCAL_FUNCTION quic_on_open_stream
    ENTER   0
    mv      s5, a0
    ld      a0, QUIC_EV_CONN(s5)
    call    quic_conn
    beqz    a0, 7f
    mv      s1, a0
    ld      t0, C_STATE(s1)
    li      t1, CS_ACTIVE
    bne     t0, t1, 7f
    li      a0, NONE
    li      a1, 1
    call    quic_stream_new
    beqz    a0, 7f
    ld      t0, QUIC_EV_OPEN_TAG(s5)
    sd      t0, S_TAG(a0)
    call    quic_assign_ids
    j       9f
7:  li      a0, QUIC_ACTION_STREAM_OPENED   # no stream: handle 0
    li      a1, QUIC_ACT_OPENED_SIZE
    call    quic_action
    beqz    a0, 9f
    ld      t0, QUIC_EV_CONN(s5)
    sd      t0, QUIC_ACT_S_CONN(a0)
    ld      t0, QUIC_EV_OPEN_TAG(s5)
    sd      t0, QUIC_ACT_S_TAG(a0)
9:  LEAVE   0
END_FUNCTION quic_on_open_stream

/*
 * quic_on_stream_write(event): the bytes join the send queue of the stream as
 * one chunk. A stream whose queue would pass stream_queue, or whose chunk the
 * heap cannot hold, is reset with code 0. A stream the application closed or
 * reset ignores it.
 */
LOCAL_FUNCTION quic_on_stream_write
    ENTER   0
    mv      s5, a0
    ld      a0, QUIC_EV_STREAM(s5)
    call    quic_stream
    beqz    a0, 9f
    mv      s2, a0
    ld      t0, S_FLAGS(s2)
    ANDV    t0, (SF_FIN_WANT | SF_RESET)
    bnez    t0, 9f
    ld      s6, QUIC_EV_WRITE_COUNT(s5)
    beqz    s6, 9f
    ld      t0, S_WRITTEN(s2)
    ld      t1, S_Q_BASE(s2)
    sub     t0, t0, t1
    add     t0, t0, s6
    CFG     t1, QUIC_CFG_STREAM_QUEUE
    bltu    t1, t0, 8f
    addi    a0, s6, Q_DATA
    call    quic_heap_alloc
    beqz    a0, 8f
    mv      s3, a0
    add     s4, s9, s3
    sd      zero, Q_NEXT(s4)
    sd      s6, Q_LEN(s4)
    addi    a0, s4, Q_DATA
    addi    a1, s5, QUIC_EV_WRITE_DATA
    mv      a2, s6
    call    quic_copy
    ld      t0, S_Q_TAIL(s2)
    beqz    t0, 1f
    add     t0, s9, t0
    sd      s3, Q_NEXT(t0)
    j       2f
1:  sd      s3, S_Q_HEAD(s2)
    ld      t0, S_WRITTEN(s2)
    sd      t0, S_Q_BASE(s2)
2:  sd      s3, S_Q_TAIL(s2)
    ld      t0, S_WRITTEN(s2)
    add     t0, t0, s6
    sd      t0, S_WRITTEN(s2)
    j       9f
8:  mv      a0, s2
    li      a1, 0
    call    quic_stream_reset_local
9:  LEAVE   0
END_FUNCTION quic_on_stream_write

/* quic_on_stream_close(event): no more bytes: a FIN follows the queue. */
LOCAL_FUNCTION quic_on_stream_close
    ENTER   0
    ld      a0, QUIC_EV_STREAM(a0)
    call    quic_stream
    beqz    a0, 9f
    ld      t0, S_FLAGS(a0)
    ori     t0, t0, SF_FIN_WANT
    sd      t0, S_FLAGS(a0)
9:  LEAVE   0
END_FUNCTION quic_on_stream_close

/* quic_on_stream_reset(event): the application resets the stream both ways with its code. */
LOCAL_FUNCTION quic_on_stream_reset
    ENTER   0
    mv      s2, a0
    ld      a0, QUIC_EV_STREAM(s2)
    call    quic_stream
    beqz    a0, 9f
    ld      a1, QUIC_EV_CODE(s2)
    call    quic_stream_reset_local
9:  LEAVE   0
END_FUNCTION quic_on_stream_reset

/*
 * quic_stream_reset_local(stream, code): RESET_STREAM and STOP_SENDING with
 * the code go out; the queue is dropped; the peer's data is no longer heard.
 * The application is not told.
 */
LOCAL_FUNCTION quic_stream_reset_local
    ENTER   0
    mv      s2, a0
    sd      a1, S_APP_CODE(s2)
    ld      t0, S_FLAGS(s2)
    mv      t1, t0
    ANDV    t1, SF_RESET
    bnez    t1, 9f
    ORV     t0, (SF_RESET | SF_RESET_SEND | SF_TOLD_RESET)
    andi    t1, t0, SF_RX_DONE
    bnez    t1, 1f
    ORV     t0, (SF_STOP_SEND | SF_RX_DONE)
1:  BICV    t0, (SF_TELL_RESET | SF_TELL_FIN)
    sd      t0, S_FLAGS(s2)
    call    quic_stream_drop
9:  LEAVE   0
END_FUNCTION quic_stream_reset_local

/* quic_stream_drop(): the queue of the stream at s2 is freed, and its segments when its receive side is over. */
LOCAL_FUNCTION quic_stream_drop
    ENTER   0
1:  ld      a0, S_Q_HEAD(s2)
    beqz    a0, 2f
    add     t0, s9, a0
    ld      t0, Q_NEXT(t0)
    sd      t0, S_Q_HEAD(s2)
    call    quic_heap_free
    j       1b
2:  sd      zero, S_Q_TAIL(s2)
    sd      zero, S_NLOST(s2)
    ld      t0, S_FLAGS(s2)
    andi    t0, t0, SF_RX_DONE
    beqz    t0, 9f
    call    quic_stream_drop_rx
9:  LEAVE   0
END_FUNCTION quic_stream_drop

/* quic_stream_drop_rx(): the segments of the stream at s2 are freed. */
LOCAL_FUNCTION quic_stream_drop_rx
    ENTER   0
1:  ld      a0, S_RX_HEAD(s2)
    beqz    a0, 9f
    add     t0, s9, a0
    ld      t0, R_NEXT(t0)
    sd      t0, S_RX_HEAD(s2)
    call    quic_heap_free
    j       1b
9:  LEAVE   0
END_FUNCTION quic_stream_drop_rx

/* ---------------------------------------------------------------- Acknowledged and lost data */

/*
 * quic_stream_acked(stream, offset, len, fin): a STREAM frame of ours is
 * acknowledged: the range joins the acknowledged ranges, S_ACKED moves over
 * every range that touches it, and the chunks below it are freed.
 * s2 stream, s3 start, s4 end, s5 fin.
 */
LOCAL_FUNCTION quic_stream_acked
    ENTER   0
    mv      s2, a0
    mv      s3, a1
    add     s4, a1, a2
    mv      s5, a3
    ld      t0, S_FLAGS(s2)
    mv      t1, t0
    ANDV    t1, SF_RESET
    bnez    t1, 9f
    beqz    s5, 1f
    ori     t0, t0, SF_FIN_SENT
    sd      t0, S_FLAGS(s2)
    li      t0, 1                           # the FIN is acknowledged: kept in S_NACKS bit 63
    slli    t0, t0, 63
    ld      t1, S_NACKS(s2)
    or      t1, t1, t0
    sd      t1, S_NACKS(s2)
1:  mv      a0, s2
    mv      a1, s3
    mv      a2, s4
    addi    a3, s2, S_NACKS
    li      a4, 6
    call    quic_ranges_add
    call    quic_stream_advance
9:  LEAVE   0
END_FUNCTION quic_stream_acked

/*
 * quic_stream_advance(): S_ACKED moves over the acknowledged ranges that touch
 * it; chunks wholly below it are freed; a stream whose FIN and data are all
 * acknowledged gets SF_FIN_ACKED. s2 the stream.
 */
LOCAL_FUNCTION quic_stream_advance
    ENTER   0
1:  ld      t0, S_NACKS(s2)
    andi    t1, t0, 0xFF
    beqz    t1, 3f
    ld      t2, S_ACKS(s2)
    ld      t3, (S_ACKS + 8)(s2)
    ld      t4, S_ACKED(s2)
    bltu    t4, t2, 3f
    bgeu    t4, t3, 11f
    mv      t4, t3
11: sd      t4, S_ACKED(s2)
    mv      a0, s2                          # the first range goes
    addi    a1, s2, S_NACKS
    li      a2, 0
    call    quic_ranges_remove
    j       1b
3:  ld      s3, S_ACKED(s2)                 # free the chunks below
4:  ld      a0, S_Q_HEAD(s2)
    beqz    a0, 5f
    add     t0, s9, a0
    ld      t1, Q_LEN(t0)
    ld      t2, S_Q_BASE(s2)
    add     t3, t2, t1
    bltu    s3, t3, 5f
    sd      t3, S_Q_BASE(s2)
    ld      t1, Q_NEXT(t0)
    sd      t1, S_Q_HEAD(s2)
    bnez    t1, 41f
    sd      zero, S_Q_TAIL(s2)
41: call    quic_heap_free
    j       4b
5:  ld      t0, S_NACKS(s2)                 # FIN acknowledged and all data
    bgez    t0, 9f
    ld      t1, S_WRITTEN(s2)
    bltu    s3, t1, 9f
    ld      t0, S_FLAGS(s2)
    ori     t0, t0, SF_FIN_ACKED
    sd      t0, S_FLAGS(s2)
9:  LEAVE   0
END_FUNCTION quic_stream_advance

/*
 * quic_stream_lost(stream, offset, len, fin): a STREAM frame of ours was lost:
 * the part not yet acknowledged joins the lost ranges, and a FIN goes out again.
 */
LOCAL_FUNCTION quic_stream_lost
    ENTER   0
    mv      s2, a0
    mv      s3, a1
    add     s4, a1, a2
    ld      t0, S_FLAGS(s2)
    mv      t1, t0
    ANDV    t1, SF_RESET
    bnez    t1, 9f
    beqz    a3, 1f
    ld      t1, S_NACKS(s2)
    bltz    t1, 1f
    ori     t0, t0, SF_FIN_LOST
    sd      t0, S_FLAGS(s2)
1:  ld      t0, S_ACKED(s2)
    bgeu    s3, t0, 2f
    mv      s3, t0
2:  bgeu    s3, s4, 9f
    mv      a0, s2
    mv      a1, s3
    mv      a2, s4
    addi    a3, s2, S_NLOST
    li      a4, 4
    call    quic_ranges_add
9:  LEAVE   0
END_FUNCTION quic_stream_lost

/* quic_stream_reset_acked(stream): our RESET_STREAM is acknowledged: our side is over. */
LOCAL_FUNCTION quic_stream_reset_acked
    ENTER   0
    ld      t0, S_FLAGS(a0)
    ori     t0, t0, SF_FIN_ACKED
    sd      t0, S_FLAGS(a0)
    LEAVE   0
END_FUNCTION quic_stream_reset_acked

/*
 * quic_ranges_add(stream, start, end, list, max): adds [start, end) to a list
 * of ranges kept in order and joined: the u8 count at list (other bits kept),
 * then max pairs at list + 8. When the list is full the range joins the last
 * one, covering the gap: lost ranges then send a little more again, and
 * acknowledged ones cannot lose a range.
 * s1 list, s2 count word, s3 start, s4 end, s5 the pairs, s6 count, s7 max, s8 index.
 */
LOCAL_FUNCTION quic_ranges_add
    ENTER   0
    mv      s1, a3
    mv      s3, a1
    mv      s4, a2
    mv      s7, a4
    addi    s5, s1, 8
    ld      s2, 0(s1)
    andi    s6, s2, 0xFF
    li      s8, 0
1:  bgeu    s8, s6, 5f
    slli    t0, s8, 4
    add     t0, s5, t0
    ld      t1, 0(t0)
    ld      t2, 8(t0)
    bltu    s4, t1, 4f                      # wholly before this range: insert here
    bltu    t2, s3, 3f                      # wholly after: next
    bgeu    s3, t1, 11f                     # they touch: join
    mv      t1, s3
11: bgeu    t2, s4, 12f
    mv      t2, s4
12: sd      t1, 0(t0)
    sd      t2, 8(t0)
2:  addi    t3, s8, 1                       # join the ranges after that now touch
    bgeu    t3, s6, 9f
    slli    t4, t3, 4
    add     t4, s5, t4
    ld      t5, 0(t4)
    ld      t6, 8(t4)
    bltu    t2, t5, 9f
    bgeu    t2, t6, 21f
    mv      t2, t6
21: sd      t2, 8(t0)
    mv      a0, s1
    mv      a1, s1
    mv      a2, t3
    call    quic_ranges_remove
    ld      s2, 0(s1)
    andi    s6, s2, 0xFF
    j       2b
3:  addi    s8, s8, 1
    j       1b
4:  bgeu    s6, s7, 6f                      # insert at s8
    mv      t3, s6
41: bgeu    s8, t3, 42f
    addi    t4, t3, -1
    slli    t5, t4, 4
    add     t5, s5, t5
    ld      t6, 0(t5)
    ld      a7, 8(t5)
    sd      t6, 16(t5)
    sd      a7, 24(t5)
    mv      t3, t4
    j       41b
42: slli    t0, s8, 4
    add     t0, s5, t0
    sd      s3, 0(t0)
    sd      s4, 8(t0)
    addi    s2, s2, 1
    sd      s2, 0(s1)
    j       9f
5:  bgeu    s6, s7, 6f                      # append
    j       42b
6:  beqz    s6, 9f                          # full: join the last range
    addi    s8, s6, -1
    slli    t0, s8, 4
    add     t0, s5, t0
    ld      t1, 0(t0)
    ld      t2, 8(t0)
    bgeu    s3, t1, 61f
    mv      t1, s3
61: bgeu    t2, s4, 62f
    mv      t2, s4
62: sd      t1, 0(t0)
    sd      t2, 8(t0)
9:  LEAVE   0
END_FUNCTION quic_ranges_add

/*
 * quic_ranges_remove(stream, list, index): the range at index of the list goes.
 * A leaf of a0-a7 only: quic_ranges_add keeps a range in t0.
 */
LOCAL_FUNCTION quic_ranges_remove
    UNWIND_END_PROLOGUE
    ld      a3, 0(a1)
    andi    a4, a3, 0xFF
    addi    a5, a1, 8
1:  addi    a6, a2, 1
    bgeu    a6, a4, 2f
    slli    a7, a6, 4
    add     a7, a5, a7
    ld      a0, 0(a7)
    sd      a0, -16(a7)
    ld      a0, 8(a7)
    sd      a0, -8(a7)
    mv      a2, a6
    j       1b
2:  addi    a3, a3, -1
    sd      a3, 0(a1)
    ret
END_FUNCTION quic_ranges_remove

/* ---------------------------------------------------------------- Frames of the peer */

/*
 * quic_peer_stream(id) -> a0 the stream of the ID for a frame of the peer, or
 * 0 when the frame is to be ignored (a stream that is over); a1 0, or the
 * error code. A stream the peer may open that is new opens, with every lower
 * one of its kind (RFC 9000 section 3.2). s1 the connection.
 * s2 id, s3 the stream number, s4 the error.
 */
LOCAL_FUNCTION quic_peer_stream
    ENTER   0
    mv      s2, a0
    li      s4, 0
    andi    t0, s2, 2                       # unidirectional: we allow none
    beqz    t0, 1f
    li      s4, ERR_STREAM_LIMIT
    j       8f
1:  call    quic_stream_find
    bnez    a0, 9f
    andi    t0, s2, 1                       # who opened it
    ld      t1, C_ROLE(s1)
    bne     t0, t1, 2f
    srli    s3, s2, 2                       # ours: a stream we opened and is over, or one we never opened
    LDX     t0, s1, C_LOCAL_OPEN
    bltu    s3, t0, 8f
    li      s4, ERR_STREAM_STATE
    j       8f
2:  srli    s3, s2, 2
    LDX     t0, s1, C_PEER_MAX
    bltu    s3, t0, 3f
    li      s4, ERR_STREAM_LIMIT
    j       8f
3:  LDX     s5, s1, C_PEER_OPEN
    bltu    s3, s5, 8f                      # opened before and over
4:  bltu    s3, s5, 6f
    slli    a0, s5, 2
    andi    t0, s2, 3
    or      a0, a0, t0
    li      a1, 0
    call    quic_stream_new
    beqz    a0, 5f
    addi    s5, s5, 1
    SDX     s5, s1, C_PEER_OPEN
    j       4b
5:  li      s4, ERR_INTERNAL                # no slot
    j       8f
6:  mv      a0, s2
    call    quic_stream_find
    j       9f
8:  li      a0, 0
9:  mv      a1, s4
    LEAVE   0
END_FUNCTION quic_peer_stream

/*
 * quic_rx_limits(stream, end) -> 0 or the error code: the flow control of the
 * stream and the connection for data up to end, and the final size rules
 * (RFC 9000 sections 4.1 and 4.5). S_RX_SEEN and C_RX_SEEN move up.
 */
LOCAL_FUNCTION quic_rx_limits
    ENTER   0
    mv      s2, a0
    ld      t0, S_RX_FINAL(s2)
    li      t1, -1
    beq     t0, t1, 1f
    bltu    t0, a1, 7f
1:  ld      t0, S_RX_MAX(s2)
    bltu    t0, a1, 6f
    ld      t0, S_RX_SEEN(s2)
    bgeu    t0, a1, 2f
    sub     t1, a1, t0
    sd      a1, S_RX_SEEN(s2)
    LDX     t2, s1, C_RX_SEEN
    add     t2, t2, t1
    SDX     t2, s1, C_RX_SEEN
    LDX     t3, s1, C_RX_MAX
    bltu    t3, t2, 6f
2:  li      a0, 0
    j       9f
6:  li      a0, ERR_FLOW_CONTROL
    j       9f
7:  li      a0, ERR_FINAL_SIZE
9:  LEAVE   0
END_FUNCTION quic_rx_limits

/*
 * quic_on_stream_frame(id, offset, data, len, fin) -> 0 or the error code: a
 * STREAM frame. Its bytes past those delivered join the segments of the
 * stream, in order, overlaps cut.
 * s2 stream, s3 offset, s4 data, s5 len, s6 fin, s7 end, s8 id.
 */
LOCAL_FUNCTION quic_on_stream_frame
    ENTER   0
    mv      s8, a0
    mv      s3, a1
    mv      s4, a2
    mv      s5, a3
    mv      s6, a4
    add     s7, s3, s5
    li      t0, 1
    slli    t0, t0, 62
    bgeu    s7, t0, 7f
    mv      a0, s8
    call    quic_peer_stream
    bnez    a1, 8f
    beqz    a0, 9f
    mv      s2, a0
    ld      t0, S_FLAGS(s2)
    andi    t0, t0, SF_RX_DONE
    bnez    t0, 9f                          # reset: late data is not heard
    mv      a0, s2
    mv      a1, s7
    call    quic_rx_limits
    bnez    a0, 99f
    beqz    s6, 1f
    ld      t0, S_RX_FINAL(s2)              # a final size, once
    li      t1, -1
    beq     t0, t1, 11f
    bne     t0, s7, 71f
11: ld      t0, S_RX_SEEN(s2)
    bltu    s7, t0, 71f
    sd      s7, S_RX_FINAL(s2)
1:  ld      t0, S_RX_DONE(s2)               # drop what is delivered
    bgeu    s3, t0, 2f
    sub     t1, t0, s3
    bgeu    t1, s5, 9f
    add     s4, s4, t1
    sub     s5, s5, t1
    mv      s3, t0
2:  beqz    s5, 9f
    mv      a0, s2
    mv      a1, s3
    mv      a2, s4
    mv      a3, s5
    call    quic_segment_add
    j       99f
7:  li      a1, ERR_FLOW_CONTROL
8:  mv      a0, a1
    j       99f
71: li      a0, ERR_FINAL_SIZE
    j       99f
9:  li      a0, 0
99: LEAVE   0
END_FUNCTION quic_on_stream_frame

/*
 * quic_segment_add(stream, offset, data, len) -> 0, or ERR_INTERNAL when the
 * heap has no room: the bytes not held yet go into new segments in order.
 * s2 stream, s3 offset, s4 data, s5 end, s6 the link to the next segment,
 * s7 the segment there, s8 the end of the new segment.
 */
LOCAL_FUNCTION quic_segment_add
    ENTER   0
    mv      s2, a0
    mv      s3, a1
    mv      s4, a2
    add     s5, a1, a3
    addi    s6, s2, S_RX_HEAD
1:  bgeu    s3, s5, 8f
    ld      s7, 0(s6)
    beqz    s7, 3f
    add     t0, s9, s7
    ld      t1, R_OFFSET(t0)
    ld      t2, R_LEN(t0)
    add     t2, t1, t2
    bltu    s3, t2, 2f
    addi    s6, t0, R_NEXT                  # this segment ends before: on
    j       1b
2:  bgeu    s3, t1, 21f
    mv      s8, t1                          # a new segment before it, up to its start
    bgeu    s5, t1, 4f
    mv      s8, s5
    j       4f
21: sub     t3, t2, s3                      # inside it: skip what it holds
    add     s3, s3, t3
    add     s4, s4, t3
    addi    s6, t0, R_NEXT
    j       1b
3:  mv      s8, s5                          # past every segment
4:  sub     a0, s8, s3
    addi    a0, a0, R_DATA
    call    quic_heap_alloc
    beqz    a0, 7f
    add     t0, s9, a0
    sd      s7, R_NEXT(t0)
    sd      s3, R_OFFSET(t0)
    sub     t1, s8, s3
    sd      t1, R_LEN(t0)
    sd      a0, 0(s6)
    addi    s6, t0, R_NEXT
    addi    a0, t0, R_DATA
    mv      a1, s4
    mv      a2, t1
    call    quic_copy
    sub     t1, s8, s3
    add     s4, s4, t1
    mv      s3, s8
    j       1b
7:  li      a0, ERR_INTERNAL
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_segment_add

/*
 * quic_on_reset_stream(id, code, final) -> 0 or the error code: the peer reset
 * its side: the final size is checked and counted, the segments go, and the
 * application hears STREAM_RESET with the code.
 */
LOCAL_FUNCTION quic_on_reset_stream
    ENTER   0
    mv      s5, a1
    mv      s6, a2
    call    quic_peer_stream
    bnez    a1, 8f
    beqz    a0, 9f
    mv      s2, a0
    ld      t0, S_FLAGS(s2)
    andi    t0, t0, SF_RX_DONE
    bnez    t0, 9f
    ld      t0, S_RX_FINAL(s2)
    li      t1, -1
    beq     t0, t1, 1f
    bne     t0, s6, 7f
1:  ld      t0, S_RX_SEEN(s2)
    bltu    s6, t0, 7f
    mv      a0, s2
    mv      a1, s6
    call    quic_rx_limits
    bnez    a0, 99f
    sd      s6, S_RX_FINAL(s2)
    sd      s5, S_RESET_CODE(s2)
    ld      t0, S_RX_DONE(s2)               # the bytes never delivered count as delivered
    sub     t1, s6, t0
    LDX     t2, s1, C_RX_DONE
    add     t2, t2, t1
    SDX     t2, s1, C_RX_DONE
    sd      s6, S_RX_DONE(s2)
    ld      t0, S_FLAGS(s2)
    ORV     t0, (SF_RX_DONE | SF_TELL_RESET)
    BICV    t0, SF_TELL_FIN
    sd      t0, S_FLAGS(s2)
    call    quic_stream_drop_rx
    j       9f
7:  li      a0, ERR_FINAL_SIZE
    j       99f
8:  mv      a0, a1
    j       99f
9:  li      a0, 0
99: LEAVE   0
END_FUNCTION quic_on_reset_stream

/*
 * quic_on_stop_sending(id, code) -> 0 or the error code: the peer stops our
 * side: RESET_STREAM goes out (RFC 9000 section 3.5) and the application
 * hears STREAM_RESET with the code.
 */
LOCAL_FUNCTION quic_on_stop_sending
    ENTER   0
    mv      s5, a1
    call    quic_peer_stream
    bnez    a1, 8f
    beqz    a0, 9f
    mv      s2, a0
    ld      t0, S_FLAGS(s2)
    mv      t1, t0
    ANDV    t1, SF_RESET
    bnez    t1, 9f
    sd      s5, S_RESET_CODE(s2)
    sd      s5, S_APP_CODE(s2)
    ORV     t0, (SF_RESET | SF_RESET_SEND)
    mv      t1, t0
    ANDV    t1, SF_TOLD_RESET
    bnez    t1, 1f
    ori     t0, t0, SF_TELL_RESET
1:  sd      t0, S_FLAGS(s2)
    call    quic_stream_drop
    j       9f
8:  mv      a0, a1
    j       99f
9:  li      a0, 0
99: LEAVE   0
END_FUNCTION quic_on_stop_sending

/* quic_on_max_stream_data(id, max) -> 0 or the error code. */
LOCAL_FUNCTION quic_on_max_stream_data
    ENTER   0
    mv      s5, a1
    call    quic_peer_stream
    bnez    a1, 8f
    beqz    a0, 9f
    ld      t0, S_TX_MAX(a0)
    bgeu    t0, s5, 1f
    mv      t0, s5
1:  sd      t0, S_TX_MAX(a0)
    j       9f
8:  mv      a0, a1
    j       99f
9:  li      a0, 0
99: LEAVE   0
END_FUNCTION quic_on_max_stream_data

/* ---------------------------------------------------------------- What the application hears */

/*
 * quic_stream_tell(stream) -> 1 when the stream is over and freed; else 0
 * after STREAM_OPENED, STREAM_DATA of the bytes in order, STREAM_FIN,
 * STREAM_RESET and STREAM_ACKED go out while the action room allows; new
 * credit is given.
 * s1 the connection. s2 stream, s3 the next segment.
 */
LOCAL_FUNCTION quic_stream_tell
    ENTER   0
    mv      s2, a0
    ld      t0, S_FLAGS(s2)
    andi    t0, t0, SF_TELL_OPEN
    beqz    t0, 1f
    ld      t0, S_ID(s2)
    li      t1, -1
    bne     t0, t1, 11f
    ld      t0, S_FLAGS(s2)
    andi    t0, t0, SF_LOCAL
    beqz    t0, 1f
11: call    quic_room
    li      t0, QUIC_ACT_OPENED_SIZE
    bltu    a0, t0, 8f
    li      a0, QUIC_ACTION_STREAM_OPENED
    li      a1, QUIC_ACT_OPENED_SIZE
    call    quic_action
    mv      s3, a0
    mv      a0, s2
    call    quic_stream_handle
    sd      a0, QUIC_ACT_STREAM(s3)
    mv      a0, s1
    call    quic_conn_handle
    sd      a0, QUIC_ACT_S_CONN(s3)
    ld      t0, S_TAG(s2)
    sd      t0, QUIC_ACT_S_TAG(s3)
    ld      t0, S_FLAGS(s2)
    andi    t0, t0, ~SF_TELL_OPEN
    sd      t0, S_FLAGS(s2)
1:  ld      t0, S_FLAGS(s2)                 # data in order
    andi    t0, t0, SF_TELL_OPEN
    bnez    t0, 8f
2:  ld      s3, S_RX_HEAD(s2)
    beqz    s3, 4f
    add     s4, s9, s3
    ld      t0, R_OFFSET(s4)
    ld      t1, S_RX_DONE(s2)
    bne     t0, t1, 4f
    call    quic_room
    li      t0, (QUIC_ACT_S_DATA + 8)
    bgeu    t0, a0, 8f
    sub     s5, a0, t0
    ld      s6, R_LEN(s4)
    bgeu    s5, s6, 21f                     # the bytes that fit
    mv      s6, s5
21: addi    a1, s6, (QUIC_ACT_S_DATA + 7)
    andi    a1, a1, -8
    li      a0, QUIC_ACTION_STREAM_DATA
    call    quic_action
    mv      s7, a0
    mv      a0, s2
    call    quic_stream_handle
    sd      a0, QUIC_ACT_STREAM(s7)
    sd      s6, QUIC_ACT_S_COUNT(s7)
    addi    a0, s7, QUIC_ACT_S_DATA
    addi    a1, s4, R_DATA
    mv      a2, s6
    call    quic_copy
    ld      t0, S_RX_DONE(s2)
    add     t0, t0, s6
    sd      t0, S_RX_DONE(s2)
    LDX     t0, s1, C_RX_DONE
    add     t0, t0, s6
    SDX     t0, s1, C_RX_DONE
    ld      t1, R_LEN(s4)
    bltu    s6, t1, 3f
    ld      t0, R_NEXT(s4)                  # the whole segment went
    sd      t0, S_RX_HEAD(s2)
    mv      a0, s3
    call    quic_heap_free
    j       2b
3:  sub     t1, t1, s6                      # part of it: move the rest down
    sd      t1, R_LEN(s4)
    ld      t0, R_OFFSET(s4)
    add     t0, t0, s6
    sd      t0, R_OFFSET(s4)
    addi    a0, s4, R_DATA
    add     a1, a0, s6
    mv      a2, t1
    call    quic_copy
    j       8f
4:  ld      t0, S_FLAGS(s2)                 # FIN
    mv      t1, t0
    ANDV    t1, (SF_TOLD_FIN | SF_TOLD_RESET)
    bnez    t1, 5f
    ld      t1, S_RX_FINAL(s2)
    ld      t2, S_RX_DONE(s2)
    bne     t1, t2, 5f
    call    quic_room
    li      t0, QUIC_ACT_FIN_SIZE
    bltu    a0, t0, 8f
    li      a0, QUIC_ACTION_STREAM_FIN
    li      a1, QUIC_ACT_FIN_SIZE
    call    quic_action
    mv      s3, a0
    mv      a0, s2
    call    quic_stream_handle
    sd      a0, QUIC_ACT_STREAM(s3)
    ld      t0, S_FLAGS(s2)
    ORV     t0, (SF_TOLD_FIN | SF_RX_DONE)
    sd      t0, S_FLAGS(s2)
5:  ld      t0, S_FLAGS(s2)                 # RESET
    andi    t0, t0, SF_TELL_RESET
    beqz    t0, 6f
    call    quic_room
    li      t0, QUIC_ACT_RESET_SIZE
    bltu    a0, t0, 8f
    li      a0, QUIC_ACTION_STREAM_RESET
    li      a1, QUIC_ACT_RESET_SIZE
    call    quic_action
    mv      s3, a0
    mv      a0, s2
    call    quic_stream_handle
    sd      a0, QUIC_ACT_STREAM(s3)
    ld      t0, S_RESET_CODE(s2)
    sd      t0, QUIC_ACT_S_CODE(s3)
    ld      t0, S_FLAGS(s2)
    andi    t0, t0, ~SF_TELL_RESET
    ORV     t0, SF_TOLD_RESET
    sd      t0, S_FLAGS(s2)
6:  ld      t0, S_ACKED(s2)                 # bytes the peer acknowledged
    ld      t1, S_ACK_TOLD(s2)
    beq     t0, t1, 61f
    call    quic_room
    li      t0, QUIC_ACT_ACKED_SIZE
    bltu    a0, t0, 8f
    li      a0, QUIC_ACTION_STREAM_ACKED
    li      a1, QUIC_ACT_ACKED_SIZE
    call    quic_action
    mv      s3, a0
    mv      a0, s2
    call    quic_stream_handle
    sd      a0, QUIC_ACT_STREAM(s3)
    ld      t0, S_ACKED(s2)
    ld      t1, S_ACK_TOLD(s2)
    sub     t1, t0, t1
    sd      t1, QUIC_ACT_S_COUNT(s3)
    sd      t0, S_ACK_TOLD(s2)
61: call    quic_stream_credit
    ld      t0, S_FLAGS(s2)                 # over both ways?
    andi    t1, t0, SF_FIN_ACKED
    beqz    t1, 8f
    andi    t1, t0, SF_RX_DONE
    beqz    t1, 8f
    mv      t1, t0
    ANDV    t1, (SF_TOLD_FIN | SF_TOLD_RESET)
    beqz    t1, 8f
    andi    t1, t0, (SF_TELL_RESET | SF_RESET_SEND | SF_STOP_SEND)
    bnez    t1, 8f
    andi    t1, t0, SF_LOCAL
    bnez    t1, 7f
    LDX     t0, s1, C_PEER_DONE             # a stream of the peer is over: room for one more
    addi    t0, t0, 1
    SDX     t0, s1, C_PEER_DONE
    CFG     t1, QUIC_CFG_MAX_STREAMS
    add     t1, t1, t0
    LDX     t2, s1, C_PEER_MAX
    bgeu    t2, t1, 7f
    SDX     t1, s1, C_PEER_MAX
    ld      t0, C_FLAGS(s1)
    ori     t0, t0, CF_MAX_STREAMS
    sd      t0, C_FLAGS(s1)
7:  mv      a0, s2
    call    quic_stream_free
    li      a0, 1
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_stream_tell

/*
 * quic_stream_credit(): new flow control credit: MAX_STREAM_DATA when half the
 * window of the stream is used, and MAX_DATA when half that of the
 * connection is. s1 the connection, s2 the stream.
 */
LOCAL_FUNCTION quic_stream_credit
    ENTER   0
    ld      t0, S_FLAGS(s2)
    andi    t1, t0, SF_RX_DONE
    bnez    t1, 1f
    ld      t1, S_RX_FINAL(s2)
    li      t2, -1
    bne     t1, t2, 1f
    CFG     t1, QUIC_CFG_STREAM_DATA
    ld      t2, S_RX_DONE(s2)
    ld      t3, S_RX_MAX(s2)
    sub     t4, t3, t2
    srli    t5, t1, 1
    bgeu    t4, t5, 1f
    add     t3, t2, t1
    sd      t3, S_RX_MAX(s2)
    ORV     t0, SF_MSD
    sd      t0, S_FLAGS(s2)
1:  CFG     t1, QUIC_CFG_MAX_DATA
    LDX     t2, s1, C_RX_DONE
    LDX     t3, s1, C_RX_MAX
    sub     t4, t3, t2
    srli    t5, t1, 1
    bgeu    t4, t5, 9f
    add     t3, t2, t1
    SDX     t3, s1, C_RX_MAX
    ld      t0, C_FLAGS(s1)
    ori     t0, t0, CF_MAX_DATA
    sd      t0, C_FLAGS(s1)
9:  LEAVE   0
END_FUNCTION quic_stream_credit
