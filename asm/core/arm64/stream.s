/*
 * Bidirectional streams (RFC 9000 sections 2, 3 and 4): slots, the send queue
 * with its acknowledged and lost ranges, the receive segments, flow control,
 * and what the application hears. x19 the connection, where a function uses it.
 */

.set ERR_FLOW_CONTROL, 0x03
.set ERR_STREAM_LIMIT, 0x04
.set ERR_STREAM_STATE, 0x05
.set ERR_FINAL_SIZE, 0x06

/* ---------------------------------------------------------------- Slots */

/*
 * quic_stream_new(id, local) -> a new stream of the connection with the ID (or
 * NONE), linked first in its list; 0 when no slot is free. x19 the connection.
 */
LOCAL_FUNCTION quic_stream_new
    ENTER   0
    mov     x20, x0
    mov     x21, x1
    mov     x0, #ST_STREAM_OFF
    mov     x1, #ST_STREAM_COUNT
    mov     x2, #S_SIZE
    bl      quic_alloc_slot
    cbz     x0, 9f
    mov     x22, x0
    mov     x0, x19
    bl      quic_conn_index
    str     x0, [x22, #S_CONN]
    ldr     w9, [x19, #C_GEN]
    str     x9, [x22, #S_CONN_GEN]
    str     x20, [x22, #S_ID]
    mov     x9, #SF_TELL_OPEN
    cbz     x21, 1f
    orr     x9, x9, #SF_LOCAL
1:  str     x9, [x22, #S_FLAGS]
    mov     x9, #NONE
    str     x9, [x22, #S_RX_FINAL]
    ldr     x9, [x27, #(ST_CONFIG + QUIC_CFG_STREAM_DATA)]
    str     x9, [x22, #S_RX_MAX]
    ldr     x9, [x19, #C_P_SD_LOCAL]        /* the peer's limit for streams it opened */
    ldr     x10, [x19, #C_P_SD_REMOTE]      /* and for streams we opened */
    cmp     x21, #0
    csel    x9, x10, x9, ne
    str     x9, [x22, #S_TX_MAX]
    ldr     x9, [x19, #C_STREAM_HEAD]
    str     x9, [x22, #S_NEXT]
    mov     x0, x22
    bl      quic_stream_index
    str     x0, [x19, #C_STREAM_HEAD]
    mov     x0, x22
9:  LEAVE   0
END_FUNCTION quic_stream_new

/*
 * quic_stream_free(stream): its chunks and segments go, it leaves the list of
 * its connection, and the slot is free.
 */
LOCAL_FUNCTION quic_stream_free
    ENTER   0
    mov     x20, x0
    ldr     x0, [x20, #S_CONN]
    bl      quic_conn_at
    mov     x21, x0
1:  ldr     x0, [x20, #S_Q_HEAD]
    cbz     x0, 2f
    add     x9, x27, x0
    ldr     x9, [x9, #Q_NEXT]
    str     x9, [x20, #S_Q_HEAD]
    bl      quic_heap_free
    b       1b
2:  ldr     x0, [x20, #S_RX_HEAD]
    cbz     x0, 3f
    add     x9, x27, x0
    ldr     x9, [x9, #R_NEXT]
    str     x9, [x20, #S_RX_HEAD]
    bl      quic_heap_free
    b       2b
3:  mov     x0, x20                         /* unlink */
    bl      quic_stream_index
    mov     x22, x0
    ldr     x9, [x21, #C_STREAM_HEAD]
    cmp     x9, x22
    b.ne    4f
    ldr     x10, [x20, #S_NEXT]
    str     x10, [x21, #C_STREAM_HEAD]
    b       6f
4:  cmn     x9, #1
    b.eq    6f
    mov     x0, x9
    bl      quic_stream_at
    ldr     x9, [x0, #S_NEXT]
    cmp     x9, x22
    b.ne    4b
    ldr     x10, [x20, #S_NEXT]
    str     x10, [x0, #S_NEXT]
6:  str     wzr, [x20, #S_USED]
    LEAVE   0
END_FUNCTION quic_stream_free

/* quic_stream_find(id) -> the stream of the connection with the ID, or 0. x19 the connection. */
LOCAL_FUNCTION quic_stream_find
    ENTER   0
    mov     x20, x0
    ldr     x21, [x19, #C_STREAM_HEAD]
1:  cmn     x21, #1
    b.eq    8f
    mov     x0, x21
    bl      quic_stream_at
    ldr     x9, [x0, #S_ID]
    cmp     x9, x20
    b.eq    9f
    ldr     x21, [x0, #S_NEXT]
    b       1b
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_stream_find

/*
 * quic_assign_ids(): our streams that wait get IDs while the peer's
 * MAX_STREAMS allows: 4n for a client, 4n + 1 for a server. x19 the connection.
 */
LOCAL_FUNCTION quic_assign_ids
    ENTER   0
0:  ldr     x20, [x19, #C_STREAM_HEAD]
    mov     x21, #NONE                      /* the oldest waiting stream is last in the list */
1:  cmn     x20, #1
    b.eq    2f
    mov     x0, x20
    bl      quic_stream_at
    ldr     x9, [x0, #S_ID]
    cmn     x9, #1
    csel    x21, x20, x21, eq
    ldr     x20, [x0, #S_NEXT]
    b       1b
2:  cmn     x21, #1
    b.eq    9f
    ldr     x9, [x19, #C_LOCAL_OPEN]
    ldr     x10, [x19, #C_P_STREAMS]
    cmp     x9, x10
    b.hs    9f
    mov     x0, x21
    bl      quic_stream_at
    ldr     x9, [x19, #C_LOCAL_OPEN]
    ldr     x10, [x19, #C_ROLE]
    orr     x11, x10, x9, lsl #2
    str     x11, [x0, #S_ID]
    add     x9, x9, #1
    str     x9, [x19, #C_LOCAL_OPEN]
    b       0b
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
    mov     x23, x0
    ldr     x0, [x23, #QUIC_EV_CONN]
    bl      quic_conn
    cbz     x0, 7f
    mov     x19, x0
    ldr     x9, [x19, #C_STATE]
    cmp     x9, #CS_ACTIVE
    b.ne    7f
    mov     x0, #NONE
    mov     x1, #1
    bl      quic_stream_new
    cbz     x0, 7f
    ldr     x9, [x23, #QUIC_EV_OPEN_TAG]
    str     x9, [x0, #S_TAG]
    bl      quic_assign_ids
    b       9f
7:  mov     x0, #QUIC_ACTION_STREAM_OPENED   /* no stream: handle 0 */
    mov     x1, #QUIC_ACT_OPENED_SIZE
    bl      quic_action
    cbz     x0, 9f
    ldr     x9, [x23, #QUIC_EV_CONN]
    str     x9, [x0, #QUIC_ACT_S_CONN]
    ldr     x9, [x23, #QUIC_EV_OPEN_TAG]
    str     x9, [x0, #QUIC_ACT_S_TAG]
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
    mov     x23, x0
    ldr     x0, [x23, #QUIC_EV_STREAM]
    bl      quic_stream
    cbz     x0, 9f
    mov     x20, x0
    ldr     x9, [x20, #S_FLAGS]
    mov     x10, #(SF_FIN_WANT | SF_RESET)
    tst     x9, x10
    b.ne    9f
    ldr     x24, [x23, #QUIC_EV_WRITE_COUNT]
    cbz     x24, 9f
    ldr     x9, [x20, #S_WRITTEN]
    ldr     x10, [x20, #S_Q_BASE]
    sub     x9, x9, x10
    add     x9, x9, x24
    ldr     x10, [x27, #(ST_CONFIG + QUIC_CFG_STREAM_QUEUE)]
    cmp     x9, x10
    b.hi    8f
    add     x0, x24, #Q_DATA
    bl      quic_heap_alloc
    cbz     x0, 8f
    mov     x21, x0
    add     x22, x27, x21
    str     xzr, [x22, #Q_NEXT]
    str     x24, [x22, #Q_LEN]
    add     x0, x22, #Q_DATA
    add     x1, x23, #QUIC_EV_WRITE_DATA
    mov     x2, x24
    bl      quic_copy
    ldr     x9, [x20, #S_Q_TAIL]
    cbz     x9, 1f
    add     x9, x27, x9
    str     x21, [x9, #Q_NEXT]
    b       2f
1:  str     x21, [x20, #S_Q_HEAD]
    ldr     x9, [x20, #S_WRITTEN]
    str     x9, [x20, #S_Q_BASE]
2:  str     x21, [x20, #S_Q_TAIL]
    ldr     x9, [x20, #S_WRITTEN]
    add     x9, x9, x24
    str     x9, [x20, #S_WRITTEN]
    b       9f
8:  mov     x0, x20
    mov     x1, #0
    bl      quic_stream_reset_local
9:  LEAVE   0
END_FUNCTION quic_on_stream_write

/* quic_on_stream_close(event): no more bytes: a FIN follows the queue. */
LOCAL_FUNCTION quic_on_stream_close
    ENTER   0
    ldr     x0, [x0, #QUIC_EV_STREAM]
    bl      quic_stream
    cbz     x0, 9f
    ldr     x9, [x0, #S_FLAGS]
    orr     x9, x9, #SF_FIN_WANT
    str     x9, [x0, #S_FLAGS]
9:  LEAVE   0
END_FUNCTION quic_on_stream_close

/* quic_on_stream_reset(event): the application resets the stream both ways with its code. */
LOCAL_FUNCTION quic_on_stream_reset
    ENTER   0
    mov     x20, x0
    ldr     x0, [x20, #QUIC_EV_STREAM]
    bl      quic_stream
    cbz     x0, 9f
    ldr     x1, [x20, #QUIC_EV_CODE]
    bl      quic_stream_reset_local
9:  LEAVE   0
END_FUNCTION quic_on_stream_reset

/*
 * quic_stream_reset_local(stream, code): RESET_STREAM and STOP_SENDING with
 * the code go out; the queue is dropped; the peer's data is no longer heard.
 * The application is not told.
 */
LOCAL_FUNCTION quic_stream_reset_local
    ENTER   0
    mov     x20, x0
    str     x1, [x20, #S_APP_CODE]
    ldr     x9, [x20, #S_FLAGS]
    tst     x9, #SF_RESET
    b.ne    9f
    mov     x10, #(SF_RESET | SF_RESET_SEND | SF_TOLD_RESET)
    orr     x9, x9, x10
    tst     x9, #SF_RX_DONE
    b.ne    1f
    mov     x10, #(SF_STOP_SEND | SF_RX_DONE)
    orr     x9, x9, x10
1:  bic     x9, x9, #(SF_TELL_RESET | SF_TELL_FIN)
    str     x9, [x20, #S_FLAGS]
    bl      quic_stream_drop
9:  LEAVE   0
END_FUNCTION quic_stream_reset_local

/* quic_stream_drop(): the queue of the stream at x20 is freed, and its segments when its receive side is over. */
LOCAL_FUNCTION quic_stream_drop
    ENTER   0
1:  ldr     x0, [x20, #S_Q_HEAD]
    cbz     x0, 2f
    add     x9, x27, x0
    ldr     x9, [x9, #Q_NEXT]
    str     x9, [x20, #S_Q_HEAD]
    bl      quic_heap_free
    b       1b
2:  str     xzr, [x20, #S_Q_TAIL]
    str     xzr, [x20, #S_NLOST]
    ldr     x9, [x20, #S_FLAGS]
    tst     x9, #SF_RX_DONE
    b.eq    9f
    bl      quic_stream_drop_rx
9:  LEAVE   0
END_FUNCTION quic_stream_drop

/* quic_stream_drop_rx(): the segments of the stream at x20 are freed. */
LOCAL_FUNCTION quic_stream_drop_rx
    ENTER   0
1:  ldr     x0, [x20, #S_RX_HEAD]
    cbz     x0, 9f
    add     x9, x27, x0
    ldr     x9, [x9, #R_NEXT]
    str     x9, [x20, #S_RX_HEAD]
    bl      quic_heap_free
    b       1b
9:  LEAVE   0
END_FUNCTION quic_stream_drop_rx

/* ---------------------------------------------------------------- Acknowledged and lost data */

/*
 * quic_stream_acked(stream, offset, len, fin): a STREAM frame of ours is
 * acknowledged: the range joins the acknowledged ranges, S_ACKED moves over
 * every range that touches it, and the chunks below it are freed.
 * x20 stream, x21 start, x22 end, x23 fin.
 */
LOCAL_FUNCTION quic_stream_acked
    ENTER   0
    mov     x20, x0
    mov     x21, x1
    add     x22, x1, x2
    mov     x23, x3
    ldr     x9, [x20, #S_FLAGS]
    tst     x9, #SF_RESET
    b.ne    9f
    cbz     x23, 1f
    orr     x9, x9, #SF_FIN_SENT
    str     x9, [x20, #S_FLAGS]
    mov     x9, #1                          /* the FIN is acknowledged: kept in S_NACKS bit 63 */
    lsl     x9, x9, #63
    ldr     x10, [x20, #S_NACKS]
    orr     x10, x10, x9
    str     x10, [x20, #S_NACKS]
1:  mov     x0, x20
    mov     x1, x21
    mov     x2, x22
    add     x3, x20, #S_NACKS
    mov     x4, #6
    bl      quic_ranges_add
    bl      quic_stream_advance
9:  LEAVE   0
END_FUNCTION quic_stream_acked

/*
 * quic_stream_advance(): S_ACKED moves over the acknowledged ranges that touch
 * it; chunks wholly below it are freed; a stream whose FIN and data are all
 * acknowledged gets SF_FIN_ACKED. x20 the stream.
 */
LOCAL_FUNCTION quic_stream_advance
    ENTER   0
1:  ldr     x9, [x20, #S_NACKS]
    and     x10, x9, #0xFF
    cbz     x10, 3f
    ldp     x11, x12, [x20, #S_ACKS]
    ldr     x13, [x20, #S_ACKED]
    cmp     x11, x13
    b.hi    3f
    cmp     x12, x13
    csel    x13, x12, x13, hi
    str     x13, [x20, #S_ACKED]
    mov     x0, x20                         /* the first range goes */
    add     x1, x20, #S_NACKS
    mov     x2, #0
    bl      quic_ranges_remove
    b       1b
3:  ldr     x21, [x20, #S_ACKED]            /* free the chunks below */
4:  ldr     x0, [x20, #S_Q_HEAD]
    cbz     x0, 5f
    add     x9, x27, x0
    ldr     x10, [x9, #Q_LEN]
    ldr     x11, [x20, #S_Q_BASE]
    add     x12, x11, x10
    cmp     x12, x21
    b.hi    5f
    str     x12, [x20, #S_Q_BASE]
    ldr     x10, [x9, #Q_NEXT]
    str     x10, [x20, #S_Q_HEAD]
    cbnz    x10, 41f
    str     xzr, [x20, #S_Q_TAIL]
41: bl      quic_heap_free
    b       4b
5:  ldr     x9, [x20, #S_NACKS]             /* FIN acknowledged and all data */
    tbz     x9, #63, 9f
    ldr     x10, [x20, #S_WRITTEN]
    cmp     x21, x10
    b.lo    9f
    ldr     x9, [x20, #S_FLAGS]
    orr     x9, x9, #SF_FIN_ACKED
    str     x9, [x20, #S_FLAGS]
9:  LEAVE   0
END_FUNCTION quic_stream_advance

/*
 * quic_stream_lost(stream, offset, len, fin): a STREAM frame of ours was lost:
 * the part not yet acknowledged joins the lost ranges, and a FIN goes out again.
 */
LOCAL_FUNCTION quic_stream_lost
    ENTER   0
    mov     x20, x0
    mov     x21, x1
    add     x22, x1, x2
    ldr     x9, [x20, #S_FLAGS]
    tst     x9, #SF_RESET
    b.ne    9f
    cbz     x3, 1f
    ldr     x10, [x20, #S_NACKS]
    tbnz    x10, #63, 1f
    orr     x9, x9, #SF_FIN_LOST
    str     x9, [x20, #S_FLAGS]
1:  ldr     x9, [x20, #S_ACKED]
    cmp     x21, x9
    csel    x21, x9, x21, lo
    cmp     x21, x22
    b.hs    9f
    mov     x0, x20
    mov     x1, x21
    mov     x2, x22
    add     x3, x20, #S_NLOST
    mov     x4, #4
    bl      quic_ranges_add
9:  LEAVE   0
END_FUNCTION quic_stream_lost

/* quic_stream_reset_acked(stream): our RESET_STREAM is acknowledged: our side is over. */
LOCAL_FUNCTION quic_stream_reset_acked
    ENTER   0
    ldr     x9, [x0, #S_FLAGS]
    orr     x9, x9, #SF_FIN_ACKED
    str     x9, [x0, #S_FLAGS]
    LEAVE   0
END_FUNCTION quic_stream_reset_acked

/*
 * quic_ranges_add(stream, start, end, list, max): adds [start, end) to a list
 * of ranges kept in order and joined: the u8 count at list (other bits kept),
 * then max pairs at list + 8. When the list is full the range joins the last
 * one, covering the gap: lost ranges then send a little more again, and
 * acknowledged ones cannot lose a range.
 * x20 list count word, x21 start, x22 end, x23 the pairs, x24 count, x25 max, x26 index.
 */
LOCAL_FUNCTION quic_ranges_add
    ENTER   0
    mov     x19, x3
    mov     x21, x1
    mov     x22, x2
    mov     x25, x4
    add     x23, x19, #8
    ldr     x20, [x19]
    and     x24, x20, #0xFF
    mov     x26, #0
1:  cmp     x26, x24
    b.hs    5f
    add     x9, x23, x26, lsl #4
    ldp     x10, x11, [x9]
    cmp     x22, x10
    b.lo    4f                              /* wholly before this range: insert here */
    cmp     x21, x11
    b.hi    3f                              /* wholly after: next */
    cmp     x21, x10                        /* they touch: join */
    csel    x10, x21, x10, lo
    cmp     x22, x11
    csel    x11, x22, x11, hi
    stp     x10, x11, [x9]
2:  add     x12, x26, #1                    /* join the ranges after that now touch */
    cmp     x12, x24
    b.hs    9f
    add     x13, x23, x12, lsl #4
    ldp     x14, x15, [x13]
    cmp     x14, x11
    b.hi    9f
    cmp     x15, x11
    csel    x11, x15, x11, hi
    str     x11, [x9, #8]
    mov     x0, x19
    mov     x1, x19
    mov     x2, x12
    bl      quic_ranges_remove
    ldr     x20, [x19]
    and     x24, x20, #0xFF
    b       2b
3:  add     x26, x26, #1
    b       1b
4:  cmp     x24, x25                        /* insert at x26 */
    b.hs    6f
    mov     x12, x24
41: cmp     x12, x26
    b.ls    42f
    sub     x13, x12, #1
    add     x14, x23, x13, lsl #4
    ldp     x15, x16, [x14]
    stp     x15, x16, [x14, #16]
    mov     x12, x13
    b       41b
42: add     x9, x23, x26, lsl #4
    stp     x21, x22, [x9]
    add     x20, x20, #1
    str     x20, [x19]
    b       9f
5:  cmp     x24, x25                        /* append */
    b.hs    6f
    b       42b
6:  cbz     x24, 9f                         /* full: join the last range */
    sub     x26, x24, #1
    add     x9, x23, x26, lsl #4
    ldp     x10, x11, [x9]
    cmp     x21, x10
    csel    x10, x21, x10, lo
    cmp     x22, x11
    csel    x11, x22, x11, hi
    stp     x10, x11, [x9]
9:  LEAVE   0
END_FUNCTION quic_ranges_add

/* quic_ranges_remove(stream, list, index): the range at index of the list goes. A leaf. */
LOCAL_FUNCTION quic_ranges_remove
    UNWIND_END_PROLOGUE
    ldr     x3, [x1]
    and     x4, x3, #0xFF
    add     x5, x1, #8
1:  add     x6, x2, #1
    cmp     x6, x4
    b.hs    2f
    add     x7, x5, x6, lsl #4
    ldp     x0, x8, [x7]                    /* x9 and above stay: quic_ranges_add keeps a range there */
    stp     x0, x8, [x7, #-16]
    mov     x2, x6
    b       1b
2:  sub     x3, x3, #1
    str     x3, [x1]
    ret
END_FUNCTION quic_ranges_remove

/* ---------------------------------------------------------------- Frames of the peer */

/*
 * quic_peer_stream(id) -> x0 the stream of the ID for a frame of the peer, or
 * 0 when the frame is to be ignored (a stream that is over); x1 0, or the
 * error code. A stream the peer may open that is new opens, with every lower
 * one of its kind (RFC 9000 section 3.2). x19 the connection.
 * x20 id, x21 the stream number, x22 the error.
 */
LOCAL_FUNCTION quic_peer_stream
    ENTER   0
    mov     x20, x0
    mov     x22, #0
    tst     x20, #2                         /* unidirectional: we allow none */
    b.eq    1f
    mov     x22, #ERR_STREAM_LIMIT
    b       8f
1:  bl      quic_stream_find
    cbnz    x0, 9f
    and     x9, x20, #1                     /* who opened it */
    ldr     x10, [x19, #C_ROLE]
    cmp     x9, x10
    b.ne    2f
    lsr     x21, x20, #2                    /* ours: a stream we opened and is over, or one we never opened */
    ldr     x9, [x19, #C_LOCAL_OPEN]
    cmp     x21, x9
    b.lo    8f
    mov     x22, #ERR_STREAM_STATE
    b       8f
2:  lsr     x21, x20, #2
    ldr     x9, [x19, #C_PEER_MAX]
    cmp     x21, x9
    b.lo    3f
    mov     x22, #ERR_STREAM_LIMIT
    b       8f
3:  ldr     x23, [x19, #C_PEER_OPEN]
    cmp     x21, x23
    b.lo    8f                              /* opened before and over */
4:  cmp     x23, x21
    b.hi    6f
    lsl     x0, x23, #2
    and     x9, x20, #3
    orr     x0, x0, x9
    mov     x1, #0
    bl      quic_stream_new
    cbz     x0, 5f
    add     x23, x23, #1
    str     x23, [x19, #C_PEER_OPEN]
    b       4b
5:  mov     x22, #ERR_INTERNAL              /* no slot */
    b       8f
6:  mov     x0, x20
    bl      quic_stream_find
    b       9f
8:  mov     x0, #0
9:  mov     x1, x22
    LEAVE   0
END_FUNCTION quic_peer_stream

/*
 * quic_rx_limits(stream, end) -> 0 or the error code: the flow control of the
 * stream and the connection for data up to end, and the final size rules
 * (RFC 9000 sections 4.1 and 4.5). S_RX_SEEN and C_RX_SEEN move up.
 */
LOCAL_FUNCTION quic_rx_limits
    ENTER   0
    mov     x20, x0
    ldr     x9, [x20, #S_RX_FINAL]
    cmn     x9, #1
    b.eq    1f
    cmp     x1, x9
    b.hi    7f
1:  ldr     x9, [x20, #S_RX_MAX]
    cmp     x1, x9
    b.hi    6f
    ldr     x9, [x20, #S_RX_SEEN]
    cmp     x1, x9
    b.ls    2f
    sub     x10, x1, x9
    str     x1, [x20, #S_RX_SEEN]
    ldr     x11, [x19, #C_RX_SEEN]
    add     x11, x11, x10
    str     x11, [x19, #C_RX_SEEN]
    ldr     x12, [x19, #C_RX_MAX]
    cmp     x11, x12
    b.hi    6f
2:  mov     x0, #0
    b       9f
6:  mov     x0, #ERR_FLOW_CONTROL
    b       9f
7:  mov     x0, #ERR_FINAL_SIZE
9:  LEAVE   0
END_FUNCTION quic_rx_limits

/*
 * quic_on_stream_frame(id, offset, data, len, fin) -> 0 or the error code: a
 * STREAM frame. Its bytes past those delivered join the segments of the
 * stream, in order, overlaps cut.
 * x20 stream, x21 offset, x22 data, x23 len, x24 fin, x25 end, x26 id.
 */
LOCAL_FUNCTION quic_on_stream_frame
    ENTER   0
    mov     x26, x0
    mov     x21, x1
    mov     x22, x2
    mov     x23, x3
    mov     x24, x4
    add     x25, x21, x23
    mov     x9, #1
    lsl     x9, x9, #62
    cmp     x25, x9
    b.hs    7f
    mov     x0, x26
    bl      quic_peer_stream
    cbnz    x1, 8f
    cbz     x0, 9f
    mov     x20, x0
    ldr     x9, [x20, #S_FLAGS]
    tst     x9, #SF_RX_DONE
    b.ne    9f                              /* reset: late data is not heard */
    mov     x0, x20
    mov     x1, x25
    bl      quic_rx_limits
    cbnz    x0, 99f
    cbz     x24, 1f
    ldr     x9, [x20, #S_RX_FINAL]          /* a final size, once */
    cmn     x9, #1
    b.eq    11f
    cmp     x9, x25
    b.ne    71f
11: ldr     x9, [x20, #S_RX_SEEN]
    cmp     x25, x9
    b.lo    71f
    str     x25, [x20, #S_RX_FINAL]
1:  ldr     x9, [x20, #S_RX_DONE]           /* drop what is delivered */
    cmp     x21, x9
    b.hs    2f
    sub     x10, x9, x21
    cmp     x10, x23
    b.hs    9f
    add     x22, x22, x10
    sub     x23, x23, x10
    mov     x21, x9
2:  cbz     x23, 9f
    mov     x0, x20
    mov     x1, x21
    mov     x2, x22
    mov     x3, x23
    bl      quic_segment_add
    b       99f
7:  mov     x1, #ERR_FLOW_CONTROL
8:  mov     x0, x1
    b       99f
71: mov     x0, #ERR_FINAL_SIZE
    b       99f
9:  mov     x0, #0
99: LEAVE   0
END_FUNCTION quic_on_stream_frame

/*
 * quic_segment_add(stream, offset, data, len) -> 0, or ERR_INTERNAL when the
 * heap has no room: the bytes not held yet go into new segments in order.
 * x20 stream, x21 offset, x22 data, x23 end, x24 the link to the next segment,
 * x25 the segment there.
 */
LOCAL_FUNCTION quic_segment_add
    ENTER   0
    mov     x20, x0
    mov     x21, x1
    mov     x22, x2
    add     x23, x1, x3
    add     x24, x20, #S_RX_HEAD
1:  cmp     x21, x23
    b.hs    8f
    ldr     x25, [x24]
    cbz     x25, 3f
    add     x9, x27, x25
    ldr     x10, [x9, #R_OFFSET]
    ldr     x11, [x9, #R_LEN]
    add     x11, x10, x11
    cmp     x21, x11
    b.lo    2f
    add     x24, x9, #R_NEXT                /* this segment ends before: on */
    b       1b
2:  cmp     x21, x10
    b.hs    21f
    cmp     x23, x10                        /* a new segment before it, up to its start */
    csel    x26, x23, x10, lo
    b       4f
21: sub     x12, x11, x21                   /* inside it: skip what it holds */
    add     x21, x21, x12
    add     x22, x22, x12
    add     x24, x9, #R_NEXT
    b       1b
3:  mov     x26, x23                        /* past every segment */
4:  sub     x0, x26, x21
    add     x0, x0, #R_DATA
    bl      quic_heap_alloc
    cbz     x0, 7f
    add     x9, x27, x0
    str     x25, [x9, #R_NEXT]
    str     x21, [x9, #R_OFFSET]
    sub     x10, x26, x21
    str     x10, [x9, #R_LEN]
    str     x0, [x24]
    add     x24, x9, #R_NEXT
    add     x0, x9, #R_DATA
    mov     x1, x22
    mov     x2, x10
    bl      quic_copy
    sub     x10, x26, x21
    add     x22, x22, x10
    mov     x21, x26
    b       1b
7:  mov     x0, #ERR_INTERNAL
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_segment_add

/*
 * quic_on_reset_stream(id, code, final) -> 0 or the error code: the peer reset
 * its side: the final size is checked and counted, the segments go, and the
 * application hears STREAM_RESET with the code.
 */
LOCAL_FUNCTION quic_on_reset_stream
    ENTER   0
    mov     x23, x1
    mov     x24, x2
    bl      quic_peer_stream
    cbnz    x1, 8f
    cbz     x0, 9f
    mov     x20, x0
    ldr     x9, [x20, #S_FLAGS]
    tst     x9, #SF_RX_DONE
    b.ne    9f
    ldr     x9, [x20, #S_RX_FINAL]
    cmn     x9, #1
    b.eq    1f
    cmp     x9, x24
    b.ne    7f
1:  ldr     x9, [x20, #S_RX_SEEN]
    cmp     x24, x9
    b.lo    7f
    mov     x0, x20
    mov     x1, x24
    bl      quic_rx_limits
    cbnz    x0, 99f
    str     x24, [x20, #S_RX_FINAL]
    str     x23, [x20, #S_RESET_CODE]
    ldr     x9, [x20, #S_RX_DONE]           /* the bytes never delivered count as delivered */
    sub     x10, x24, x9
    ldr     x11, [x19, #C_RX_DONE]
    add     x11, x11, x10
    str     x11, [x19, #C_RX_DONE]
    str     x24, [x20, #S_RX_DONE]
    ldr     x9, [x20, #S_FLAGS]
    mov     x10, #(SF_RX_DONE | SF_TELL_RESET)
    orr     x9, x9, x10
    bic     x9, x9, #SF_TELL_FIN
    str     x9, [x20, #S_FLAGS]
    bl      quic_stream_drop_rx
    b       9f
7:  mov     x0, #ERR_FINAL_SIZE
    b       99f
8:  mov     x0, x1
    b       99f
9:  mov     x0, #0
99: LEAVE   0
END_FUNCTION quic_on_reset_stream

/*
 * quic_on_stop_sending(id, code) -> 0 or the error code: the peer stops our
 * side: RESET_STREAM goes out (RFC 9000 section 3.5) and the application
 * hears STREAM_RESET with the code.
 */
LOCAL_FUNCTION quic_on_stop_sending
    ENTER   0
    mov     x23, x1
    bl      quic_peer_stream
    cbnz    x1, 8f
    cbz     x0, 9f
    mov     x20, x0
    ldr     x9, [x20, #S_FLAGS]
    tst     x9, #SF_RESET
    b.ne    9f
    str     x23, [x20, #S_RESET_CODE]
    str     x23, [x20, #S_APP_CODE]
    mov     x10, #(SF_RESET | SF_RESET_SEND)
    orr     x9, x9, x10
    tst     x9, #SF_TOLD_RESET
    b.ne    1f
    orr     x9, x9, #SF_TELL_RESET
1:  str     x9, [x20, #S_FLAGS]
    bl      quic_stream_drop
    b       9f
8:  mov     x0, x1
    b       99f
9:  mov     x0, #0
99: LEAVE   0
END_FUNCTION quic_on_stop_sending

/* quic_on_max_stream_data(id, max) -> 0 or the error code. */
LOCAL_FUNCTION quic_on_max_stream_data
    ENTER   0
    mov     x23, x1
    bl      quic_peer_stream
    cbnz    x1, 8f
    cbz     x0, 9f
    ldr     x9, [x0, #S_TX_MAX]
    cmp     x23, x9
    csel    x9, x23, x9, hi
    str     x9, [x0, #S_TX_MAX]
    b       9f
8:  mov     x0, x1
    b       99f
9:  mov     x0, #0
99: LEAVE   0
END_FUNCTION quic_on_max_stream_data

/* ---------------------------------------------------------------- What the application hears */

/*
 * quic_stream_tell(stream) -> 1 when the stream is over and freed; else 0
 * after STREAM_OPENED, STREAM_DATA of the bytes in order, STREAM_FIN and
 * STREAM_RESET go out while the action room allows; new credit is given.
 * x19 the connection. x20 stream, x21 the next segment.
 */
LOCAL_FUNCTION quic_stream_tell
    ENTER   0
    mov     x20, x0
    ldr     x9, [x20, #S_FLAGS]
    tst     x9, #SF_TELL_OPEN
    b.eq    1f
    ldr     x9, [x20, #S_ID]
    cmn     x9, #1
    b.ne    11f
    ldr     x9, [x20, #S_FLAGS]
    tst     x9, #SF_LOCAL
    b.eq    1f
11: bl      quic_room
    cmp     x0, #QUIC_ACT_OPENED_SIZE
    b.lo    8f
    mov     x0, #QUIC_ACTION_STREAM_OPENED
    mov     x1, #QUIC_ACT_OPENED_SIZE
    bl      quic_action
    mov     x21, x0
    mov     x0, x20
    bl      quic_stream_handle
    str     x0, [x21, #QUIC_ACT_STREAM]
    mov     x0, x19
    bl      quic_conn_handle
    str     x0, [x21, #QUIC_ACT_S_CONN]
    ldr     x9, [x20, #S_TAG]
    str     x9, [x21, #QUIC_ACT_S_TAG]
    ldr     x9, [x20, #S_FLAGS]
    bic     x9, x9, #SF_TELL_OPEN
    str     x9, [x20, #S_FLAGS]
1:  ldr     x9, [x20, #S_FLAGS]             /* data in order */
    tst     x9, #SF_TELL_OPEN
    b.ne    8f
2:  ldr     x21, [x20, #S_RX_HEAD]
    cbz     x21, 4f
    add     x22, x27, x21
    ldr     x9, [x22, #R_OFFSET]
    ldr     x10, [x20, #S_RX_DONE]
    cmp     x9, x10
    b.ne    4f
    bl      quic_room
    subs    x23, x0, #(QUIC_ACT_S_DATA + 8)
    b.ls    8f
    ldr     x24, [x22, #R_LEN]
    cmp     x24, x23
    csel    x24, x24, x23, ls               /* the bytes that fit */
    add     x1, x24, #(QUIC_ACT_S_DATA + 7)
    and     x1, x1, #~7
    mov     x0, #QUIC_ACTION_STREAM_DATA
    bl      quic_action
    mov     x25, x0
    mov     x0, x20
    bl      quic_stream_handle
    str     x0, [x25, #QUIC_ACT_STREAM]
    str     x24, [x25, #QUIC_ACT_S_COUNT]
    add     x0, x25, #QUIC_ACT_S_DATA
    add     x1, x22, #R_DATA
    mov     x2, x24
    bl      quic_copy
    ldr     x9, [x20, #S_RX_DONE]
    add     x9, x9, x24
    str     x9, [x20, #S_RX_DONE]
    ldr     x9, [x19, #C_RX_DONE]
    add     x9, x9, x24
    str     x9, [x19, #C_RX_DONE]
    ldr     x10, [x22, #R_LEN]
    cmp     x24, x10
    b.lo    3f
    ldr     x9, [x22, #R_NEXT]              /* the whole segment went */
    str     x9, [x20, #S_RX_HEAD]
    mov     x0, x21
    bl      quic_heap_free
    b       2b
3:  sub     x10, x10, x24                   /* part of it: move the rest down */
    str     x10, [x22, #R_LEN]
    ldr     x9, [x22, #R_OFFSET]
    add     x9, x9, x24
    str     x9, [x22, #R_OFFSET]
    add     x0, x22, #R_DATA
    add     x1, x0, x24
    mov     x2, x10
    bl      quic_copy
    b       8f
4:  ldr     x9, [x20, #S_FLAGS]             /* FIN */
    tst     x9, #(SF_TOLD_FIN | SF_TOLD_RESET)
    b.ne    5f
    ldr     x10, [x20, #S_RX_FINAL]
    ldr     x11, [x20, #S_RX_DONE]
    cmp     x10, x11
    b.ne    5f
    bl      quic_room
    cmp     x0, #QUIC_ACT_FIN_SIZE
    b.lo    8f
    mov     x0, #QUIC_ACTION_STREAM_FIN
    mov     x1, #QUIC_ACT_FIN_SIZE
    bl      quic_action
    mov     x21, x0
    mov     x0, x20
    bl      quic_stream_handle
    str     x0, [x21, #QUIC_ACT_STREAM]
    ldr     x9, [x20, #S_FLAGS]
    mov     x10, #(SF_TOLD_FIN | SF_RX_DONE)
    orr     x9, x9, x10
    str     x9, [x20, #S_FLAGS]
5:  ldr     x9, [x20, #S_FLAGS]             /* RESET */
    tst     x9, #SF_TELL_RESET
    b.eq    6f
    bl      quic_room
    cmp     x0, #QUIC_ACT_RESET_SIZE
    b.lo    8f
    mov     x0, #QUIC_ACTION_STREAM_RESET
    mov     x1, #QUIC_ACT_RESET_SIZE
    bl      quic_action
    mov     x21, x0
    mov     x0, x20
    bl      quic_stream_handle
    str     x0, [x21, #QUIC_ACT_STREAM]
    ldr     x9, [x20, #S_RESET_CODE]
    str     x9, [x21, #QUIC_ACT_S_CODE]
    ldr     x9, [x20, #S_FLAGS]
    bic     x9, x9, #SF_TELL_RESET
    orr     x9, x9, #SF_TOLD_RESET
    str     x9, [x20, #S_FLAGS]
6:  bl      quic_stream_credit
    ldr     x9, [x20, #S_FLAGS]             /* over both ways? */
    tst     x9, #SF_FIN_ACKED
    b.eq    8f
    tst     x9, #SF_RX_DONE
    b.eq    8f
    tst     x9, #(SF_TOLD_FIN | SF_TOLD_RESET)
    b.eq    8f
    mov     x10, #(SF_TELL_RESET | SF_RESET_SEND | SF_STOP_SEND)
    tst     x9, x10
    b.ne    8f
    tst     x9, #SF_LOCAL
    b.ne    7f
    ldr     x9, [x19, #C_PEER_DONE]         /* a stream of the peer is over: room for one more */
    add     x9, x9, #1
    str     x9, [x19, #C_PEER_DONE]
    ldr     x10, [x27, #(ST_CONFIG + QUIC_CFG_MAX_STREAMS)]
    add     x10, x10, x9
    ldr     x11, [x19, #C_PEER_MAX]
    cmp     x10, x11
    b.ls    7f
    str     x10, [x19, #C_PEER_MAX]
    ldr     x9, [x19, #C_FLAGS]
    orr     x9, x9, #CF_MAX_STREAMS
    str     x9, [x19, #C_FLAGS]
7:  mov     x0, x20
    bl      quic_stream_free
    mov     x0, #1
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_stream_tell

/*
 * quic_stream_credit(): new flow control credit: MAX_STREAM_DATA when half the
 * window of the stream is used, and MAX_DATA when half that of the
 * connection is. x19 the connection, x20 the stream.
 */
LOCAL_FUNCTION quic_stream_credit
    ENTER   0
    ldr     x9, [x20, #S_FLAGS]
    tst     x9, #SF_RX_DONE
    b.ne    1f
    ldr     x10, [x20, #S_RX_FINAL]
    cmn     x10, #1
    b.ne    1f
    ldr     x10, [x27, #(ST_CONFIG + QUIC_CFG_STREAM_DATA)]
    ldr     x11, [x20, #S_RX_DONE]
    ldr     x12, [x20, #S_RX_MAX]
    sub     x13, x12, x11
    cmp     x13, x10, lsr #1
    b.hs    1f
    add     x12, x11, x10
    str     x12, [x20, #S_RX_MAX]
    orr     x9, x9, #SF_MSD
    str     x9, [x20, #S_FLAGS]
1:  ldr     x10, [x27, #(ST_CONFIG + QUIC_CFG_MAX_DATA)]
    ldr     x11, [x19, #C_RX_DONE]
    ldr     x12, [x19, #C_RX_MAX]
    sub     x13, x12, x11
    cmp     x13, x10, lsr #1
    b.hs    9f
    add     x12, x11, x10
    str     x12, [x19, #C_RX_MAX]
    ldr     x9, [x19, #C_FLAGS]
    orr     x9, x9, #CF_MAX_DATA
    str     x9, [x19, #C_FLAGS]
9:  LEAVE   0
END_FUNCTION quic_stream_credit
