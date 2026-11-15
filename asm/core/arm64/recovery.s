/*
 * Loss detection and congestion control of RFC 9002: the ring of sent
 * packets, acknowledgements and RTT samples, the packet and time thresholds,
 * the probe timeout, and NewReno. Also the packet numbers received, for ACK
 * frames. x19 the connection in every function here.
 */

.set K_PACKET_THRESHOLD, 3
.set K_GRANULARITY, 1000                /* 1 ms */

/* ---------------------------------------------------------------- Packet numbers received */

/*
 * quic_recv_pn(space, pn) -> 1 when pn was received before, else 0 after it
 * is added to the ranges of the space (largest first, at most SP_MAX_RANGES;
 * the smallest range goes when they are full). x21 the space, x22 pn.
 */
LOCAL_FUNCTION quic_recv_pn
    ENTER   0
    mov     x21, x0
    mov     x22, x1
    add     x23, x21, #SP_RANGES
    ldr     x24, [x21, #SP_NRANGES]
    mov     x25, #0                         /* index */
1:  cmp     x25, x24
    b.hs    6f                              /* below every range: a new last range */
    add     x9, x23, x25, lsl #4
    ldp     x10, x11, [x9]                  /* smallest, largest */
    cmp     x22, x11
    b.hi    2f
    cmp     x22, x10
    b.hs    90f                             /* inside: a duplicate */
    sub     x12, x10, #1
    cmp     x22, x12
    b.ne    3f
    str     x22, [x9]                       /* just below: the range grows down */
    add     x13, x25, #1                    /* joins the next range */
    cmp     x13, x24
    b.hs    80f
    ldp     x14, x15, [x9, #16]
    add     x15, x15, #1
    cmp     x15, x22
    b.ne    80f
    str     x14, [x9]
    mov     x0, x21
    mov     x1, x13
    bl      quic_range_remove
    b       80f
3:  add     x25, x25, #1
    b       1b
2:  add     x12, x11, #1                    /* above this range */
    cmp     x22, x12
    b.ne    5f
    str     x22, [x9, #8]                   /* just above: grows up; it cannot touch the range before */
    b       80f
5:  mov     x0, x21                         /* a new range before index x25 */
    mov     x1, x25
    mov     x2, x22
    bl      quic_range_insert
    b       80f
6:  mov     x0, x21
    mov     x1, x24
    mov     x2, x22
    bl      quic_range_insert
80: mov     x0, #0
    b       9f
90: mov     x0, #1
9:  LEAVE   0
END_FUNCTION quic_recv_pn

/* quic_range_insert(space, index, pn): a range [pn, pn] at index; the last range goes when full. */
LOCAL_FUNCTION quic_range_insert
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    ldr     x22, [x19, #SP_NRANGES]
    cmp     x20, #SP_MAX_RANGES
    b.hs    9f
    cmp     x22, #SP_MAX_RANGES
    b.lo    1f
    mov     x22, #(SP_MAX_RANGES - 1)
1:  add     x23, x19, #SP_RANGES            /* shift [index, n) up by one, from the end */
    mov     x24, x22
2:  cmp     x24, x20
    b.ls    3f
    sub     x9, x24, #1
    add     x10, x23, x9, lsl #4
    ldp     x11, x12, [x10]
    stp     x11, x12, [x10, #16]
    sub     x24, x24, #1
    b       2b
3:  add     x10, x23, x20, lsl #4
    stp     x21, x21, [x10]
    add     x22, x22, #1
    str     x22, [x19, #SP_NRANGES]
9:  LEAVE   0
END_FUNCTION quic_range_insert

/* quic_range_remove(space, index): the range at index goes. A leaf. */
LOCAL_FUNCTION quic_range_remove
    UNWIND_END_PROLOGUE
    ldr     x2, [x0, #SP_NRANGES]
    add     x3, x0, #SP_RANGES
1:  add     x4, x1, #1
    cmp     x4, x2
    b.hs    2f
    add     x5, x3, x4, lsl #4
    ldp     x6, x7, [x5]
    stp     x6, x7, [x5, #-16]
    mov     x1, x4
    b       1b
2:  sub     x2, x2, #1
    str     x2, [x0, #SP_NRANGES]
    ret
END_FUNCTION quic_range_remove

/* ---------------------------------------------------------------- The ring of sent packets */

/* quic_ring_free() -> 1 when the ring has room for a record. A leaf. */
LOCAL_FUNCTION quic_ring_free
    UNWIND_END_PROLOGUE
    ldr     x0, [x19, #C_SENT_COUNT]
    ldr     x1, [x19, #C_SENT_CAP]
    cmp     x0, x1
    cset    x0, lo
    ret
END_FUNCTION quic_ring_free

/* quic_record_at(i) -> the record i places after the oldest. A leaf. */
LOCAL_FUNCTION quic_record_at
    UNWIND_END_PROLOGUE
    ldr     x1, [x19, #C_SENT_HEAD]
    add     x1, x1, x0
    ldr     x2, [x19, #C_SENT_CAP]
    udiv    x3, x1, x2
    msub    x1, x3, x2, x1
    ldr     x0, [x19, #C_SENT]
    add     x0, x27, x0
    add     x0, x0, x1, lsl #7
    ret
END_FUNCTION quic_record_at

/*
 * quic_record_sent(space, pn, size, flags, frames, n): a new live record of a
 * packet sent now, with n frame refs; bytes in flight, the ack-eliciting count
 * and the loss timer follow. The caller checked quic_ring_free.
 */
LOCAL_FUNCTION quic_record_sent
    ENTER   0
    mov     x20, x0
    mov     x21, x1
    mov     x22, x2
    mov     x23, x3
    mov     x24, x4
    mov     x25, x5
    ldr     x0, [x19, #C_SENT_COUNT]
    bl      quic_record_at
    mov     x26, x0
    ldr     x9, [x19, #C_SENT_COUNT]
    add     x9, x9, #1
    str     x9, [x19, #C_SENT_COUNT]
    str     x21, [x26, #SR_PN]
    ldr     x9, [x27, #ST_NOW]
    str     x9, [x26, #SR_TIME]
    orr     x9, x23, #SRF_LIVE
    and     x10, x22, #0xFFFF
    orr     x10, x10, x20, lsl #16
    orr     x10, x10, x9, lsl #24
    orr     x10, x10, x25, lsl #32
    str     x10, [x26, #SR_INFO]
    add     x0, x26, #SR_FRAMES
    mov     x1, x24
    lsl     x2, x25, #4
    bl      quic_copy
    tst     x23, #SRF_FLIGHT
    b.eq    1f
    ldr     x9, [x19, #C_IN_FLIGHT]
    add     x9, x9, x22
    str     x9, [x19, #C_IN_FLIGHT]
1:  tst     x23, #SRF_ELICIT
    b.eq    2f
    mov     x0, x19
    mov     x1, x20
    bl      quic_space
    ldr     x9, [x0, #SP_ELICIT]
    add     x9, x9, #1
    str     x9, [x0, #SP_ELICIT]
    ldr     x9, [x27, #ST_NOW]
    str     x9, [x0, #SP_LAST_ELICIT]
    bl      quic_set_loss_timer
2:  LEAVE   0
END_FUNCTION quic_record_sent

/*
 * quic_record_gone(record, acked): a live record leaves: bytes in flight, the
 * ack-eliciting count and its frame refs follow (quic_ref_acked or
 * quic_ref_lost).
 */
LOCAL_FUNCTION quic_record_gone
    ENTER   0
    mov     x20, x0
    mov     x21, x1
    ldr     x22, [x20, #SR_INFO]
    bic     x9, x22, #(SRF_LIVE << 24)
    str     x9, [x20, #SR_INFO]
    lsr     x23, x22, #24
    and     x23, x23, #0xFF                 /* flags */
    tst     x23, #SRF_FLIGHT
    b.eq    1f
    and     x9, x22, #0xFFFF
    ldr     x10, [x19, #C_IN_FLIGHT]
    subs    x10, x10, x9
    csel    x10, xzr, x10, lo
    str     x10, [x19, #C_IN_FLIGHT]
1:  tst     x23, #SRF_ELICIT
    b.eq    2f
    mov     x0, x19
    ubfx    x1, x22, #16, #8
    bl      quic_space
    ldr     x9, [x0, #SP_ELICIT]
    subs    x9, x9, #1
    csel    x9, xzr, x9, lo
    str     x9, [x0, #SP_ELICIT]
2:  ubfx    x24, x22, #32, #8               /* the frame refs */
    add     x25, x20, #SR_FRAMES
3:  cbz     x24, 9f
    mov     x0, x25
    ubfx    x1, x22, #16, #8
    cbz     x21, 4f
    bl      quic_ref_acked
    b       5f
4:  bl      quic_ref_lost
5:  add     x25, x25, #16
    sub     x24, x24, #1
    b       3b
9:  LEAVE   0
END_FUNCTION quic_record_gone

/* quic_ring_tidy(): the oldest records that are no longer live leave the ring. */
LOCAL_FUNCTION quic_ring_tidy
    ENTER   0
1:  ldr     x20, [x19, #C_SENT_COUNT]
    cbz     x20, 9f
    mov     x0, #0
    bl      quic_record_at
    ldr     x9, [x0, #SR_INFO]
    tst     x9, #(SRF_LIVE << 24)
    b.ne    9f
    sub     x20, x20, #1
    str     x20, [x19, #C_SENT_COUNT]
    ldr     x9, [x19, #C_SENT_HEAD]
    add     x9, x9, #1
    ldr     x10, [x19, #C_SENT_CAP]
    cmp     x9, x10
    csel    x9, xzr, x9, hs
    str     x9, [x19, #C_SENT_HEAD]
    b       1b
9:  LEAVE   0
END_FUNCTION quic_ring_tidy

/*
 * quic_drop_space_records(space): every live record of the space leaves
 * without being acknowledged or lost (its keys are gone).
 */
LOCAL_FUNCTION quic_drop_space_records
    ENTER   0
    mov     x20, x0
    mov     x21, #0
1:  ldr     x9, [x19, #C_SENT_COUNT]
    cmp     x21, x9
    b.hs    8f
    mov     x0, x21
    bl      quic_record_at
    add     x21, x21, #1
    ldr     x22, [x0, #SR_INFO]
    tst     x22, #(SRF_LIVE << 24)
    b.eq    1b
    ubfx    x9, x22, #16, #8
    cmp     x9, x20
    b.ne    1b
    bic     x9, x22, #(SRF_LIVE << 24)
    str     x9, [x0, #SR_INFO]
    lsr     x9, x22, #24
    tst     x9, #SRF_FLIGHT
    b.eq    1b
    and     x9, x22, #0xFFFF
    ldr     x10, [x19, #C_IN_FLIGHT]
    subs    x10, x10, x9
    csel    x10, xzr, x10, lo
    str     x10, [x19, #C_IN_FLIGHT]
    b       1b
8:  mov     x0, x19
    mov     x1, x20
    bl      quic_space
    str     xzr, [x0, #SP_ELICIT]
    bl      quic_ring_tidy
    LEAVE   0
END_FUNCTION quic_drop_space_records

/* ---------------------------------------------------------------- Frame refs */

/* quic_ref_acked(ref, space): a frame of an acknowledged packet. */
LOCAL_FUNCTION quic_ref_acked
    ENTER   0
    mov     x20, x0
    ldrb    w9, [x20]
    cmp     w9, #FR_STREAM
    b.eq    1f
    cmp     w9, #FR_RESET
    b.eq    2f
    b       9f
1:  bl      quic_ref_stream
    cbz     x0, 9f
    ldr     x1, [x20, #8]
    and     x1, x1, #0xFFFFFFFFFFFF
    ldrh    w2, [x20, #14]
    ldrb    w3, [x20, #1]
    and     w3, w3, #1
    bl      quic_stream_acked
    b       9f
2:  bl      quic_ref_stream
    cbz     x0, 9f
    bl      quic_stream_reset_acked
9:  LEAVE   0
END_FUNCTION quic_ref_acked

/* quic_ref_lost(ref, space): a frame of a lost packet goes out again. */
LOCAL_FUNCTION quic_ref_lost
    ENTER   0
    mov     x20, x0
    mov     x21, x1
    ldrb    w9, [x20]
    cmp     w9, #FR_CRYPTO
    b.ne    1f
    mov     x0, x19
    mov     x1, x21
    bl      quic_space
    ldr     x9, [x0, #SP_FLAGS]
    tst     x9, #SPF_DISCARDED
    b.ne    9f
    ldr     x9, [x20, #8]
    and     x9, x9, #0xFFFFFFFFFFFF
    ldr     x10, [x0, #SP_CTX_SENT]
    cmp     x9, x10
    csel    x10, x9, x10, lo
    str     x10, [x0, #SP_CTX_SENT]
    b       9f
1:  cmp     w9, #FR_STREAM
    b.ne    2f
    bl      quic_ref_stream
    cbz     x0, 9f
    ldr     x1, [x20, #8]
    and     x1, x1, #0xFFFFFFFFFFFF
    ldrh    w2, [x20, #14]
    ldrb    w3, [x20, #1]
    and     w3, w3, #1
    bl      quic_stream_lost
    b       9f
2:  mov     x10, #CF_MAX_DATA
    cmp     w9, #FR_MAX_DATA
    b.eq    7f
    mov     x10, #CF_MAX_STREAMS
    cmp     w9, #FR_MAX_STREAMS
    b.eq    7f
    mov     x10, #CF_DONE_FRAME
    cmp     w9, #FR_DONE
    b.eq    7f
    cmp     w9, #FR_RETIRE
    b.ne    3f
    ldr     w10, [x20, #4]
    str     x10, [x19, #C_RETIRE_SEQ]
    b       9f
3:  mov     x11, #SF_MSD
    cmp     w9, #FR_MAX_STREAM_DATA
    b.eq    4f
    mov     x11, #SF_RESET_SEND
    cmp     w9, #FR_RESET
    b.eq    4f
    mov     x11, #SF_STOP_SEND
    cmp     w9, #FR_STOP
    b.ne    9f
4:  mov     x21, x11
    bl      quic_ref_stream
    cbz     x0, 9f
    ldr     x9, [x0, #S_FLAGS]
    orr     x9, x9, x21
    str     x9, [x0, #S_FLAGS]
    b       9f
7:  ldr     x9, [x19, #C_FLAGS]
    orr     x9, x9, x10
    str     x9, [x19, #C_FLAGS]
9:  LEAVE   0
END_FUNCTION quic_ref_lost

/* quic_ref_stream() -> the live stream of the ref at x20 when its generation matches, or 0. */
LOCAL_FUNCTION quic_ref_stream
    ENTER   0
    ldr     w9, [x20, #4]
    ldr     x10, [x27, #ST_STREAM_COUNT]
    cmp     x9, x10
    b.hs    8f
    mov     x0, x9
    bl      quic_stream_at
    ldr     w9, [x0, #S_USED]
    cbz     w9, 8f
    ldr     w9, [x0, #S_GEN]
    ldrh    w10, [x20, #2]
    and     w9, w9, #0xFFFF
    cmp     w9, w10
    b.ne    8f
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_ref_stream

/* ---------------------------------------------------------------- Acknowledgements */

/*
 * quic_on_ack(space, ranges, n, ack_delay): an ACK frame of the space: n
 * ranges (smallest, largest), largest first; ack_delay in microseconds. The
 * records it covers leave as acknowledged; an RTT sample comes from the
 * largest when it is new and an ack-eliciting packet is among them; then loss
 * detection and the timer (RFC 9002 sections 5, 6 and 7).
 * x20 space, x21 ranges, x22 n, x23 ack_delay, x24 index, x25 newly acked
 * flags (bit 0 any, bit 1 ack-eliciting, bit 2 the largest), x26 the space record.
 */
.set OA_LARGEST_TIME, 0
.set OA_SAVE, 8                         /* a record and its info, over a call */
.set OA_FRAME, 32
LOCAL_FUNCTION quic_on_ack
    ENTER   0, OA_FRAME
    mov     x20, x0
    mov     x21, x1
    mov     x22, x2
    mov     x23, x3
    mov     x25, #0
    cbz     x22, 9f
    mov     x0, x19
    mov     x1, x20
    bl      quic_space
    mov     x26, x0
    ldr     x9, [x21, #8]                   /* the largest acknowledged */
    ldr     x10, [x26, #SP_LARGEST_ACKED]
    cmn     x10, #1
    b.eq    1f
    cmp     x9, x10
    b.ls    2f
1:  str     x9, [x26, #SP_LARGEST_ACKED]
2:  mov     x24, #0
3:  ldr     x9, [x19, #C_SENT_COUNT]
    cmp     x24, x9
    b.hs    6f
    mov     x0, x24
    bl      quic_record_at
    add     x24, x24, #1
    ldr     x9, [x0, #SR_INFO]
    tst     x9, #(SRF_LIVE << 24)
    b.eq    3b
    ubfx    x10, x9, #16, #8
    cmp     x10, x20
    b.ne    3b
    ldr     x10, [x0, #SR_PN]
    mov     x11, #0                         /* is it in a range? */
4:  cmp     x11, x22
    b.hs    3b
    add     x12, x21, x11, lsl #4
    ldp     x13, x14, [x12]
    add     x11, x11, #1
    cmp     x10, x13
    b.lo    4b
    cmp     x10, x14
    b.hi    4b
    orr     x25, x25, #1
    lsr     x12, x9, #24
    tst     x12, #SRF_ELICIT
    b.eq    5f
    orr     x25, x25, #2
5:  ldr     x13, [x21, #8]
    cmp     x10, x13
    b.ne    51f
    orr     x25, x25, #4
    ldr     x13, [x0, #SR_TIME]
    str     x13, [sp, #OA_LARGEST_TIME]
51: stp     x0, x9, [sp, #OA_SAVE]
    mov     x1, #1
    bl      quic_record_gone
    ldp     x0, x9, [sp, #OA_SAVE]
    lsr     x12, x9, #24
    tst     x12, #SRF_FLIGHT
    b.eq    3b
    ldr     x1, [x0, #SR_TIME]
    and     x2, x9, #0xFFFF
    mov     x0, x1
    mov     x1, x2
    bl      quic_cc_acked
    b       3b
6:  cbz     x25, 9f
    and     x9, x25, #6
    cmp     x9, #6
    b.ne    7f
    ldr     x9, [x27, #ST_NOW]
    ldr     x10, [sp, #OA_LARGEST_TIME]
    sub     x0, x9, x10
    mov     x1, x23
    cmp     x20, #SPACE_APP
    csel    x1, x1, xzr, eq
    bl      quic_rtt_sample
7:  ldr     x9, [x19, #C_ROLE]              /* a client keeps its backoff until the server is heard in Handshake */
    cbnz    x9, 71f
    cmp     x20, #SPACE_INITIAL
    b.eq    72f
71: str     xzr, [x19, #C_PTO_COUNT]
72: mov     x0, x20
    bl      quic_detect_loss
    bl      quic_ring_tidy
    bl      quic_set_loss_timer
9:  LEAVE   0, OA_FRAME
END_FUNCTION quic_on_ack

/*
 * quic_rtt_sample(latest, ack_delay): RFC 9002 section 5.3. ack_delay is
 * capped by max_ack_delay once the handshake is confirmed.
 */
LOCAL_FUNCTION quic_rtt_sample
    ENTER   0
    mov     x20, x0
    mov     x21, x1
    str     x20, [x19, #C_RTT_LATEST]
    ldr     x9, [x19, #C_RTT_FIRST]
    cmn     x9, #1
    b.ne    1f
    ldr     x9, [x27, #ST_NOW]
    str     x9, [x19, #C_RTT_FIRST]
    str     x20, [x19, #C_RTT_MIN]
    str     x20, [x19, #C_RTT_SMOOTH]
    lsr     x9, x20, #1
    str     x9, [x19, #C_RTT_VAR]
    b       9f
1:  ldr     x9, [x19, #C_RTT_MIN]
    cmp     x20, x9
    csel    x9, x20, x9, lo
    str     x9, [x19, #C_RTT_MIN]
    ldr     x10, [x19, #C_FLAGS]
    tst     x10, #CF_CONFIRMED
    b.eq    2f
    ldr     x10, [x19, #C_P_ACK_DELAY]
    cmp     x21, x10
    csel    x21, x21, x10, lo
2:  add     x10, x9, x21                    /* adjusted_rtt */
    mov     x11, x20
    cmp     x20, x10
    b.lo    3f
    sub     x11, x20, x21
3:  ldr     x12, [x19, #C_RTT_SMOOTH]
    subs    x13, x12, x11
    cneg    x13, x13, lo                    /* |smoothed - adjusted| */
    ldr     x14, [x19, #C_RTT_VAR]
    add     x15, x14, x14, lsl #1
    add     x15, x15, x13
    lsr     x15, x15, #2
    str     x15, [x19, #C_RTT_VAR]
    lsl     x15, x12, #3
    sub     x15, x15, x12
    add     x15, x15, x11
    lsr     x15, x15, #3
    str     x15, [x19, #C_RTT_SMOOTH]
9:  LEAVE   0
END_FUNCTION quic_rtt_sample

/*
 * quic_detect_loss(space): the live records of the space below the largest
 * acknowledged are lost when 3 later packets are acknowledged or they were
 * sent 9/8 RTT ago; the others set the loss time (RFC 9002 section 6.1).
 * x20 space, x21 the space record, x22 loss delay, x23 lost send time,
 * x24 index, x25 the largest acknowledged, x26 the largest lost send time.
 */
LOCAL_FUNCTION quic_detect_loss
    ENTER   0
    mov     x20, x0
    mov     x0, x19
    mov     x1, x20
    bl      quic_space
    mov     x21, x0
    mov     x9, #NONE
    str     x9, [x21, #SP_LOSS_TIME]
    ldr     x25, [x21, #SP_LARGEST_ACKED]
    cmn     x25, #1
    b.eq    9f
    ldr     x9, [x19, #C_RTT_LATEST]
    ldr     x10, [x19, #C_RTT_SMOOTH]
    cmp     x9, x10
    csel    x9, x9, x10, hi
    add     x22, x9, x9, lsl #3
    lsr     x22, x22, #3
    mov     x9, #K_GRANULARITY
    cmp     x22, x9
    csel    x22, x22, x9, hi
    ldr     x9, [x27, #ST_NOW]
    subs    x23, x9, x22
    csel    x23, xzr, x23, lo
    mov     x26, #0
    mov     x24, #0
1:  ldr     x9, [x19, #C_SENT_COUNT]
    cmp     x24, x9
    b.hs    5f
    mov     x0, x24
    bl      quic_record_at
    add     x24, x24, #1
    ldr     x9, [x0, #SR_INFO]
    tst     x9, #(SRF_LIVE << 24)
    b.eq    1b
    ubfx    x10, x9, #16, #8
    cmp     x10, x20
    b.ne    1b
    ldr     x10, [x0, #SR_PN]
    cmp     x10, x25
    b.hi    1b
    ldr     x11, [x0, #SR_TIME]
    cmp     x11, x23
    b.ls    2f
    add     x12, x10, #K_PACKET_THRESHOLD
    cmp     x25, x12
    b.hs    2f
    add     x11, x11, x22                   /* not yet: the loss time */
    ldr     x12, [x21, #SP_LOSS_TIME]
    cmp     x11, x12
    csel    x12, x11, x12, lo
    str     x12, [x21, #SP_LOSS_TIME]
    b       1b
2:  lsr     x12, x9, #24                    /* lost */
    tst     x12, #SRF_FLIGHT
    b.eq    3f
    cmp     x11, x26
    csel    x26, x11, x26, hi
3:  mov     x1, #0
    bl      quic_record_gone
    b       1b
5:  cbz     x26, 9f
    mov     x0, x26
    bl      quic_cc_lost
9:  LEAVE   0
END_FUNCTION quic_detect_loss

/* ---------------------------------------------------------------- Congestion control (NewReno) */

/* quic_cc_acked(sent_time, size): slow start, or congestion avoidance; nothing inside recovery. A leaf. */
LOCAL_FUNCTION quic_cc_acked
    UNWIND_END_PROLOGUE
    ldr     x2, [x19, #C_RECOVERY]
    cmp     x0, x2
    b.ls    9f
    ldr     x2, [x19, #C_CWND]
    ldr     x3, [x19, #C_SSTHRESH]
    cmp     x2, x3
    b.hs    1f
    add     x2, x2, x1
    b       2f
1:  mov     x4, #MAX_DATAGRAM
    mul     x4, x4, x1
    udiv    x4, x4, x2
    add     x2, x2, x4
2:  str     x2, [x19, #C_CWND]
9:  ret
END_FUNCTION quic_cc_acked

/*
 * quic_cc_lost(sent_time): a congestion event when the lost packet was sent
 * after the last recovery began: ssthresh and the window halve, to at least
 * the minimum window. A leaf.
 */
LOCAL_FUNCTION quic_cc_lost
    UNWIND_END_PROLOGUE
    ldr     x2, [x19, #C_RECOVERY]
    cmp     x0, x2
    b.ls    9f
    ldr     x2, [x27, #ST_NOW]
    str     x2, [x19, #C_RECOVERY]
    ldr     x2, [x19, #C_CWND]
    lsr     x2, x2, #1
    mov     x3, #MINIMUM_WINDOW
    cmp     x2, x3
    csel    x2, x2, x3, hi
    str     x2, [x19, #C_SSTHRESH]
    str     x2, [x19, #C_CWND]
9:  ret
END_FUNCTION quic_cc_lost

/* ---------------------------------------------------------------- The loss detection timer */

/*
 * quic_set_loss_timer(): C_LOSS_AT: the earliest loss time of a space, else
 * the probe timeout of the earliest space with ack-eliciting packets in
 * flight (the Application space only after the handshake is confirmed); a
 * client still in its handshake keeps a probe armed (RFC 9002 section 6.2.2.1).
 * x20 index, x21 the earliest time, x22 the space record.
 */
LOCAL_FUNCTION quic_set_loss_timer
    ENTER   0
    mov     x21, #NONE
    mov     x20, #0
1:  mov     x0, x19
    mov     x1, x20
    bl      quic_space
    ldr     x9, [x0, #SP_LOSS_TIME]
    cmp     x9, x21
    csel    x21, x9, x21, lo
    add     x20, x20, #1
    cmp     x20, #3
    b.lo    1b
    cmn     x21, #1
    b.ne    8f
    ldr     x9, [x19, #C_STATE]
    cmp     x9, #CS_CLOSING
    b.hs    8f
    mov     x20, #0
2:  mov     x0, x19
    mov     x1, x20
    bl      quic_space
    mov     x22, x0
    ldr     x9, [x22, #SP_ELICIT]
    cbz     x9, 3f
    cmp     x20, #SPACE_APP
    b.ne    21f
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_CONFIRMED
    b.eq    3f
21: mov     x0, x19
    mov     x1, x20
    bl      quic_pto_period
    ldr     x9, [x22, #SP_LAST_ELICIT]
    add     x9, x9, x0
    cmp     x9, x21
    csel    x21, x9, x21, lo
3:  add     x20, x20, #1
    cmp     x20, #3
    b.lo    2b
    cmn     x21, #1
    b.ne    8f
    ldr     x9, [x19, #C_ROLE]              /* the anti-deadlock probe of a client */
    cbnz    x9, 8f
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_CONFIRMED
    b.ne    8f
    mov     x0, x19
    mov     x1, #SPACE_INITIAL
    bl      quic_pto_period
    ldr     x9, [x27, #ST_NOW]
    add     x21, x9, x0
8:  str     x21, [x19, #C_LOSS_AT]
    LEAVE   0
END_FUNCTION quic_set_loss_timer

/*
 * quic_on_loss_timer(): the loss detection timer fired: loss detection in the
 * space of the earliest loss time, or a probe timeout: the space of the
 * earliest probe sends an ack-eliciting probe, with its unacknowledged CRYPTO
 * data again, and the backoff doubles (RFC 9002 section 6.2.4).
 * x20 index, x21 the earliest, x22 its space, x23 the space record.
 */
LOCAL_FUNCTION quic_on_loss_timer
    ENTER   0
    mov     x21, #NONE
    mov     x22, #0
    mov     x20, #0
1:  mov     x0, x19
    mov     x1, x20
    bl      quic_space
    ldr     x9, [x0, #SP_LOSS_TIME]
    cmp     x9, x21
    b.hs    2f
    mov     x21, x9
    mov     x22, x20
2:  add     x20, x20, #1
    cmp     x20, #3
    b.lo    1b
    cmn     x21, #1
    b.eq    3f
    mov     x0, x22
    bl      quic_detect_loss
    bl      quic_ring_tidy
    bl      quic_set_loss_timer
    b       9f
3:  mov     x22, #NONE                      /* PTO: the space whose probe is earliest */
    mov     x20, #0
4:  mov     x0, x19
    mov     x1, x20
    bl      quic_space
    mov     x23, x0
    ldr     x9, [x23, #SP_ELICIT]
    cbz     x9, 5f
    cmp     x20, #SPACE_APP
    b.ne    41f
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_CONFIRMED
    b.eq    5f
41: mov     x0, x19
    mov     x1, x20
    bl      quic_pto_period
    ldr     x9, [x23, #SP_LAST_ELICIT]
    add     x9, x9, x0
    cmp     x9, x21
    b.hs    5f
    mov     x21, x9
    mov     x22, x20
5:  add     x20, x20, #1
    cmp     x20, #3
    b.lo    4b
    cmn     x22, #1
    b.ne    6f
    mov     x22, #SPACE_INITIAL             /* the anti-deadlock probe: Handshake when its keys exist */
    mov     x0, x19
    mov     x1, #SPACE_HANDSHAKE
    bl      quic_space
    ldr     x9, [x0, #SP_FLAGS]
    tst     x9, #SPF_TX
    b.eq    6f
    tst     x9, #SPF_DISCARDED
    b.ne    6f
    mov     x22, #SPACE_HANDSHAKE
6:  mov     x0, x19
    mov     x1, x22
    bl      quic_space
    mov     x23, x0
    ldr     x9, [x23, #SP_FLAGS]
    orr     x9, x9, #SPF_PROBE
    str     x9, [x23, #SP_FLAGS]
    cmp     x22, #SPACE_APP
    b.eq    7f
    mov     x0, x22                         /* CRYPTO data not yet acknowledged goes out again */
    bl      quic_crypto_unacked
    ldr     x9, [x23, #SP_CTX_SENT]
    cmp     x0, x9
    csel    x9, x0, x9, lo
    str     x9, [x23, #SP_CTX_SENT]
7:  ldr     x9, [x19, #C_PTO_COUNT]
    add     x9, x9, #1
    str     x9, [x19, #C_PTO_COUNT]
    bl      quic_set_loss_timer
9:  LEAVE   0
END_FUNCTION quic_on_loss_timer

/*
 * quic_crypto_unacked(space) -> the smallest CRYPTO offset in a live record of
 * the space; SP_CTX_SENT when there is none.
 * x20 space, x21 index, x22 the result.
 */
LOCAL_FUNCTION quic_crypto_unacked
    ENTER   0
    mov     x20, x0
    mov     x0, x19
    mov     x1, x20
    bl      quic_space
    ldr     x22, [x0, #SP_CTX_SENT]
    mov     x21, #0
1:  ldr     x9, [x19, #C_SENT_COUNT]
    cmp     x21, x9
    b.hs    8f
    mov     x0, x21
    bl      quic_record_at
    add     x21, x21, #1
    ldr     x9, [x0, #SR_INFO]
    tst     x9, #(SRF_LIVE << 24)
    b.eq    1b
    ubfx    x10, x9, #16, #8
    cmp     x10, x20
    b.ne    1b
    ubfx    x11, x9, #32, #8
    add     x12, x0, #SR_FRAMES
2:  cbz     x11, 1b
    ldrb    w13, [x12]
    cmp     w13, #FR_CRYPTO
    b.ne    3f
    ldr     x13, [x12, #8]
    and     x13, x13, #0xFFFFFFFFFFFF
    cmp     x13, x22
    csel    x22, x13, x22, lo
3:  add     x12, x12, #16
    sub     x11, x11, #1
    b       2b
8:  mov     x0, x22
    LEAVE   0
END_FUNCTION quic_crypto_unacked
