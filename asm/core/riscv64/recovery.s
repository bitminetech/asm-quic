/*
 * Loss detection and congestion control of RFC 9002: the ring of sent
 * packets, acknowledgements and RTT samples, the packet and time thresholds,
 * the probe timeout, and NewReno. Also the packet numbers received, for ACK
 * frames. s1 the connection in every function here.
 */

.set K_PACKET_THRESHOLD, 3
.set K_GRANULARITY, 1000                /* 1 ms */

/* ---------------------------------------------------------------- Packet numbers received */

/*
 * quic_recv_pn(space, pn) -> 1 when pn was received before, else 0 after it
 * is added to the ranges of the space (largest first, at most SP_MAX_RANGES;
 * the smallest range goes when they are full). s3 the space, s4 pn.
 */
LOCAL_FUNCTION quic_recv_pn
    ENTER   0
    mv      s3, a0
    mv      s4, a1
    addi    s5, s3, SP_RANGES
    ld      s6, SP_NRANGES(s3)
    li      s7, 0                           # index
1:  bgeu    s7, s6, 6f                      # below every range: a new last range
    slli    t0, s7, 4
    add     t0, s5, t0
    ld      t1, 0(t0)                       # smallest
    ld      t2, 8(t0)                       # largest
    bltu    t2, s4, 2f
    bgeu    s4, t1, 90f                     # inside: a duplicate
    addi    t3, t1, -1
    bne     s4, t3, 3f
    sd      s4, 0(t0)                       # just below: the range grows down
    addi    t4, s7, 1                       # joins the next range
    bgeu    t4, s6, 80f
    ld      t5, 16(t0)
    ld      t6, 24(t0)
    addi    t6, t6, 1
    bne     t6, s4, 80f
    sd      t5, 0(t0)
    mv      a0, s3
    mv      a1, t4
    call    quic_range_remove
    j       80f
3:  addi    s7, s7, 1
    j       1b
2:  addi    t3, t2, 1                       # above this range
    bne     s4, t3, 5f
    sd      s4, 8(t0)                       # just above: grows up; it cannot touch the range before
    j       80f
5:  mv      a0, s3                          # a new range before index s7
    mv      a1, s7
    mv      a2, s4
    call    quic_range_insert
    j       80f
6:  mv      a0, s3
    mv      a1, s6
    mv      a2, s4
    call    quic_range_insert
80: li      a0, 0
    j       9f
90: li      a0, 1
9:  LEAVE   0
END_FUNCTION quic_recv_pn

/* quic_range_insert(space, index, pn): a range [pn, pn] at index; the last range goes when full. */
LOCAL_FUNCTION quic_range_insert
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    ld      s4, SP_NRANGES(s1)
    li      t0, SP_MAX_RANGES
    bgeu    s2, t0, 9f
    bltu    s4, t0, 1f
    li      s4, (SP_MAX_RANGES - 1)
1:  addi    s5, s1, SP_RANGES               # shift [index, n) up by one, from the end
    mv      s6, s4
2:  bgeu    s2, s6, 3f
    addi    t0, s6, -1
    slli    t0, t0, 4
    add     t1, s5, t0
    ld      t2, 0(t1)
    ld      t3, 8(t1)
    sd      t2, 16(t1)
    sd      t3, 24(t1)
    addi    s6, s6, -1
    j       2b
3:  slli    t0, s2, 4
    add     t1, s5, t0
    sd      s3, 0(t1)
    sd      s3, 8(t1)
    addi    s4, s4, 1
    sd      s4, SP_NRANGES(s1)
9:  LEAVE   0
END_FUNCTION quic_range_insert

/* quic_range_remove(space, index): the range at index goes. A leaf. */
LOCAL_FUNCTION quic_range_remove
    UNWIND_END_PROLOGUE
    ld      a2, SP_NRANGES(a0)
    addi    a3, a0, SP_RANGES
1:  addi    a4, a1, 1
    bgeu    a4, a2, 2f
    slli    a5, a4, 4
    add     a5, a3, a5
    ld      a6, 0(a5)
    ld      a7, 8(a5)
    sd      a6, -16(a5)
    sd      a7, -8(a5)
    mv      a1, a4
    j       1b
2:  addi    a2, a2, -1
    sd      a2, SP_NRANGES(a0)
    ret
END_FUNCTION quic_range_remove

/* ---------------------------------------------------------------- The ring of sent packets */

/* quic_ring_free() -> 1 when the ring has room for a record. A leaf. */
LOCAL_FUNCTION quic_ring_free
    UNWIND_END_PROLOGUE
    addi    a2, s1, 2047
    ld      a0, (C_SENT_COUNT - 2047)(a2)
    ld      a1, (C_SENT_CAP - 2047)(a2)
    sltu    a0, a0, a1
    ret
END_FUNCTION quic_ring_free

/* quic_record_at(i) -> the record i places after the oldest. A leaf. */
LOCAL_FUNCTION quic_record_at
    UNWIND_END_PROLOGUE
    addi    a3, s1, 2047
    ld      a1, (C_SENT_HEAD - 2047)(a3)
    add     a1, a1, a0
    ld      a2, (C_SENT_CAP - 2047)(a3)
    remu    a1, a1, a2
    ld      a0, (C_SENT - 2047)(a3)
    add     a0, s9, a0
    slli    a1, a1, 7
    add     a0, a0, a1
    ret
END_FUNCTION quic_record_at

/*
 * quic_record_sent(space, pn, size, flags, frames, n): a new live record of a
 * packet sent now, with n frame refs; bytes in flight, the ack-eliciting count
 * and the loss timer follow. The caller checked quic_ring_free.
 */
LOCAL_FUNCTION quic_record_sent
    ENTER   0
    mv      s2, a0
    mv      s3, a1
    mv      s4, a2
    mv      s5, a3
    mv      s6, a4
    mv      s7, a5
    LDX     a0, s1, C_SENT_COUNT
    call    quic_record_at
    mv      s8, a0
    LDX     t0, s1, C_SENT_COUNT
    addi    t0, t0, 1
    SDX     t0, s1, C_SENT_COUNT
    sd      s3, SR_PN(s8)
    ld      t0, ST_NOW(s9)
    sd      t0, SR_TIME(s8)
    ori     t0, s5, SRF_LIVE
    li      t2, 0xFFFF
    and     t1, s4, t2
    slli    t2, s2, 16
    or      t1, t1, t2
    slli    t2, t0, 24
    or      t1, t1, t2
    slli    t2, s7, 32
    or      t1, t1, t2
    sd      t1, SR_INFO(s8)
    addi    a0, s8, SR_FRAMES
    mv      a1, s6
    slli    a2, s7, 4
    call    quic_copy
    andi    t0, s5, SRF_FLIGHT
    beqz    t0, 1f
    LDX     t0, s1, C_IN_FLIGHT
    add     t0, t0, s4
    SDX     t0, s1, C_IN_FLIGHT
1:  andi    t0, s5, SRF_ELICIT
    beqz    t0, 2f
    mv      a0, s1
    mv      a1, s2
    call    quic_space
    ld      t0, SP_ELICIT(a0)
    addi    t0, t0, 1
    sd      t0, SP_ELICIT(a0)
    ld      t0, ST_NOW(s9)
    sd      t0, SP_LAST_ELICIT(a0)
    call    quic_set_loss_timer
2:  LEAVE   0
END_FUNCTION quic_record_sent

/*
 * quic_record_gone(record, acked): a live record leaves: bytes in flight, the
 * ack-eliciting count and its frame refs follow (quic_ref_acked or
 * quic_ref_lost).
 */
LOCAL_FUNCTION quic_record_gone
    ENTER   0
    mv      s2, a0
    mv      s3, a1
    ld      s4, SR_INFO(s2)
    mv      t0, s4
    BICV    t0, (SRF_LIVE << 24)
    sd      t0, SR_INFO(s2)
    srli    s5, s4, 24
    andi    s5, s5, 0xFF                    # flags
    andi    t0, s5, SRF_FLIGHT
    beqz    t0, 1f
    li      t1, 0xFFFF
    and     t0, s4, t1
    LDX     t2, s1, C_IN_FLIGHT
    sub     t3, t2, t0
    bgeu    t2, t0, 11f
    li      t3, 0
11: SDX     t3, s1, C_IN_FLIGHT
1:  andi    t0, s5, SRF_ELICIT
    beqz    t0, 2f
    mv      a0, s1
    srli    a1, s4, 16
    andi    a1, a1, 0xFF
    call    quic_space
    ld      t0, SP_ELICIT(a0)
    addi    t1, t0, -1
    bnez    t0, 12f
    li      t1, 0
12: sd      t1, SP_ELICIT(a0)
2:  srli    s6, s4, 32                      # the frame refs
    andi    s6, s6, 0xFF
    addi    s7, s2, SR_FRAMES
3:  beqz    s6, 9f
    mv      a0, s7
    srli    a1, s4, 16
    andi    a1, a1, 0xFF
    beqz    s3, 4f
    call    quic_ref_acked
    j       5f
4:  call    quic_ref_lost
5:  addi    s7, s7, 16
    addi    s6, s6, -1
    j       3b
9:  LEAVE   0
END_FUNCTION quic_record_gone

/* quic_ring_tidy(): the oldest records that are no longer live leave the ring. */
LOCAL_FUNCTION quic_ring_tidy
    ENTER   0
1:  LDX     s2, s1, C_SENT_COUNT
    beqz    s2, 9f
    li      a0, 0
    call    quic_record_at
    ld      t0, SR_INFO(a0)
    li      t1, (SRF_LIVE << 24)
    and     t0, t0, t1
    bnez    t0, 9f
    addi    s2, s2, -1
    SDX     s2, s1, C_SENT_COUNT
    LDX     t0, s1, C_SENT_HEAD
    addi    t0, t0, 1
    LDX     t1, s1, C_SENT_CAP
    bltu    t0, t1, 2f
    li      t0, 0
2:  SDX     t0, s1, C_SENT_HEAD
    j       1b
9:  LEAVE   0
END_FUNCTION quic_ring_tidy

/*
 * quic_drop_space_records(space): every live record of the space leaves
 * without being acknowledged or lost (its keys are gone).
 */
LOCAL_FUNCTION quic_drop_space_records
    ENTER   0
    mv      s2, a0
    li      s3, 0
1:  LDX     t0, s1, C_SENT_COUNT
    bgeu    s3, t0, 8f
    mv      a0, s3
    call    quic_record_at
    addi    s3, s3, 1
    ld      s4, SR_INFO(a0)
    li      t1, (SRF_LIVE << 24)
    and     t0, s4, t1
    beqz    t0, 1b
    srli    t0, s4, 16
    andi    t0, t0, 0xFF
    bne     t0, s2, 1b
    mv      t0, s4
    BICV    t0, (SRF_LIVE << 24)
    sd      t0, SR_INFO(a0)
    srli    t0, s4, 24
    andi    t0, t0, SRF_FLIGHT
    beqz    t0, 1b
    li      t1, 0xFFFF
    and     t0, s4, t1
    LDX     t2, s1, C_IN_FLIGHT
    sub     t3, t2, t0
    bgeu    t2, t0, 2f
    li      t3, 0
2:  SDX     t3, s1, C_IN_FLIGHT
    j       1b
8:  mv      a0, s1
    mv      a1, s2
    call    quic_space
    sd      zero, SP_ELICIT(a0)
    call    quic_ring_tidy
    LEAVE   0
END_FUNCTION quic_drop_space_records

/* ---------------------------------------------------------------- Frame refs */

/* quic_ref_acked(ref, space): a frame of an acknowledged packet. */
LOCAL_FUNCTION quic_ref_acked
    ENTER   0
    mv      s2, a0
    lbu     t0, 0(s2)
    li      t1, FR_STREAM
    beq     t0, t1, 1f
    li      t1, FR_RESET
    beq     t0, t1, 2f
    j       9f
1:  call    quic_ref_stream
    beqz    a0, 9f
    ld      a1, 8(s2)
    slli    a1, a1, 16
    srli    a1, a1, 16
    lhu     a2, 14(s2)
    lbu     a3, 1(s2)
    andi    a3, a3, 1
    call    quic_stream_acked
    j       9f
2:  call    quic_ref_stream
    beqz    a0, 9f
    call    quic_stream_reset_acked
9:  LEAVE   0
END_FUNCTION quic_ref_acked

/* quic_ref_lost(ref, space): a frame of a lost packet goes out again. */
LOCAL_FUNCTION quic_ref_lost
    ENTER   0
    mv      s2, a0
    mv      s3, a1
    lbu     t0, 0(s2)
    li      t1, FR_CRYPTO
    bne     t0, t1, 1f
    mv      a0, s1
    mv      a1, s3
    call    quic_space
    ld      t0, SP_FLAGS(a0)
    andi    t0, t0, SPF_DISCARDED
    bnez    t0, 9f
    ld      t0, 8(s2)
    slli    t0, t0, 16
    srli    t0, t0, 16
    ld      t1, SP_CTX_SENT(a0)
    bgeu    t0, t1, 11f
    mv      t1, t0
11: sd      t1, SP_CTX_SENT(a0)
    j       9f
1:  li      t1, FR_STREAM
    bne     t0, t1, 2f
    call    quic_ref_stream
    beqz    a0, 9f
    ld      a1, 8(s2)
    slli    a1, a1, 16
    srli    a1, a1, 16
    lhu     a2, 14(s2)
    lbu     a3, 1(s2)
    andi    a3, a3, 1
    call    quic_stream_lost
    j       9f
2:  li      t1, CF_MAX_DATA
    li      t2, FR_MAX_DATA
    beq     t0, t2, 7f
    li      t1, CF_MAX_STREAMS
    li      t2, FR_MAX_STREAMS
    beq     t0, t2, 7f
    li      t1, CF_DONE_FRAME
    li      t2, FR_DONE
    beq     t0, t2, 7f
    li      t2, FR_RETIRE
    bne     t0, t2, 3f
    lwu     t1, 4(s2)
    sd      t1, C_RETIRE_SEQ(s1)
    j       9f
3:  li      t2, SF_MSD
    li      t3, FR_MAX_STREAM_DATA
    beq     t0, t3, 4f
    li      t2, SF_RESET_SEND
    li      t3, FR_RESET
    beq     t0, t3, 4f
    li      t2, SF_STOP_SEND
    li      t3, FR_STOP
    bne     t0, t3, 9f
4:  mv      s3, t2
    call    quic_ref_stream
    beqz    a0, 9f
    ld      t0, S_FLAGS(a0)
    or      t0, t0, s3
    sd      t0, S_FLAGS(a0)
    j       9f
7:  ld      t0, C_FLAGS(s1)
    or      t0, t0, t1
    sd      t0, C_FLAGS(s1)
9:  LEAVE   0
END_FUNCTION quic_ref_lost

/* quic_ref_stream() -> the live stream of the ref at s2 when its generation matches, or 0. */
LOCAL_FUNCTION quic_ref_stream
    ENTER   0
    lwu     t0, 4(s2)
    ld      t1, ST_STREAM_COUNT(s9)
    bgeu    t0, t1, 8f
    mv      a0, t0
    call    quic_stream_at
    lwu     t0, S_USED(a0)
    beqz    t0, 8f
    lwu     t0, S_GEN(a0)
    lhu     t1, 2(s2)
    li      t2, 0xFFFF
    and     t0, t0, t2
    bne     t0, t1, 8f
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_ref_stream

/* ---------------------------------------------------------------- Acknowledgements */

/*
 * quic_on_ack(space, ranges, n, ack_delay): an ACK frame of the space: n
 * ranges (smallest, largest), largest first; ack_delay in microseconds. The
 * records it covers leave as acknowledged; an RTT sample comes from the
 * largest when it is new and an ack-eliciting packet is among them; then loss
 * detection and the timer (RFC 9002 sections 5, 6 and 7).
 * s2 space, s3 ranges, s4 n, s5 ack_delay, s6 index, s7 newly acked
 * flags (bit 0 any, bit 1 ack-eliciting, bit 2 the largest), s8 the space record.
 */
.set OA_LARGEST_TIME, 0
.set OA_SAVE, 8                         /* a record and its info, over a call */
.set OA_FRAME, 32
LOCAL_FUNCTION quic_on_ack
    ENTER   0, OA_FRAME
    mv      s2, a0
    mv      s3, a1
    mv      s4, a2
    mv      s5, a3
    li      s7, 0
    beqz    s4, 9f
    mv      a0, s1
    mv      a1, s2
    call    quic_space
    mv      s8, a0
    ld      t0, 8(s3)                       # the largest acknowledged
    ld      t1, SP_LARGEST_ACKED(s8)
    li      t2, -1
    beq     t1, t2, 1f
    bgeu    t1, t0, 2f
1:  sd      t0, SP_LARGEST_ACKED(s8)
2:  li      s6, 0
3:  LDX     t0, s1, C_SENT_COUNT
    bgeu    s6, t0, 6f
    mv      a0, s6
    call    quic_record_at
    addi    s6, s6, 1
    ld      t0, SR_INFO(a0)
    li      t1, (SRF_LIVE << 24)
    and     t1, t0, t1
    beqz    t1, 3b
    srli    t1, t0, 16
    andi    t1, t1, 0xFF
    bne     t1, s2, 3b
    ld      t1, SR_PN(a0)
    li      t2, 0                           # is it in a range?
4:  bgeu    t2, s4, 3b
    slli    t3, t2, 4
    add     t3, s3, t3
    ld      t4, 0(t3)
    ld      t5, 8(t3)
    addi    t2, t2, 1
    bltu    t1, t4, 4b
    bltu    t5, t1, 4b
    ori     s7, s7, 1
    srli    t3, t0, 24
    andi    t3, t3, SRF_ELICIT
    beqz    t3, 5f
    ori     s7, s7, 2
5:  ld      t4, 8(s3)
    bne     t1, t4, 51f
    ori     s7, s7, 4
    ld      t4, SR_TIME(a0)
    sd      t4, (FL + OA_LARGEST_TIME)(sp)
51: sd      a0, (FL + OA_SAVE)(sp)
    sd      t0, (FL + OA_SAVE + 8)(sp)
    li      a1, 1
    call    quic_record_gone
    ld      a0, (FL + OA_SAVE)(sp)
    ld      t0, (FL + OA_SAVE + 8)(sp)
    srli    t3, t0, 24
    andi    t3, t3, SRF_FLIGHT
    beqz    t3, 3b
    ld      a1, SR_TIME(a0)
    li      t2, 0xFFFF
    and     a2, t0, t2
    mv      a0, a1
    mv      a1, a2
    call    quic_cc_acked
    j       3b
6:  beqz    s7, 9f
    andi    t0, s7, 6
    li      t1, 6
    bne     t0, t1, 7f
    ld      t0, ST_NOW(s9)
    ld      t1, (FL + OA_LARGEST_TIME)(sp)
    sub     a0, t0, t1
    li      a1, 0
    li      t2, SPACE_APP
    bne     s2, t2, 61f
    mv      a1, s5
61: call    quic_rtt_sample
7:  ld      t0, C_ROLE(s1)                  # a client keeps its backoff until the server is heard in Handshake
    bnez    t0, 71f
    li      t1, SPACE_INITIAL
    beq     s2, t1, 72f
71: SDX     zero, s1, C_PTO_COUNT
72: mv      a0, s2
    call    quic_detect_loss
    call    quic_ring_tidy
    call    quic_set_loss_timer
9:  LEAVE   0, OA_FRAME
END_FUNCTION quic_on_ack

/*
 * quic_rtt_sample(latest, ack_delay): RFC 9002 section 5.3. ack_delay is
 * capped by max_ack_delay once the handshake is confirmed.
 */
LOCAL_FUNCTION quic_rtt_sample
    ENTER   0
    mv      s2, a0
    mv      s3, a1
    SDX     s2, s1, C_RTT_LATEST
    LDX     t0, s1, C_RTT_FIRST
    li      t1, -1
    bne     t0, t1, 1f
    ld      t0, ST_NOW(s9)
    SDX     t0, s1, C_RTT_FIRST
    SDX     s2, s1, C_RTT_MIN
    SDX     s2, s1, C_RTT_SMOOTH
    srli    t0, s2, 1
    SDX     t0, s1, C_RTT_VAR
    j       9f
1:  LDX     t0, s1, C_RTT_MIN
    bgeu    s2, t0, 11f
    mv      t0, s2
11: SDX     t0, s1, C_RTT_MIN
    ld      t1, C_FLAGS(s1)
    andi    t1, t1, CF_CONFIRMED
    beqz    t1, 2f
    LDX     t1, s1, C_P_ACK_DELAY
    bltu    s3, t1, 2f
    mv      s3, t1
2:  add     t1, t0, s3                      # adjusted_rtt
    mv      t2, s2
    bltu    s2, t1, 3f
    sub     t2, s2, s3
3:  LDX     t3, s1, C_RTT_SMOOTH
    sub     t4, t3, t2
    bgeu    t3, t2, 31f
    sub     t4, t2, t3                      # |smoothed - adjusted|
31: LDX     t5, s1, C_RTT_VAR
    slli    a0, t5, 1
    add     a0, a0, t5
    add     a0, a0, t4
    srli    a0, a0, 2
    SDX     a0, s1, C_RTT_VAR
    slli    a0, t3, 3
    sub     a0, a0, t3
    add     a0, a0, t2
    srli    a0, a0, 3
    SDX     a0, s1, C_RTT_SMOOTH
9:  LEAVE   0
END_FUNCTION quic_rtt_sample

/*
 * quic_detect_loss(space): the live records of the space below the largest
 * acknowledged are lost when 3 later packets are acknowledged or they were
 * sent 9/8 RTT ago; the others set the loss time (RFC 9002 section 6.1).
 * s2 space, s3 the space record, s4 loss delay, s5 lost send time,
 * s6 index, s7 the largest acknowledged, s8 the largest lost send time.
 */
LOCAL_FUNCTION quic_detect_loss
    ENTER   0
    mv      s2, a0
    mv      a0, s1
    mv      a1, s2
    call    quic_space
    mv      s3, a0
    li      t0, NONE
    sd      t0, SP_LOSS_TIME(s3)
    ld      s7, SP_LARGEST_ACKED(s3)
    li      t0, -1
    beq     s7, t0, 9f
    LDX     t0, s1, C_RTT_LATEST
    LDX     t1, s1, C_RTT_SMOOTH
    bltu    t1, t0, 11f
    mv      t0, t1
11: slli    s4, t0, 3
    add     s4, s4, t0
    srli    s4, s4, 3
    li      t0, K_GRANULARITY
    bltu    t0, s4, 12f
    mv      s4, t0
12: ld      t0, ST_NOW(s9)
    sub     s5, t0, s4
    bgeu    t0, s4, 13f
    li      s5, 0
13: li      s8, 0
    li      s6, 0
1:  LDX     t0, s1, C_SENT_COUNT
    bgeu    s6, t0, 5f
    mv      a0, s6
    call    quic_record_at
    addi    s6, s6, 1
    ld      t0, SR_INFO(a0)
    li      t1, (SRF_LIVE << 24)
    and     t1, t0, t1
    beqz    t1, 1b
    srli    t1, t0, 16
    andi    t1, t1, 0xFF
    bne     t1, s2, 1b
    ld      t1, SR_PN(a0)
    bltu    s7, t1, 1b
    ld      t2, SR_TIME(a0)
    bgeu    s5, t2, 2f
    addi    t3, t1, K_PACKET_THRESHOLD
    bgeu    s7, t3, 2f
    add     t2, t2, s4                      # not yet: the loss time
    ld      t3, SP_LOSS_TIME(s3)
    bgeu    t2, t3, 14f
    mv      t3, t2
14: sd      t3, SP_LOSS_TIME(s3)
    j       1b
2:  srli    t3, t0, 24                      # lost
    andi    t3, t3, SRF_FLIGHT
    beqz    t3, 3f
    bgeu    s8, t2, 3f
    mv      s8, t2
3:  li      a1, 0
    call    quic_record_gone
    j       1b
5:  beqz    s8, 9f
    mv      a0, s8
    call    quic_cc_lost
9:  LEAVE   0
END_FUNCTION quic_detect_loss

/* ---------------------------------------------------------------- Congestion control (NewReno) */

/* quic_cc_acked(sent_time, size): slow start, or congestion avoidance; nothing inside recovery. A leaf. */
LOCAL_FUNCTION quic_cc_acked
    UNWIND_END_PROLOGUE
    addi    a5, s1, 2047
    ld      a2, (C_RECOVERY - 2047)(a5)
    bgeu    a2, a0, 9f
    ld      a2, (C_CWND - 2047)(a5)
    ld      a3, (C_SSTHRESH - 2047)(a5)
    bgeu    a2, a3, 1f
    add     a2, a2, a1
    j       2f
1:  li      a4, MAX_DATAGRAM
    mul     a4, a4, a1
    divu    a4, a4, a2
    add     a2, a2, a4
2:  sd      a2, (C_CWND - 2047)(a5)
9:  ret
END_FUNCTION quic_cc_acked

/*
 * quic_cc_lost(sent_time): a congestion event when the lost packet was sent
 * after the last recovery began: ssthresh and the window halve, to at least
 * the minimum window. A leaf.
 */
LOCAL_FUNCTION quic_cc_lost
    UNWIND_END_PROLOGUE
    addi    a5, s1, 2047
    ld      a2, (C_RECOVERY - 2047)(a5)
    bgeu    a2, a0, 9f
    ld      a2, ST_NOW(s9)
    sd      a2, (C_RECOVERY - 2047)(a5)
    ld      a2, (C_CWND - 2047)(a5)
    srli    a2, a2, 1
    li      a3, MINIMUM_WINDOW
    bltu    a3, a2, 1f
    mv      a2, a3
1:  sd      a2, (C_SSTHRESH - 2047)(a5)
    sd      a2, (C_CWND - 2047)(a5)
9:  ret
END_FUNCTION quic_cc_lost

/* ---------------------------------------------------------------- The loss detection timer */

/*
 * quic_set_loss_timer(): C_LOSS_AT: the earliest loss time of a space, else
 * the probe timeout of the earliest space with ack-eliciting packets in
 * flight (the Application space only after the handshake is confirmed); a
 * client still in its handshake keeps a probe armed (RFC 9002 section 6.2.2.1).
 * s2 index, s3 the earliest time, s4 the space record.
 */
LOCAL_FUNCTION quic_set_loss_timer
    ENTER   0
    li      s3, NONE
    li      s2, 0
1:  mv      a0, s1
    mv      a1, s2
    call    quic_space
    ld      t0, SP_LOSS_TIME(a0)
    bgeu    t0, s3, 11f
    mv      s3, t0
11: addi    s2, s2, 1
    li      t0, 3
    bltu    s2, t0, 1b
    li      t0, -1
    bne     s3, t0, 8f
    ld      t0, C_STATE(s1)
    li      t1, CS_CLOSING
    bgeu    t0, t1, 8f
    li      s2, 0
2:  mv      a0, s1
    mv      a1, s2
    call    quic_space
    mv      s4, a0
    ld      t0, SP_ELICIT(s4)
    beqz    t0, 3f
    li      t1, SPACE_APP
    bne     s2, t1, 21f
    ld      t0, C_FLAGS(s1)
    andi    t0, t0, CF_CONFIRMED
    beqz    t0, 3f
21: mv      a0, s1
    mv      a1, s2
    call    quic_pto_period
    ld      t0, SP_LAST_ELICIT(s4)
    add     t0, t0, a0
    bgeu    t0, s3, 3f
    mv      s3, t0
3:  addi    s2, s2, 1
    li      t0, 3
    bltu    s2, t0, 2b
    li      t0, -1
    bne     s3, t0, 8f
    ld      t0, C_ROLE(s1)                  # the anti-deadlock probe of a client
    bnez    t0, 8f
    ld      t0, C_FLAGS(s1)
    andi    t0, t0, CF_CONFIRMED
    bnez    t0, 8f
    mv      a0, s1
    li      a1, SPACE_INITIAL
    call    quic_pto_period
    ld      t0, ST_NOW(s9)
    add     s3, t0, a0
8:  SDX     s3, s1, C_LOSS_AT
    LEAVE   0
END_FUNCTION quic_set_loss_timer

/*
 * quic_on_loss_timer(): the loss detection timer fired: loss detection in the
 * space of the earliest loss time, or a probe timeout: the space of the
 * earliest probe sends an ack-eliciting probe, with its unacknowledged CRYPTO
 * data again, and the backoff doubles (RFC 9002 section 6.2.4).
 * s2 index, s3 the earliest, s4 its space, s5 the space record.
 */
LOCAL_FUNCTION quic_on_loss_timer
    ENTER   0
    li      s3, NONE
    li      s4, 0
    li      s2, 0
1:  mv      a0, s1
    mv      a1, s2
    call    quic_space
    ld      t0, SP_LOSS_TIME(a0)
    bgeu    t0, s3, 2f
    mv      s3, t0
    mv      s4, s2
2:  addi    s2, s2, 1
    li      t0, 3
    bltu    s2, t0, 1b
    li      t0, -1
    beq     s3, t0, 3f
    mv      a0, s4
    call    quic_detect_loss
    call    quic_ring_tidy
    call    quic_set_loss_timer
    j       9f
3:  li      s4, NONE                        # PTO: the space whose probe is earliest
    li      s2, 0
4:  mv      a0, s1
    mv      a1, s2
    call    quic_space
    mv      s5, a0
    ld      t0, SP_ELICIT(s5)
    beqz    t0, 5f
    li      t1, SPACE_APP
    bne     s2, t1, 41f
    ld      t0, C_FLAGS(s1)
    andi    t0, t0, CF_CONFIRMED
    beqz    t0, 5f
41: mv      a0, s1
    mv      a1, s2
    call    quic_pto_period
    ld      t0, SP_LAST_ELICIT(s5)
    add     t0, t0, a0
    bgeu    t0, s3, 5f
    mv      s3, t0
    mv      s4, s2
5:  addi    s2, s2, 1
    li      t0, 3
    bltu    s2, t0, 4b
    li      t0, -1
    bne     s4, t0, 6f
    li      s4, SPACE_INITIAL               # the anti-deadlock probe: Handshake when its keys exist
    mv      a0, s1
    li      a1, SPACE_HANDSHAKE
    call    quic_space
    ld      t0, SP_FLAGS(a0)
    andi    t1, t0, SPF_TX
    beqz    t1, 6f
    andi    t1, t0, SPF_DISCARDED
    bnez    t1, 6f
    li      s4, SPACE_HANDSHAKE
6:  mv      a0, s1
    mv      a1, s4
    call    quic_space
    mv      s5, a0
    ld      t0, SP_FLAGS(s5)
    ori     t0, t0, SPF_PROBE
    sd      t0, SP_FLAGS(s5)
    li      t1, SPACE_APP
    beq     s4, t1, 7f
    mv      a0, s4                          # CRYPTO data not yet acknowledged goes out again
    call    quic_crypto_unacked
    ld      t0, SP_CTX_SENT(s5)
    bgeu    a0, t0, 61f
    mv      t0, a0
61: sd      t0, SP_CTX_SENT(s5)
7:  LDX     t0, s1, C_PTO_COUNT
    addi    t0, t0, 1
    SDX     t0, s1, C_PTO_COUNT
    call    quic_set_loss_timer
9:  LEAVE   0
END_FUNCTION quic_on_loss_timer

/*
 * quic_crypto_unacked(space) -> the smallest CRYPTO offset in a live record of
 * the space; SP_CTX_SENT when there is none.
 * s2 space, s3 index, s4 the result.
 */
LOCAL_FUNCTION quic_crypto_unacked
    ENTER   0
    mv      s2, a0
    mv      a0, s1
    mv      a1, s2
    call    quic_space
    ld      s4, SP_CTX_SENT(a0)
    li      s3, 0
1:  LDX     t0, s1, C_SENT_COUNT
    bgeu    s3, t0, 8f
    mv      a0, s3
    call    quic_record_at
    addi    s3, s3, 1
    ld      t0, SR_INFO(a0)
    li      t1, (SRF_LIVE << 24)
    and     t1, t0, t1
    beqz    t1, 1b
    srli    t1, t0, 16
    andi    t1, t1, 0xFF
    bne     t1, s2, 1b
    srli    t2, t0, 32
    andi    t2, t2, 0xFF
    addi    t3, a0, SR_FRAMES
2:  beqz    t2, 1b
    lbu     t4, 0(t3)
    li      t5, FR_CRYPTO
    bne     t4, t5, 3f
    ld      t4, 8(t3)
    slli    t4, t4, 16
    srli    t4, t4, 16
    bgeu    t4, s4, 3f
    mv      s4, t4
3:  addi    t3, t3, 16
    addi    t2, t2, -1
    j       2b
8:  mv      a0, s4
    LEAVE   0
END_FUNCTION quic_crypto_unacked
