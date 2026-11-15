/*
 * Sending (RFC 9000 sections 12, 13, 14 and 17): datagrams of up to three
 * coalesced packets, their frames by priority, the padding of datagrams with
 * Initial packets, packet protection, the records for recovery, the
 * anti-amplification limit and the congestion window.
 * s1 the connection in every function here.
 */

.set PN_LEN, 4                          /* every packet number is sent in 4 bytes */
.set TAG_LEN, 16

/* One packet of the datagram being built, PK_SIZE bytes on the stack of quic_datagram. */
.set PK_START, 0                        /* its first byte */
.set PK_HEADER, 8                       /* header bytes */
.set PK_PAYLOAD, 16                     /* payload bytes */
.set PK_PN, 24
.set PK_SPACE, 32
.set PK_FLAGS, 40                       /* SRF_* */
.set PK_NREFS, 48
.set PK_LEN_AT, 56                      /* the 2-byte Length field of a long header, or 0 */
.set PK_REFS, 64                        /* SR_MAX_FRAMES refs */
.set PK_SIZE, 64 + 16 * SR_MAX_FRAMES

/* ---------------------------------------------------------------- Datagrams */

/*
 * quic_conn_output(): datagrams of the connection while the action room, the
 * amplification limit and something to send allow; each one SEND action.
 */
LOCAL_FUNCTION quic_conn_output
    ENTER   0
1:  ld      t0, C_STATE(s1)
    li      t1, CS_DRAINING
    bgeu    t0, t1, 9f
    call    quic_room
    li      t0, (QUIC_ACT_DATA + MAX_DATAGRAM + 8)
    bltu    a0, t0, 9f
    li      s2, MAX_DATAGRAM
    ld      t0, C_ROLE(s1)                  # a server before validation: 3 times the bytes received
    beqz    t0, 2f
    ld      t0, C_FLAGS(s1)
    andi    t0, t0, CF_VALIDATED
    bnez    t0, 2f
    LDX     t0, s1, C_RX_BYTES
    slli    t1, t0, 1
    add     t0, t0, t1
    LDX     t1, s1, C_TX_BYTES
    bgeu    t1, t0, 9f
    sub     t0, t0, t1
    bgeu    t0, s2, 11f
    mv      s2, t0
11: li      t0, MAX_DATAGRAM                # Initial datagrams need 1200 bytes
    bltu    s2, t0, 9f
2:  SCR     a0, SC_OUT
    mv      a1, s2
    call    quic_datagram
    beqz    a0, 9f
    mv      s3, a0
    addi    a1, s3, (QUIC_ACT_DATA + 7)
    andi    a1, a1, -8
    li      a0, QUIC_ACTION_SEND
    call    quic_action
    beqz    a0, 9f
    mv      s4, a0
    ld      t0, C_SOCKET(s1)
    sd      t0, QUIC_ACT_SOCKET(s4)
    addi    a0, s4, QUIC_ACT_ADDR
    addi    a1, s1, C_ADDR
    li      a2, QUIC_ADDR_SIZE
    call    quic_copy
    sd      s3, QUIC_ACT_COUNT(s4)
    addi    a0, s4, QUIC_ACT_DATA
    SCR     a1, SC_OUT
    mv      a2, s3
    call    quic_copy
    LDX     t0, s1, C_TX_BYTES
    add     t0, t0, s3
    SDX     t0, s1, C_TX_BYTES
    j       1b
9:  LEAVE   0
END_FUNCTION quic_conn_output

/*
 * quic_datagram(buf, max) -> the bytes of a datagram built at buf, at most
 * max, or 0 when there is nothing to send: a packet for each space that has
 * something, Initial first; padding to 1200 bytes when it holds an Initial
 * packet of a client, or an ack-eliciting one of a server (RFC 9000 section
 * 14.1); then each packet is protected and recorded.
 * s2 buf, s3 max, s4 position, s5 space, s6 packets, s7 pad.
 */
.set DGM_PACKETS, 0                     /* 3 packets */
.set DGM_FRAME, 3 * PK_SIZE
LOCAL_FUNCTION quic_datagram
    ENTER   0, DGM_FRAME
    mv      s2, a0
    mv      s3, a1
    mv      s4, a0
    li      s6, 0
    li      s7, 0
    li      s5, 0
1:  li      t0, 3
    bgeu    s5, t0, 3f
    mv      a0, s1
    mv      a1, s5
    call    quic_space
    ld      t0, SP_FLAGS(a0)
    andi    t1, t0, SPF_TX
    beqz    t1, 2f
    andi    t1, t0, SPF_DISCARDED
    bnez    t1, 2f
    sub     t0, s4, s2
    sub     t0, s3, t0                      # room left
    li      t1, 96
    bltu    t0, t1, 3f
    li      t1, PK_SIZE
    mul     t1, s6, t1
    addi    a3, sp, (FL + DGM_PACKETS)
    add     a3, a3, t1
    mv      a0, s5
    mv      a1, s4
    mv      a2, t0
    call    quic_packet_build
    beqz    a0, 2f
    li      t1, PK_SIZE
    mul     t1, s6, t1
    addi    t2, sp, (FL + DGM_PACKETS)
    add     t2, t2, t1
    ld      t3, PK_HEADER(t2)
    ld      t4, PK_PAYLOAD(t2)
    add     t3, t3, t4
    addi    t3, t3, TAG_LEN
    add     s4, s4, t3
    addi    s6, s6, 1
    li      t0, SPACE_INITIAL
    bne     s5, t0, 2f
    ld      t0, C_ROLE(s1)
    beqz    t0, 11f
    ld      t0, PK_FLAGS(t2)
    andi    t0, t0, SRF_ELICIT
    beqz    t0, 2f
11: li      s7, 1
2:  addi    s5, s5, 1
    j       1b
3:  li      a0, 0
    beqz    s6, 9f
    beqz    s7, 5f                          # padding: into the last packet
    sub     t0, s4, s2
    li      t1, MAX_DATAGRAM
    bgeu    t0, t1, 5f
    sub     t1, t1, t0                      # bytes to add
    addi    t2, s6, -1
    li      t3, PK_SIZE
    mul     t2, t2, t3
    addi    t3, sp, (FL + DGM_PACKETS)
    add     t2, t3, t2
    ld      t3, PK_START(t2)
    ld      t4, PK_HEADER(t2)
    ld      t5, PK_PAYLOAD(t2)
    add     a0, t3, t4
    add     a0, a0, t5
    mv      a1, t1
    sd      t1, SC_FRAME(s10)
    sd      t2, (SC_FRAME + 8)(s10)
    call    quic_zero                       # PADDING frames
    ld      t1, SC_FRAME(s10)
    ld      t2, (SC_FRAME + 8)(s10)
    ld      t5, PK_PAYLOAD(t2)
    add     t5, t5, t1
    sd      t5, PK_PAYLOAD(t2)
    add     s4, s4, t1
    ld      t0, PK_FLAGS(t2)
    ori     t0, t0, SRF_FLIGHT
    sd      t0, PK_FLAGS(t2)
5:  li      s5, 0                           # protect and record each packet
6:  bgeu    s5, s6, 8f
    li      t0, PK_SIZE
    mul     t0, s5, t0
    addi    a0, sp, (FL + DGM_PACKETS)
    add     a0, a0, t0
    call    quic_packet_finish
    addi    s5, s5, 1
    j       6b
8:  sub     a0, s4, s2
9:  LEAVE   0, DGM_FRAME
END_FUNCTION quic_datagram

/*
 * quic_packet_finish(packet): the Length of a long header, then protection,
 * then the record of an ack-eliciting or padded packet. A client drops its
 * Initial keys when it sends its first Handshake packet (RFC 9001 section 4.9.1).
 * s2 the packet, s3 the space record.
 */
LOCAL_FUNCTION quic_packet_finish
    ENTER   0
    mv      s2, a0
    ld      t0, PK_LEN_AT(s2)
    beqz    t0, 1f
    ld      t1, PK_PAYLOAD(s2)
    addi    a1, t1, (PN_LEN + TAG_LEN)
    mv      a0, t0
    call    quic_vput2
1:  mv      a0, s1
    ld      a1, PK_SPACE(s2)
    call    quic_space
    mv      s3, a0
    addi    a0, s3, SP_TX_KEYS
    ld      a1, PK_START(s2)
    ld      a2, PK_HEADER(s2)
    ld      a3, PK_PAYLOAD(s2)
    ld      a4, PK_PN(s2)
    SCR     a5, SC_PKT_WORK
    call    quic_seal
    mv      s4, a0                          # the packet size
    ld      t0, PK_FLAGS(s2)
    andi    t0, t0, SRF_ELICIT
    beqz    t0, 2f
    ld      a0, PK_SPACE(s2)
    ld      a1, PK_PN(s2)
    mv      a2, s4
    ld      a3, PK_FLAGS(s2)
    addi    a4, s2, PK_REFS
    ld      a5, PK_NREFS(s2)
    call    quic_record_sent
    ld      t0, C_FLAGS(s1)
    mv      t1, t0
    ANDV    t1, CF_ELICIT_SENT
    bnez    t1, 2f
    ORV     t0, CF_ELICIT_SENT              # the first ack-eliciting packet since the last one received
    sd      t0, C_FLAGS(s1)
    call    quic_idle_reset
2:  ld      t0, PK_SPACE(s2)
    li      t1, SPACE_APP
    bne     t0, t1, 3f
    LDX     t0, s1, C_PHASE_SENT
    addi    t0, t0, 1
    SDX     t0, s1, C_PHASE_SENT
3:  ld      t0, PK_SPACE(s2)
    li      t1, SPACE_HANDSHAKE
    bne     t0, t1, 9f
    ld      t0, C_ROLE(s1)
    bnez    t0, 9f
    li      a0, SPACE_INITIAL
    call    quic_discard_space
9:  LEAVE   0
END_FUNCTION quic_packet_finish

/* ---------------------------------------------------------------- Packets */

/*
 * quic_packet_build(space, dst, room, packet) -> 1 when a packet of the space
 * with at least one frame is built at dst, unprotected, with room for its
 * tag; else 0 and nothing is kept. The packet fields go to packet.
 * s2 space, s3 dst, s4 room, s5 packet, s6 position, s7 end of frames,
 * s8 the space record.
 */
LOCAL_FUNCTION quic_packet_build
    ENTER   0
    mv      s2, a0
    mv      s3, a1
    mv      s4, a2
    mv      s5, a3
    mv      a0, s1
    mv      a1, s2
    call    quic_space
    mv      s8, a0
    mv      a0, s5
    li      a1, PK_SIZE
    call    quic_zero
    sd      s3, PK_START(s5)
    sd      s2, PK_SPACE(s5)
    ld      t0, SP_NEXT_PN(s8)
    sd      t0, PK_PN(s5)
    /* The header. */
    mv      s6, s3
    li      t0, SPACE_APP
    beq     s2, t0, 2f
    li      t0, 0xC3                        # long: Initial (type 0) or Handshake (type 2), 4-byte number
    li      t1, SPACE_HANDSHAKE
    bne     s2, t1, 11f
    li      t0, 0xE3
11: sb      t0, 0(s6)
    sb      zero, 1(s6)
    sb      zero, 2(s6)
    sb      zero, 3(s6)
    li      t0, 1
    sb      t0, 4(s6)
    ld      a2, (C_RCID + QUIC_CID_LENGTH)(s1)
    sb      a2, 5(s6)
    addi    a0, s6, 6
    addi    a1, s1, (C_RCID + QUIC_CID_ID)
    call    quic_copy
    li      t0, 8
    sb      t0, 0(a0)
    addi    a0, a0, 1
    addi    a1, s1, C_LCID
    li      a2, 8
    call    quic_copy
    mv      s6, a0
    li      t0, SPACE_INITIAL
    bne     s2, t0, 1f
    ld      t0, C_ROLE(s1)                  # the token: a client's Retry token, else empty
    ld      a1, C_TOKEN_LEN(s1)
    beqz    t0, 12f
    li      a1, 0
12: mv      a0, s6
    mv      s7, a1
    call    quic_vput
    mv      s6, a0
    beqz    s7, 1f
    ld      a1, C_TOKEN(s1)
    add     a1, s9, a1
    mv      a2, s7
    call    quic_copy
    mv      s6, a0
1:  sd      s6, PK_LEN_AT(s5)               # Length: written when the payload is known
    addi    s6, s6, 2
    j       3f
2:  LDX     t0, s1, C_KEY_PHASE             # short: the key phase, 4-byte number
    slli    t0, t0, 2
    ori     t0, t0, 0x43
    sb      t0, 0(s6)
    ld      a2, (C_RCID + QUIC_CID_LENGTH)(s1)
    addi    a0, s6, 1
    addi    a1, s1, (C_RCID + QUIC_CID_ID)
    call    quic_copy
    mv      s6, a0
3:  ld      t0, PK_PN(s5)
    srli    t1, t0, 24
    sb      t1, 0(s6)
    srli    t1, t0, 16
    sb      t1, 1(s6)
    srli    t1, t0, 8
    sb      t1, 2(s6)
    sb      t0, 3(s6)
    addi    s6, s6, 4
    sub     t0, s6, s3
    sd      t0, PK_HEADER(s5)
    add     s7, s3, s4
    addi    s7, s7, -TAG_LEN                # the end of the frames
    /* The frames. */
    mv      a0, s6
    mv      a1, s7
    call    quic_frames_out
    sub     t0, a0, s6
    beqz    t0, 8f
    sd      t0, PK_PAYLOAD(s5)
    ld      t0, SP_NEXT_PN(s8)
    addi    t0, t0, 1
    sd      t0, SP_NEXT_PN(s8)
    li      a0, 1
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_packet_build

/*
 * quic_may_elicit(needs_ref) -> 1 when an ack-eliciting frame may go in the
 * packet: a free record, a free frame ref (for frames that need one: 1), and
 * room in the congestion window, or a probe due in the space. s5 the packet,
 * s8 the space record.
 */
LOCAL_FUNCTION quic_may_elicit
    ENTER   0
    mv      s2, a0
    call    quic_ring_free
    beqz    a0, 9f
    beqz    s2, 1f
    ld      t0, PK_NREFS(s5)
    li      t1, SR_MAX_FRAMES
    bgeu    t0, t1, 8f
1:  ld      t0, PK_FLAGS(s5)                # this packet counts already
    andi    t0, t0, SRF_ELICIT
    bnez    t0, 7f
    ld      t0, SP_FLAGS(s8)
    andi    t0, t0, SPF_PROBE
    bnez    t0, 7f
    LDX     t0, s1, C_IN_FLIGHT
    addi    t0, t0, MAX_DATAGRAM
    LDX     t1, s1, C_CWND
    bltu    t1, t0, 8f
7:  li      a0, 1
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_may_elicit

/* quic_elicit(): the packet is ack-eliciting and in flight. A leaf. s5 the packet. */
LOCAL_FUNCTION quic_elicit
    UNWIND_END_PROLOGUE
    ld      t0, PK_FLAGS(s5)
    ori     t0, t0, (SRF_ELICIT | SRF_FLIGHT)
    sd      t0, PK_FLAGS(s5)
    ret
END_FUNCTION quic_elicit

/*
 * quic_add_ref(kind, flags, slot_gen, value, offset_len): a frame ref of the
 * packet: kind u8, flags u8, generation u16, slot or value u32, offset and
 * length u64. A leaf. s5 the packet.
 */
LOCAL_FUNCTION quic_add_ref
    UNWIND_END_PROLOGUE
    ld      a5, PK_NREFS(s5)
    slli    a6, a5, 4
    add     a6, a6, s5
    addi    a6, a6, PK_REFS
    sb      a0, 0(a6)
    sb      a1, 1(a6)
    sh      a2, 2(a6)
    sw      a3, 4(a6)
    sd      a4, 8(a6)
    addi    a5, a5, 1
    sd      a5, PK_NREFS(s5)
    ret
END_FUNCTION quic_add_ref

/*
 * quic_frames_out(p, end) -> the position after the frames of the packet:
 * ACK; CONNECTION_CLOSE alone when closing; CRYPTO; then in the Application
 * space HANDSHAKE_DONE, PATH_RESPONSE, RETIRE_CONNECTION_ID, MAX_DATA,
 * MAX_STREAMS and the stream frames; PING for a probe or a keep-alive.
 * s2 space, s3 position, s4 end, s5 the packet, s8 the space record.
 */
LOCAL_FUNCTION quic_frames_out
    ENTER   0
    mv      s3, a0
    mv      s4, a1
    ld      t0, C_STATE(s1)                 # closing: CONNECTION_CLOSE alone
    li      t1, CS_CLOSING
    beq     t0, t1, 2f
    /* ACK */
    ld      t0, SP_NRANGES(s8)
    beqz    t0, 2f
    ld      t0, SP_ACK_COUNT(s8)
    ld      t1, SP_FLAGS(s8)
    andi    t1, t1, SPF_ACK_NOW
    bnez    t1, 1f
    beqz    t0, 2f
    li      t1, SPACE_APP
    bne     s2, t1, 1f
    ld      t1, SP_ACK_AT(s8)
    ld      t2, ST_NOW(s9)
    bgeu    t2, t1, 1f
    call    quic_app_pending                # not due: only with other frames
    beqz    a0, 2f
1:  mv      a0, s3
    mv      a1, s4
    call    quic_ack_frame
    beqz    a0, 2f
    mv      s3, a0
    sd      zero, SP_ACK_COUNT(s8)
    li      t0, NONE
    sd      t0, SP_ACK_AT(s8)
    ld      t0, SP_FLAGS(s8)
    andi    t0, t0, ~SPF_ACK_NOW
    sd      t0, SP_FLAGS(s8)
2:  ld      t0, C_STATE(s1)                 # CONNECTION_CLOSE
    li      t1, CS_CLOSING
    bne     t0, t1, 3f
    ld      t0, C_FLAGS(s1)
    andi    t0, t0, CF_CLOSE_FRAME
    beqz    t0, 90f
    sub     t0, s4, s3
    li      t1, 24
    bltu    t0, t1, 90f
    ld      t0, C_FLAGS(s1)
    andi    t0, t0, CF_APP_CLOSE
    beqz    t0, 21f
    li      t1, SPACE_APP
    bne     s2, t1, 22f
    li      t0, 0x1D                        # the application's close
    sb      t0, 0(s3)
    addi    a0, s3, 1
    ld      a1, C_ERROR(s1)
    call    quic_vput
    sb      zero, 0(a0)
    addi    s3, a0, 1
    j       23f
22: li      t0, 0x1C                        # in Initial and Handshake: APPLICATION_ERROR
    sb      t0, 0(s3)
    li      t0, 0x0C
    sb      t0, 1(s3)
    sb      zero, 2(s3)
    sb      zero, 3(s3)
    addi    s3, s3, 4
    j       23f
21: li      t0, 0x1C
    sb      t0, 0(s3)
    addi    a0, s3, 1
    ld      a1, C_ERROR(s1)
    call    quic_vput
    sb      zero, 0(a0)
    sb      zero, 1(a0)
    addi    s3, a0, 2
23: li      t0, SPACE_APP                   # every space with keys gets one; the flag goes with the last
    beq     s2, t0, 24f
    mv      a0, s1
    li      a1, SPACE_APP
    call    quic_space
    ld      t0, SP_FLAGS(a0)
    andi    t0, t0, SPF_TX
    bnez    t0, 90f
    li      t0, SPACE_HANDSHAKE
    beq     s2, t0, 24f
    mv      a0, s1
    li      a1, SPACE_HANDSHAKE
    call    quic_space
    ld      t0, SP_FLAGS(a0)
    andi    t1, t0, SPF_TX
    beqz    t1, 24f
    andi    t1, t0, SPF_DISCARDED
    beqz    t1, 90f
24: ld      t0, C_FLAGS(s1)
    andi    t0, t0, ~CF_CLOSE_FRAME
    sd      t0, C_FLAGS(s1)
    j       90f
3:  /* CRYPTO */
    ld      t0, SP_CTX_SENT(s8)
    ld      t1, SP_CTX_LEN(s8)
    bgeu    t0, t1, 4f
    li      a0, 1
    call    quic_may_elicit
    beqz    a0, 4f
    sub     t2, s4, s3
    li      t3, (1 + 8 + 2)                 # type, offset, 2-byte length
    bgeu    t3, t2, 4f
    sub     t2, t2, t3
    ld      t0, SP_CTX_SENT(s8)
    ld      t1, SP_CTX_LEN(s8)
    sub     t3, t1, t0
    bgeu    t2, t3, 31f                     # the bytes that fit
    mv      t3, t2
31: li      t4, 0x06
    sb      t4, 0(s3)
    addi    s3, s3, 1
    sd      t0, SC_FRAME(s10)
    sd      t3, (SC_FRAME + 8)(s10)
    mv      a0, s3
    mv      a1, t0
    call    quic_vput
    ld      a1, (SC_FRAME + 8)(s10)
    call    quic_vput2
    ld      a1, SP_CTX(s8)
    add     a1, s9, a1
    ld      t0, SC_FRAME(s10)
    ld      t3, (SC_FRAME + 8)(s10)
    add     a1, a1, t0
    mv      a2, t3
    call    quic_copy
    mv      s3, a0
    ld      t0, SC_FRAME(s10)
    ld      t3, (SC_FRAME + 8)(s10)
    add     t1, t0, t3
    sd      t1, SP_CTX_SENT(s8)
    li      a0, FR_CRYPTO
    li      a1, 0
    li      a2, 0
    li      a3, 0
    slli    a4, t3, 48
    or      a4, a4, t0
    call    quic_add_ref
    call    quic_elicit
4:  li      t0, SPACE_APP
    bne     s2, t0, 80f
    ld      t0, C_STATE(s1)
    li      t1, CS_ACTIVE
    bne     t0, t1, 80f
    call    quic_app_frames
    mv      s3, a0
80: /* PING: a probe, or a keep-alive, with no other ack-eliciting frame */
    ld      t0, PK_FLAGS(s5)
    andi    t0, t0, SRF_ELICIT
    bnez    t0, 85f
    ld      t0, SP_FLAGS(s8)
    andi    t0, t0, SPF_PROBE
    bnez    t0, 81f
    li      t1, SPACE_APP
    bne     s2, t1, 90f
    ld      t0, C_FLAGS(s1)
    ANDV    t0, CF_PING
    beqz    t0, 90f
81: bgeu    s3, s4, 90f
    li      a0, 0
    call    quic_may_elicit
    beqz    a0, 90f
    li      t0, 0x01
    sb      t0, 0(s3)
    addi    s3, s3, 1
    call    quic_elicit
    ld      t0, C_FLAGS(s1)
    BICV    t0, CF_PING
    sd      t0, C_FLAGS(s1)
85: ld      t0, SP_FLAGS(s8)                # the probe went
    andi    t0, t0, ~SPF_PROBE
    sd      t0, SP_FLAGS(s8)
90: mv      a0, s3
    LEAVE   0
END_FUNCTION quic_frames_out

/*
 * quic_ack_frame(p, end) -> the position after an ACK frame of the received
 * ranges of the space, as many as fit, or 0 when none fits. The delay is
 * in units of 8 microseconds (ack_delay_exponent 3) in the Application space.
 * s2 space, s3 p, s4 end, s5 the ranges, s6 index, s7 count kept, s8 the space record.
 */
LOCAL_FUNCTION quic_ack_frame
    ENTER   0
    mv      s3, a0
    mv      s4, a1
    sub     t0, s4, s3
    li      t1, 40
    bltu    t0, t1, 8f
    addi    s5, s8, SP_RANGES
    ld      s7, SP_NRANGES(s8)
    sub     t0, s4, s3                      # ranges that fit: 16 bytes each at most
    addi    t0, t0, -32
    srli    t0, t0, 4
    addi    t0, t0, 1
    bgeu    t0, s7, 11f
    mv      s7, t0
11: li      t0, 0x02
    sb      t0, 0(s3)
    addi    s3, s3, 1
    mv      a0, s3
    ld      a1, 8(s5)                       # the largest
    call    quic_vput
    li      a1, 0
    li      t0, SPACE_APP
    bne     s2, t0, 1f
    ld      t0, ST_NOW(s9)
    ld      t1, SP_RECV_TIME(s8)
    sub     a1, t0, t1
    bgeu    t0, t1, 12f
    li      a1, 0
12: srli    a1, a1, 3
    li      t0, 0x3FFFFFFF
    bgeu    t0, a1, 1f
    mv      a1, t0
1:  call    quic_vput
    addi    a1, s7, -1
    call    quic_vput
    ld      t0, 0(s5)
    ld      t1, 8(s5)
    sub     a1, t1, t0                      # the first range
    call    quic_vput
    li      s6, 1
2:  bgeu    s6, s7, 3f
    slli    t0, s6, 4
    add     t0, s5, t0
    ld      t1, 0(t0)                       # this range
    ld      t2, 8(t0)
    ld      t3, -16(t0)                     # the smallest of the one before
    sub     a1, t3, t2
    addi    a1, a1, -2                      # gap
    sd      t1, SC_FRAME(s10)
    sd      t2, (SC_FRAME + 8)(s10)
    call    quic_vput
    ld      t1, SC_FRAME(s10)
    ld      t2, (SC_FRAME + 8)(s10)
    sub     a1, t2, t1
    call    quic_vput
    addi    s6, s6, 1
    j       2b
3:  j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_ack_frame

/*
 * quic_app_pending() -> 1 when the Application space has frames to send other
 * than ACK, so an ACK not yet due may go with them.
 */
LOCAL_FUNCTION quic_app_pending
    ENTER   0
    ld      t0, C_FLAGS(s1)
    li      t1, (CF_DONE_FRAME | CF_MAX_DATA | CF_MAX_STREAMS | CF_PING | CF_CHALLENGE)
    and     t1, t0, t1
    bnez    t1, 7f
    ld      t0, C_RETIRE_SEQ(s1)
    li      t1, -1
    bne     t0, t1, 7f
    LDX     s2, s1, C_STREAM_HEAD
1:  li      t0, -1
    beq     s2, t0, 8f
    mv      a0, s2
    call    quic_stream_at
    ld      s2, S_NEXT(a0)
    ld      t0, S_ID(a0)
    li      t1, -1
    beq     t0, t1, 1b
    ld      t0, S_FLAGS(a0)
    li      t1, (SF_RESET_SEND | SF_STOP_SEND | SF_MSD | SF_FIN_LOST)
    and     t1, t0, t1
    bnez    t1, 7f
    ld      t1, S_NLOST(a0)
    andi    t1, t1, 0xFF
    bnez    t1, 7f
    ld      t1, S_SENT(a0)
    ld      t2, S_WRITTEN(a0)
    bltu    t1, t2, 7f
    andi    t1, t0, SF_FIN_WANT
    beqz    t1, 1b
    andi    t1, t0, SF_FIN_SENT
    beqz    t1, 7f
    j       1b
7:  li      a0, 1
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_app_pending

/*
 * quic_app_frames() -> the position after the frames of the Application
 * space that are not ACK, CRYPTO or PING. s2 space, s3 position, s4 end,
 * s5 the packet, s8 the space record.
 */
LOCAL_FUNCTION quic_app_frames
    ENTER   0
    /* HANDSHAKE_DONE */
    ld      t0, C_FLAGS(s1)
    andi    t0, t0, CF_DONE_FRAME
    beqz    t0, 1f
    bgeu    s3, s4, 1f
    li      a0, 1
    call    quic_may_elicit
    beqz    a0, 1f
    li      t0, 0x1E
    sb      t0, 0(s3)
    addi    s3, s3, 1
    ld      t0, C_FLAGS(s1)
    andi    t0, t0, ~CF_DONE_FRAME
    sd      t0, C_FLAGS(s1)
    li      a0, FR_DONE
    li      a1, 0
    li      a2, 0
    li      a3, 0
    li      a4, 0
    call    quic_add_ref
    call    quic_elicit
1:  /* PATH_RESPONSE */
    ld      t0, C_FLAGS(s1)
    ANDV    t0, CF_CHALLENGE
    beqz    t0, 2f
    sub     t1, s4, s3
    li      t2, 9
    bltu    t1, t2, 2f
    li      a0, 0
    call    quic_may_elicit
    beqz    a0, 2f
    li      t0, 0x1B
    sb      t0, 0(s3)
    addi    a0, s3, 1
    ADDX    a1, s1, C_CHALLENGE
    li      a2, 8
    call    quic_copy
    mv      s3, a0
    ld      t0, C_FLAGS(s1)
    BICV    t0, CF_CHALLENGE
    sd      t0, C_FLAGS(s1)
    call    quic_elicit
2:  /* RETIRE_CONNECTION_ID */
    ld      s6, C_RETIRE_SEQ(s1)
    li      t0, -1
    beq     s6, t0, 3f
    sub     t1, s4, s3
    li      t2, 9
    bltu    t1, t2, 3f
    li      a0, 1
    call    quic_may_elicit
    beqz    a0, 3f
    li      t0, 0x19
    sb      t0, 0(s3)
    addi    a0, s3, 1
    mv      a1, s6
    call    quic_vput
    mv      s3, a0
    li      t0, NONE
    sd      t0, C_RETIRE_SEQ(s1)
    li      a0, FR_RETIRE
    li      a1, 0
    li      a2, 0
    mv      a3, s6
    li      a4, 0
    call    quic_add_ref
    call    quic_elicit
3:  /* MAX_DATA */
    ld      t0, C_FLAGS(s1)
    andi    t0, t0, CF_MAX_DATA
    beqz    t0, 4f
    sub     t1, s4, s3
    li      t2, 9
    bltu    t1, t2, 4f
    li      a0, 1
    call    quic_may_elicit
    beqz    a0, 4f
    li      t0, 0x10
    sb      t0, 0(s3)
    addi    a0, s3, 1
    LDX     a1, s1, C_RX_MAX
    call    quic_vput
    mv      s3, a0
    ld      t0, C_FLAGS(s1)
    andi    t0, t0, ~CF_MAX_DATA
    sd      t0, C_FLAGS(s1)
    li      a0, FR_MAX_DATA
    li      a1, 0
    li      a2, 0
    li      a3, 0
    li      a4, 0
    call    quic_add_ref
    call    quic_elicit
4:  /* MAX_STREAMS */
    ld      t0, C_FLAGS(s1)
    andi    t0, t0, CF_MAX_STREAMS
    beqz    t0, 5f
    sub     t1, s4, s3
    li      t2, 9
    bltu    t1, t2, 5f
    li      a0, 1
    call    quic_may_elicit
    beqz    a0, 5f
    li      t0, 0x12
    sb      t0, 0(s3)
    addi    a0, s3, 1
    LDX     a1, s1, C_PEER_MAX
    call    quic_vput
    mv      s3, a0
    ld      t0, C_FLAGS(s1)
    andi    t0, t0, ~CF_MAX_STREAMS
    sd      t0, C_FLAGS(s1)
    li      a0, FR_MAX_STREAMS
    li      a1, 0
    li      a2, 0
    li      a3, 0
    li      a4, 0
    call    quic_add_ref
    call    quic_elicit
5:  /* The streams, in list order. */
    LDX     s6, s1, C_STREAM_HEAD
6:  li      t0, -1
    beq     s6, t0, 9f
    mv      a0, s6
    call    quic_stream_at
    ld      s6, S_NEXT(a0)
    ld      t0, S_ID(a0)
    li      t1, -1
    beq     t0, t1, 6b
    call    quic_stream_out
    mv      s3, a0
    j       6b
9:  mv      a0, s3
    LEAVE   0
END_FUNCTION quic_app_frames

/*
 * quic_stream_out(stream) -> the position after the frames of one stream that
 * fit: RESET_STREAM, STOP_SENDING, MAX_STREAM_DATA, then STREAM frames: lost
 * ranges first, then new bytes within the flow control limits, with the FIN
 * when the last byte goes. s3 position, s4 end, s5 the packet.
 * s2 the stream, s7 the stream slot.
 */
LOCAL_FUNCTION quic_stream_out
    ENTER   0
    mv      s2, a0
    call    quic_stream_index
    mv      s7, a0
    /* RESET_STREAM: id, our code, the final size (the bytes written) */
    ld      t0, S_FLAGS(s2)
    andi    t0, t0, SF_RESET_SEND
    beqz    t0, 1f
    sub     t1, s4, s3
    li      t2, 25
    bltu    t1, t2, 1f
    li      a0, 1
    call    quic_may_elicit
    beqz    a0, 1f
    li      t0, 0x04
    sb      t0, 0(s3)
    addi    a0, s3, 1
    ld      a1, S_ID(s2)
    call    quic_vput
    ld      a1, S_APP_CODE(s2)
    call    quic_vput
    ld      a1, S_SENT(s2)                  # the final size: the bytes sent
    call    quic_vput
    mv      s3, a0
    ld      t0, S_FLAGS(s2)
    andi    t0, t0, ~SF_RESET_SEND
    sd      t0, S_FLAGS(s2)
    li      a0, FR_RESET
    call    quic_stream_ref
    call    quic_elicit
1:  ld      t0, S_FLAGS(s2)                 # STOP_SENDING
    andi    t0, t0, SF_STOP_SEND
    beqz    t0, 2f
    sub     t1, s4, s3
    li      t2, 17
    bltu    t1, t2, 2f
    li      a0, 1
    call    quic_may_elicit
    beqz    a0, 2f
    li      t0, 0x05
    sb      t0, 0(s3)
    addi    a0, s3, 1
    ld      a1, S_ID(s2)
    call    quic_vput
    ld      a1, S_APP_CODE(s2)
    call    quic_vput
    mv      s3, a0
    ld      t0, S_FLAGS(s2)
    andi    t0, t0, ~SF_STOP_SEND
    sd      t0, S_FLAGS(s2)
    li      a0, FR_STOP
    call    quic_stream_ref
    call    quic_elicit
2:  ld      t0, S_FLAGS(s2)                 # MAX_STREAM_DATA
    mv      t1, t0
    ANDV    t1, SF_MSD
    beqz    t1, 3f
    andi    t1, t0, SF_RX_DONE
    bnez    t1, 21f
    sub     t1, s4, s3
    li      t2, 17
    bltu    t1, t2, 3f
    li      a0, 1
    call    quic_may_elicit
    beqz    a0, 3f
    li      t0, 0x11
    sb      t0, 0(s3)
    addi    a0, s3, 1
    ld      a1, S_ID(s2)
    call    quic_vput
    ld      a1, S_RX_MAX(s2)
    call    quic_vput
    mv      s3, a0
    li      a0, FR_MAX_STREAM_DATA
    call    quic_stream_ref
    call    quic_elicit
21: ld      t0, S_FLAGS(s2)
    BICV    t0, SF_MSD
    sd      t0, S_FLAGS(s2)
3:  ld      t0, S_FLAGS(s2)                 # no data after our reset
    ANDV    t0, SF_RESET
    bnez    t0, 9f
4:  ld      t0, S_NLOST(s2)                 # lost ranges
    andi    t0, t0, 0xFF
    beqz    t0, 5f
    ld      t1, S_LOST(s2)
    ld      t2, (S_LOST + 8)(s2)
    sub     a2, t2, t1
    mv      a0, t1
    li      a1, 0
    call    quic_stream_frame
    li      t0, -1
    beq     a0, t0, 9f
    mv      s3, a1
    beqz    a0, 9f
    ld      t1, S_LOST(s2)
    ld      t2, (S_LOST + 8)(s2)
    add     t1, t1, a0
    sd      t1, S_LOST(s2)
    bltu    t1, t2, 4b
    mv      a0, s2
    addi    a1, s2, S_NLOST
    li      a2, 0
    call    quic_ranges_remove
    j       4b
5:  ld      t0, S_FLAGS(s2)                 # a FIN to send again
    andi    t0, t0, SF_FIN_LOST
    beqz    t0, 6f
    ld      t1, S_SENT(s2)
    ld      t2, S_WRITTEN(s2)
    bltu    t1, t2, 6f
    mv      a0, t2
    li      a1, 1
    li      a2, 0
    call    quic_stream_frame
    li      t0, -1
    beq     a0, t0, 9f
    mv      s3, a1
    ld      t0, S_FLAGS(s2)
    andi    t0, t0, ~SF_FIN_LOST
    sd      t0, S_FLAGS(s2)
6:  ld      t1, S_SENT(s2)                  # new bytes
    ld      t2, S_WRITTEN(s2)
    sub     a2, t2, t1
    ld      t3, S_TX_MAX(s2)
    sub     t4, t3, t1
    bgeu    t3, t1, 63f
    li      t4, 0
63: bgeu    t4, a2, 64f
    mv      a2, t4
64: LDX     t3, s1, C_TX_MAX
    LDX     t5, s1, C_TX_SENT
    sub     t4, t3, t5
    bgeu    t3, t5, 65f
    li      t4, 0
65: bgeu    t4, a2, 66f
    mv      a2, t4
66: ld      t0, S_FLAGS(s2)
    li      a1, 0
    andi    t3, t0, SF_FIN_WANT
    beqz    t3, 61f
    andi    t3, t0, SF_FIN_SENT
    bnez    t3, 61f
    add     t3, t1, a2
    sub     t3, t3, t2
    seqz    a1, t3                          # the FIN goes with the last byte
61: bnez    a1, 62f
    beqz    a2, 9f
62: mv      a0, t1
    sd      a1, (SC_FRAME + 64)(s10)
    sd      a2, (SC_FRAME + 72)(s10)
    call    quic_stream_frame
    li      t0, -1
    beq     a0, t0, 9f
    mv      s3, a1
    ld      a1, (SC_FRAME + 64)(s10)
    ld      a2, (SC_FRAME + 72)(s10)
    ld      t1, S_SENT(s2)
    add     t1, t1, a0
    sd      t1, S_SENT(s2)
    LDX     t2, s1, C_TX_SENT
    add     t2, t2, a0
    SDX     t2, s1, C_TX_SENT
    bltu    a0, a2, 9f                      # not all fit: no FIN yet
    beqz    a1, 9f
    ld      t0, S_FLAGS(s2)
    ori     t0, t0, SF_FIN_SENT
    sd      t0, S_FLAGS(s2)
9:  mv      a0, s3                          # the position after
    LEAVE   0
END_FUNCTION quic_stream_out

/* quic_stream_ref(kind): a frame ref of the stream at s2 (slot s7). */
LOCAL_FUNCTION quic_stream_ref
    ENTER   0
    lwu     a2, S_GEN(s2)
    li      a1, 0
    mv      a3, s7
    li      a4, 0
    call    quic_add_ref
    LEAVE   0
END_FUNCTION quic_stream_ref

/*
 * quic_stream_frame(offset, fin, n) -> a0 the bytes of the stream from offset
 * put in one STREAM frame with the FIN when fin and all n fit, or -1 when no
 * frame fits (0 bytes with a FIN is a frame); a1 the position after.
 * s2 the stream, s3 the position, s4 end, s5 the packet, s7 the slot.
 */
LOCAL_FUNCTION quic_stream_frame
    ENTER   0, 32
    sd      a0, (FL + 0)(sp)
    sd      a1, (FL + 8)(sp)
    sd      a2, (FL + 16)(sp)
    li      a0, 1
    call    quic_may_elicit
    beqz    a0, 8f
    ld      a0, S_ID(s2)
    call    quic_vlen
    mv      s6, a0
    ld      a0, (FL + 0)(sp)
    call    quic_vlen
    add     s6, s6, a0
    addi    s6, s6, 3                       # type and a 2-byte length
    sub     t0, s4, s3
    bgeu    s6, t0, 8f
    sub     t0, t0, s6                      # bytes that fit
    ld      t1, (FL + 16)(sp)
    mv      s8, t1
    bgeu    t0, t1, 11f
    mv      s8, t0
11: ld      a1, (FL + 8)(sp)
    beq     s8, t1, 12f                     # the FIN only when all fit
    li      a1, 0
12: sd      a1, (FL + 8)(sp)
    bnez    s8, 1f
    beqz    a1, 8f
1:  li      t0, 0x0E                        # OFF and LEN
    or      t0, t0, a1
    sb      t0, 0(s3)
    addi    a0, s3, 1
    ld      a1, S_ID(s2)
    call    quic_vput
    ld      a1, (FL + 0)(sp)
    call    quic_vput
    mv      a1, s8
    call    quic_vput2
    mv      s3, a0
    ld      a1, (FL + 0)(sp)
    mv      a2, s8
    call    quic_stream_read
    add     s3, s3, s8
    ld      t0, (FL + 0)(sp)
    slli    a4, s8, 48
    or      a4, a4, t0
    li      a0, FR_STREAM
    ld      a1, (FL + 8)(sp)
    lwu     a2, S_GEN(s2)
    mv      a3, s7
    call    quic_add_ref
    call    quic_elicit
    mv      a0, s8
    j       9f
8:  li      a0, -1
9:  mv      a1, s3                          # the position after
    LEAVE   0, 32
END_FUNCTION quic_stream_frame

/*
 * quic_stream_read(dst, offset, n): copies n queued bytes of the stream from
 * offset to dst, across chunks. s2 the stream.
 * s3 dst, s4 offset, s5 n, s6 the chunk, s7 its start.
 */
LOCAL_FUNCTION quic_stream_read
    ENTER   0
    mv      s3, a0
    mv      s4, a1
    mv      s5, a2
    ld      s6, S_Q_HEAD(s2)
    ld      s7, S_Q_BASE(s2)
1:  beqz    s5, 9f
    beqz    s6, 9f
    add     t0, s9, s6
    ld      t1, Q_LEN(t0)
    add     t2, s7, t1                      # the chunk end
    bltu    s4, t2, 2f
    mv      s7, t2
    ld      s6, Q_NEXT(t0)
    j       1b
2:  sub     t3, s4, s7                      # the place in the chunk
    sub     t4, t1, t3
    bgeu    s5, t4, 21f
    mv      t4, s5
21: addi    a1, t0, Q_DATA
    add     a1, a1, t3
    mv      a0, s3
    mv      a2, t4
    mv      s8, t4
    call    quic_copy
    add     s3, s3, s8
    add     s4, s4, s8
    sub     s5, s5, s8
    j       1b
9:  LEAVE   0
END_FUNCTION quic_stream_read
