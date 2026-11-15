/*
 * Sending (RFC 9000 sections 12, 13, 14 and 17): datagrams of up to three
 * coalesced packets, their frames by priority, the padding of datagrams with
 * Initial packets, packet protection, the records for recovery, the
 * anti-amplification limit and the congestion window.
 * x19 the connection in every function here.
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
1:  ldr     x9, [x19, #C_STATE]
    cmp     x9, #CS_DRAINING
    b.hs    9f
    bl      quic_room
    cmp     x0, #(QUIC_ACT_DATA + MAX_DATAGRAM + 8)
    b.lo    9f
    mov     x20, #MAX_DATAGRAM
    ldr     x9, [x19, #C_ROLE]              /* a server before validation: 3 times the bytes received */
    cbz     x9, 2f
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_VALIDATED
    b.ne    2f
    ldr     x9, [x19, #C_RX_BYTES]
    add     x9, x9, x9, lsl #1
    ldr     x10, [x19, #C_TX_BYTES]
    subs    x9, x9, x10
    b.ls    9f
    cmp     x9, x20
    csel    x20, x9, x20, lo
    cmp     x20, #MAX_DATAGRAM              /* Initial datagrams need 1200 bytes */
    b.lo    9f
2:  SCR     x0, SC_OUT
    mov     x1, x20
    bl      quic_datagram
    cbz     x0, 9f
    mov     x21, x0
    add     x1, x21, #(QUIC_ACT_DATA + 7)
    and     x1, x1, #~7
    mov     x0, #QUIC_ACTION_SEND
    bl      quic_action
    cbz     x0, 9f
    mov     x22, x0
    ldr     x9, [x19, #C_SOCKET]
    str     x9, [x22, #QUIC_ACT_SOCKET]
    add     x0, x22, #QUIC_ACT_ADDR
    add     x1, x19, #C_ADDR
    mov     x2, #QUIC_ADDR_SIZE
    bl      quic_copy
    str     x21, [x22, #QUIC_ACT_COUNT]
    add     x0, x22, #QUIC_ACT_DATA
    SCR     x1, SC_OUT
    mov     x2, x21
    bl      quic_copy
    ldr     x9, [x19, #C_TX_BYTES]
    add     x9, x9, x21
    str     x9, [x19, #C_TX_BYTES]
    b       1b
9:  LEAVE   0
END_FUNCTION quic_conn_output

/*
 * quic_datagram(buf, max) -> the bytes of a datagram built at buf, at most
 * max, or 0 when there is nothing to send: a packet for each space that has
 * something, Initial first; padding to 1200 bytes when it holds an Initial
 * packet of a client, or an ack-eliciting one of a server (RFC 9000 section
 * 14.1); then each packet is protected and recorded.
 * x20 buf, x21 max, x22 position, x23 space, x24 packets, x25 pad.
 */
.set DGM_PACKETS, 0                     /* 3 packets */
.set DGM_FRAME, 3 * PK_SIZE
LOCAL_FUNCTION quic_datagram
    ENTER   0, DGM_FRAME
    mov     x20, x0
    mov     x21, x1
    mov     x22, x0
    mov     x24, #0
    mov     x25, #0
    mov     x23, #0
1:  cmp     x23, #3
    b.hs    3f
    mov     x0, x19
    mov     x1, x23
    bl      quic_space
    ldr     x9, [x0, #SP_FLAGS]
    tst     x9, #SPF_TX
    b.eq    2f
    tst     x9, #SPF_DISCARDED
    b.ne    2f
    sub     x9, x22, x20
    sub     x9, x21, x9                     /* room left */
    cmp     x9, #96
    b.lo    3f
    mov     x10, #PK_SIZE
    mov     x11, sp
    madd    x3, x24, x10, x11
    mov     x0, x23
    mov     x1, x22
    mov     x2, x9
    bl      quic_packet_build
    cbz     x0, 2f
    mov     x10, #PK_SIZE
    mov     x11, sp
    madd    x11, x24, x10, x11
    ldr     x12, [x11, #PK_HEADER]
    ldr     x13, [x11, #PK_PAYLOAD]
    add     x12, x12, x13
    add     x12, x12, #TAG_LEN
    add     x22, x22, x12
    add     x24, x24, #1
    cmp     x23, #SPACE_INITIAL
    b.ne    2f
    ldr     x9, [x19, #C_ROLE]
    cbz     x9, 11f
    ldr     x9, [x11, #PK_FLAGS]
    tst     x9, #SRF_ELICIT
    b.eq    2f
11: mov     x25, #1
2:  add     x23, x23, #1
    b       1b
3:  mov     x0, #0
    cbz     x24, 9f
    cbz     x25, 5f                         /* padding: into the last packet */
    sub     x9, x22, x20
    mov     x10, #MAX_DATAGRAM
    cmp     x9, x10
    b.hs    5f
    sub     x10, x10, x9                    /* bytes to add */
    sub     x11, x24, #1
    mov     x12, #PK_SIZE
    mov     x13, sp
    madd    x11, x11, x12, x13
    ldr     x12, [x11, #PK_START]
    ldr     x13, [x11, #PK_HEADER]
    ldr     x14, [x11, #PK_PAYLOAD]
    add     x0, x12, x13
    add     x0, x0, x14
    mov     x1, x10
    stp     x10, x11, [x28, #(SC_FRAME + 0)]
    bl      quic_zero                       /* PADDING frames */
    ldp     x10, x11, [x28, #(SC_FRAME + 0)]
    ldr     x14, [x11, #PK_PAYLOAD]
    add     x14, x14, x10
    str     x14, [x11, #PK_PAYLOAD]
    add     x22, x22, x10
    ldr     x9, [x11, #PK_FLAGS]
    orr     x9, x9, #SRF_FLIGHT
    str     x9, [x11, #PK_FLAGS]
5:  mov     x23, #0                         /* protect and record each packet */
6:  cmp     x23, x24
    b.hs    8f
    mov     x9, #PK_SIZE
    mov     x10, sp
    madd    x0, x23, x9, x10
    bl      quic_packet_finish
    add     x23, x23, #1
    b       6b
8:  sub     x0, x22, x20
9:  LEAVE   0, DGM_FRAME
END_FUNCTION quic_datagram

/*
 * quic_packet_finish(packet): the Length of a long header, then protection,
 * then the record of an ack-eliciting or padded packet. A client drops its
 * Initial keys when it sends its first Handshake packet (RFC 9001 section 4.9.1).
 * x20 the packet, x21 the space record.
 */
LOCAL_FUNCTION quic_packet_finish
    ENTER   0
    mov     x20, x0
    ldr     x9, [x20, #PK_LEN_AT]
    cbz     x9, 1f
    ldr     x10, [x20, #PK_PAYLOAD]
    add     x1, x10, #(PN_LEN + TAG_LEN)
    mov     x0, x9
    bl      quic_vput2
1:  mov     x0, x19
    ldr     x1, [x20, #PK_SPACE]
    bl      quic_space
    mov     x21, x0
    add     x0, x21, #SP_TX_KEYS
    ldr     x1, [x20, #PK_START]
    ldr     x2, [x20, #PK_HEADER]
    ldr     x3, [x20, #PK_PAYLOAD]
    ldr     x4, [x20, #PK_PN]
    add     x5, x28, #SC_PKT_WORK
    bl      quic_seal
    mov     x22, x0                         /* the packet size */
    ldr     x9, [x20, #PK_FLAGS]
    tst     x9, #SRF_ELICIT
    b.eq    2f
    ldr     x0, [x20, #PK_SPACE]
    ldr     x1, [x20, #PK_PN]
    mov     x2, x22
    ldr     x3, [x20, #PK_FLAGS]
    add     x4, x20, #PK_REFS
    ldr     x5, [x20, #PK_NREFS]
    bl      quic_record_sent
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_ELICIT_SENT
    b.ne    2f
    orr     x9, x9, #CF_ELICIT_SENT         /* the first ack-eliciting packet since the last one received */
    str     x9, [x19, #C_FLAGS]
    bl      quic_idle_reset
2:  ldr     x9, [x20, #PK_SPACE]
    cmp     x9, #SPACE_APP
    b.ne    3f
    ldr     x9, [x19, #C_PHASE_SENT]
    add     x9, x9, #1
    str     x9, [x19, #C_PHASE_SENT]
3:  ldr     x9, [x20, #PK_SPACE]
    cmp     x9, #SPACE_HANDSHAKE
    b.ne    9f
    ldr     x9, [x19, #C_ROLE]
    cbnz    x9, 9f
    mov     x0, #SPACE_INITIAL
    bl      quic_discard_space
9:  LEAVE   0
END_FUNCTION quic_packet_finish

/* ---------------------------------------------------------------- Packets */

/*
 * quic_packet_build(space, dst, room, packet) -> 1 when a packet of the space
 * with at least one frame is built at dst, unprotected, with room for its
 * tag; else 0 and nothing is kept. The packet fields go to packet.
 * x20 space, x21 dst, x22 room, x23 packet, x24 position, x25 end of frames,
 * x26 the space record.
 */
LOCAL_FUNCTION quic_packet_build
    ENTER   0
    mov     x20, x0
    mov     x21, x1
    mov     x22, x2
    mov     x23, x3
    mov     x0, x19
    mov     x1, x20
    bl      quic_space
    mov     x26, x0
    mov     x0, x23
    mov     x1, #PK_SIZE
    bl      quic_zero
    str     x21, [x23, #PK_START]
    str     x20, [x23, #PK_SPACE]
    ldr     x9, [x26, #SP_NEXT_PN]
    str     x9, [x23, #PK_PN]
    /* The header. */
    mov     x24, x21
    cmp     x20, #SPACE_APP
    b.eq    2f
    mov     w9, #0xC3                       /* long: Initial (type 0) or Handshake (type 2), 4-byte number */
    cmp     x20, #SPACE_HANDSHAKE
    mov     w10, #0xE3
    csel    w9, w10, w9, eq
    strb    w9, [x24], #1
    strb    wzr, [x24], #1
    strb    wzr, [x24], #1
    strb    wzr, [x24], #1
    mov     w9, #1
    strb    w9, [x24], #1
    ldr     x2, [x19, #(C_RCID + QUIC_CID_LENGTH)]
    strb    w2, [x24], #1
    mov     x0, x24
    add     x1, x19, #(C_RCID + QUIC_CID_ID)
    bl      quic_copy
    mov     w9, #8
    strb    w9, [x0], #1
    ldr     x9, [x19, #C_LCID]
    str     x9, [x0], #8
    mov     x24, x0
    cmp     x20, #SPACE_INITIAL
    b.ne    1f
    ldr     x9, [x19, #C_ROLE]              /* the token: a client's Retry token, else empty */
    ldr     x1, [x19, #C_TOKEN_LEN]
    cmp     x9, #0
    csel    x1, x1, xzr, eq
    mov     x0, x24
    mov     x25, x1
    bl      quic_vput
    mov     x24, x0
    cbz     x25, 1f
    ldr     x1, [x19, #C_TOKEN]
    add     x1, x27, x1
    mov     x2, x25
    bl      quic_copy
    mov     x24, x0
1:  str     x24, [x23, #PK_LEN_AT]          /* Length: written when the payload is known */
    add     x24, x24, #2
    b       3f
2:  ldr     x9, [x19, #C_KEY_PHASE]         /* short: the key phase, 4-byte number */
    mov     w10, #0x43
    orr     w10, w10, w9, lsl #2
    strb    w10, [x24], #1
    ldr     x2, [x19, #(C_RCID + QUIC_CID_LENGTH)]
    mov     x0, x24
    add     x1, x19, #(C_RCID + QUIC_CID_ID)
    bl      quic_copy
    mov     x24, x0
3:  ldr     x9, [x23, #PK_PN]
    rev     w9, w9
    str     w9, [x24], #4
    sub     x9, x24, x21
    str     x9, [x23, #PK_HEADER]
    add     x25, x21, x22
    sub     x25, x25, #TAG_LEN              /* the end of the frames */
    /* The frames. */
    mov     x0, x24
    mov     x1, x25
    bl      quic_frames_out
    sub     x9, x0, x24
    cbz     x9, 8f
    str     x9, [x23, #PK_PAYLOAD]
    ldr     x9, [x26, #SP_NEXT_PN]
    add     x9, x9, #1
    str     x9, [x26, #SP_NEXT_PN]
    mov     x0, #1
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_packet_build

/*
 * quic_may_elicit(needs_ref) -> 1 when an ack-eliciting frame may go in the
 * packet: a free record, a free frame ref (for frames that need one: 1), and
 * room in the congestion window, or a probe due in the space.
 * x23 the packet, x26 the space record; x20 needs_ref.
 */
LOCAL_FUNCTION quic_may_elicit
    ENTER   0
    mov     x20, x0
    bl      quic_ring_free
    cbz     x0, 9f
    cbz     x20, 1f
    ldr     x9, [x23, #PK_NREFS]
    cmp     x9, #SR_MAX_FRAMES
    b.hs    8f
1:  ldr     x9, [x23, #PK_FLAGS]            /* this packet counts already */
    tst     x9, #SRF_ELICIT
    b.ne    7f
    ldr     x9, [x26, #SP_FLAGS]
    tst     x9, #SPF_PROBE
    b.ne    7f
    ldr     x9, [x19, #C_IN_FLIGHT]
    add     x9, x9, #MAX_DATAGRAM
    ldr     x10, [x19, #C_CWND]
    cmp     x9, x10
    b.hi    8f
7:  mov     x0, #1
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_may_elicit

/* quic_elicit(): the packet is ack-eliciting and in flight. A leaf. x23 the packet. */
LOCAL_FUNCTION quic_elicit
    UNWIND_END_PROLOGUE
    ldr     x9, [x23, #PK_FLAGS]
    orr     x9, x9, #(SRF_ELICIT | SRF_FLIGHT)
    str     x9, [x23, #PK_FLAGS]
    ret
END_FUNCTION quic_elicit

/*
 * quic_add_ref(kind, flags, slot_gen, value, offset_len): a frame ref of the
 * packet: kind u8, flags u8, generation u16, slot or value u32, offset and
 * length u64. A leaf. x23 the packet.
 */
LOCAL_FUNCTION quic_add_ref
    UNWIND_END_PROLOGUE
    ldr     x5, [x23, #PK_NREFS]
    add     x6, x23, #PK_REFS
    add     x6, x6, x5, lsl #4
    strb    w0, [x6]
    strb    w1, [x6, #1]
    strh    w2, [x6, #2]
    str     w3, [x6, #4]
    str     x4, [x6, #8]
    add     x5, x5, #1
    str     x5, [x23, #PK_NREFS]
    ret
END_FUNCTION quic_add_ref

/*
 * quic_frames_out(p, end) -> the position after the frames of the packet:
 * ACK; CONNECTION_CLOSE alone when closing; CRYPTO; then in the Application
 * space HANDSHAKE_DONE, PATH_RESPONSE, RETIRE_CONNECTION_ID, MAX_DATA,
 * MAX_STREAMS and the stream frames; PING for a probe or a keep-alive.
 * x20 space, x21 position, x22 end, x23 the packet, x26 the space record.
 */
LOCAL_FUNCTION quic_frames_out
    ENTER   0
    mov     x21, x0
    mov     x22, x1
    ldr     x9, [x19, #C_STATE]             /* closing: CONNECTION_CLOSE alone */
    cmp     x9, #CS_CLOSING
    b.eq    2f
    /* ACK */
    ldr     x9, [x26, #SP_NRANGES]
    cbz     x9, 2f
    ldr     x9, [x26, #SP_ACK_COUNT]
    ldr     x10, [x26, #SP_FLAGS]
    tst     x10, #SPF_ACK_NOW
    b.ne    1f
    cbz     x9, 2f
    cmp     x20, #SPACE_APP
    b.ne    1f
    ldr     x10, [x26, #SP_ACK_AT]
    ldr     x11, [x27, #ST_NOW]
    cmp     x11, x10
    b.hs    1f
    bl      quic_app_pending                /* not due: only with other frames */
    cbz     x0, 2f
1:  mov     x0, x21
    mov     x1, x22
    bl      quic_ack_frame
    cbz     x0, 2f
    mov     x21, x0
    str     xzr, [x26, #SP_ACK_COUNT]
    mov     x9, #NONE
    str     x9, [x26, #SP_ACK_AT]
    ldr     x9, [x26, #SP_FLAGS]
    bic     x9, x9, #SPF_ACK_NOW
    str     x9, [x26, #SP_FLAGS]
2:  ldr     x9, [x19, #C_STATE]             /* CONNECTION_CLOSE */
    cmp     x9, #CS_CLOSING
    b.ne    3f
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_CLOSE_FRAME
    b.eq    90f
    sub     x9, x22, x21
    cmp     x9, #24
    b.lo    90f
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_APP_CLOSE
    b.eq    21f
    cmp     x20, #SPACE_APP
    b.ne    22f
    mov     w9, #0x1D                       /* the application's close */
    strb    w9, [x21], #1
    mov     x0, x21
    ldr     x1, [x19, #C_ERROR]
    bl      quic_vput
    strb    wzr, [x0], #1
    mov     x21, x0
    b       23f
22: mov     w9, #0x1C                       /* in Initial and Handshake: APPLICATION_ERROR */
    strb    w9, [x21], #1
    mov     w9, #0x0C
    strb    w9, [x21], #1
    strb    wzr, [x21], #1
    strb    wzr, [x21], #1
    b       23f
21: mov     w9, #0x1C
    strb    w9, [x21], #1
    mov     x0, x21
    ldr     x1, [x19, #C_ERROR]
    bl      quic_vput
    strb    wzr, [x0], #1
    strb    wzr, [x0], #1
    mov     x21, x0
23: cmp     x20, #SPACE_APP                 /* every space with keys gets one; the flag goes with the last */
    b.eq    24f
    mov     x0, x19
    mov     x1, #SPACE_APP
    bl      quic_space
    ldr     x9, [x0, #SP_FLAGS]
    tst     x9, #SPF_TX
    b.ne    90f
    cmp     x20, #SPACE_HANDSHAKE
    b.eq    24f
    mov     x0, x19
    mov     x1, #SPACE_HANDSHAKE
    bl      quic_space
    ldr     x9, [x0, #SP_FLAGS]
    tst     x9, #SPF_TX
    b.eq    24f
    tst     x9, #SPF_DISCARDED
    b.eq    90f
24: ldr     x9, [x19, #C_FLAGS]
    bic     x9, x9, #CF_CLOSE_FRAME
    str     x9, [x19, #C_FLAGS]
    b       90f
3:  /* CRYPTO */
    ldr     x9, [x26, #SP_CTX_SENT]
    ldr     x10, [x26, #SP_CTX_LEN]
    cmp     x9, x10
    b.hs    4f
    mov     x0, #1
    bl      quic_may_elicit
    cbz     x0, 4f
    sub     x11, x22, x21
    subs    x11, x11, #(1 + 8 + 2)          /* type, offset, 2-byte length */
    b.ls    4f
    ldr     x9, [x26, #SP_CTX_SENT]
    ldr     x10, [x26, #SP_CTX_LEN]
    sub     x12, x10, x9
    cmp     x12, x11
    csel    x12, x12, x11, ls               /* the bytes that fit */
    mov     w13, #0x06
    strb    w13, [x21], #1
    stp     x9, x12, [x28, #SC_FRAME]
    mov     x0, x21
    mov     x1, x9
    bl      quic_vput
    ldp     x9, x12, [x28, #SC_FRAME]
    mov     x1, x12
    bl      quic_vput2
    ldr     x1, [x26, #SP_CTX]
    add     x1, x27, x1
    ldp     x9, x12, [x28, #SC_FRAME]
    add     x1, x1, x9
    mov     x2, x12
    bl      quic_copy
    mov     x21, x0
    ldp     x9, x12, [x28, #SC_FRAME]
    add     x10, x9, x12
    str     x10, [x26, #SP_CTX_SENT]
    mov     x0, #FR_CRYPTO
    mov     x1, #0
    mov     x2, #0
    mov     x3, #0
    orr     x4, x9, x12, lsl #48
    bl      quic_add_ref
    bl      quic_elicit
4:  cmp     x20, #SPACE_APP
    b.ne    80f
    ldr     x9, [x19, #C_STATE]
    cmp     x9, #CS_ACTIVE
    b.ne    80f
    bl      quic_app_frames
    mov     x21, x0
80: /* PING: a probe, or a keep-alive, with no other ack-eliciting frame */
    ldr     x9, [x23, #PK_FLAGS]
    tst     x9, #SRF_ELICIT
    b.ne    85f
    ldr     x9, [x26, #SP_FLAGS]
    tst     x9, #SPF_PROBE
    b.ne    81f
    cmp     x20, #SPACE_APP
    b.ne    90f
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_PING
    b.eq    90f
81: cmp     x21, x22
    b.hs    90f
    mov     x0, #0
    bl      quic_may_elicit
    cbz     x0, 90f
    mov     w9, #0x01
    strb    w9, [x21], #1
    bl      quic_elicit
    ldr     x9, [x19, #C_FLAGS]
    bic     x9, x9, #CF_PING
    str     x9, [x19, #C_FLAGS]
85: ldr     x9, [x26, #SP_FLAGS]            /* the probe went */
    bic     x9, x9, #SPF_PROBE
    str     x9, [x26, #SP_FLAGS]
90: mov     x0, x21
    LEAVE   0
END_FUNCTION quic_frames_out

/*
 * quic_ack_frame(p, end) -> the position after an ACK frame of the received
 * ranges of the space, as many as fit, or 0 when none fits. The delay is
 * in units of 8 microseconds (ack_delay_exponent 3) in the Application space.
 * x20 space, x21 p, x22 end, x23 the ranges, x24 index, x25 count kept, x26 the space record.
 */
LOCAL_FUNCTION quic_ack_frame
    ENTER   0
    mov     x21, x0
    mov     x22, x1
    sub     x9, x22, x21
    cmp     x9, #40
    b.lo    8f
    add     x23, x26, #SP_RANGES
    ldr     x25, [x26, #SP_NRANGES]
    sub     x9, x22, x21                    /* ranges that fit: 16 bytes each at most */
    sub     x9, x9, #32
    lsr     x9, x9, #4
    add     x9, x9, #1
    cmp     x25, x9
    csel    x25, x25, x9, ls
    mov     w9, #0x02
    strb    w9, [x21], #1
    mov     x0, x21
    ldr     x1, [x23, #8]                   /* the largest */
    bl      quic_vput
    mov     x1, #0
    cmp     x20, #SPACE_APP
    b.ne    1f
    ldr     x9, [x27, #ST_NOW]
    ldr     x10, [x26, #SP_RECV_TIME]
    subs    x1, x9, x10
    csel    x1, xzr, x1, lo
    lsr     x1, x1, #3
    MOV64   x9, 0x3FFFFFFF
    cmp     x1, x9
    csel    x1, x1, x9, ls
1:  bl      quic_vput
    sub     x1, x25, #1
    bl      quic_vput
    ldp     x9, x10, [x23]
    sub     x1, x10, x9                     /* the first range */
    bl      quic_vput
    mov     x24, #1
2:  cmp     x24, x25
    b.hs    3f
    add     x9, x23, x24, lsl #4
    ldp     x10, x11, [x9]                  /* this range */
    ldr     x12, [x9, #-16]                 /* the smallest of the one before */
    sub     x1, x12, x11
    sub     x1, x1, #2                      /* gap */
    stp     x10, x11, [x28, #SC_FRAME]
    bl      quic_vput
    ldp     x10, x11, [x28, #SC_FRAME]
    sub     x1, x11, x10
    bl      quic_vput
    add     x24, x24, #1
    b       2b
3:  b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_ack_frame

/*
 * quic_app_pending() -> 1 when the Application space has frames to send other
 * than ACK, so an ACK not yet due may go with them.
 */
LOCAL_FUNCTION quic_app_pending
    ENTER   0
    ldr     x9, [x19, #C_FLAGS]
    mov     x10, #(CF_DONE_FRAME | CF_MAX_DATA | CF_MAX_STREAMS | CF_PING | CF_CHALLENGE)
    tst     x9, x10
    b.ne    7f
    ldr     x9, [x19, #C_RETIRE_SEQ]
    cmn     x9, #1
    b.ne    7f
    ldr     x20, [x19, #C_STREAM_HEAD]
1:  cmn     x20, #1
    b.eq    8f
    mov     x0, x20
    bl      quic_stream_at
    ldr     x20, [x0, #S_NEXT]
    ldr     x9, [x0, #S_ID]
    cmn     x9, #1
    b.eq    1b
    ldr     x9, [x0, #S_FLAGS]
    mov     x10, #(SF_RESET_SEND | SF_STOP_SEND | SF_MSD | SF_FIN_LOST)
    tst     x9, x10
    b.ne    7f
    ldr     x10, [x0, #S_NLOST]
    tst     x10, #0xFF
    b.ne    7f
    ldr     x10, [x0, #S_SENT]
    ldr     x11, [x0, #S_WRITTEN]
    cmp     x10, x11
    b.lo    7f
    tst     x9, #SF_FIN_WANT
    b.eq    1b
    tst     x9, #SF_FIN_SENT
    b.eq    7f
    b       1b
7:  mov     x0, #1
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_app_pending

/*
 * quic_app_frames() -> the position after the frames of the Application
 * space that are not ACK, CRYPTO or PING. x20 space, x21 position, x22 end,
 * x23 the packet, x26 the space record.
 */
LOCAL_FUNCTION quic_app_frames
    ENTER   0
    /* HANDSHAKE_DONE */
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_DONE_FRAME
    b.eq    1f
    cmp     x21, x22
    b.hs    1f
    mov     x0, #1
    bl      quic_may_elicit
    cbz     x0, 1f
    mov     w9, #0x1E
    strb    w9, [x21], #1
    ldr     x9, [x19, #C_FLAGS]
    bic     x9, x9, #CF_DONE_FRAME
    str     x9, [x19, #C_FLAGS]
    mov     x0, #FR_DONE
    mov     x1, #0
    mov     x2, #0
    mov     x3, #0
    mov     x4, #0
    bl      quic_add_ref
    bl      quic_elicit
1:  /* PATH_RESPONSE */
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_CHALLENGE
    b.eq    2f
    sub     x10, x22, x21
    cmp     x10, #9
    b.lo    2f
    mov     x0, #0
    bl      quic_may_elicit
    cbz     x0, 2f
    mov     w9, #0x1B
    strb    w9, [x21], #1
    ldr     x9, [x19, #C_CHALLENGE]
    str     x9, [x21], #8
    ldr     x9, [x19, #C_FLAGS]
    bic     x9, x9, #CF_CHALLENGE
    str     x9, [x19, #C_FLAGS]
    bl      quic_elicit
2:  /* RETIRE_CONNECTION_ID */
    ldr     x24, [x19, #C_RETIRE_SEQ]
    cmn     x24, #1
    b.eq    3f
    sub     x10, x22, x21
    cmp     x10, #9
    b.lo    3f
    mov     x0, #1
    bl      quic_may_elicit
    cbz     x0, 3f
    mov     w9, #0x19
    strb    w9, [x21], #1
    mov     x0, x21
    mov     x1, x24
    bl      quic_vput
    mov     x21, x0
    mov     x9, #NONE
    str     x9, [x19, #C_RETIRE_SEQ]
    mov     x0, #FR_RETIRE
    mov     x1, #0
    mov     x2, #0
    mov     x3, x24
    mov     x4, #0
    bl      quic_add_ref
    bl      quic_elicit
3:  /* MAX_DATA */
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_MAX_DATA
    b.eq    4f
    sub     x10, x22, x21
    cmp     x10, #9
    b.lo    4f
    mov     x0, #1
    bl      quic_may_elicit
    cbz     x0, 4f
    mov     w9, #0x10
    strb    w9, [x21], #1
    mov     x0, x21
    ldr     x1, [x19, #C_RX_MAX]
    bl      quic_vput
    mov     x21, x0
    ldr     x9, [x19, #C_FLAGS]
    bic     x9, x9, #CF_MAX_DATA
    str     x9, [x19, #C_FLAGS]
    mov     x0, #FR_MAX_DATA
    mov     x1, #0
    mov     x2, #0
    mov     x3, #0
    mov     x4, #0
    bl      quic_add_ref
    bl      quic_elicit
4:  /* MAX_STREAMS */
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_MAX_STREAMS
    b.eq    5f
    sub     x10, x22, x21
    cmp     x10, #9
    b.lo    5f
    mov     x0, #1
    bl      quic_may_elicit
    cbz     x0, 5f
    mov     w9, #0x12
    strb    w9, [x21], #1
    mov     x0, x21
    ldr     x1, [x19, #C_PEER_MAX]
    bl      quic_vput
    mov     x21, x0
    ldr     x9, [x19, #C_FLAGS]
    bic     x9, x9, #CF_MAX_STREAMS
    str     x9, [x19, #C_FLAGS]
    mov     x0, #FR_MAX_STREAMS
    mov     x1, #0
    mov     x2, #0
    mov     x3, #0
    mov     x4, #0
    bl      quic_add_ref
    bl      quic_elicit
5:  /* The streams, in list order. */
    ldr     x24, [x19, #C_STREAM_HEAD]
6:  cmn     x24, #1
    b.eq    9f
    mov     x0, x24
    bl      quic_stream_at
    ldr     x24, [x0, #S_NEXT]
    ldr     x9, [x0, #S_ID]
    cmn     x9, #1
    b.eq    6b
    bl      quic_stream_out
    mov     x21, x0
    b       6b
9:  mov     x0, x21
    LEAVE   0
END_FUNCTION quic_app_frames

/*
 * quic_stream_out(stream) -> the position after the frames of one stream that
 * fit: RESET_STREAM, STOP_SENDING, MAX_STREAM_DATA, then STREAM frames: lost
 * ranges first, then new bytes within the flow control limits, with the FIN
 * when the last byte goes. x21 position, x22 end, x23 the packet.
 * x20 the stream, x25 the stream generation and slot.
 */
LOCAL_FUNCTION quic_stream_out
    ENTER   0
    mov     x20, x0
    bl      quic_stream_index
    mov     x25, x0
    /* RESET_STREAM: id, our code, the final size (the bytes written) */
    ldr     x9, [x20, #S_FLAGS]
    tst     x9, #SF_RESET_SEND
    b.eq    1f
    sub     x10, x22, x21
    cmp     x10, #25
    b.lo    1f
    mov     x0, #1
    bl      quic_may_elicit
    cbz     x0, 1f
    mov     w9, #0x04
    strb    w9, [x21], #1
    mov     x0, x21
    ldr     x1, [x20, #S_ID]
    bl      quic_vput
    ldr     x1, [x20, #S_APP_CODE]
    bl      quic_vput
    ldr     x1, [x20, #S_SENT]              /* the final size: the bytes sent */
    bl      quic_vput
    mov     x21, x0
    ldr     x9, [x20, #S_FLAGS]
    bic     x9, x9, #SF_RESET_SEND
    str     x9, [x20, #S_FLAGS]
    mov     x0, #FR_RESET
    bl      quic_stream_ref
    bl      quic_elicit
1:  ldr     x9, [x20, #S_FLAGS]             /* STOP_SENDING */
    tst     x9, #SF_STOP_SEND
    b.eq    2f
    sub     x10, x22, x21
    cmp     x10, #17
    b.lo    2f
    mov     x0, #1
    bl      quic_may_elicit
    cbz     x0, 2f
    mov     w9, #0x05
    strb    w9, [x21], #1
    mov     x0, x21
    ldr     x1, [x20, #S_ID]
    bl      quic_vput
    ldr     x1, [x20, #S_APP_CODE]
    bl      quic_vput
    mov     x21, x0
    ldr     x9, [x20, #S_FLAGS]
    bic     x9, x9, #SF_STOP_SEND
    str     x9, [x20, #S_FLAGS]
    mov     x0, #FR_STOP
    bl      quic_stream_ref
    bl      quic_elicit
2:  ldr     x9, [x20, #S_FLAGS]             /* MAX_STREAM_DATA */
    tst     x9, #SF_MSD
    b.eq    3f
    tst     x9, #SF_RX_DONE
    b.ne    21f
    sub     x10, x22, x21
    cmp     x10, #17
    b.lo    3f
    mov     x0, #1
    bl      quic_may_elicit
    cbz     x0, 3f
    mov     w9, #0x11
    strb    w9, [x21], #1
    mov     x0, x21
    ldr     x1, [x20, #S_ID]
    bl      quic_vput
    ldr     x1, [x20, #S_RX_MAX]
    bl      quic_vput
    mov     x21, x0
    mov     x0, #FR_MAX_STREAM_DATA
    bl      quic_stream_ref
    bl      quic_elicit
21: ldr     x9, [x20, #S_FLAGS]
    bic     x9, x9, #SF_MSD
    str     x9, [x20, #S_FLAGS]
3:  ldr     x9, [x20, #S_FLAGS]             /* no data after our reset */
    tst     x9, #SF_RESET
    b.ne    9f
4:  ldr     x9, [x20, #S_NLOST]             /* lost ranges */
    tst     x9, #0xFF
    b.eq    5f
    ldp     x10, x11, [x20, #S_LOST]
    sub     x2, x11, x10
    mov     x0, x10
    mov     x1, #0
    bl      quic_stream_frame
    cmn     x0, #1
    b.eq    9f
    mov     x21, x1
    cbz     x0, 9f
    ldp     x10, x11, [x20, #S_LOST]
    add     x10, x10, x0
    str     x10, [x20, #S_LOST]
    cmp     x10, x11
    b.lo    4b
    mov     x0, x20
    add     x1, x20, #S_NLOST
    mov     x2, #0
    bl      quic_ranges_remove
    b       4b
5:  ldr     x9, [x20, #S_FLAGS]             /* a FIN to send again */
    tst     x9, #SF_FIN_LOST
    b.eq    6f
    ldr     x10, [x20, #S_SENT]
    ldr     x11, [x20, #S_WRITTEN]
    cmp     x10, x11
    b.lo    6f
    mov     x0, x11
    mov     x1, #1
    mov     x2, #0
    bl      quic_stream_frame
    cmn     x0, #1
    b.eq    9f
    mov     x21, x1
    ldr     x9, [x20, #S_FLAGS]
    bic     x9, x9, #SF_FIN_LOST
    str     x9, [x20, #S_FLAGS]
6:  ldr     x10, [x20, #S_SENT]             /* new bytes */
    ldr     x11, [x20, #S_WRITTEN]
    sub     x2, x11, x10
    ldr     x12, [x20, #S_TX_MAX]
    subs    x12, x12, x10
    csel    x12, xzr, x12, lo
    cmp     x2, x12
    csel    x2, x2, x12, ls
    ldr     x12, [x19, #C_TX_MAX]
    ldr     x13, [x19, #C_TX_SENT]
    subs    x12, x12, x13
    csel    x12, xzr, x12, lo
    cmp     x2, x12
    csel    x2, x2, x12, ls
    ldr     x9, [x20, #S_FLAGS]
    mov     x1, #0
    tst     x9, #SF_FIN_WANT
    b.eq    61f
    tst     x9, #SF_FIN_SENT
    b.ne    61f
    add     x12, x10, x2
    cmp     x12, x11
    cset    x1, eq                          /* the FIN goes with the last byte */
61: cbnz    x1, 62f
    cbz     x2, 9f
62: mov     x0, x10
    stp     x1, x2, [x28, #(SC_FRAME + 64)]
    bl      quic_stream_frame
    cmn     x0, #1
    b.eq    9f
    mov     x21, x1
    ldp     x1, x2, [x28, #(SC_FRAME + 64)]
    ldr     x10, [x20, #S_SENT]
    add     x10, x10, x0
    str     x10, [x20, #S_SENT]
    ldr     x11, [x19, #C_TX_SENT]
    add     x11, x11, x0
    str     x11, [x19, #C_TX_SENT]
    cmp     x0, x2
    b.lo    9f                              /* not all fit: no FIN yet */
    cbz     x1, 9f
    ldr     x9, [x20, #S_FLAGS]
    orr     x9, x9, #SF_FIN_SENT
    str     x9, [x20, #S_FLAGS]
9:  mov     x0, x21                         /* the position after */
    LEAVE   0
END_FUNCTION quic_stream_out

/* quic_stream_ref(kind): a frame ref of the stream at x20 (slot x25). */
LOCAL_FUNCTION quic_stream_ref
    ENTER   0
    mov     x21, x0
    ldr     w2, [x20, #S_GEN]
    mov     x1, #0
    mov     x3, x25
    mov     x4, #0
    bl      quic_add_ref
    LEAVE   0
END_FUNCTION quic_stream_ref

/*
 * quic_stream_frame(offset, fin, n) -> x0 the bytes of the stream from offset
 * put in one STREAM frame with the FIN when fin and all n fit, or -1 when no
 * frame fits (0 bytes with a FIN is a frame); x1 the position after.
 * x20 the stream, x21 the position, x22 end, x23 the packet, x25 the slot.
 */
LOCAL_FUNCTION quic_stream_frame
    ENTER   0, 32
    stp     x0, x1, [sp]
    str     x2, [sp, #16]
    mov     x0, #1
    bl      quic_may_elicit
    cbz     x0, 8f
    ldr     x0, [x20, #S_ID]
    bl      quic_vlen
    mov     x24, x0
    ldr     x0, [sp]
    bl      quic_vlen
    add     x24, x24, x0
    add     x24, x24, #3                    /* type and a 2-byte length */
    sub     x9, x22, x21
    cmp     x9, x24
    b.ls    8f
    sub     x9, x9, x24                     /* bytes that fit */
    ldr     x10, [sp, #16]
    cmp     x10, x9
    csel    x26, x10, x9, ls
    ldp     x0, x1, [sp]
    cmp     x26, x10
    csel    x1, x1, xzr, eq                 /* the FIN only when all fit */
    str     x1, [sp, #8]
    cbnz    x26, 1f
    cbz     x1, 8f
1:  mov     w9, #0x0E                       /* OFF and LEN */
    orr     w9, w9, w1
    strb    w9, [x21], #1
    mov     x0, x21
    ldr     x1, [x20, #S_ID]
    bl      quic_vput
    ldr     x1, [sp]
    bl      quic_vput
    mov     x1, x26
    bl      quic_vput2
    mov     x21, x0
    ldr     x1, [sp]
    mov     x2, x26
    bl      quic_stream_read
    add     x21, x21, x26
    ldr     x9, [sp]
    orr     x4, x9, x26, lsl #48
    mov     x0, #FR_STREAM
    ldr     x1, [sp, #8]
    ldr     w2, [x20, #S_GEN]
    mov     x3, x25
    bl      quic_add_ref
    bl      quic_elicit
    mov     x0, x26
    b       9f
8:  mov     x0, #-1
9:  mov     x1, x21                         /* the position after */
    LEAVE   0, 32
END_FUNCTION quic_stream_frame

/*
 * quic_stream_read(dst, offset, n): copies n queued bytes of the stream from
 * offset to dst, across chunks. x20 the stream.
 * x21 dst, x22 offset, x23 n, x24 the chunk, x25 its start.
 */
LOCAL_FUNCTION quic_stream_read
    ENTER   0
    mov     x21, x0
    mov     x22, x1
    mov     x23, x2
    ldr     x24, [x20, #S_Q_HEAD]
    ldr     x25, [x20, #S_Q_BASE]
1:  cbz     x23, 9f
    cbz     x24, 9f
    add     x9, x27, x24
    ldr     x10, [x9, #Q_LEN]
    add     x11, x25, x10                   /* the chunk end */
    cmp     x22, x11
    b.lo    2f
    mov     x25, x11
    ldr     x24, [x9, #Q_NEXT]
    b       1b
2:  sub     x12, x22, x25                   /* the place in the chunk */
    sub     x13, x10, x12
    cmp     x13, x23
    csel    x13, x13, x23, ls
    add     x1, x9, #Q_DATA
    add     x1, x1, x12
    mov     x0, x21
    mov     x2, x13
    mov     x26, x13
    bl      quic_copy
    add     x21, x21, x26
    add     x22, x22, x26
    sub     x23, x23, x26
    b       1b
9:  LEAVE   0
END_FUNCTION quic_stream_read
