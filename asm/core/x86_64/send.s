/*
 * Sending (RFC 9000 sections 12, 13, 14 and 17): datagrams of up to three
 * coalesced packets, their frames by priority, the padding of datagrams with
 * Initial packets, packet protection, the records for recovery, the
 * anti-amplification limit and the congestion window.
 * rbx the connection in every function here. While a packet is built, the
 * scratch words SC_PACKET and SC_SPREC hold the packet and its space record,
 * and SC_SLOT the slot of the stream whose frames go in (ARM64 x23, x26, x25).
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
 * rbp the most bytes, r12 the bytes, r13 the action.
 */
LOCAL_FUNCTION quic_conn_output
    ENTER   0
1:  cmpq    $CS_DRAINING, C_STATE(%rbx)
    jae     9f
    call    quic_room
    cmp     $(QUIC_ACT_DATA + MAX_DATAGRAM + 8), %rax
    jb      9f
    mov     $MAX_DATAGRAM, %ebp
    cmpq    $0, C_ROLE(%rbx)                /* a server before validation: 3 times the bytes received */
    je      2f
    testq   $CF_VALIDATED, C_FLAGS(%rbx)
    jnz     2f
    mov     C_RX_BYTES(%rbx), %rax
    lea     (%rax,%rax,2), %rax
    mov     C_TX_BYTES(%rbx), %rcx
    cmp     %rax, %rcx
    jae     9f
    sub     %rcx, %rax
    cmp     %rbp, %rax
    jae     11f
    mov     %rax, %rbp
11: cmp     $MAX_DATAGRAM, %rbp             /* Initial datagrams need 1200 bytes */
    jb      9f
2:  lea     SC_OUT(%r14), %rdi
    mov     %rbp, %rsi
    call    quic_datagram
    test    %rax, %rax
    jz      9f
    mov     %rax, %r12
    lea     (QUIC_ACT_DATA + 7)(%r12), %rsi
    and     $-8, %rsi
    mov     $QUIC_ACTION_SEND, %edi
    call    quic_action
    test    %rax, %rax
    jz      9f
    mov     %rax, %r13
    mov     C_SOCKET(%rbx), %rcx
    mov     %rcx, QUIC_ACT_SOCKET(%r13)
    lea     QUIC_ACT_ADDR(%r13), %rdi
    lea     C_ADDR(%rbx), %rsi
    mov     $QUIC_ADDR_SIZE, %edx
    call    quic_copy
    mov     %r12, QUIC_ACT_COUNT(%r13)
    lea     QUIC_ACT_DATA(%r13), %rdi
    lea     SC_OUT(%r14), %rsi
    mov     %r12, %rdx
    call    quic_copy
    add     %r12, C_TX_BYTES(%rbx)
    jmp     1b
9:  LEAVE   0
END_FUNCTION quic_conn_output

/*
 * quic_datagram(buf, max) -> the bytes of a datagram built at buf, at most
 * max, or 0 when there is nothing to send: a packet for each space that has
 * something, Initial first; padding to 1200 bytes when it holds an Initial
 * packet of a client, or an ack-eliciting one of a server (RFC 9000 section
 * 14.1); then each packet is protected and recorded.
 * rbp buf, r12 max, r13 position, X23 space, X24 packets, X25 pad.
 */
.set DGM_PACKETS, 0                     /* 3 packets */
.set DGM_FRAME, 3 * PK_SIZE
LOCAL_FUNCTION quic_datagram
    ENTER   0, DGM_FRAME
    mov     %rdi, %rbp
    mov     %rsi, %r12
    mov     %rdi, %r13
    movq    $0, X24(%rsp)
    movq    $0, X25(%rsp)
    movq    $0, X23(%rsp)
1:  cmpq    $3, X23(%rsp)
    jae     3f
    mov     %rbx, %rdi
    mov     X23(%rsp), %rsi
    call    quic_space
    mov     SP_FLAGS(%rax), %rcx
    test    $SPF_TX, %cl
    jz      2f
    test    $SPF_DISCARDED, %cl
    jnz     2f
    mov     %r13, %rdx
    sub     %rbp, %rdx
    neg     %rdx
    add     %r12, %rdx                      /* room left */
    cmp     $96, %rdx
    jb      3f
    imul    $PK_SIZE, X24(%rsp), %rcx
    lea     (32 + DGM_PACKETS)(%rsp,%rcx), %rcx
    mov     X23(%rsp), %rdi
    mov     %r13, %rsi
    call    quic_packet_build
    test    %rax, %rax
    jz      2f
    imul    $PK_SIZE, X24(%rsp), %rcx
    lea     (32 + DGM_PACKETS)(%rsp,%rcx), %rcx
    mov     PK_HEADER(%rcx), %rax
    add     PK_PAYLOAD(%rcx), %rax
    add     $TAG_LEN, %rax
    add     %rax, %r13
    incq    X24(%rsp)
    cmpq    $SPACE_INITIAL, X23(%rsp)
    jne     2f
    cmpq    $0, C_ROLE(%rbx)
    je      11f
    testq   $SRF_ELICIT, PK_FLAGS(%rcx)
    jz      2f
11: movq    $1, X25(%rsp)
2:  incq    X23(%rsp)
    jmp     1b
3:  xor     %eax, %eax
    cmpq    $0, X24(%rsp)
    je      9f
    cmpq    $0, X25(%rsp)                   /* padding: into the last packet */
    je      5f
    mov     %r13, %rax
    sub     %rbp, %rax
    cmp     $MAX_DATAGRAM, %rax
    jae     5f
    mov     $MAX_DATAGRAM, %ecx
    sub     %rax, %rcx                      /* bytes to add */
    mov     X24(%rsp), %rax
    dec     %rax
    imul    $PK_SIZE, %rax, %rax
    lea     (32 + DGM_PACKETS)(%rsp,%rax), %rax
    mov     %rcx, SC_FRAME(%r14)
    mov     %rax, (SC_FRAME + 8)(%r14)
    mov     PK_START(%rax), %rdi
    add     PK_HEADER(%rax), %rdi
    add     PK_PAYLOAD(%rax), %rdi
    mov     %rcx, %rsi
    call    quic_zero                       /* PADDING frames */
    mov     SC_FRAME(%r14), %rcx
    mov     (SC_FRAME + 8)(%r14), %rax
    add     %rcx, PK_PAYLOAD(%rax)
    add     %rcx, %r13
    orq     $SRF_FLIGHT, PK_FLAGS(%rax)
5:  movq    $0, X23(%rsp)                   /* protect and record each packet */
6:  mov     X23(%rsp), %rax
    cmp     X24(%rsp), %rax
    jae     8f
    imul    $PK_SIZE, %rax, %rax
    lea     (32 + DGM_PACKETS)(%rsp,%rax), %rdi
    call    quic_packet_finish
    incq    X23(%rsp)
    jmp     6b
8:  mov     %r13, %rax
    sub     %rbp, %rax
9:  LEAVE   0, DGM_FRAME
END_FUNCTION quic_datagram

/*
 * quic_packet_finish(packet): the Length of a long header, then protection,
 * then the record of an ack-eliciting or padded packet. A client drops its
 * Initial keys when it sends its first Handshake packet (RFC 9001 section 4.9.1).
 * rbp the packet, r12 the space record, r13 the packet size.
 */
LOCAL_FUNCTION quic_packet_finish
    ENTER   0
    mov     %rdi, %rbp
    mov     PK_LEN_AT(%rbp), %rdi
    test    %rdi, %rdi
    jz      1f
    mov     PK_PAYLOAD(%rbp), %rsi
    add     $(PN_LEN + TAG_LEN), %rsi
    call    quic_vput2
1:  mov     %rbx, %rdi
    mov     PK_SPACE(%rbp), %rsi
    call    quic_space
    mov     %rax, %r12
    lea     SP_TX_KEYS(%r12), %rdi
    mov     PK_START(%rbp), %rsi
    mov     PK_HEADER(%rbp), %rdx
    mov     PK_PAYLOAD(%rbp), %rcx
    mov     PK_PN(%rbp), %r8
    lea     SC_PKT_WORK(%r14), %r9
    call    quic_seal
    mov     %rax, %r13                      /* the packet size */
    testq   $SRF_ELICIT, PK_FLAGS(%rbp)
    jz      2f
    mov     PK_SPACE(%rbp), %rdi
    mov     PK_PN(%rbp), %rsi
    mov     %r13, %rdx
    mov     PK_FLAGS(%rbp), %rcx
    lea     PK_REFS(%rbp), %r8
    mov     PK_NREFS(%rbp), %r9
    call    quic_record_sent
    testq   $CF_ELICIT_SENT, C_FLAGS(%rbx)
    jnz     2f
    orq     $CF_ELICIT_SENT, C_FLAGS(%rbx)  /* the first ack-eliciting packet since the last one received */
    call    quic_idle_reset
2:  cmpq    $SPACE_APP, PK_SPACE(%rbp)
    jne     3f
    incq    C_PHASE_SENT(%rbx)
3:  cmpq    $SPACE_HANDSHAKE, PK_SPACE(%rbp)
    jne     9f
    cmpq    $0, C_ROLE(%rbx)
    jne     9f
    mov     $SPACE_INITIAL, %edi
    call    quic_discard_space
9:  LEAVE   0
END_FUNCTION quic_packet_finish

/* ---------------------------------------------------------------- Packets */

/*
 * quic_packet_build(space, dst, room, packet) -> 1 when a packet of the space
 * with at least one frame is built at dst, unprotected, with room for its
 * tag; else 0 and nothing is kept. The packet fields go to packet.
 * rbp space, r12 dst, r13 room, X23 packet, X24 position, X25 a token length,
 * then the end of the frames, X26 the space record.
 */
LOCAL_FUNCTION quic_packet_build
    ENTER   0
    mov     %rdi, %rbp
    mov     %rsi, %r12
    mov     %rdx, %r13
    mov     %rcx, X23(%rsp)
    mov     %rcx, SC_PACKET(%r14)
    mov     %rbx, %rdi
    mov     %rbp, %rsi
    call    quic_space
    mov     %rax, X26(%rsp)
    mov     %rax, SC_SPREC(%r14)
    mov     X23(%rsp), %rdi
    mov     $PK_SIZE, %esi
    call    quic_zero
    mov     X23(%rsp), %rax
    mov     %r12, PK_START(%rax)
    mov     %rbp, PK_SPACE(%rax)
    mov     X26(%rsp), %rcx
    mov     SP_NEXT_PN(%rcx), %rcx
    mov     %rcx, PK_PN(%rax)
    /* The header. */
    mov     %r12, %rdi
    cmp     $SPACE_APP, %rbp
    je      2f
    mov     $0xC3, %eax                     /* long: Initial (type 0) or Handshake (type 2), 4-byte number */
    cmp     $SPACE_HANDSHAKE, %rbp
    jne     11f
    mov     $0xE3, %eax
11: movb    %al, (%rdi)
    movl    $0x01000000, 1(%rdi)            /* version 1 */
    mov     (C_RCID + QUIC_CID_LENGTH)(%rbx), %rdx
    movb    %dl, 5(%rdi)
    add     $6, %rdi
    lea     (C_RCID + QUIC_CID_ID)(%rbx), %rsi
    call    quic_copy
    movb    $8, (%rax)
    mov     C_LCID(%rbx), %rcx
    mov     %rcx, 1(%rax)
    add     $9, %rax
    mov     %rax, X24(%rsp)
    cmp     $SPACE_INITIAL, %rbp
    jne     1f
    xor     %esi, %esi                      /* the token: a client's Retry token, else empty */
    cmpq    $0, C_ROLE(%rbx)
    jne     12f
    mov     C_TOKEN_LEN(%rbx), %rsi
12: mov     %rsi, X25(%rsp)
    mov     %rax, %rdi
    call    quic_vput
    mov     %rax, X24(%rsp)
    cmpq    $0, X25(%rsp)
    je      1f
    mov     %rax, %rdi
    mov     C_TOKEN(%rbx), %rsi
    add     %r15, %rsi
    mov     X25(%rsp), %rdx
    call    quic_copy
    mov     %rax, X24(%rsp)
1:  mov     X24(%rsp), %rax                 /* Length: written when the payload is known */
    mov     X23(%rsp), %rcx
    mov     %rax, PK_LEN_AT(%rcx)
    add     $2, %rax
    mov     %rax, X24(%rsp)
    jmp     3f
2:  mov     C_KEY_PHASE(%rbx), %rax         /* short: the key phase, 4-byte number */
    shl     $2, %eax
    or      $0x43, %eax
    movb    %al, (%rdi)
    inc     %rdi
    mov     (C_RCID + QUIC_CID_LENGTH)(%rbx), %rdx
    lea     (C_RCID + QUIC_CID_ID)(%rbx), %rsi
    call    quic_copy
    mov     %rax, X24(%rsp)
3:  mov     X23(%rsp), %rcx
    mov     PK_PN(%rcx), %rax
    bswap   %eax
    mov     X24(%rsp), %rdx
    movl    %eax, (%rdx)
    add     $4, %rdx
    mov     %rdx, X24(%rsp)
    mov     %rdx, %rax
    sub     %r12, %rax
    mov     %rax, PK_HEADER(%rcx)
    lea     -TAG_LEN(%r12,%r13), %rax       /* the end of the frames */
    mov     %rax, X25(%rsp)
    /* The frames. */
    mov     X24(%rsp), %rdi
    mov     X25(%rsp), %rsi
    call    quic_frames_out
    sub     X24(%rsp), %rax
    jz      8f
    mov     X23(%rsp), %rcx
    mov     %rax, PK_PAYLOAD(%rcx)
    mov     X26(%rsp), %rcx
    incq    SP_NEXT_PN(%rcx)
    mov     $1, %eax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_packet_build

/*
 * quic_may_elicit(needs_ref) -> 1 when an ack-eliciting frame may go in the
 * packet: a free record, a free frame ref (for frames that need one: 1), and
 * room in the congestion window, or a probe due in the space. rbp needs_ref.
 */
LOCAL_FUNCTION quic_may_elicit
    ENTER   0
    mov     %rdi, %rbp
    call    quic_ring_free
    test    %rax, %rax
    jz      9f
    mov     SC_PACKET(%r14), %rcx
    test    %rbp, %rbp
    jz      1f
    cmpq    $SR_MAX_FRAMES, PK_NREFS(%rcx)
    jae     8f
1:  testq   $SRF_ELICIT, PK_FLAGS(%rcx)     /* this packet counts already */
    jnz     7f
    mov     SC_SPREC(%r14), %rdx
    testq   $SPF_PROBE, SP_FLAGS(%rdx)
    jnz     7f
    mov     C_IN_FLIGHT(%rbx), %rax
    add     $MAX_DATAGRAM, %rax
    cmp     C_CWND(%rbx), %rax
    ja      8f
7:  mov     $1, %eax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_may_elicit

/* quic_elicit(): the packet is ack-eliciting and in flight. A leaf. */
LOCAL_FUNCTION quic_elicit
    UNWIND_END_PROLOGUE
    mov     SC_PACKET(%r14), %rax
    orq     $(SRF_ELICIT | SRF_FLIGHT), PK_FLAGS(%rax)
    ret
END_FUNCTION quic_elicit

/*
 * quic_add_ref(kind, flags, slot_gen, value, offset_len): a frame ref of the
 * packet: kind u8, flags u8, generation u16, slot or value u32, offset and
 * length u64. A leaf.
 */
LOCAL_FUNCTION quic_add_ref
    UNWIND_END_PROLOGUE
    mov     SC_PACKET(%r14), %r9
    mov     PK_NREFS(%r9), %r10
    mov     %r10, %r11
    shl     $4, %r11
    lea     PK_REFS(%r9,%r11), %r11
    movb    %dil, (%r11)
    movb    %sil, 1(%r11)
    movw    %dx, 2(%r11)
    movl    %ecx, 4(%r11)
    mov     %r8, 8(%r11)
    inc     %r10
    mov     %r10, PK_NREFS(%r9)
    ret
END_FUNCTION quic_add_ref

/*
 * quic_frames_out(p, end) -> the position after the frames of the packet:
 * ACK; CONNECTION_CLOSE alone when closing; CRYPTO; then in the Application
 * space HANDSHAKE_DONE, PATH_RESPONSE, RETIRE_CONNECTION_ID, MAX_DATA,
 * MAX_STREAMS and the stream frames; PING for a probe or a keep-alive.
 * rbp space, r12 position, r13 end.
 */
LOCAL_FUNCTION quic_frames_out
    ENTER   0
    mov     %rdi, %r12
    mov     %rsi, %r13
    cmpq    $CS_CLOSING, C_STATE(%rbx)      /* closing: CONNECTION_CLOSE alone */
    je      2f
    /* ACK */
    mov     SC_SPREC(%r14), %rax
    cmpq    $0, SP_NRANGES(%rax)
    je      2f
    mov     SP_ACK_COUNT(%rax), %rcx
    testq   $SPF_ACK_NOW, SP_FLAGS(%rax)
    jnz     1f
    test    %rcx, %rcx
    jz      2f
    cmp     $SPACE_APP, %rbp
    jne     1f
    mov     ST_NOW(%r15), %rdx
    cmp     SP_ACK_AT(%rax), %rdx
    jae     1f
    call    quic_app_pending                /* not due: only with other frames */
    test    %rax, %rax
    jz      2f
1:  mov     %r12, %rdi
    mov     %r13, %rsi
    call    quic_ack_frame
    test    %rax, %rax
    jz      2f
    mov     %rax, %r12
    mov     SC_SPREC(%r14), %rax
    movq    $0, SP_ACK_COUNT(%rax)
    movq    $NONE, SP_ACK_AT(%rax)
    andq    $~SPF_ACK_NOW, SP_FLAGS(%rax)
2:  cmpq    $CS_CLOSING, C_STATE(%rbx)      /* CONNECTION_CLOSE */
    jne     3f
    testq   $CF_CLOSE_FRAME, C_FLAGS(%rbx)
    jz      90f
    mov     %r13, %rax
    sub     %r12, %rax
    cmp     $24, %rax
    jb      90f
    testq   $CF_APP_CLOSE, C_FLAGS(%rbx)
    jz      21f
    cmp     $SPACE_APP, %rbp
    jne     22f
    movb    $0x1D, (%r12)                   /* the application's close */
    lea     1(%r12), %rdi
    mov     C_ERROR(%rbx), %rsi
    call    quic_vput
    movb    $0, (%rax)
    lea     1(%rax), %r12
    jmp     23f
22: movb    $0x1C, (%r12)                   /* in Initial and Handshake: APPLICATION_ERROR */
    movb    $0x0C, 1(%r12)
    movb    $0, 2(%r12)
    movb    $0, 3(%r12)
    add     $4, %r12
    jmp     23f
21: movb    $0x1C, (%r12)
    lea     1(%r12), %rdi
    mov     C_ERROR(%rbx), %rsi
    call    quic_vput
    movb    $0, (%rax)
    movb    $0, 1(%rax)
    lea     2(%rax), %r12
23: cmp     $SPACE_APP, %rbp                /* every space with keys gets one; the flag goes with the last */
    je      24f
    mov     %rbx, %rdi
    mov     $SPACE_APP, %esi
    call    quic_space
    testq   $SPF_TX, SP_FLAGS(%rax)
    jnz     90f
    cmp     $SPACE_HANDSHAKE, %rbp
    je      24f
    mov     %rbx, %rdi
    mov     $SPACE_HANDSHAKE, %esi
    call    quic_space
    mov     SP_FLAGS(%rax), %rcx
    test    $SPF_TX, %cl
    jz      24f
    test    $SPF_DISCARDED, %cl
    jz      90f
24: andq    $~CF_CLOSE_FRAME, C_FLAGS(%rbx)
    jmp     90f
3:  /* CRYPTO */
    mov     SC_SPREC(%r14), %rax
    mov     SP_CTX_SENT(%rax), %rcx
    cmp     SP_CTX_LEN(%rax), %rcx
    jae     4f
    mov     $1, %edi
    call    quic_may_elicit
    test    %rax, %rax
    jz      4f
    mov     %r13, %rdx
    sub     %r12, %rdx
    cmp     $(1 + 8 + 2), %rdx              /* type, offset, 2-byte length */
    jbe     4f
    sub     $(1 + 8 + 2), %rdx
    mov     SC_SPREC(%r14), %rax
    mov     SP_CTX_SENT(%rax), %rcx
    mov     SP_CTX_LEN(%rax), %r8
    sub     %rcx, %r8
    cmp     %rdx, %r8
    jbe     31f                             /* the bytes that fit */
    mov     %rdx, %r8
31: movb    $0x06, (%r12)
    inc     %r12
    mov     %rcx, SC_FRAME(%r14)
    mov     %r8, (SC_FRAME + 8)(%r14)
    mov     %r12, %rdi
    mov     %rcx, %rsi
    call    quic_vput
    mov     %rax, %rdi
    mov     (SC_FRAME + 8)(%r14), %rsi
    call    quic_vput2
    mov     %rax, %rdi
    mov     SC_SPREC(%r14), %rcx
    mov     SP_CTX(%rcx), %rsi
    add     %r15, %rsi
    add     SC_FRAME(%r14), %rsi
    mov     (SC_FRAME + 8)(%r14), %rdx
    call    quic_copy
    mov     %rax, %r12
    mov     SC_FRAME(%r14), %rcx
    mov     (SC_FRAME + 8)(%r14), %rdx
    mov     SC_SPREC(%r14), %rax
    lea     (%rcx,%rdx), %r8
    mov     %r8, SP_CTX_SENT(%rax)
    shl     $48, %rdx
    or      %rcx, %rdx
    mov     %rdx, %r8
    mov     $FR_CRYPTO, %edi
    xor     %esi, %esi
    xor     %edx, %edx
    xor     %ecx, %ecx
    call    quic_add_ref
    call    quic_elicit
4:  cmp     $SPACE_APP, %rbp
    jne     80f
    cmpq    $CS_ACTIVE, C_STATE(%rbx)
    jne     80f
    call    quic_app_frames
    mov     %rax, %r12
80: /* PING: a probe, or a keep-alive, with no other ack-eliciting frame */
    mov     SC_PACKET(%r14), %rax
    testq   $SRF_ELICIT, PK_FLAGS(%rax)
    jnz     85f
    mov     SC_SPREC(%r14), %rax
    testq   $SPF_PROBE, SP_FLAGS(%rax)
    jnz     81f
    cmp     $SPACE_APP, %rbp
    jne     90f
    testq   $CF_PING, C_FLAGS(%rbx)
    jz      90f
81: cmp     %r13, %r12
    jae     90f
    xor     %edi, %edi
    call    quic_may_elicit
    test    %rax, %rax
    jz      90f
    movb    $0x01, (%r12)
    inc     %r12
    call    quic_elicit
    andq    $~CF_PING, C_FLAGS(%rbx)
85: mov     SC_SPREC(%r14), %rax            /* the probe went */
    andq    $~SPF_PROBE, SP_FLAGS(%rax)
90: mov     %r12, %rax
    LEAVE   0
END_FUNCTION quic_frames_out

/*
 * quic_ack_frame(p, end) -> the position after an ACK frame of the received
 * ranges of the space, as many as fit, or 0 when none fits. The delay is
 * in units of 8 microseconds (ack_delay_exponent 3) in the Application space.
 * rbp space, r12 p, r13 end, X23 the ranges, X24 index, X25 count kept, X26 the position.
 */
LOCAL_FUNCTION quic_ack_frame
    ENTER   0
    mov     %rdi, %r12
    mov     %rsi, %r13
    mov     %r13, %rax
    sub     %r12, %rax
    cmp     $40, %rax
    jb      8f
    mov     SC_SPREC(%r14), %rcx
    lea     SP_RANGES(%rcx), %rdx
    mov     %rdx, X23(%rsp)
    mov     SP_NRANGES(%rcx), %r8
    sub     $32, %rax                       /* ranges that fit: 16 bytes each at most */
    shr     $4, %rax
    inc     %rax
    cmp     %r8, %rax
    jae     11f
    mov     %rax, %r8
11: mov     %r8, X25(%rsp)
    movb    $0x02, (%r12)
    lea     1(%r12), %rdi
    mov     8(%rdx), %rsi                   /* the largest */
    call    quic_vput
    xor     %esi, %esi
    cmp     $SPACE_APP, %rbp
    jne     1f
    mov     SC_SPREC(%r14), %rcx
    mov     ST_NOW(%r15), %rsi
    sub     SP_RECV_TIME(%rcx), %rsi
    jae     12f
    xor     %esi, %esi
12: shr     $3, %rsi
    cmp     $0x3FFFFFFF, %rsi
    jbe     1f
    mov     $0x3FFFFFFF, %esi
1:  mov     %rax, %rdi
    call    quic_vput
    mov     %rax, %rdi
    mov     X25(%rsp), %rsi
    dec     %rsi
    call    quic_vput
    mov     X23(%rsp), %rcx
    mov     8(%rcx), %rsi
    sub     (%rcx), %rsi                    /* the first range */
    mov     %rax, %rdi
    call    quic_vput
    movq    $1, X24(%rsp)
2:  mov     X24(%rsp), %rcx
    cmp     X25(%rsp), %rcx
    jae     9f
    mov     %rax, X26(%rsp)
    shl     $4, %rcx
    add     X23(%rsp), %rcx
    mov     -16(%rcx), %rsi                 /* the smallest of the one before */
    sub     8(%rcx), %rsi
    sub     $2, %rsi                        /* gap */
    mov     X26(%rsp), %rdi
    call    quic_vput
    mov     X24(%rsp), %rcx
    shl     $4, %rcx
    add     X23(%rsp), %rcx
    mov     8(%rcx), %rsi
    sub     (%rcx), %rsi
    mov     %rax, %rdi
    call    quic_vput
    incq    X24(%rsp)
    jmp     2b
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_ack_frame

/*
 * quic_app_pending() -> 1 when the Application space has frames to send other
 * than ACK, so an ACK not yet due may go with them. rbp the stream index.
 */
LOCAL_FUNCTION quic_app_pending
    ENTER   0
    testq   $(CF_DONE_FRAME | CF_MAX_DATA | CF_MAX_STREAMS | CF_PING | CF_CHALLENGE), C_FLAGS(%rbx)
    jnz     7f
    cmpq    $-1, C_RETIRE_SEQ(%rbx)
    jne     7f
    mov     C_STREAM_HEAD(%rbx), %rbp
1:  cmp     $-1, %rbp
    je      8f
    mov     %rbp, %rdi
    call    quic_stream_at
    mov     S_NEXT(%rax), %rbp
    cmpq    $-1, S_ID(%rax)
    je      1b
    mov     S_FLAGS(%rax), %rcx
    test    $(SF_RESET_SEND | SF_STOP_SEND | SF_MSD | SF_FIN_LOST), %rcx
    jnz     7f
    testb   $0xFF, S_NLOST(%rax)
    jnz     7f
    mov     S_SENT(%rax), %rdx
    cmp     S_WRITTEN(%rax), %rdx
    jb      7f
    test    $SF_FIN_WANT, %cl
    jz      1b
    test    $SF_FIN_SENT, %cl
    jz      7f
    jmp     1b
7:  mov     $1, %eax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_app_pending

/*
 * quic_app_frames() -> the position after the frames of the Application
 * space that are not ACK, CRYPTO or PING. r12 position, r13 end.
 * X23 the sequence to retire, then the next stream.
 */
LOCAL_FUNCTION quic_app_frames
    ENTER   0
    /* HANDSHAKE_DONE */
    testq   $CF_DONE_FRAME, C_FLAGS(%rbx)
    jz      1f
    cmp     %r13, %r12
    jae     1f
    mov     $1, %edi
    call    quic_may_elicit
    test    %rax, %rax
    jz      1f
    movb    $0x1E, (%r12)
    inc     %r12
    andq    $~CF_DONE_FRAME, C_FLAGS(%rbx)
    mov     $FR_DONE, %edi
    xor     %esi, %esi
    xor     %edx, %edx
    xor     %ecx, %ecx
    xor     %r8d, %r8d
    call    quic_add_ref
    call    quic_elicit
1:  /* PATH_RESPONSE */
    testq   $CF_CHALLENGE, C_FLAGS(%rbx)
    jz      2f
    mov     %r13, %rax
    sub     %r12, %rax
    cmp     $9, %rax
    jb      2f
    xor     %edi, %edi
    call    quic_may_elicit
    test    %rax, %rax
    jz      2f
    movb    $0x1B, (%r12)
    mov     C_CHALLENGE(%rbx), %rax
    mov     %rax, 1(%r12)
    add     $9, %r12
    andq    $~CF_CHALLENGE, C_FLAGS(%rbx)
    call    quic_elicit
2:  /* RETIRE_CONNECTION_ID */
    mov     C_RETIRE_SEQ(%rbx), %rax
    mov     %rax, X23(%rsp)
    cmp     $-1, %rax
    je      3f
    mov     %r13, %rax
    sub     %r12, %rax
    cmp     $9, %rax
    jb      3f
    mov     $1, %edi
    call    quic_may_elicit
    test    %rax, %rax
    jz      3f
    movb    $0x19, (%r12)
    lea     1(%r12), %rdi
    mov     X23(%rsp), %rsi
    call    quic_vput
    mov     %rax, %r12
    movq    $NONE, C_RETIRE_SEQ(%rbx)
    mov     $FR_RETIRE, %edi
    xor     %esi, %esi
    xor     %edx, %edx
    mov     X23(%rsp), %rcx
    xor     %r8d, %r8d
    call    quic_add_ref
    call    quic_elicit
3:  /* MAX_DATA */
    testq   $CF_MAX_DATA, C_FLAGS(%rbx)
    jz      4f
    mov     %r13, %rax
    sub     %r12, %rax
    cmp     $9, %rax
    jb      4f
    mov     $1, %edi
    call    quic_may_elicit
    test    %rax, %rax
    jz      4f
    movb    $0x10, (%r12)
    lea     1(%r12), %rdi
    mov     C_RX_MAX(%rbx), %rsi
    call    quic_vput
    mov     %rax, %r12
    andq    $~CF_MAX_DATA, C_FLAGS(%rbx)
    mov     $FR_MAX_DATA, %edi
    xor     %esi, %esi
    xor     %edx, %edx
    xor     %ecx, %ecx
    xor     %r8d, %r8d
    call    quic_add_ref
    call    quic_elicit
4:  /* MAX_STREAMS */
    testq   $CF_MAX_STREAMS, C_FLAGS(%rbx)
    jz      5f
    mov     %r13, %rax
    sub     %r12, %rax
    cmp     $9, %rax
    jb      5f
    mov     $1, %edi
    call    quic_may_elicit
    test    %rax, %rax
    jz      5f
    movb    $0x12, (%r12)
    lea     1(%r12), %rdi
    mov     C_PEER_MAX(%rbx), %rsi
    call    quic_vput
    mov     %rax, %r12
    andq    $~CF_MAX_STREAMS, C_FLAGS(%rbx)
    mov     $FR_MAX_STREAMS, %edi
    xor     %esi, %esi
    xor     %edx, %edx
    xor     %ecx, %ecx
    xor     %r8d, %r8d
    call    quic_add_ref
    call    quic_elicit
5:  /* The streams, in list order. */
    mov     C_STREAM_HEAD(%rbx), %rax
    mov     %rax, X23(%rsp)
6:  mov     X23(%rsp), %rdi
    cmp     $-1, %rdi
    je      9f
    call    quic_stream_at
    mov     S_NEXT(%rax), %rcx
    mov     %rcx, X23(%rsp)
    cmpq    $-1, S_ID(%rax)
    je      6b
    mov     %rax, %rdi
    call    quic_stream_out
    mov     %rax, %r12
    jmp     6b
9:  mov     %r12, %rax
    LEAVE   0
END_FUNCTION quic_app_frames

/*
 * quic_stream_out(stream) -> the position after the frames of one stream that
 * fit: RESET_STREAM, STOP_SENDING, MAX_STREAM_DATA, then STREAM frames: lost
 * ranges first, then new bytes within the flow control limits, with the FIN
 * when the last byte goes. r12 position, r13 end.
 * rbp the stream; SC_SLOT its slot.
 */
LOCAL_FUNCTION quic_stream_out
    ENTER   0
    mov     %rdi, %rbp
    call    quic_stream_index
    mov     %rax, SC_SLOT(%r14)
    /* RESET_STREAM: id, our code, the final size (the bytes written) */
    testq   $SF_RESET_SEND, S_FLAGS(%rbp)
    jz      1f
    mov     %r13, %rax
    sub     %r12, %rax
    cmp     $25, %rax
    jb      1f
    mov     $1, %edi
    call    quic_may_elicit
    test    %rax, %rax
    jz      1f
    movb    $0x04, (%r12)
    lea     1(%r12), %rdi
    mov     S_ID(%rbp), %rsi
    call    quic_vput
    mov     %rax, %rdi
    mov     S_APP_CODE(%rbp), %rsi
    call    quic_vput
    mov     %rax, %rdi
    mov     S_SENT(%rbp), %rsi              /* the final size: the bytes sent */
    call    quic_vput
    mov     %rax, %r12
    andq    $~SF_RESET_SEND, S_FLAGS(%rbp)
    mov     $FR_RESET, %edi
    call    quic_stream_ref
    call    quic_elicit
1:  testq   $SF_STOP_SEND, S_FLAGS(%rbp)    /* STOP_SENDING */
    jz      2f
    mov     %r13, %rax
    sub     %r12, %rax
    cmp     $17, %rax
    jb      2f
    mov     $1, %edi
    call    quic_may_elicit
    test    %rax, %rax
    jz      2f
    movb    $0x05, (%r12)
    lea     1(%r12), %rdi
    mov     S_ID(%rbp), %rsi
    call    quic_vput
    mov     %rax, %rdi
    mov     S_APP_CODE(%rbp), %rsi
    call    quic_vput
    mov     %rax, %r12
    andq    $~SF_STOP_SEND, S_FLAGS(%rbp)
    mov     $FR_STOP, %edi
    call    quic_stream_ref
    call    quic_elicit
2:  mov     S_FLAGS(%rbp), %rax             /* MAX_STREAM_DATA */
    test    $SF_MSD, %rax
    jz      3f
    test    $SF_RX_DONE, %rax
    jnz     21f
    mov     %r13, %rax
    sub     %r12, %rax
    cmp     $17, %rax
    jb      3f
    mov     $1, %edi
    call    quic_may_elicit
    test    %rax, %rax
    jz      3f
    movb    $0x11, (%r12)
    lea     1(%r12), %rdi
    mov     S_ID(%rbp), %rsi
    call    quic_vput
    mov     %rax, %rdi
    mov     S_RX_MAX(%rbp), %rsi
    call    quic_vput
    mov     %rax, %r12
    mov     $FR_MAX_STREAM_DATA, %edi
    call    quic_stream_ref
    call    quic_elicit
21: andq    $~SF_MSD, S_FLAGS(%rbp)
3:  testq   $SF_RESET, S_FLAGS(%rbp)        /* no data after our reset */
    jnz     9f
4:  testb   $0xFF, S_NLOST(%rbp)            /* lost ranges */
    jz      5f
    mov     S_LOST(%rbp), %rdi
    mov     (S_LOST + 8)(%rbp), %rdx
    sub     %rdi, %rdx
    xor     %esi, %esi
    call    quic_stream_frame
    cmp     $-1, %rax
    je      9f
    mov     %rdx, %r12
    test    %rax, %rax
    jz      9f
    add     S_LOST(%rbp), %rax
    mov     %rax, S_LOST(%rbp)
    cmp     (S_LOST + 8)(%rbp), %rax
    jb      4b
    mov     %rbp, %rdi
    lea     S_NLOST(%rbp), %rsi
    xor     %edx, %edx
    call    quic_ranges_remove
    jmp     4b
5:  testq   $SF_FIN_LOST, S_FLAGS(%rbp)     /* a FIN to send again */
    jz      6f
    mov     S_SENT(%rbp), %rax
    cmp     S_WRITTEN(%rbp), %rax
    jb      6f
    mov     S_WRITTEN(%rbp), %rdi
    mov     $1, %esi
    xor     %edx, %edx
    call    quic_stream_frame
    cmp     $-1, %rax
    je      9f
    mov     %rdx, %r12
    andq    $~SF_FIN_LOST, S_FLAGS(%rbp)
6:  mov     S_SENT(%rbp), %r8               /* new bytes */
    mov     S_WRITTEN(%rbp), %r9
    mov     %r9, %rdx
    sub     %r8, %rdx
    mov     S_TX_MAX(%rbp), %rax
    sub     %r8, %rax
    jae     63f
    xor     %eax, %eax
63: cmp     %rdx, %rax
    jae     64f
    mov     %rax, %rdx
64: mov     C_TX_MAX(%rbx), %rax
    sub     C_TX_SENT(%rbx), %rax
    jae     65f
    xor     %eax, %eax
65: cmp     %rdx, %rax
    jae     66f
    mov     %rax, %rdx
66: xor     %esi, %esi
    mov     S_FLAGS(%rbp), %rax
    test    $SF_FIN_WANT, %al
    jz      61f
    test    $SF_FIN_SENT, %al
    jnz     61f
    lea     (%r8,%rdx), %rcx
    cmp     %r9, %rcx
    sete    %sil                            /* the FIN goes with the last byte */
61: test    %rsi, %rsi
    jnz     62f
    test    %rdx, %rdx
    jz      9f
62: mov     %r8, %rdi
    mov     %rsi, (SC_FRAME + 64)(%r14)
    mov     %rdx, (SC_FRAME + 72)(%r14)
    call    quic_stream_frame
    cmp     $-1, %rax
    je      9f
    mov     %rdx, %r12
    add     %rax, S_SENT(%rbp)
    add     %rax, C_TX_SENT(%rbx)
    cmp     (SC_FRAME + 72)(%r14), %rax
    jb      9f                              /* not all fit: no FIN yet */
    cmpq    $0, (SC_FRAME + 64)(%r14)
    je      9f
    orq     $SF_FIN_SENT, S_FLAGS(%rbp)
9:  mov     %r12, %rax                      /* the position after */
    LEAVE   0
END_FUNCTION quic_stream_out

/* quic_stream_ref(kind): a frame ref of the stream at rbp (slot at SC_SLOT). */
LOCAL_FUNCTION quic_stream_ref
    ENTER   0
    movl    S_GEN(%rbp), %edx
    xor     %esi, %esi
    mov     SC_SLOT(%r14), %rcx
    xor     %r8d, %r8d
    call    quic_add_ref
    LEAVE   0
END_FUNCTION quic_stream_ref

/*
 * quic_stream_frame(offset, fin, n) -> rax the bytes of the stream from offset
 * put in one STREAM frame with the FIN when fin and all n fit, or -1 when no
 * frame fits (0 bytes with a FIN is a frame); rdx the position after.
 * rbp the stream, r12 the position, r13 end; SC_SLOT the slot.
 * X24 the frame overhead, X26 the bytes that fit.
 */
LOCAL_FUNCTION quic_stream_frame
    ENTER   0, 32
    mov     %rdi, (32 + 0)(%rsp)
    mov     %rsi, (32 + 8)(%rsp)
    mov     %rdx, (32 + 16)(%rsp)
    mov     $1, %edi
    call    quic_may_elicit
    test    %rax, %rax
    jz      8f
    mov     S_ID(%rbp), %rdi
    call    quic_vlen
    mov     %rax, X24(%rsp)
    mov     (32 + 0)(%rsp), %rdi
    call    quic_vlen
    add     X24(%rsp), %rax
    add     $3, %rax                        /* type and a 2-byte length */
    mov     %rax, X24(%rsp)
    mov     %r13, %rcx
    sub     %r12, %rcx
    cmp     %rcx, %rax
    jae     8f
    sub     %rax, %rcx                      /* bytes that fit */
    mov     (32 + 16)(%rsp), %rdx
    mov     %rdx, X26(%rsp)
    cmp     %rdx, %rcx
    jae     11f
    mov     %rcx, X26(%rsp)
11: mov     (32 + 8)(%rsp), %rsi
    cmp     %rdx, X26(%rsp)
    je      12f                             /* the FIN only when all fit */
    xor     %esi, %esi
12: mov     %rsi, (32 + 8)(%rsp)
    cmpq    $0, X26(%rsp)
    jne     1f
    test    %rsi, %rsi
    jz      8f
1:  mov     %esi, %eax                      /* OFF and LEN */
    or      $0x0E, %eax
    movb    %al, (%r12)
    lea     1(%r12), %rdi
    mov     S_ID(%rbp), %rsi
    call    quic_vput
    mov     %rax, %rdi
    mov     (32 + 0)(%rsp), %rsi
    call    quic_vput
    mov     %rax, %rdi
    mov     X26(%rsp), %rsi
    call    quic_vput2
    mov     %rax, %r12
    mov     %rax, %rdi
    mov     (32 + 0)(%rsp), %rsi
    mov     X26(%rsp), %rdx
    call    quic_stream_read
    add     X26(%rsp), %r12
    mov     X26(%rsp), %r8
    shl     $48, %r8
    or      (32 + 0)(%rsp), %r8
    mov     $FR_STREAM, %edi
    mov     (32 + 8)(%rsp), %rsi
    movl    S_GEN(%rbp), %edx
    mov     SC_SLOT(%r14), %rcx
    call    quic_add_ref
    call    quic_elicit
    mov     X26(%rsp), %rax
    jmp     9f
8:  mov     $-1, %rax
9:  mov     %r12, %rdx                      /* the position after */
    LEAVE   0, 32
END_FUNCTION quic_stream_frame

/*
 * quic_stream_read(dst, offset, n): copies n queued bytes of the stream from
 * offset to dst, across chunks. rbp the stream.
 * r12 dst, r13 offset, X23 n, X24 the chunk, X25 its start, X26 the bytes.
 */
LOCAL_FUNCTION quic_stream_read
    ENTER   0
    mov     %rdi, %r12
    mov     %rsi, %r13
    mov     %rdx, X23(%rsp)
    mov     S_Q_HEAD(%rbp), %rax
    mov     %rax, X24(%rsp)
    mov     S_Q_BASE(%rbp), %rax
    mov     %rax, X25(%rsp)
1:  cmpq    $0, X23(%rsp)
    je      9f
    mov     X24(%rsp), %rax
    test    %rax, %rax
    jz      9f
    lea     (%r15,%rax), %rax
    mov     Q_LEN(%rax), %rcx
    mov     X25(%rsp), %rdx
    add     %rcx, %rdx                      /* the chunk end */
    cmp     %rdx, %r13
    jb      2f
    mov     %rdx, X25(%rsp)
    mov     Q_NEXT(%rax), %rdx
    mov     %rdx, X24(%rsp)
    jmp     1b
2:  mov     %r13, %rsi                      /* the place in the chunk */
    sub     X25(%rsp), %rsi
    sub     %rsi, %rcx
    cmp     X23(%rsp), %rcx
    jbe     21f
    mov     X23(%rsp), %rcx
21: mov     %rcx, X26(%rsp)
    lea     Q_DATA(%rax,%rsi), %rsi
    mov     %r12, %rdi
    mov     %rcx, %rdx
    call    quic_copy
    mov     X26(%rsp), %rcx
    add     %rcx, %r12
    add     %rcx, %r13
    sub     %rcx, X23(%rsp)
    jmp     1b
9:  LEAVE   0
END_FUNCTION quic_stream_read
