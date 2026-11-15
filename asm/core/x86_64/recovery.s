/*
 * Loss detection and congestion control of RFC 9002: the ring of sent
 * packets, acknowledgements and RTT samples, the packet and time thresholds,
 * the probe timeout, and NewReno. Also the packet numbers received, for ACK
 * frames. rbx the connection in every function here.
 */

.set K_PACKET_THRESHOLD, 3
.set K_GRANULARITY, 1000                /* 1 ms */

/* ---------------------------------------------------------------- Packet numbers received */

/*
 * quic_recv_pn(space, pn) -> 1 when pn was received before, else 0 after it
 * is added to the ranges of the space (largest first, at most SP_MAX_RANGES;
 * the smallest range goes when they are full). r12 the space, r13 pn,
 * X23 the ranges, X24 their count, X25 the index.
 */
LOCAL_FUNCTION quic_recv_pn
    ENTER   0
    mov     %rdi, %r12
    mov     %rsi, %r13
    lea     SP_RANGES(%r12), %rax
    mov     %rax, X23(%rsp)
    mov     SP_NRANGES(%r12), %rax
    mov     %rax, X24(%rsp)
    movq    $0, X25(%rsp)                   /* index */
1:  mov     X25(%rsp), %rcx
    cmp     X24(%rsp), %rcx
    jae     6f                              /* below every range: a new last range */
    mov     %rcx, %r8
    shl     $4, %r8
    add     X23(%rsp), %r8
    mov     (%r8), %r9                      /* smallest */
    mov     8(%r8), %r10                    /* largest */
    cmp     %r13, %r10
    jb      2f
    cmp     %r9, %r13
    jae     90f                             /* inside: a duplicate */
    lea     -1(%r9), %r11
    cmp     %r11, %r13
    jne     3f
    mov     %r13, (%r8)                     /* just below: the range grows down */
    lea     1(%rcx), %rdx                   /* joins the next range */
    cmp     X24(%rsp), %rdx
    jae     80f
    mov     16(%r8), %r9
    mov     24(%r8), %r10
    inc     %r10
    cmp     %r13, %r10
    jne     80f
    mov     %r9, (%r8)
    mov     %r12, %rdi
    mov     %rdx, %rsi
    call    quic_range_remove
    jmp     80f
3:  incq    X25(%rsp)
    jmp     1b
2:  lea     1(%r10), %r11                   /* above this range */
    cmp     %r11, %r13
    jne     5f
    mov     %r13, 8(%r8)                    /* just above: grows up; it cannot touch the range before */
    jmp     80f
5:  mov     %r12, %rdi                      /* a new range before the index */
    mov     X25(%rsp), %rsi
    mov     %r13, %rdx
    call    quic_range_insert
    jmp     80f
6:  mov     %r12, %rdi
    mov     X24(%rsp), %rsi
    mov     %r13, %rdx
    call    quic_range_insert
80: xor     %eax, %eax
    jmp     9f
90: mov     $1, %eax
9:  LEAVE   0
END_FUNCTION quic_recv_pn

/*
 * quic_range_insert(space, index, pn): a range [pn, pn] at index; the last range goes when full.
 * rbx space, rbp index, r12 pn, r13 count.
 */
LOCAL_FUNCTION quic_range_insert
    ENTER   0
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     SP_NRANGES(%rbx), %r13
    cmp     $SP_MAX_RANGES, %rbp
    jae     9f
    cmp     $SP_MAX_RANGES, %r13
    jb      1f
    mov     $(SP_MAX_RANGES - 1), %r13d
1:  lea     SP_RANGES(%rbx), %r8            /* shift [index, n) up by one, from the end */
    mov     %r13, %rcx
2:  cmp     %rcx, %rbp
    jae     3f
    lea     -1(%rcx), %rax
    shl     $4, %rax
    add     %r8, %rax
    mov     (%rax), %r9
    mov     8(%rax), %r10
    mov     %r9, 16(%rax)
    mov     %r10, 24(%rax)
    dec     %rcx
    jmp     2b
3:  mov     %rbp, %rax
    shl     $4, %rax
    add     %r8, %rax
    mov     %r12, (%rax)
    mov     %r12, 8(%rax)
    inc     %r13
    mov     %r13, SP_NRANGES(%rbx)
9:  LEAVE   0
END_FUNCTION quic_range_insert

/* quic_range_remove(space, index): the range at index goes. A leaf. */
LOCAL_FUNCTION quic_range_remove
    UNWIND_END_PROLOGUE
    mov     SP_NRANGES(%rdi), %rdx
    lea     SP_RANGES(%rdi), %rcx
1:  lea     1(%rsi), %r8
    cmp     %rdx, %r8
    jae     2f
    mov     %r8, %r9
    shl     $4, %r9
    add     %rcx, %r9
    mov     (%r9), %rax
    mov     %rax, -16(%r9)
    mov     8(%r9), %rax
    mov     %rax, -8(%r9)
    mov     %r8, %rsi
    jmp     1b
2:  dec     %rdx
    mov     %rdx, SP_NRANGES(%rdi)
    ret
END_FUNCTION quic_range_remove

/* ---------------------------------------------------------------- The ring of sent packets */

/* quic_ring_free() -> 1 when the ring has room for a record. A leaf. */
LOCAL_FUNCTION quic_ring_free
    UNWIND_END_PROLOGUE
    mov     C_SENT_COUNT(%rbx), %rax
    cmp     C_SENT_CAP(%rbx), %rax
    setb    %al
    movzbl  %al, %eax
    ret
END_FUNCTION quic_ring_free

/* quic_record_at(i) -> the record i places after the oldest. A leaf. */
LOCAL_FUNCTION quic_record_at
    UNWIND_END_PROLOGUE
    mov     C_SENT_HEAD(%rbx), %rax
    add     %rdi, %rax
    xor     %edx, %edx
    divq    C_SENT_CAP(%rbx)
    mov     C_SENT(%rbx), %rax
    add     %r15, %rax
    shl     $7, %rdx
    add     %rdx, %rax
    ret
END_FUNCTION quic_record_at

/*
 * quic_record_sent(space, pn, size, flags, frames, n): a new live record of a
 * packet sent now, with n frame refs; bytes in flight, the ack-eliciting count
 * and the loss timer follow. The caller checked quic_ring_free.
 * rbp space, r12 pn, r13 size, X23 flags, X24 frames, X25 n, X26 the record.
 */
LOCAL_FUNCTION quic_record_sent
    ENTER   0
    mov     %rdi, %rbp
    mov     %rsi, %r12
    mov     %rdx, %r13
    mov     %rcx, X23(%rsp)
    mov     %r8, X24(%rsp)
    mov     %r9, X25(%rsp)
    mov     C_SENT_COUNT(%rbx), %rdi
    call    quic_record_at
    mov     %rax, X26(%rsp)
    incq    C_SENT_COUNT(%rbx)
    mov     %r12, SR_PN(%rax)
    mov     ST_NOW(%r15), %rcx
    mov     %rcx, SR_TIME(%rax)
    mov     X23(%rsp), %rcx
    or      $SRF_LIVE, %rcx
    movzwl  %r13w, %edx
    mov     %rbp, %r8
    shl     $16, %r8
    or      %r8, %rdx
    shl     $24, %rcx
    or      %rcx, %rdx
    mov     X25(%rsp), %r8
    shl     $32, %r8
    or      %r8, %rdx
    mov     %rdx, SR_INFO(%rax)
    lea     SR_FRAMES(%rax), %rdi
    mov     X24(%rsp), %rsi
    mov     X25(%rsp), %rdx
    shl     $4, %rdx
    call    quic_copy
    testq   $SRF_FLIGHT, X23(%rsp)
    jz      1f
    add     %r13, C_IN_FLIGHT(%rbx)
1:  testq   $SRF_ELICIT, X23(%rsp)
    jz      2f
    mov     %rbx, %rdi
    mov     %rbp, %rsi
    call    quic_space
    incq    SP_ELICIT(%rax)
    mov     ST_NOW(%r15), %rcx
    mov     %rcx, SP_LAST_ELICIT(%rax)
    mov     %rax, %rdi
    call    quic_set_loss_timer
2:  LEAVE   0
END_FUNCTION quic_record_sent

/*
 * quic_record_gone(record, acked): a live record leaves: bytes in flight, the
 * ack-eliciting count and its frame refs follow (quic_ref_acked or
 * quic_ref_lost). rbp record, r12 acked, r13 its info, X23 flags, X24 refs
 * left, X25 the ref.
 */
LOCAL_FUNCTION quic_record_gone
    ENTER   0
    mov     %rdi, %rbp
    mov     %rsi, %r12
    mov     SR_INFO(%rbp), %r13
    mov     %r13, %rax
    and     $~(SRF_LIVE << 24), %rax
    mov     %rax, SR_INFO(%rbp)
    mov     %r13, %rax
    shr     $24, %rax
    and     $0xFF, %eax                     /* flags */
    mov     %rax, X23(%rsp)
    test    $SRF_FLIGHT, %al
    jz      1f
    movzwl  %r13w, %eax
    mov     C_IN_FLIGHT(%rbx), %rcx
    sub     %rax, %rcx
    jae     11f
    xor     %ecx, %ecx
11: mov     %rcx, C_IN_FLIGHT(%rbx)
1:  testq   $SRF_ELICIT, X23(%rsp)
    jz      2f
    mov     %rbx, %rdi
    mov     %r13, %rsi
    shr     $16, %rsi
    and     $0xFF, %esi
    call    quic_space
    mov     SP_ELICIT(%rax), %rcx
    test    %rcx, %rcx
    jz      12f
    dec     %rcx
12: mov     %rcx, SP_ELICIT(%rax)
2:  mov     %r13, %rax                      /* the frame refs */
    shr     $32, %rax
    and     $0xFF, %eax
    mov     %rax, X24(%rsp)
    lea     SR_FRAMES(%rbp), %rax
    mov     %rax, X25(%rsp)
3:  cmpq    $0, X24(%rsp)
    je      9f
    mov     X25(%rsp), %rdi
    mov     %r13, %rsi
    shr     $16, %rsi
    and     $0xFF, %esi
    test    %r12, %r12
    jz      4f
    call    quic_ref_acked
    jmp     5f
4:  call    quic_ref_lost
5:  addq    $16, X25(%rsp)
    decq    X24(%rsp)
    jmp     3b
9:  LEAVE   0
END_FUNCTION quic_record_gone

/* quic_ring_tidy(): the oldest records that are no longer live leave the ring. rbp the count. */
LOCAL_FUNCTION quic_ring_tidy
    ENTER   0
1:  mov     C_SENT_COUNT(%rbx), %rbp
    test    %rbp, %rbp
    jz      9f
    xor     %edi, %edi
    call    quic_record_at
    testq   $(SRF_LIVE << 24), SR_INFO(%rax)
    jnz     9f
    dec     %rbp
    mov     %rbp, C_SENT_COUNT(%rbx)
    mov     C_SENT_HEAD(%rbx), %rax
    inc     %rax
    cmp     C_SENT_CAP(%rbx), %rax
    jb      2f
    xor     %eax, %eax
2:  mov     %rax, C_SENT_HEAD(%rbx)
    jmp     1b
9:  LEAVE   0
END_FUNCTION quic_ring_tidy

/*
 * quic_drop_space_records(space): every live record of the space leaves
 * without being acknowledged or lost (its keys are gone).
 * rbp space, r12 index, r13 the info.
 */
LOCAL_FUNCTION quic_drop_space_records
    ENTER   0
    mov     %rdi, %rbp
    xor     %r12d, %r12d
1:  cmp     C_SENT_COUNT(%rbx), %r12
    jae     8f
    mov     %r12, %rdi
    call    quic_record_at
    inc     %r12
    mov     SR_INFO(%rax), %r13
    test    $(SRF_LIVE << 24), %r13
    jz      1b
    mov     %r13, %rcx
    shr     $16, %rcx
    and     $0xFF, %ecx
    cmp     %rbp, %rcx
    jne     1b
    mov     %r13, %rcx
    and     $~(SRF_LIVE << 24), %rcx
    mov     %rcx, SR_INFO(%rax)
    mov     %r13, %rcx
    shr     $24, %rcx
    test    $SRF_FLIGHT, %cl
    jz      1b
    movzwl  %r13w, %ecx
    mov     C_IN_FLIGHT(%rbx), %rdx
    sub     %rcx, %rdx
    jae     2f
    xor     %edx, %edx
2:  mov     %rdx, C_IN_FLIGHT(%rbx)
    jmp     1b
8:  mov     %rbx, %rdi
    mov     %rbp, %rsi
    call    quic_space
    movq    $0, SP_ELICIT(%rax)
    call    quic_ring_tidy
    LEAVE   0
END_FUNCTION quic_drop_space_records

/* ---------------------------------------------------------------- Frame refs */

/* quic_ref_acked(ref, space): a frame of an acknowledged packet. rbp the ref. */
LOCAL_FUNCTION quic_ref_acked
    ENTER   0
    mov     %rdi, %rbp
    movzbl  (%rbp), %eax
    cmp     $FR_STREAM, %eax
    je      1f
    cmp     $FR_RESET, %eax
    je      2f
    jmp     9f
1:  call    quic_ref_stream
    test    %rax, %rax
    jz      9f
    mov     %rax, %rdi
    mov     8(%rbp), %rsi
    shl     $16, %rsi
    shr     $16, %rsi
    movzwl  14(%rbp), %edx
    movzbl  1(%rbp), %ecx
    and     $1, %ecx
    call    quic_stream_acked
    jmp     9f
2:  call    quic_ref_stream
    test    %rax, %rax
    jz      9f
    mov     %rax, %rdi
    call    quic_stream_reset_acked
9:  LEAVE   0
END_FUNCTION quic_ref_acked

/* quic_ref_lost(ref, space): a frame of a lost packet goes out again. rbp the ref, r12 the space, then a flag. */
LOCAL_FUNCTION quic_ref_lost
    ENTER   0
    mov     %rdi, %rbp
    mov     %rsi, %r12
    movzbl  (%rbp), %eax
    cmp     $FR_CRYPTO, %eax
    jne     1f
    mov     %rbx, %rdi
    mov     %r12, %rsi
    call    quic_space
    testq   $SPF_DISCARDED, SP_FLAGS(%rax)
    jnz     9f
    mov     8(%rbp), %rcx
    shl     $16, %rcx
    shr     $16, %rcx
    cmp     SP_CTX_SENT(%rax), %rcx
    jae     9f
    mov     %rcx, SP_CTX_SENT(%rax)
    jmp     9f
1:  cmp     $FR_STREAM, %eax
    jne     2f
    call    quic_ref_stream
    test    %rax, %rax
    jz      9f
    mov     %rax, %rdi
    mov     8(%rbp), %rsi
    shl     $16, %rsi
    shr     $16, %rsi
    movzwl  14(%rbp), %edx
    movzbl  1(%rbp), %ecx
    and     $1, %ecx
    call    quic_stream_lost
    jmp     9f
2:  mov     $CF_MAX_DATA, %ecx
    cmp     $FR_MAX_DATA, %eax
    je      7f
    mov     $CF_MAX_STREAMS, %ecx
    cmp     $FR_MAX_STREAMS, %eax
    je      7f
    mov     $CF_DONE_FRAME, %ecx
    cmp     $FR_DONE, %eax
    je      7f
    cmp     $FR_RETIRE, %eax
    jne     3f
    movl    4(%rbp), %ecx
    mov     %rcx, C_RETIRE_SEQ(%rbx)
    jmp     9f
3:  mov     $SF_MSD, %ecx
    cmp     $FR_MAX_STREAM_DATA, %eax
    je      4f
    mov     $SF_RESET_SEND, %ecx
    cmp     $FR_RESET, %eax
    je      4f
    mov     $SF_STOP_SEND, %ecx
    cmp     $FR_STOP, %eax
    jne     9f
4:  mov     %rcx, %r12
    call    quic_ref_stream
    test    %rax, %rax
    jz      9f
    or      %r12, S_FLAGS(%rax)
    jmp     9f
7:  or      %rcx, C_FLAGS(%rbx)
9:  LEAVE   0
END_FUNCTION quic_ref_lost

/* quic_ref_stream() -> the live stream of the ref at rbp when its generation matches, or 0. */
LOCAL_FUNCTION quic_ref_stream
    ENTER   0
    movl    4(%rbp), %edi
    cmp     ST_STREAM_COUNT(%r15), %rdi
    jae     8f
    call    quic_stream_at
    cmpl    $0, S_USED(%rax)
    je      8f
    movzwl  S_GEN(%rax), %ecx
    movzwl  2(%rbp), %edx
    cmp     %edx, %ecx
    jne     8f
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_ref_stream

/* ---------------------------------------------------------------- Acknowledgements */

/*
 * quic_on_ack(space, ranges, n, ack_delay): an ACK frame of the space: n
 * ranges (smallest, largest), largest first; ack_delay in microseconds. The
 * records it covers leave as acknowledged; an RTT sample comes from the
 * largest when it is new and an ack-eliciting packet is among them; then loss
 * detection and the timer (RFC 9002 sections 5, 6 and 7).
 * rbp space, r12 ranges, r13 n, X23 ack_delay, X24 index, X25 newly acked
 * flags (bit 0 any, bit 1 ack-eliciting, bit 2 the largest), X26 the space record.
 */
.set OA_LARGEST_TIME, 0
.set OA_SAVE, 8                         /* a record and its info, over a call */
.set OA_FRAME, 32
LOCAL_FUNCTION quic_on_ack
    ENTER   0, OA_FRAME
    mov     %rdi, %rbp
    mov     %rsi, %r12
    mov     %rdx, %r13
    mov     %rcx, X23(%rsp)
    movq    $0, X25(%rsp)
    test    %r13, %r13
    jz      9f
    mov     %rbx, %rdi
    mov     %rbp, %rsi
    call    quic_space
    mov     %rax, X26(%rsp)
    mov     8(%r12), %rcx                   /* the largest acknowledged */
    mov     SP_LARGEST_ACKED(%rax), %rdx
    cmp     $-1, %rdx
    je      1f
    cmp     %rdx, %rcx
    jbe     2f
1:  mov     %rcx, SP_LARGEST_ACKED(%rax)
2:  movq    $0, X24(%rsp)
3:  mov     X24(%rsp), %rdi
    cmp     C_SENT_COUNT(%rbx), %rdi
    jae     6f
    call    quic_record_at
    incq    X24(%rsp)
    mov     SR_INFO(%rax), %rcx
    test    $(SRF_LIVE << 24), %rcx
    jz      3b
    mov     %rcx, %rdx
    shr     $16, %rdx
    and     $0xFF, %edx
    cmp     %rbp, %rdx
    jne     3b
    mov     SR_PN(%rax), %rdx
    xor     %r8d, %r8d                      /* is it in a range? */
4:  cmp     %r13, %r8
    jae     3b
    mov     %r8, %r9
    shl     $4, %r9
    add     %r12, %r9
    mov     (%r9), %r10
    mov     8(%r9), %r11
    inc     %r8
    cmp     %r10, %rdx
    jb      4b
    cmp     %r11, %rdx
    ja      4b
    orq     $1, X25(%rsp)
    mov     %rcx, %r9
    shr     $24, %r9
    test    $SRF_ELICIT, %r9b
    jz      5f
    orq     $2, X25(%rsp)
5:  cmp     8(%r12), %rdx
    jne     51f
    orq     $4, X25(%rsp)
    mov     SR_TIME(%rax), %r9
    mov     %r9, (32 + OA_LARGEST_TIME)(%rsp)
51: mov     %rax, (32 + OA_SAVE)(%rsp)
    mov     %rcx, (32 + OA_SAVE + 8)(%rsp)
    mov     %rax, %rdi
    mov     $1, %esi
    call    quic_record_gone
    mov     (32 + OA_SAVE)(%rsp), %rax
    mov     (32 + OA_SAVE + 8)(%rsp), %rcx
    mov     %rcx, %r9
    shr     $24, %r9
    test    $SRF_FLIGHT, %r9b
    jz      3b
    mov     SR_TIME(%rax), %rdi
    movzwl  %cx, %esi
    call    quic_cc_acked
    jmp     3b
6:  cmpq    $0, X25(%rsp)
    je      9f
    mov     X25(%rsp), %rax
    and     $6, %eax
    cmp     $6, %eax
    jne     7f
    mov     ST_NOW(%r15), %rdi
    sub     (32 + OA_LARGEST_TIME)(%rsp), %rdi
    xor     %esi, %esi
    cmp     $SPACE_APP, %rbp
    jne     61f
    mov     X23(%rsp), %rsi
61: call    quic_rtt_sample
7:  cmpq    $0, C_ROLE(%rbx)                /* a client keeps its backoff until the server is heard in Handshake */
    jne     71f
    cmp     $SPACE_INITIAL, %rbp
    je      72f
71: movq    $0, C_PTO_COUNT(%rbx)
72: mov     %rbp, %rdi
    call    quic_detect_loss
    call    quic_ring_tidy
    call    quic_set_loss_timer
9:  LEAVE   0, OA_FRAME
END_FUNCTION quic_on_ack

/*
 * quic_rtt_sample(latest, ack_delay): RFC 9002 section 5.3. ack_delay is
 * capped by max_ack_delay once the handshake is confirmed. rbp latest, r12 ack_delay.
 */
LOCAL_FUNCTION quic_rtt_sample
    ENTER   0
    mov     %rdi, %rbp
    mov     %rsi, %r12
    mov     %rbp, C_RTT_LATEST(%rbx)
    cmpq    $-1, C_RTT_FIRST(%rbx)
    jne     1f
    mov     ST_NOW(%r15), %rax
    mov     %rax, C_RTT_FIRST(%rbx)
    mov     %rbp, C_RTT_MIN(%rbx)
    mov     %rbp, C_RTT_SMOOTH(%rbx)
    mov     %rbp, %rax
    shr     $1, %rax
    mov     %rax, C_RTT_VAR(%rbx)
    jmp     9f
1:  mov     C_RTT_MIN(%rbx), %rax
    cmp     %rax, %rbp
    jae     11f
    mov     %rbp, %rax
11: mov     %rax, C_RTT_MIN(%rbx)
    testq   $CF_CONFIRMED, C_FLAGS(%rbx)
    jz      2f
    mov     C_P_ACK_DELAY(%rbx), %rcx
    cmp     %rcx, %r12
    jb      2f
    mov     %rcx, %r12
2:  lea     (%rax,%r12), %rcx               /* adjusted_rtt */
    mov     %rbp, %rdx
    cmp     %rcx, %rbp
    jb      3f
    sub     %r12, %rdx
3:  mov     C_RTT_SMOOTH(%rbx), %r8
    mov     %r8, %r9
    sub     %rdx, %r9
    jae     31f
    mov     %rdx, %r9                       /* |smoothed - adjusted| */
    sub     %r8, %r9
31: mov     C_RTT_VAR(%rbx), %r10
    lea     (%r10,%r10,2), %rax
    add     %r9, %rax
    shr     $2, %rax
    mov     %rax, C_RTT_VAR(%rbx)
    lea     0(,%r8,8), %rax
    sub     %r8, %rax
    add     %rdx, %rax
    shr     $3, %rax
    mov     %rax, C_RTT_SMOOTH(%rbx)
9:  LEAVE   0
END_FUNCTION quic_rtt_sample

/*
 * quic_detect_loss(space): the live records of the space below the largest
 * acknowledged are lost when 3 later packets are acknowledged or they were
 * sent 9/8 RTT ago; the others set the loss time (RFC 9002 section 6.1).
 * rbp space, r12 the space record, r13 loss delay, X23 lost send time,
 * X24 index, X25 the largest acknowledged, X26 the largest lost send time.
 */
LOCAL_FUNCTION quic_detect_loss
    ENTER   0
    mov     %rdi, %rbp
    mov     %rbx, %rdi
    mov     %rbp, %rsi
    call    quic_space
    mov     %rax, %r12
    movq    $NONE, SP_LOSS_TIME(%r12)
    mov     SP_LARGEST_ACKED(%r12), %rax
    mov     %rax, X25(%rsp)
    cmp     $-1, %rax
    je      9f
    mov     C_RTT_LATEST(%rbx), %rax
    mov     C_RTT_SMOOTH(%rbx), %rcx
    cmp     %rcx, %rax
    ja      11f
    mov     %rcx, %rax
11: lea     (%rax,%rax,8), %r13
    shr     $3, %r13
    cmp     $K_GRANULARITY, %r13
    ja      12f
    mov     $K_GRANULARITY, %r13d
12: mov     ST_NOW(%r15), %rax
    sub     %r13, %rax
    jae     13f
    xor     %eax, %eax
13: mov     %rax, X23(%rsp)
    movq    $0, X26(%rsp)
    movq    $0, X24(%rsp)
1:  mov     X24(%rsp), %rdi
    cmp     C_SENT_COUNT(%rbx), %rdi
    jae     5f
    call    quic_record_at
    incq    X24(%rsp)
    mov     SR_INFO(%rax), %rcx
    test    $(SRF_LIVE << 24), %rcx
    jz      1b
    mov     %rcx, %rdx
    shr     $16, %rdx
    and     $0xFF, %edx
    cmp     %rbp, %rdx
    jne     1b
    mov     SR_PN(%rax), %rdx
    cmp     X25(%rsp), %rdx
    ja      1b
    mov     SR_TIME(%rax), %r8
    cmp     X23(%rsp), %r8
    jbe     2f
    lea     K_PACKET_THRESHOLD(%rdx), %r9
    cmp     %r9, X25(%rsp)
    jae     2f
    add     %r13, %r8                       /* not yet: the loss time */
    cmp     SP_LOSS_TIME(%r12), %r8
    jae     1b
    mov     %r8, SP_LOSS_TIME(%r12)
    jmp     1b
2:  shr     $24, %rcx                       /* lost */
    test    $SRF_FLIGHT, %cl
    jz      3f
    cmp     X26(%rsp), %r8
    jbe     3f
    mov     %r8, X26(%rsp)
3:  mov     %rax, %rdi
    xor     %esi, %esi
    call    quic_record_gone
    jmp     1b
5:  mov     X26(%rsp), %rdi
    test    %rdi, %rdi
    jz      9f
    call    quic_cc_lost
9:  LEAVE   0
END_FUNCTION quic_detect_loss

/* ---------------------------------------------------------------- Congestion control (NewReno) */

/* quic_cc_acked(sent_time, size): slow start, or congestion avoidance; nothing inside recovery. A leaf. */
LOCAL_FUNCTION quic_cc_acked
    UNWIND_END_PROLOGUE
    cmp     C_RECOVERY(%rbx), %rdi
    jbe     9f
    mov     C_CWND(%rbx), %rax
    cmp     C_SSTHRESH(%rbx), %rax
    jae     1f
    add     %rsi, %rax
    jmp     2f
1:  mov     %rax, %rcx
    imul    $MAX_DATAGRAM, %rsi, %rax
    xor     %edx, %edx
    div     %rcx
    add     %rcx, %rax
2:  mov     %rax, C_CWND(%rbx)
9:  ret
END_FUNCTION quic_cc_acked

/*
 * quic_cc_lost(sent_time): a congestion event when the lost packet was sent
 * after the last recovery began: ssthresh and the window halve, to at least
 * the minimum window. A leaf.
 */
LOCAL_FUNCTION quic_cc_lost
    UNWIND_END_PROLOGUE
    cmp     C_RECOVERY(%rbx), %rdi
    jbe     9f
    mov     ST_NOW(%r15), %rax
    mov     %rax, C_RECOVERY(%rbx)
    mov     C_CWND(%rbx), %rax
    shr     $1, %rax
    cmp     $MINIMUM_WINDOW, %rax
    ja      1f
    mov     $MINIMUM_WINDOW, %eax
1:  mov     %rax, C_SSTHRESH(%rbx)
    mov     %rax, C_CWND(%rbx)
9:  ret
END_FUNCTION quic_cc_lost

/* ---------------------------------------------------------------- The loss detection timer */

/*
 * quic_set_loss_timer(): C_LOSS_AT: the earliest loss time of a space, else
 * the probe timeout of the earliest space with ack-eliciting packets in
 * flight (the Application space only after the handshake is confirmed); a
 * client still in its handshake keeps a probe armed (RFC 9002 section 6.2.2.1).
 * rbp index, r12 the earliest time, r13 the space record.
 */
LOCAL_FUNCTION quic_set_loss_timer
    ENTER   0
    mov     $NONE, %r12
    xor     %ebp, %ebp
1:  mov     %rbx, %rdi
    mov     %rbp, %rsi
    call    quic_space
    mov     SP_LOSS_TIME(%rax), %rcx
    cmp     %r12, %rcx
    jae     11f
    mov     %rcx, %r12
11: inc     %rbp
    cmp     $3, %rbp
    jb      1b
    cmp     $-1, %r12
    jne     8f
    cmpq    $CS_CLOSING, C_STATE(%rbx)
    jae     8f
    xor     %ebp, %ebp
2:  mov     %rbx, %rdi
    mov     %rbp, %rsi
    call    quic_space
    mov     %rax, %r13
    cmpq    $0, SP_ELICIT(%r13)
    je      3f
    cmp     $SPACE_APP, %rbp
    jne     21f
    testq   $CF_CONFIRMED, C_FLAGS(%rbx)
    jz      3f
21: mov     %rbx, %rdi
    mov     %rbp, %rsi
    call    quic_pto_period
    add     SP_LAST_ELICIT(%r13), %rax
    cmp     %r12, %rax
    jae     3f
    mov     %rax, %r12
3:  inc     %rbp
    cmp     $3, %rbp
    jb      2b
    cmp     $-1, %r12
    jne     8f
    cmpq    $0, C_ROLE(%rbx)                /* the anti-deadlock probe of a client */
    jne     8f
    testq   $CF_CONFIRMED, C_FLAGS(%rbx)
    jnz     8f
    mov     %rbx, %rdi
    mov     $SPACE_INITIAL, %esi
    call    quic_pto_period
    add     ST_NOW(%r15), %rax
    mov     %rax, %r12
8:  mov     %r12, C_LOSS_AT(%rbx)
    LEAVE   0
END_FUNCTION quic_set_loss_timer

/*
 * quic_on_loss_timer(): the loss detection timer fired: loss detection in the
 * space of the earliest loss time, or a probe timeout: the space of the
 * earliest probe sends an ack-eliciting probe, with its unacknowledged CRYPTO
 * data again, and the backoff doubles (RFC 9002 section 6.2.4).
 * rbp index, r12 the earliest, r13 its space, X23 the space record.
 */
LOCAL_FUNCTION quic_on_loss_timer
    ENTER   0
    mov     $NONE, %r12
    xor     %r13d, %r13d
    xor     %ebp, %ebp
1:  mov     %rbx, %rdi
    mov     %rbp, %rsi
    call    quic_space
    mov     SP_LOSS_TIME(%rax), %rcx
    cmp     %r12, %rcx
    jae     2f
    mov     %rcx, %r12
    mov     %rbp, %r13
2:  inc     %rbp
    cmp     $3, %rbp
    jb      1b
    cmp     $-1, %r12
    je      3f
    mov     %r13, %rdi
    call    quic_detect_loss
    call    quic_ring_tidy
    call    quic_set_loss_timer
    jmp     9f
3:  mov     $NONE, %r13                     /* PTO: the space whose probe is earliest */
    xor     %ebp, %ebp
4:  mov     %rbx, %rdi
    mov     %rbp, %rsi
    call    quic_space
    mov     %rax, X23(%rsp)
    cmpq    $0, SP_ELICIT(%rax)
    je      5f
    cmp     $SPACE_APP, %rbp
    jne     41f
    testq   $CF_CONFIRMED, C_FLAGS(%rbx)
    jz      5f
41: mov     %rbx, %rdi
    mov     %rbp, %rsi
    call    quic_pto_period
    mov     X23(%rsp), %rcx
    add     SP_LAST_ELICIT(%rcx), %rax
    cmp     %r12, %rax
    jae     5f
    mov     %rax, %r12
    mov     %rbp, %r13
5:  inc     %rbp
    cmp     $3, %rbp
    jb      4b
    cmp     $-1, %r13
    jne     6f
    mov     $SPACE_INITIAL, %r13d           /* the anti-deadlock probe: Handshake when its keys exist */
    mov     %rbx, %rdi
    mov     $SPACE_HANDSHAKE, %esi
    call    quic_space
    mov     SP_FLAGS(%rax), %rcx
    test    $SPF_TX, %cl
    jz      6f
    test    $SPF_DISCARDED, %cl
    jnz     6f
    mov     $SPACE_HANDSHAKE, %r13d
6:  mov     %rbx, %rdi
    mov     %r13, %rsi
    call    quic_space
    mov     %rax, X23(%rsp)
    orq     $SPF_PROBE, SP_FLAGS(%rax)
    cmp     $SPACE_APP, %r13
    je      7f
    mov     %r13, %rdi                      /* CRYPTO data not yet acknowledged goes out again */
    call    quic_crypto_unacked
    mov     X23(%rsp), %rcx
    cmp     SP_CTX_SENT(%rcx), %rax
    jae     7f
    mov     %rax, SP_CTX_SENT(%rcx)
7:  incq    C_PTO_COUNT(%rbx)
    call    quic_set_loss_timer
9:  LEAVE   0
END_FUNCTION quic_on_loss_timer

/*
 * quic_crypto_unacked(space) -> the smallest CRYPTO offset in a live record of
 * the space; SP_CTX_SENT when there is none.
 * rbp space, r12 index, r13 the result.
 */
LOCAL_FUNCTION quic_crypto_unacked
    ENTER   0
    mov     %rdi, %rbp
    mov     %rbx, %rdi
    mov     %rbp, %rsi
    call    quic_space
    mov     SP_CTX_SENT(%rax), %r13
    xor     %r12d, %r12d
1:  cmp     C_SENT_COUNT(%rbx), %r12
    jae     8f
    mov     %r12, %rdi
    call    quic_record_at
    inc     %r12
    mov     SR_INFO(%rax), %rcx
    test    $(SRF_LIVE << 24), %rcx
    jz      1b
    mov     %rcx, %rdx
    shr     $16, %rdx
    and     $0xFF, %edx
    cmp     %rbp, %rdx
    jne     1b
    shr     $32, %rcx
    and     $0xFF, %ecx
    lea     SR_FRAMES(%rax), %rdx
2:  test    %rcx, %rcx
    jz      1b
    cmpb    $FR_CRYPTO, (%rdx)
    jne     3f
    mov     8(%rdx), %r8
    shl     $16, %r8
    shr     $16, %r8
    cmp     %r13, %r8
    jae     3f
    mov     %r8, %r13
3:  add     $16, %rdx
    dec     %rcx
    jmp     2b
8:  mov     %r13, %rax
    LEAVE   0
END_FUNCTION quic_crypto_unacked
