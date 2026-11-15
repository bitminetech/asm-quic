/*
 * Bidirectional streams (RFC 9000 sections 2, 3 and 4): slots, the send queue
 * with its acknowledged and lost ranges, the receive segments, flow control,
 * and what the application hears. rbx the connection, where a function uses it.
 */

.set ERR_FLOW_CONTROL, 0x03
.set ERR_STREAM_LIMIT, 0x04
.set ERR_STREAM_STATE, 0x05
.set ERR_FINAL_SIZE, 0x06

/* ---------------------------------------------------------------- Slots */

/*
 * quic_stream_new(id, local) -> a new stream of the connection with the ID (or
 * NONE), linked first in its list; 0 when no slot is free. rbx the connection.
 * rbp id, r12 local, r13 the stream.
 */
LOCAL_FUNCTION quic_stream_new
    ENTER   0
    mov     %rdi, %rbp
    mov     %rsi, %r12
    mov     $ST_STREAM_OFF, %edi
    mov     $ST_STREAM_COUNT, %esi
    mov     $S_SIZE, %edx
    call    quic_alloc_slot
    test    %rax, %rax
    jz      9f
    mov     %rax, %r13
    mov     %rbx, %rdi
    call    quic_conn_index
    mov     %rax, S_CONN(%r13)
    movl    C_GEN(%rbx), %eax
    mov     %rax, S_CONN_GEN(%r13)
    mov     %rbp, S_ID(%r13)
    mov     $SF_TELL_OPEN, %eax
    test    %r12, %r12
    jz      1f
    or      $SF_LOCAL, %eax
1:  mov     %rax, S_FLAGS(%r13)
    movq    $NONE, S_RX_FINAL(%r13)
    CFG     %rax, QUIC_CFG_STREAM_DATA
    mov     %rax, S_RX_MAX(%r13)
    mov     C_P_SD_LOCAL(%rbx), %rax        /* the peer's limit for streams it opened */
    test    %r12, %r12
    jz      2f
    mov     C_P_SD_REMOTE(%rbx), %rax       /* and for streams we opened */
2:  mov     %rax, S_TX_MAX(%r13)
    mov     C_STREAM_HEAD(%rbx), %rax
    mov     %rax, S_NEXT(%r13)
    mov     %r13, %rdi
    call    quic_stream_index
    mov     %rax, C_STREAM_HEAD(%rbx)
    mov     %r13, %rax
9:  LEAVE   0
END_FUNCTION quic_stream_new

/*
 * quic_stream_free(stream): its chunks and segments go, it leaves the list of
 * its connection, and the slot is free. rbp stream, r12 its connection, r13 its index.
 */
LOCAL_FUNCTION quic_stream_free
    ENTER   0
    mov     %rdi, %rbp
    mov     S_CONN(%rbp), %rdi
    call    quic_conn_at
    mov     %rax, %r12
1:  mov     S_Q_HEAD(%rbp), %rdi
    test    %rdi, %rdi
    jz      2f
    mov     Q_NEXT(%r15,%rdi), %rax
    mov     %rax, S_Q_HEAD(%rbp)
    call    quic_heap_free
    jmp     1b
2:  mov     S_RX_HEAD(%rbp), %rdi
    test    %rdi, %rdi
    jz      3f
    mov     R_NEXT(%r15,%rdi), %rax
    mov     %rax, S_RX_HEAD(%rbp)
    call    quic_heap_free
    jmp     2b
3:  mov     %rbp, %rdi                      /* unlink */
    call    quic_stream_index
    mov     %rax, %r13
    mov     C_STREAM_HEAD(%r12), %rax
    cmp     %r13, %rax
    jne     4f
    mov     S_NEXT(%rbp), %rcx
    mov     %rcx, C_STREAM_HEAD(%r12)
    jmp     6f
4:  cmp     $-1, %rax
    je      6f
    mov     %rax, %rdi
    call    quic_stream_at
    mov     S_NEXT(%rax), %rcx
    cmp     %r13, %rcx
    je      5f
    mov     %rcx, %rax
    jmp     4b
5:  mov     S_NEXT(%rbp), %rcx
    mov     %rcx, S_NEXT(%rax)
6:  movl    $0, S_USED(%rbp)
    LEAVE   0
END_FUNCTION quic_stream_free

/* quic_stream_find(id) -> the stream of the connection with the ID, or 0. rbx the connection. */
LOCAL_FUNCTION quic_stream_find
    ENTER   0
    mov     %rdi, %rbp
    mov     C_STREAM_HEAD(%rbx), %r12
1:  cmp     $-1, %r12
    je      8f
    mov     %r12, %rdi
    call    quic_stream_at
    cmp     %rbp, S_ID(%rax)
    je      9f
    mov     S_NEXT(%rax), %r12
    jmp     1b
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_stream_find

/*
 * quic_assign_ids(): our streams that wait get IDs while the peer's
 * MAX_STREAMS allows: 4n for a client, 4n + 1 for a server. rbx the connection.
 * rbp index, r12 the oldest waiting stream.
 */
LOCAL_FUNCTION quic_assign_ids
    ENTER   0
10: mov     C_STREAM_HEAD(%rbx), %rbp
    mov     $NONE, %r12                     /* the oldest waiting stream is last in the list */
1:  cmp     $-1, %rbp
    je      2f
    mov     %rbp, %rdi
    call    quic_stream_at
    cmpq    $-1, S_ID(%rax)
    jne     11f
    mov     %rbp, %r12
11: mov     S_NEXT(%rax), %rbp
    jmp     1b
2:  cmp     $-1, %r12
    je      9f
    mov     C_LOCAL_OPEN(%rbx), %rax
    cmp     C_P_STREAMS(%rbx), %rax
    jae     9f
    mov     %r12, %rdi
    call    quic_stream_at
    mov     C_LOCAL_OPEN(%rbx), %rcx
    lea     0(,%rcx,4), %rdx
    or      C_ROLE(%rbx), %rdx
    mov     %rdx, S_ID(%rax)
    inc     %rcx
    mov     %rcx, C_LOCAL_OPEN(%rbx)
    jmp     10b
9:  LEAVE   0
END_FUNCTION quic_assign_ids

/* ---------------------------------------------------------------- Events of the application */

/*
 * quic_on_open_stream(event): a new stream of ours on the connection; its ID
 * comes when MAX_STREAMS allows. STREAM_OPENED tells the application its
 * handle; a handle 0 means no slot was free or the connection is gone.
 * X23 the event.
 */
LOCAL_FUNCTION quic_on_open_stream
    ENTER   0
    mov     %rdi, X23(%rsp)
    mov     QUIC_EV_CONN(%rdi), %rdi
    call    quic_conn
    test    %rax, %rax
    jz      7f
    mov     %rax, %rbx
    cmpq    $CS_ACTIVE, C_STATE(%rbx)
    jne     7f
    mov     $NONE, %rdi
    mov     $1, %esi
    call    quic_stream_new
    test    %rax, %rax
    jz      7f
    mov     X23(%rsp), %rcx
    mov     QUIC_EV_OPEN_TAG(%rcx), %rcx
    mov     %rcx, S_TAG(%rax)
    call    quic_assign_ids
    jmp     9f
7:  mov     $QUIC_ACTION_STREAM_OPENED, %edi /* no stream: handle 0 */
    mov     $QUIC_ACT_OPENED_SIZE, %esi
    call    quic_action
    test    %rax, %rax
    jz      9f
    mov     X23(%rsp), %rcx
    mov     QUIC_EV_CONN(%rcx), %rdx
    mov     %rdx, QUIC_ACT_S_CONN(%rax)
    mov     QUIC_EV_OPEN_TAG(%rcx), %rdx
    mov     %rdx, QUIC_ACT_S_TAG(%rax)
9:  LEAVE   0
END_FUNCTION quic_on_open_stream

/*
 * quic_on_stream_write(event): the bytes join the send queue of the stream as
 * one chunk. A stream whose queue would pass stream_queue, or whose chunk the
 * heap cannot hold, is reset with code 0. A stream the application closed or
 * reset ignores it. rbp stream, r12 the chunk offset, r13 the chunk,
 * X23 the event, X24 the count.
 */
LOCAL_FUNCTION quic_on_stream_write
    ENTER   0
    mov     %rdi, X23(%rsp)
    mov     QUIC_EV_STREAM(%rdi), %rdi
    call    quic_stream
    test    %rax, %rax
    jz      9f
    mov     %rax, %rbp
    testq   $(SF_FIN_WANT | SF_RESET), S_FLAGS(%rbp)
    jnz     9f
    mov     X23(%rsp), %rcx
    mov     QUIC_EV_WRITE_COUNT(%rcx), %rax
    mov     %rax, X24(%rsp)
    test    %rax, %rax
    jz      9f
    mov     S_WRITTEN(%rbp), %rcx
    sub     S_Q_BASE(%rbp), %rcx
    add     %rax, %rcx
    CFG     %rdx, QUIC_CFG_STREAM_QUEUE
    cmp     %rdx, %rcx
    ja      8f
    lea     Q_DATA(%rax), %rdi
    call    quic_heap_alloc
    test    %rax, %rax
    jz      8f
    mov     %rax, %r12
    lea     (%r15,%r12), %r13
    movq    $0, Q_NEXT(%r13)
    mov     X24(%rsp), %rax
    mov     %rax, Q_LEN(%r13)
    lea     Q_DATA(%r13), %rdi
    mov     X23(%rsp), %rsi
    add     $QUIC_EV_WRITE_DATA, %rsi
    mov     X24(%rsp), %rdx
    call    quic_copy
    mov     S_Q_TAIL(%rbp), %rax
    test    %rax, %rax
    jz      1f
    mov     %r12, Q_NEXT(%r15,%rax)
    jmp     2f
1:  mov     %r12, S_Q_HEAD(%rbp)
    mov     S_WRITTEN(%rbp), %rax
    mov     %rax, S_Q_BASE(%rbp)
2:  mov     %r12, S_Q_TAIL(%rbp)
    mov     X24(%rsp), %rax
    add     %rax, S_WRITTEN(%rbp)
    jmp     9f
8:  mov     %rbp, %rdi
    xor     %esi, %esi
    call    quic_stream_reset_local
9:  LEAVE   0
END_FUNCTION quic_on_stream_write

/* quic_on_stream_close(event): no more bytes: a FIN follows the queue. */
LOCAL_FUNCTION quic_on_stream_close
    ENTER   0
    mov     QUIC_EV_STREAM(%rdi), %rdi
    call    quic_stream
    test    %rax, %rax
    jz      9f
    orq     $SF_FIN_WANT, S_FLAGS(%rax)
9:  LEAVE   0
END_FUNCTION quic_on_stream_close

/* quic_on_stream_reset(event): the application resets the stream both ways with its code. */
LOCAL_FUNCTION quic_on_stream_reset
    ENTER   0
    mov     %rdi, %rbp
    mov     QUIC_EV_STREAM(%rbp), %rdi
    call    quic_stream
    test    %rax, %rax
    jz      9f
    mov     %rax, %rdi
    mov     QUIC_EV_CODE(%rbp), %rsi
    call    quic_stream_reset_local
9:  LEAVE   0
END_FUNCTION quic_on_stream_reset

/*
 * quic_stream_reset_local(stream, code): RESET_STREAM and STOP_SENDING with
 * the code go out; the queue is dropped; the peer's data is no longer heard.
 * The application is not told. rbp the stream.
 */
LOCAL_FUNCTION quic_stream_reset_local
    ENTER   0
    mov     %rdi, %rbp
    mov     %rsi, S_APP_CODE(%rbp)
    mov     S_FLAGS(%rbp), %rax
    test    $SF_RESET, %rax
    jnz     9f
    or      $(SF_RESET | SF_RESET_SEND | SF_TOLD_RESET), %rax
    test    $SF_RX_DONE, %rax
    jnz     1f
    or      $(SF_STOP_SEND | SF_RX_DONE), %rax
1:  and     $~(SF_TELL_RESET | SF_TELL_FIN), %rax
    mov     %rax, S_FLAGS(%rbp)
    call    quic_stream_drop
9:  LEAVE   0
END_FUNCTION quic_stream_reset_local

/* quic_stream_drop(): the queue of the stream at rbp is freed, and its segments when its receive side is over. */
LOCAL_FUNCTION quic_stream_drop
    ENTER   0
1:  mov     S_Q_HEAD(%rbp), %rdi
    test    %rdi, %rdi
    jz      2f
    mov     Q_NEXT(%r15,%rdi), %rax
    mov     %rax, S_Q_HEAD(%rbp)
    call    quic_heap_free
    jmp     1b
2:  movq    $0, S_Q_TAIL(%rbp)
    movq    $0, S_NLOST(%rbp)
    testq   $SF_RX_DONE, S_FLAGS(%rbp)
    jz      9f
    call    quic_stream_drop_rx
9:  LEAVE   0
END_FUNCTION quic_stream_drop

/* quic_stream_drop_rx(): the segments of the stream at rbp are freed. */
LOCAL_FUNCTION quic_stream_drop_rx
    ENTER   0
1:  mov     S_RX_HEAD(%rbp), %rdi
    test    %rdi, %rdi
    jz      9f
    mov     R_NEXT(%r15,%rdi), %rax
    mov     %rax, S_RX_HEAD(%rbp)
    call    quic_heap_free
    jmp     1b
9:  LEAVE   0
END_FUNCTION quic_stream_drop_rx

/* ---------------------------------------------------------------- Acknowledged and lost data */

/*
 * quic_stream_acked(stream, offset, len, fin): a STREAM frame of ours is
 * acknowledged: the range joins the acknowledged ranges, S_ACKED moves over
 * every range that touches it, and the chunks below it are freed.
 * rbp stream, r12 start, r13 end, X23 fin.
 */
LOCAL_FUNCTION quic_stream_acked
    ENTER   0
    mov     %rdi, %rbp
    mov     %rsi, %r12
    lea     (%rsi,%rdx), %r13
    mov     %rcx, X23(%rsp)
    testq   $SF_RESET, S_FLAGS(%rbp)
    jnz     9f
    cmpq    $0, X23(%rsp)
    je      1f
    orq     $SF_FIN_SENT, S_FLAGS(%rbp)
    btsq    $63, S_NACKS(%rbp)              /* the FIN is acknowledged: kept in S_NACKS bit 63 */
1:  mov     %rbp, %rdi
    mov     %r12, %rsi
    mov     %r13, %rdx
    lea     S_NACKS(%rbp), %rcx
    mov     $6, %r8d
    call    quic_ranges_add
    call    quic_stream_advance
9:  LEAVE   0
END_FUNCTION quic_stream_acked

/*
 * quic_stream_advance(): S_ACKED moves over the acknowledged ranges that touch
 * it; chunks wholly below it are freed; a stream whose FIN and data are all
 * acknowledged gets SF_FIN_ACKED. rbp the stream. r12 S_ACKED.
 */
LOCAL_FUNCTION quic_stream_advance
    ENTER   0
1:  mov     S_NACKS(%rbp), %rax
    test    $0xFF, %al
    jz      3f
    mov     S_ACKS(%rbp), %rcx
    mov     (S_ACKS + 8)(%rbp), %rdx
    mov     S_ACKED(%rbp), %r8
    cmp     %rcx, %r8
    jb      3f
    cmp     %rdx, %r8
    jae     11f
    mov     %rdx, %r8
11: mov     %r8, S_ACKED(%rbp)
    mov     %rbp, %rdi                      /* the first range goes */
    lea     S_NACKS(%rbp), %rsi
    xor     %edx, %edx
    call    quic_ranges_remove
    jmp     1b
3:  mov     S_ACKED(%rbp), %r12             /* free the chunks below */
4:  mov     S_Q_HEAD(%rbp), %rdi
    test    %rdi, %rdi
    jz      5f
    lea     (%r15,%rdi), %rax
    mov     Q_LEN(%rax), %rcx
    add     S_Q_BASE(%rbp), %rcx
    cmp     %rcx, %r12
    jb      5f
    mov     %rcx, S_Q_BASE(%rbp)
    mov     Q_NEXT(%rax), %rcx
    mov     %rcx, S_Q_HEAD(%rbp)
    test    %rcx, %rcx
    jnz     41f
    movq    $0, S_Q_TAIL(%rbp)
41: call    quic_heap_free
    jmp     4b
5:  cmpq    $0, S_NACKS(%rbp)               /* FIN acknowledged and all data */
    jns     9f
    cmp     S_WRITTEN(%rbp), %r12
    jb      9f
    orq     $SF_FIN_ACKED, S_FLAGS(%rbp)
9:  LEAVE   0
END_FUNCTION quic_stream_advance

/*
 * quic_stream_lost(stream, offset, len, fin): a STREAM frame of ours was lost:
 * the part not yet acknowledged joins the lost ranges, and a FIN goes out again.
 * rbp stream, r12 start, r13 end.
 */
LOCAL_FUNCTION quic_stream_lost
    ENTER   0
    mov     %rdi, %rbp
    mov     %rsi, %r12
    lea     (%rsi,%rdx), %r13
    mov     S_FLAGS(%rbp), %rax
    test    $SF_RESET, %rax
    jnz     9f
    test    %rcx, %rcx
    jz      1f
    cmpq    $0, S_NACKS(%rbp)
    js      1f
    orq     $SF_FIN_LOST, S_FLAGS(%rbp)
1:  mov     S_ACKED(%rbp), %rax
    cmp     %rax, %r12
    jae     2f
    mov     %rax, %r12
2:  cmp     %r13, %r12
    jae     9f
    mov     %rbp, %rdi
    mov     %r12, %rsi
    mov     %r13, %rdx
    lea     S_NLOST(%rbp), %rcx
    mov     $4, %r8d
    call    quic_ranges_add
9:  LEAVE   0
END_FUNCTION quic_stream_lost

/* quic_stream_reset_acked(stream): our RESET_STREAM is acknowledged: our side is over. */
LOCAL_FUNCTION quic_stream_reset_acked
    ENTER   0
    orq     $SF_FIN_ACKED, S_FLAGS(%rdi)
    LEAVE   0
END_FUNCTION quic_stream_reset_acked

/*
 * quic_ranges_add(stream, start, end, list, max): adds [start, end) to a list
 * of ranges kept in order and joined: the u8 count at list (other bits kept),
 * then max pairs at list + 8. When the list is full the range joins the last
 * one, covering the gap: lost ranges then send a little more again, and
 * acknowledged ones cannot lose a range.
 * rbx list, rbp count word, r12 start, r13 end, X23 the pairs, X24 count,
 * X25 max, X26 index.
 */
LOCAL_FUNCTION quic_ranges_add
    ENTER   0
    mov     %rcx, %rbx
    mov     %rsi, %r12
    mov     %rdx, %r13
    mov     %r8, X25(%rsp)
    lea     8(%rbx), %rax
    mov     %rax, X23(%rsp)
    mov     (%rbx), %rbp
    movzbl  %bpl, %eax
    mov     %rax, X24(%rsp)
    movq    $0, X26(%rsp)
1:  mov     X26(%rsp), %rax
    cmp     X24(%rsp), %rax
    jae     5f
    shl     $4, %rax
    add     X23(%rsp), %rax
    mov     (%rax), %rcx
    mov     8(%rax), %rdx
    cmp     %rcx, %r13
    jb      4f                              /* wholly before this range: insert here */
    cmp     %r12, %rdx
    jb      3f                              /* wholly after: next */
    cmp     %rcx, %r12                      /* they touch: join */
    jae     11f
    mov     %r12, %rcx
11: cmp     %r13, %rdx
    jae     12f
    mov     %r13, %rdx
12: mov     %rcx, (%rax)
    mov     %rdx, 8(%rax)
2:  mov     X26(%rsp), %rcx                 /* join the ranges after that now touch */
    lea     1(%rcx), %r8
    cmp     X24(%rsp), %r8
    jae     9f
    mov     X23(%rsp), %r9
    mov     %rcx, %rax
    shl     $4, %rax
    add     %r9, %rax
    mov     8(%rax), %rdx
    mov     %r8, %r10
    shl     $4, %r10
    add     %r9, %r10
    mov     (%r10), %r11
    cmp     %r11, %rdx
    jb      9f
    mov     8(%r10), %r11
    cmp     %r11, %rdx
    jae     21f
    mov     %r11, %rdx
21: mov     %rdx, 8(%rax)
    mov     %rbx, %rdi
    mov     %rbx, %rsi
    mov     %r8, %rdx
    call    quic_ranges_remove
    mov     (%rbx), %rbp
    movzbl  %bpl, %eax
    mov     %rax, X24(%rsp)
    jmp     2b
3:  incq    X26(%rsp)
    jmp     1b
4:  mov     X24(%rsp), %rcx                 /* insert at the index */
    cmp     X25(%rsp), %rcx
    jae     6f
41: cmp     X26(%rsp), %rcx
    jbe     42f
    lea     -1(%rcx), %r8
    mov     %r8, %r9
    shl     $4, %r9
    add     X23(%rsp), %r9
    mov     (%r9), %r10
    mov     8(%r9), %r11
    mov     %r10, 16(%r9)
    mov     %r11, 24(%r9)
    mov     %r8, %rcx
    jmp     41b
42: mov     X26(%rsp), %rax
    shl     $4, %rax
    add     X23(%rsp), %rax
    mov     %r12, (%rax)
    mov     %r13, 8(%rax)
    inc     %rbp
    mov     %rbp, (%rbx)
    jmp     9f
5:  mov     X24(%rsp), %rcx                 /* append */
    cmp     X25(%rsp), %rcx
    jae     6f
    jmp     42b
6:  mov     X24(%rsp), %rax                 /* full: join the last range */
    test    %rax, %rax
    jz      9f
    dec     %rax
    mov     %rax, X26(%rsp)
    shl     $4, %rax
    add     X23(%rsp), %rax
    mov     (%rax), %rcx
    mov     8(%rax), %rdx
    cmp     %rcx, %r12
    jae     61f
    mov     %r12, %rcx
61: cmp     %r13, %rdx
    jae     62f
    mov     %r13, %rdx
62: mov     %rcx, (%rax)
    mov     %rdx, 8(%rax)
9:  LEAVE   0
END_FUNCTION quic_ranges_add

/* quic_ranges_remove(stream, list, index): the range at index of the list goes. A leaf. */
LOCAL_FUNCTION quic_ranges_remove
    UNWIND_END_PROLOGUE
    mov     (%rsi), %rcx
    movzbl  %cl, %r8d
    lea     8(%rsi), %r9
1:  lea     1(%rdx), %r10
    cmp     %r8, %r10
    jae     2f
    mov     %r10, %r11
    shl     $4, %r11
    add     %r9, %r11
    mov     (%r11), %rax
    mov     %rax, -16(%r11)
    mov     8(%r11), %rax
    mov     %rax, -8(%r11)
    mov     %r10, %rdx
    jmp     1b
2:  dec     %rcx
    mov     %rcx, (%rsi)
    ret
END_FUNCTION quic_ranges_remove

/* ---------------------------------------------------------------- Frames of the peer */

/*
 * quic_peer_stream(id) -> rax the stream of the ID for a frame of the peer, or
 * 0 when the frame is to be ignored (a stream that is over); rdx 0, or the
 * error code. A stream the peer may open that is new opens, with every lower
 * one of its kind (RFC 9000 section 3.2). rbx the connection.
 * rbp id, r12 the stream number, r13 the error, X23 the streams the peer opened.
 */
LOCAL_FUNCTION quic_peer_stream
    ENTER   0
    mov     %rdi, %rbp
    xor     %r13d, %r13d
    test    $2, %rbp                        /* unidirectional: we allow none */
    jz      1f
    mov     $ERR_STREAM_LIMIT, %r13d
    jmp     8f
1:  call    quic_stream_find
    test    %rax, %rax
    jnz     9f
    mov     %rbp, %rax                      /* who opened it */
    and     $1, %eax
    cmp     C_ROLE(%rbx), %rax
    jne     2f
    mov     %rbp, %r12                      /* ours: a stream we opened and is over, or one we never opened */
    shr     $2, %r12
    cmp     C_LOCAL_OPEN(%rbx), %r12
    jb      8f
    mov     $ERR_STREAM_STATE, %r13d
    jmp     8f
2:  mov     %rbp, %r12
    shr     $2, %r12
    cmp     C_PEER_MAX(%rbx), %r12
    jb      3f
    mov     $ERR_STREAM_LIMIT, %r13d
    jmp     8f
3:  mov     C_PEER_OPEN(%rbx), %rax
    mov     %rax, X23(%rsp)
    cmp     %rax, %r12
    jb      8f                              /* opened before and over */
4:  mov     X23(%rsp), %rax
    cmp     %r12, %rax
    ja      6f
    lea     0(,%rax,4), %rdi
    mov     %rbp, %rcx
    and     $3, %ecx
    or      %rcx, %rdi
    xor     %esi, %esi
    call    quic_stream_new
    test    %rax, %rax
    jz      5f
    incq    X23(%rsp)
    mov     X23(%rsp), %rax
    mov     %rax, C_PEER_OPEN(%rbx)
    jmp     4b
5:  mov     $ERR_INTERNAL, %r13d            /* no slot */
    jmp     8f
6:  mov     %rbp, %rdi
    call    quic_stream_find
    jmp     9f
8:  xor     %eax, %eax
9:  mov     %r13, %rdx
    LEAVE   0
END_FUNCTION quic_peer_stream

/*
 * quic_rx_limits(stream, end) -> 0 or the error code: the flow control of the
 * stream and the connection for data up to end, and the final size rules
 * (RFC 9000 sections 4.1 and 4.5). S_RX_SEEN and C_RX_SEEN move up.
 */
LOCAL_FUNCTION quic_rx_limits
    ENTER   0
    mov     %rdi, %rbp
    mov     S_RX_FINAL(%rbp), %rax
    cmp     $-1, %rax
    je      1f
    cmp     %rax, %rsi
    ja      7f
1:  cmp     S_RX_MAX(%rbp), %rsi
    ja      6f
    mov     S_RX_SEEN(%rbp), %rax
    cmp     %rax, %rsi
    jbe     2f
    mov     %rsi, %rcx
    sub     %rax, %rcx
    mov     %rsi, S_RX_SEEN(%rbp)
    add     C_RX_SEEN(%rbx), %rcx
    mov     %rcx, C_RX_SEEN(%rbx)
    cmp     C_RX_MAX(%rbx), %rcx
    ja      6f
2:  xor     %eax, %eax
    jmp     9f
6:  mov     $ERR_FLOW_CONTROL, %eax
    jmp     9f
7:  mov     $ERR_FINAL_SIZE, %eax
9:  LEAVE   0
END_FUNCTION quic_rx_limits

/*
 * quic_on_stream_frame(id, offset, data, len, fin) -> 0 or the error code: a
 * STREAM frame. Its bytes past those delivered join the segments of the
 * stream, in order, overlaps cut.
 * rbp stream, r12 offset, r13 data, X23 len, X24 fin, X25 end, X26 id.
 */
LOCAL_FUNCTION quic_on_stream_frame
    ENTER   0
    mov     %rdi, X26(%rsp)
    mov     %rsi, %r12
    mov     %rdx, %r13
    mov     %rcx, X23(%rsp)
    mov     %r8, X24(%rsp)
    lea     (%rsi,%rcx), %rax
    mov     %rax, X25(%rsp)
    movabs  $(1 << 62), %rcx
    cmp     %rcx, %rax
    jae     7f
    mov     X26(%rsp), %rdi
    call    quic_peer_stream
    test    %rdx, %rdx
    jnz     8f
    test    %rax, %rax
    jz      9f
    mov     %rax, %rbp
    testq   $SF_RX_DONE, S_FLAGS(%rbp)
    jnz     9f                              /* reset: late data is not heard */
    mov     %rbp, %rdi
    mov     X25(%rsp), %rsi
    call    quic_rx_limits
    test    %rax, %rax
    jnz     99f
    cmpq    $0, X24(%rsp)
    je      1f
    mov     S_RX_FINAL(%rbp), %rax          /* a final size, once */
    cmp     $-1, %rax
    je      11f
    cmp     X25(%rsp), %rax
    jne     71f
11: mov     X25(%rsp), %rax
    cmp     S_RX_SEEN(%rbp), %rax
    jb      71f
    mov     %rax, S_RX_FINAL(%rbp)
1:  mov     S_RX_DONE(%rbp), %rax           /* drop what is delivered */
    cmp     %rax, %r12
    jae     2f
    mov     %rax, %rcx
    sub     %r12, %rcx
    cmp     X23(%rsp), %rcx
    jae     9f
    add     %rcx, %r13
    sub     %rcx, X23(%rsp)
    mov     %rax, %r12
2:  cmpq    $0, X23(%rsp)
    je      9f
    mov     %rbp, %rdi
    mov     %r12, %rsi
    mov     %r13, %rdx
    mov     X23(%rsp), %rcx
    call    quic_segment_add
    jmp     99f
7:  mov     $ERR_FLOW_CONTROL, %edx
8:  mov     %rdx, %rax
    jmp     99f
71: mov     $ERR_FINAL_SIZE, %eax
    jmp     99f
9:  xor     %eax, %eax
99: LEAVE   0
END_FUNCTION quic_on_stream_frame

/*
 * quic_segment_add(stream, offset, data, len) -> 0, or ERR_INTERNAL when the
 * heap has no room: the bytes not held yet go into new segments in order.
 * rbp stream, r12 offset, r13 data, X23 end, X24 the link to the next segment,
 * X25 the segment there, X26 the end of the new segment.
 */
LOCAL_FUNCTION quic_segment_add
    ENTER   0
    mov     %rdi, %rbp
    mov     %rsi, %r12
    mov     %rdx, %r13
    lea     (%rsi,%rcx), %rax
    mov     %rax, X23(%rsp)
    lea     S_RX_HEAD(%rbp), %rax
    mov     %rax, X24(%rsp)
1:  cmp     X23(%rsp), %r12
    jae     8f
    mov     X24(%rsp), %rax
    mov     (%rax), %rcx
    mov     %rcx, X25(%rsp)
    test    %rcx, %rcx
    jz      3f
    lea     (%r15,%rcx), %rax
    mov     R_OFFSET(%rax), %rdx
    mov     R_LEN(%rax), %r8
    add     %rdx, %r8
    cmp     %r8, %r12
    jb      2f
    lea     R_NEXT(%rax), %rcx              /* this segment ends before: on */
    mov     %rcx, X24(%rsp)
    jmp     1b
2:  cmp     %rdx, %r12
    jae     21f
    mov     %rdx, X26(%rsp)                 /* a new segment before it, up to its start */
    cmp     %rdx, X23(%rsp)
    jae     4f
    mov     X23(%rsp), %rcx
    mov     %rcx, X26(%rsp)
    jmp     4f
21: mov     %r8, %rcx                       /* inside it: skip what it holds */
    sub     %r12, %rcx
    add     %rcx, %r12
    add     %rcx, %r13
    lea     R_NEXT(%rax), %rcx
    mov     %rcx, X24(%rsp)
    jmp     1b
3:  mov     X23(%rsp), %rax                 /* past every segment */
    mov     %rax, X26(%rsp)
4:  mov     X26(%rsp), %rdi
    sub     %r12, %rdi
    add     $R_DATA, %rdi
    call    quic_heap_alloc
    test    %rax, %rax
    jz      7f
    lea     (%r15,%rax), %rcx
    mov     X25(%rsp), %rdx
    mov     %rdx, R_NEXT(%rcx)
    mov     %r12, R_OFFSET(%rcx)
    mov     X26(%rsp), %rdx
    sub     %r12, %rdx
    mov     %rdx, R_LEN(%rcx)
    mov     X24(%rsp), %r8
    mov     %rax, (%r8)
    lea     R_NEXT(%rcx), %r8
    mov     %r8, X24(%rsp)
    lea     R_DATA(%rcx), %rdi
    mov     %r13, %rsi
    call    quic_copy
    mov     X26(%rsp), %rcx
    sub     %r12, %rcx
    add     %rcx, %r13
    mov     X26(%rsp), %r12
    jmp     1b
7:  mov     $ERR_INTERNAL, %eax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_segment_add

/*
 * quic_on_reset_stream(id, code, final) -> 0 or the error code: the peer reset
 * its side: the final size is checked and counted, the segments go, and the
 * application hears STREAM_RESET with the code. rbp stream, X23 code, X24 final.
 */
LOCAL_FUNCTION quic_on_reset_stream
    ENTER   0
    mov     %rsi, X23(%rsp)
    mov     %rdx, X24(%rsp)
    call    quic_peer_stream
    test    %rdx, %rdx
    jnz     8f
    test    %rax, %rax
    jz      9f
    mov     %rax, %rbp
    testq   $SF_RX_DONE, S_FLAGS(%rbp)
    jnz     9f
    mov     S_RX_FINAL(%rbp), %rax
    cmp     $-1, %rax
    je      1f
    cmp     X24(%rsp), %rax
    jne     7f
1:  mov     X24(%rsp), %rax
    cmp     S_RX_SEEN(%rbp), %rax
    jb      7f
    mov     %rbp, %rdi
    mov     X24(%rsp), %rsi
    call    quic_rx_limits
    test    %rax, %rax
    jnz     99f
    mov     X24(%rsp), %rax
    mov     %rax, S_RX_FINAL(%rbp)
    mov     X23(%rsp), %rcx
    mov     %rcx, S_RESET_CODE(%rbp)
    mov     %rax, %rcx                      /* the bytes never delivered count as delivered */
    sub     S_RX_DONE(%rbp), %rcx
    add     %rcx, C_RX_DONE(%rbx)
    mov     %rax, S_RX_DONE(%rbp)
    mov     S_FLAGS(%rbp), %rax
    or      $(SF_RX_DONE | SF_TELL_RESET), %rax
    and     $~SF_TELL_FIN, %rax
    mov     %rax, S_FLAGS(%rbp)
    call    quic_stream_drop_rx
    jmp     9f
7:  mov     $ERR_FINAL_SIZE, %eax
    jmp     99f
8:  mov     %rdx, %rax
    jmp     99f
9:  xor     %eax, %eax
99: LEAVE   0
END_FUNCTION quic_on_reset_stream

/*
 * quic_on_stop_sending(id, code) -> 0 or the error code: the peer stops our
 * side: RESET_STREAM goes out (RFC 9000 section 3.5) and the application
 * hears STREAM_RESET with the code. rbp stream, X23 code.
 */
LOCAL_FUNCTION quic_on_stop_sending
    ENTER   0
    mov     %rsi, X23(%rsp)
    call    quic_peer_stream
    test    %rdx, %rdx
    jnz     8f
    test    %rax, %rax
    jz      9f
    mov     %rax, %rbp
    mov     S_FLAGS(%rbp), %rax
    test    $SF_RESET, %rax
    jnz     9f
    mov     X23(%rsp), %rcx
    mov     %rcx, S_RESET_CODE(%rbp)
    mov     %rcx, S_APP_CODE(%rbp)
    or      $(SF_RESET | SF_RESET_SEND), %rax
    test    $SF_TOLD_RESET, %rax
    jnz     1f
    or      $SF_TELL_RESET, %rax
1:  mov     %rax, S_FLAGS(%rbp)
    call    quic_stream_drop
    jmp     9f
8:  mov     %rdx, %rax
    jmp     99f
9:  xor     %eax, %eax
99: LEAVE   0
END_FUNCTION quic_on_stop_sending

/* quic_on_max_stream_data(id, max) -> 0 or the error code. X23 max. */
LOCAL_FUNCTION quic_on_max_stream_data
    ENTER   0
    mov     %rsi, X23(%rsp)
    call    quic_peer_stream
    test    %rdx, %rdx
    jnz     8f
    test    %rax, %rax
    jz      9f
    mov     X23(%rsp), %rcx
    cmp     S_TX_MAX(%rax), %rcx
    jbe     9f
    mov     %rcx, S_TX_MAX(%rax)
    jmp     9f
8:  mov     %rdx, %rax
    jmp     99f
9:  xor     %eax, %eax
99: LEAVE   0
END_FUNCTION quic_on_max_stream_data

/* ---------------------------------------------------------------- What the application hears */

/*
 * quic_stream_tell(stream) -> 1 when the stream is over and freed; else 0
 * after STREAM_OPENED, STREAM_DATA of the bytes in order, STREAM_FIN,
 * STREAM_RESET and STREAM_ACKED go out while the action room allows; new
 * credit is given.
 * rbx the connection. rbp stream, r12 the next segment or an action,
 * r13 the segment, X24 the bytes, X25 the action.
 */
LOCAL_FUNCTION quic_stream_tell
    ENTER   0
    mov     %rdi, %rbp
    testq   $SF_TELL_OPEN, S_FLAGS(%rbp)
    jz      1f
    cmpq    $-1, S_ID(%rbp)
    jne     11f
    testq   $SF_LOCAL, S_FLAGS(%rbp)
    jz      1f
11: call    quic_room
    cmp     $QUIC_ACT_OPENED_SIZE, %rax
    jb      8f
    mov     $QUIC_ACTION_STREAM_OPENED, %edi
    mov     $QUIC_ACT_OPENED_SIZE, %esi
    call    quic_action
    mov     %rax, %r12
    mov     %rbp, %rdi
    call    quic_stream_handle
    mov     %rax, QUIC_ACT_STREAM(%r12)
    mov     %rbx, %rdi
    call    quic_conn_handle
    mov     %rax, QUIC_ACT_S_CONN(%r12)
    mov     S_TAG(%rbp), %rax
    mov     %rax, QUIC_ACT_S_TAG(%r12)
    andq    $~SF_TELL_OPEN, S_FLAGS(%rbp)
1:  testq   $SF_TELL_OPEN, S_FLAGS(%rbp)    /* data in order */
    jnz     8f
2:  mov     S_RX_HEAD(%rbp), %r12
    test    %r12, %r12
    jz      4f
    lea     (%r15,%r12), %r13
    mov     R_OFFSET(%r13), %rax
    cmp     S_RX_DONE(%rbp), %rax
    jne     4f
    call    quic_room
    cmp     $(QUIC_ACT_S_DATA + 8), %rax
    jbe     8f
    sub     $(QUIC_ACT_S_DATA + 8), %rax
    mov     R_LEN(%r13), %rcx
    cmp     %rax, %rcx
    jbe     21f                             /* the bytes that fit */
    mov     %rax, %rcx
21: mov     %rcx, X24(%rsp)
    lea     (QUIC_ACT_S_DATA + 7)(%rcx), %rsi
    and     $-8, %rsi
    mov     $QUIC_ACTION_STREAM_DATA, %edi
    call    quic_action
    mov     %rax, X25(%rsp)
    mov     %rbp, %rdi
    call    quic_stream_handle
    mov     X25(%rsp), %rcx
    mov     %rax, QUIC_ACT_STREAM(%rcx)
    mov     X24(%rsp), %rdx
    mov     %rdx, QUIC_ACT_S_COUNT(%rcx)
    lea     QUIC_ACT_S_DATA(%rcx), %rdi
    lea     R_DATA(%r13), %rsi
    call    quic_copy
    mov     X24(%rsp), %rax
    add     %rax, S_RX_DONE(%rbp)
    add     %rax, C_RX_DONE(%rbx)
    mov     R_LEN(%r13), %rcx
    cmp     %rcx, %rax
    jb      3f
    mov     R_NEXT(%r13), %rcx              /* the whole segment went */
    mov     %rcx, S_RX_HEAD(%rbp)
    mov     %r12, %rdi
    call    quic_heap_free
    jmp     2b
3:  sub     %rax, %rcx                      /* part of it: move the rest down */
    mov     %rcx, R_LEN(%r13)
    add     %rax, R_OFFSET(%r13)
    lea     R_DATA(%r13), %rdi
    lea     (%rdi,%rax), %rsi
    mov     %rcx, %rdx
    call    quic_copy
    jmp     8f
4:  mov     S_FLAGS(%rbp), %rax             /* FIN */
    test    $(SF_TOLD_FIN | SF_TOLD_RESET), %rax
    jnz     5f
    mov     S_RX_FINAL(%rbp), %rcx
    cmp     S_RX_DONE(%rbp), %rcx
    jne     5f
    call    quic_room
    cmp     $QUIC_ACT_FIN_SIZE, %rax
    jb      8f
    mov     $QUIC_ACTION_STREAM_FIN, %edi
    mov     $QUIC_ACT_FIN_SIZE, %esi
    call    quic_action
    mov     %rax, %r12
    mov     %rbp, %rdi
    call    quic_stream_handle
    mov     %rax, QUIC_ACT_STREAM(%r12)
    orq     $(SF_TOLD_FIN | SF_RX_DONE), S_FLAGS(%rbp)
5:  testq   $SF_TELL_RESET, S_FLAGS(%rbp)   /* RESET */
    jz      6f
    call    quic_room
    cmp     $QUIC_ACT_RESET_SIZE, %rax
    jb      8f
    mov     $QUIC_ACTION_STREAM_RESET, %edi
    mov     $QUIC_ACT_RESET_SIZE, %esi
    call    quic_action
    mov     %rax, %r12
    mov     %rbp, %rdi
    call    quic_stream_handle
    mov     %rax, QUIC_ACT_STREAM(%r12)
    mov     S_RESET_CODE(%rbp), %rax
    mov     %rax, QUIC_ACT_S_CODE(%r12)
    mov     S_FLAGS(%rbp), %rax
    and     $~SF_TELL_RESET, %rax
    or      $SF_TOLD_RESET, %rax
    mov     %rax, S_FLAGS(%rbp)
6:  mov     S_ACKED(%rbp), %rax             /* bytes the peer acknowledged */
    cmp     S_ACK_TOLD(%rbp), %rax
    je      61f
    call    quic_room
    cmp     $QUIC_ACT_ACKED_SIZE, %rax
    jb      8f
    mov     $QUIC_ACTION_STREAM_ACKED, %edi
    mov     $QUIC_ACT_ACKED_SIZE, %esi
    call    quic_action
    mov     %rax, %r12
    mov     %rbp, %rdi
    call    quic_stream_handle
    mov     %rax, QUIC_ACT_STREAM(%r12)
    mov     S_ACKED(%rbp), %rax
    mov     %rax, %rcx
    sub     S_ACK_TOLD(%rbp), %rcx
    mov     %rcx, QUIC_ACT_S_COUNT(%r12)
    mov     %rax, S_ACK_TOLD(%rbp)
61: call    quic_stream_credit
    mov     S_FLAGS(%rbp), %rax             /* over both ways? */
    test    $SF_FIN_ACKED, %rax
    jz      8f
    test    $SF_RX_DONE, %rax
    jz      8f
    test    $(SF_TOLD_FIN | SF_TOLD_RESET), %rax
    jz      8f
    test    $(SF_TELL_RESET | SF_RESET_SEND | SF_STOP_SEND), %rax
    jnz     8f
    test    $SF_LOCAL, %rax
    jnz     7f
    mov     C_PEER_DONE(%rbx), %rax         /* a stream of the peer is over: room for one more */
    inc     %rax
    mov     %rax, C_PEER_DONE(%rbx)
    CFG     %rcx, QUIC_CFG_MAX_STREAMS
    add     %rax, %rcx
    cmp     C_PEER_MAX(%rbx), %rcx
    jbe     7f
    mov     %rcx, C_PEER_MAX(%rbx)
    orq     $CF_MAX_STREAMS, C_FLAGS(%rbx)
7:  mov     %rbp, %rdi
    call    quic_stream_free
    mov     $1, %eax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_stream_tell

/*
 * quic_stream_credit(): new flow control credit: MAX_STREAM_DATA when half the
 * window of the stream is used, and MAX_DATA when half that of the
 * connection is. rbx the connection, rbp the stream.
 */
LOCAL_FUNCTION quic_stream_credit
    ENTER   0
    mov     S_FLAGS(%rbp), %rax
    test    $SF_RX_DONE, %rax
    jnz     1f
    cmpq    $-1, S_RX_FINAL(%rbp)
    jne     1f
    CFG     %rcx, QUIC_CFG_STREAM_DATA
    mov     S_RX_DONE(%rbp), %rdx
    mov     S_RX_MAX(%rbp), %r8
    sub     %rdx, %r8
    mov     %rcx, %r9
    shr     $1, %r9
    cmp     %r9, %r8
    jae     1f
    add     %rcx, %rdx
    mov     %rdx, S_RX_MAX(%rbp)
    or      $SF_MSD, %rax
    mov     %rax, S_FLAGS(%rbp)
1:  CFG     %rcx, QUIC_CFG_MAX_DATA
    mov     C_RX_DONE(%rbx), %rdx
    mov     C_RX_MAX(%rbx), %r8
    sub     %rdx, %r8
    mov     %rcx, %r9
    shr     $1, %r9
    cmp     %r9, %r8
    jae     9f
    add     %rcx, %rdx
    mov     %rdx, C_RX_MAX(%rbx)
    orq     $CF_MAX_DATA, C_FLAGS(%rbx)
9:  LEAVE   0
END_FUNCTION quic_stream_credit
