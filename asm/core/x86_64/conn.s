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
 * packets and the TLS block. rbx the connection, rbp the role, then the TLS block.
 */
LOCAL_FUNCTION quic_conn_new
    ENTER   0
    mov     %rdi, %rbp
    mov     $ST_CONN_OFF, %edi
    mov     $ST_CONN_COUNT, %esi
    mov     $C_SIZE, %edx
    call    quic_alloc_slot
    test    %rax, %rax
    jz      9f
    mov     %rax, %rbx
    movq    $CS_HANDSHAKE, C_STATE(%rbx)
    mov     %rbp, C_ROLE(%rbx)
    mov     $NONE, %rax
    mov     %rax, C_NCID_SEQ(%rbx)
    mov     %rax, C_RETIRE_SEQ(%rbx)
    mov     %rax, (C_RSCID + QUIC_CID_LENGTH)(%rbx)
    mov     %rax, C_PHASE_PN(%rbx)
    mov     %rax, C_PREV_UNTIL(%rbx)
    mov     %rax, C_STREAM_HEAD(%rbx)
    mov     %rax, C_RTT_FIRST(%rbx)
    mov     %rax, C_LOSS_AT(%rbx)
    mov     %rax, C_IDLE_AT(%rbx)
    mov     %rax, C_CLOSE_AT(%rbx)
    mov     %rax, C_PING_AT(%rbx)
    mov     %rax, C_SSTHRESH(%rbx)
    lea     C_SPACES(%rbx), %rcx
    mov     $3, %edx
1:  mov     %rax, SP_LARGEST_ACKED(%rcx)
    mov     %rax, SP_LARGEST_RECV(%rcx)
    mov     %rax, SP_ACK_AT(%rcx)
    mov     %rax, SP_LOSS_TIME(%rcx)
    mov     %rax, SP_LAST_ELICIT(%rcx)
    add     $SP_SIZE, %rcx
    dec     %edx
    jnz     1b
    movq    $INITIAL_WINDOW, C_CWND(%rbx)
    movq    $INITIAL_RTT, C_RTT_SMOOTH(%rbx)
    movq    $(INITIAL_RTT / 2), C_RTT_VAR(%rbx)
    movq    $25000, C_P_ACK_DELAY(%rbx)
    movq    $3, C_P_ACK_EXP(%rbx)
    mov     ST_NOW(%r15), %rax
    mov     %rax, C_START(%rbx)
    CFG     %rax, QUIC_CFG_MAX_DATA
    mov     %rax, C_RX_MAX(%rbx)
    CFG     %rax, QUIC_CFG_MAX_STREAMS
    mov     %rax, C_PEER_MAX(%rbx)
    CFG     %rax, QUIC_CFG_IDLE
    imul    $1000, %rax, %rax
    mov     %rax, C_IDLE_US(%rbx)
    /* Our connection ID. */
    mov     %rbx, %rdi
    call    quic_conn_index
    movw    %ax, C_LCID(%rbx)
    movl    C_GEN(%rbx), %eax
    movw    %ax, (C_LCID + 2)(%rbx)
    lea     (C_LCID + 4)(%rbx), %rdi
    mov     $4, %esi
    call    quic_random
    /* The ring of sent packets. */
    CFG     %rax, QUIC_CFG_SENT
    imul    $SR_SIZE, %rax, %rdi
    call    quic_heap_alloc
    test    %rax, %rax
    jz      8f
    mov     %rax, C_SENT(%rbx)
    mov     %rax, %rdi
    call    quic_heap_room
    shr     $7, %rax                        /* SR_SIZE is 128 */
    mov     %rax, C_SENT_CAP(%rbx)
    /* The TLS block. */
    mov     $T_SIZE, %edi
    call    quic_heap_alloc
    test    %rax, %rax
    jz      8f
    mov     %rax, C_TLS(%rbx)
    lea     (%r15,%rax), %rbp
    mov     %rbp, %rdi
    mov     $T_LIST, %esi
    call    quic_zero
    movq    $(QUIC_BL_FIXED + TRANSCRIPT_ROOM), (T_LIST + QUIC_BL_SIZE)(%rbp)
    movq    $QUIC_BL_FIXED, (T_LIST + QUIC_BL_OFFSET)(%rbp)
    movq    $0, (T_LIST + QUIC_BL_COUNT)(%rbp)
    mov     %rbx, %rax
    jmp     9f
8:  mov     %rbx, %rdi
    call    quic_conn_free
    xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_conn_new

/* quic_conn_free(conn): its heap blocks and streams go, and the slot is free. */
LOCAL_FUNCTION quic_conn_free
    ENTER   0
    mov     %rdi, %rbx
    mov     C_TLS(%rbx), %rdi
    call    quic_heap_free
    mov     C_SENT(%rbx), %rdi
    call    quic_heap_free
    mov     C_TOKEN(%rbx), %rdi
    call    quic_heap_free
    lea     C_SPACES(%rbx), %rbp
    mov     $3, %r12d
1:  mov     SP_CTX(%rbp), %rdi
    call    quic_heap_free
    mov     SP_CRX(%rbp), %rdi
    call    quic_heap_free
    movq    $0, SP_CTX(%rbp)
    movq    $0, SP_CRX(%rbp)
    add     $SP_SIZE, %rbp
    dec     %r12
    jnz     1b
2:  mov     C_STREAM_HEAD(%rbx), %rdi       /* every stream of the connection */
    cmp     $-1, %rdi
    je      3f
    call    quic_stream_at
    mov     %rax, %rdi
    call    quic_stream_free
    jmp     2b
3:  movq    $0, C_TLS(%rbx)
    movq    $0, C_SENT(%rbx)
    movq    $0, C_TOKEN(%rbx)
    movl    $0, C_USED(%rbx)
    LEAVE   0
END_FUNCTION quic_conn_free

/* quic_space(conn, space) -> the space record. A leaf. */
LOCAL_FUNCTION quic_space
    UNWIND_END_PROLOGUE
    imul    $SP_SIZE, %rsi, %rax
    lea     C_SPACES(%rdi,%rax), %rax
    ret
END_FUNCTION quic_space

/*
 * quic_conn_find(dcid, n) -> the connection whose own connection ID is the n
 * bytes at dcid, or 0. Our IDs are 8 bytes: the slot index first.
 */
LOCAL_FUNCTION quic_conn_find
    ENTER   0
    mov     %rdi, %rbx
    cmp     $8, %rsi
    jne     8f
    movzwl  (%rbx), %edi
    cmp     ST_CONN_COUNT(%r15), %rdi
    jae     8f
    call    quic_conn_at
    mov     %rax, %rbp
    cmpl    $0, C_USED(%rbp)
    je      8f
    mov     C_LCID(%rbp), %rax
    cmp     (%rbx), %rax
    jne     8f
    cmpq    $CS_DONE, C_STATE(%rbp)
    je      8f
    mov     %rbp, %rax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_conn_find

/*
 * quic_conn_find_odcid(dcid, n, socket, addr) -> the server connection still in
 * its handshake that the client began with this DCID from this address, or 0.
 * rbx dcid, rbp n, r12 socket, r13 addr, X23 index, X24 the connection.
 */
LOCAL_FUNCTION quic_conn_find_odcid
    ENTER   0
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     %rcx, %r13
    movq    $0, X23(%rsp)
1:  mov     X23(%rsp), %rdi
    cmp     ST_CONN_COUNT(%r15), %rdi
    jae     8f
    call    quic_conn_at
    mov     %rax, X24(%rsp)
    incq    X23(%rsp)
    cmpl    $0, C_USED(%rax)
    je      1b
    cmpq    $0, C_ROLE(%rax)
    je      1b
    cmpq    $CS_HANDSHAKE, C_STATE(%rax)
    jne     1b
    cmp     %r12, C_SOCKET(%rax)
    jne     1b
    mov     %rbx, %rdi
    mov     %rbp, %rsi
    lea     C_ODCID(%rax), %rdx
    call    quic_cid_is
    test    %rax, %rax
    jz      1b
    mov     X24(%rsp), %rdi
    add     $C_ADDR, %rdi
    mov     %r13, %rsi
    mov     $QUIC_ADDR_SIZE, %edx
    call    quic_equal
    test    %rax, %rax
    jz      1b
    mov     X24(%rsp), %rax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_conn_find_odcid

/*
 * quic_pto_period(conn, space) -> the probe timeout of RFC 9002 section 6.2.1:
 * smoothed_rtt + max(4 * rttvar, 1 ms), plus max_ack_delay in the Application
 * space, doubled for each PTO in a row. A leaf.
 */
LOCAL_FUNCTION quic_pto_period
    UNWIND_END_PROLOGUE
    mov     C_RTT_VAR(%rdi), %rax
    shl     $2, %rax
    cmp     $1000, %rax
    ja      1f
    mov     $1000, %eax
1:  add     C_RTT_SMOOTH(%rdi), %rax
    cmp     $SPACE_APP, %rsi
    jne     2f
    add     C_P_ACK_DELAY(%rdi), %rax
2:  mov     C_PTO_COUNT(%rdi), %rcx
    cmp     $16, %rcx
    jb      3f
    mov     $16, %ecx
3:  shl     %cl, %rax
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
    mov     %rdi, %rbx
    cmpq    $CS_CLOSING, C_STATE(%rbx)
    jae     9f
    mov     %rsi, C_ERROR(%rbx)
    cmpq    $0, C_REASON(%rbx)
    jne     1f                              /* a reason set before, such as PEER_ID, stays */
    mov     %rdx, C_REASON(%rbx)
1:  movq    $CS_CLOSING, C_STATE(%rbx)
    orq     $(CF_CLOSE_FRAME | CF_GONE), C_FLAGS(%rbx)
    mov     %rbx, %rdi
    call    quic_close_timer
9:  LEAVE   0
END_FUNCTION quic_conn_close

/*
 * quic_conn_drain(conn, error): the peer closed, or a stateless reset came: the
 * connection drains for three probe timeouts and sends nothing (RFC 9000
 * section 10.2.2).
 */
LOCAL_FUNCTION quic_conn_drain
    ENTER   0
    mov     %rdi, %rbx
    mov     C_STATE(%rbx), %rax
    cmp     $CS_DRAINING, %rax
    jae     9f
    cmp     $CS_CLOSING, %rax
    je      1f
    mov     %rsi, C_ERROR(%rbx)
1:  movq    $CS_DRAINING, C_STATE(%rbx)
    mov     C_FLAGS(%rbx), %rax
    or      $CF_GONE, %rax
    and     $~CF_CLOSE_FRAME, %rax
    mov     %rax, C_FLAGS(%rbx)
    mov     %rbx, %rdi
    call    quic_close_timer
9:  LEAVE   0
END_FUNCTION quic_conn_drain

/* quic_close_timer(conn): the end of closing or draining: now + 3 PTO. */
LOCAL_FUNCTION quic_close_timer
    ENTER   0
    mov     %rdi, %rbx
    mov     $SPACE_APP, %esi
    movq    $0, C_PTO_COUNT(%rbx)
    call    quic_pto_period
    lea     (%rax,%rax,2), %rax
    add     ST_NOW(%r15), %rax
    mov     %rax, C_CLOSE_AT(%rbx)
    movq    $NONE, C_LOSS_AT(%rbx)
    movq    $NONE, C_PING_AT(%rbx)
    LEAVE   0
END_FUNCTION quic_close_timer

/*
 * quic_discard_space(space): the keys of the space go (RFC 9001 section 4.9):
 * its packets leave bytes in flight, its CRYPTO buffers are freed, and the
 * probe count starts again (RFC 9002 section 6.2.2). rbx the connection.
 * rbp the space, r12 its record.
 */
LOCAL_FUNCTION quic_discard_space
    ENTER   0
    mov     %rdi, %rbp
    mov     %rbx, %rdi
    mov     %rbp, %rsi
    call    quic_space
    mov     %rax, %r12
    testq   $SPF_DISCARDED, SP_FLAGS(%r12)
    jnz     9f
    movq    $SPF_DISCARDED, SP_FLAGS(%r12)
    mov     %rbp, %rdi
    call    quic_drop_space_records
    mov     SP_CTX(%r12), %rdi
    call    quic_heap_free
    mov     SP_CRX(%r12), %rdi
    call    quic_heap_free
    movq    $0, SP_CTX(%r12)
    movq    $0, SP_CRX(%r12)
    movq    $0, SP_CTX_LEN(%r12)
    movq    $0, SP_CTX_SENT(%r12)
    movq    $0, SP_ACK_COUNT(%r12)
    movq    $NONE, SP_ACK_AT(%r12)
    movq    $NONE, SP_LOSS_TIME(%r12)
    movq    $NONE, SP_LAST_ELICIT(%r12)
    movq    $0, C_PTO_COUNT(%rbx)
    mov     %rbx, %rdi
    call    quic_set_loss_timer
9:  LEAVE   0
END_FUNCTION quic_discard_space

/*
 * quic_confirm(): the handshake is confirmed: the Handshake keys go and the TLS
 * block is freed. rbx the connection.
 */
LOCAL_FUNCTION quic_confirm
    ENTER   0
    orq     $CF_CONFIRMED, C_FLAGS(%rbx)
    mov     $SPACE_HANDSHAKE, %edi
    call    quic_discard_space
    mov     C_TLS(%rbx), %rdi
    call    quic_heap_free
    movq    $0, C_TLS(%rbx)
    LEAVE   0
END_FUNCTION quic_confirm

/*
 * quic_idle_reset(): the idle timer starts again (RFC 9000 section 10.1): the
 * smaller of our and the peer's max_idle_timeout, at least 3 PTO; none when
 * both are 0. rbx the connection. rbp the timeout.
 */
LOCAL_FUNCTION quic_idle_reset
    ENTER   0
    mov     C_IDLE_US(%rbx), %rbp
    mov     C_P_IDLE(%rbx), %rax
    imul    $1000, %rax, %rax
    test    %rbp, %rbp
    jz      1f
    test    %rax, %rax
    jz      2f
    cmp     %rbp, %rax
    jae     2f
    mov     %rax, %rbp
    jmp     2f
1:  mov     %rax, %rbp
2:  mov     $NONE, %rax
    test    %rbp, %rbp
    jz      3f
    mov     %rbx, %rdi
    mov     $SPACE_APP, %esi
    call    quic_pto_period
    lea     (%rax,%rax,2), %rax
    cmp     %rax, %rbp
    jae     4f
    mov     %rax, %rbp
4:  mov     ST_NOW(%r15), %rax
    add     %rbp, %rax
3:  mov     %rax, C_IDLE_AT(%rbx)
    /* The keep-alive PING. */
    CFG     %rax, QUIC_CFG_KEEP_ALIVE
    mov     $NONE, %rcx
    test    %rax, %rax
    jz      5f
    imul    $1000, %rax, %rax
    mov     ST_NOW(%r15), %rcx
    add     %rax, %rcx
5:  mov     %rcx, C_PING_AT(%rbx)
    LEAVE   0
END_FUNCTION quic_idle_reset
