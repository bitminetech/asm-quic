/*
 * The node: the state size and layout, init, and the step: event checks,
 * events, timers, what the application hears, datagrams out, and the wakeup.
 */

.set EVENT_ROOM, 256                    /* the action bytes an event may add itself */

/* ---------------------------------------------------------------- Layout */

/*
 * quic_layout(config) -> rax the state size, or 0 when the config breaks a
 * rule; rdx the stream table offset, rcx the heap offset. The connection
 * table is at ST_FIXED; the heap at a multiple of 64. A leaf.
 */
LOCAL_FUNCTION quic_layout
    UNWIND_END_PROLOGUE
    cmpq    $QUIC_CFG_SIZE, QUIC_CFG_SIZE_FIELD(%rdi)
    jb      8f
    cmpq    $QUIC_VERSION, QUIC_CFG_VERSION(%rdi)
    jne     8f
    mov     QUIC_CFG_KEY_TYPE(%rdi), %rax
    cmp     $QUIC_KEY_ED25519, %rax
    je      1f
    cmp     $QUIC_KEY_SECP256K1, %rax
    jne     8f
1:  mov     QUIC_CFG_CONNS(%rdi), %r8
    test    %r8, %r8
    jz      8f
    cmp     $65536, %r8
    jae     8f
    mov     QUIC_CFG_STREAMS(%rdi), %r9
    test    %r9, %r9
    jz      8f
    cmp     $(1 << 20), %r9
    ja      8f
    mov     QUIC_CFG_HEAP(%rdi), %r10
    cmp     $(1 << 16), %r10
    jb      8f
    movabs  $(1 << 40), %r11
    cmp     %r11, %r10
    ja      8f
    lea     -1(%r10), %rax
    test    %r10, %rax
    jnz     8f                              /* a power of two */
    cmp     %r11, QUIC_CFG_IDLE(%rdi)
    jae     8f
    mov     QUIC_CFG_HANDSHAKE(%rdi), %rax
    test    %rax, %rax
    jz      8f
    cmp     %r11, %rax
    jae     8f
    cmp     %r11, QUIC_CFG_KEEP_ALIVE(%rdi)
    jae     8f
    movabs  $(1 << 60), %r11
    cmp     %r11, QUIC_CFG_MAX_DATA(%rdi)
    jae     8f
    cmp     %r11, QUIC_CFG_STREAM_DATA(%rdi)
    jae     8f
    cmp     %r11, QUIC_CFG_MAX_STREAMS(%rdi)
    jae     8f
    cmpq    $0, QUIC_CFG_STREAM_QUEUE(%rdi)
    je      8f
    cmpq    $QUIC_CFG_ACCEPT, QUIC_CFG_FLAGS(%rdi)
    ja      8f
    cmpq    $(1 << 23), QUIC_CFG_KEY_UPDATE(%rdi)
    jae     8f
    mov     QUIC_CFG_SENT(%rdi), %rax
    cmp     $16, %rax
    jb      8f
    cmp     $65536, %rax
    ja      8f
    imul    $C_SIZE, %r8, %rdx
    add     $ST_FIXED, %rdx                 /* the stream table */
    imul    $S_SIZE, %r9, %rcx
    lea     63(%rcx,%rdx), %rcx
    and     $-64, %rcx                      /* the heap */
    lea     (%rcx,%r10), %rax
    ret
8:  xor     %eax, %eax
    ret
END_FUNCTION quic_layout

/* quic_state_size(config, size) -> status: the bytes of the state quic_init builds. */
FUNCTION quic_state_size
    ENTER   0
    mov     %rsi, %rbx
    call    quic_layout
    test    %rax, %rax
    jz      8f
    mov     %rax, (%rbx)
    mov     $QUIC_OK, %eax
    jmp     9f
8:  mov     $QUIC_INVALID_CONFIG, %eax
9:  LEAVE   0
END_FUNCTION quic_state_size

/*
 * quic_init(config, state) -> status: a node with no connections: the tables,
 * the heap as one free block, the DRBG from the seed, the host public key and
 * its protobuf, a P-256 key and our certificate.
 * rbx config, rbp state (also r15), r12 size, r13 stream table, X23 heap,
 * X24 the size field, then the public key length.
 */
.set IN_PUB, 0                          /* 72 bytes */
.set IN_FRAME, 80
FUNCTION quic_init
    ENTER   0, IN_FRAME
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rsi, %r15
    call    quic_layout
    mov     %rax, %r12
    mov     %rdx, %r13
    mov     %rcx, X23(%rsp)
    mov     $QUIC_INVALID_CONFIG, %eax
    test    %r12, %r12
    jz      9f
    mov     $QUIC_BUFFER_TOO_SMALL, %eax
    cmp     %r12, ST_SIZE(%rbp)
    jb      9f
    /* The host key: secp256k1 must be from 1 to n - 1. */
    cmpq    $QUIC_KEY_SECP256K1, QUIC_CFG_KEY_TYPE(%rbx)
    jne     1f
    lea     QUIC_CFG_KEY(%rbx), %rdi
    lea     (32 + IN_PUB)(%rsp), %rsi
    CALL_GLOBAL crypto_secp256k1_public_key
    mov     %rax, %rcx
    mov     $QUIC_INVALID_KEY, %eax
    test    %rcx, %rcx
    jnz     9f
1:  mov     ST_SIZE(%rbp), %rax             /* the state: zero, then its fields */
    mov     %rax, X24(%rsp)
    lea     8(%rbp), %rdi
    mov     X23(%rsp), %rsi
    sub     $8, %rsi
    call    quic_zero
    mov     X24(%rsp), %rax
    mov     %rax, ST_SIZE(%rbp)
    movq    $QUIC_VERSION, ST_VERSION(%rbp)
    lea     ST_CONFIG(%rbp), %rdi
    mov     %rbx, %rsi
    mov     $QUIC_CFG_SIZE, %edx
    call    quic_copy
    movq    $ST_FIXED, ST_CONN_OFF(%rbp)
    mov     QUIC_CFG_CONNS(%rbx), %rax
    mov     %rax, ST_CONN_COUNT(%rbp)
    mov     %r13, ST_STREAM_OFF(%rbp)
    mov     QUIC_CFG_STREAMS(%rbx), %rax
    mov     %rax, ST_STREAM_COUNT(%rbp)
    mov     X23(%rsp), %rax
    mov     %rax, ST_HEAP_OFF(%rbp)
    mov     QUIC_CFG_HEAP(%rbx), %rax
    mov     %rax, ST_HEAP_SIZE(%rbp)
    lea     ST_HEAP_FREE(%rbp), %rdi        /* the heap: one free block of the top order */
    mov     $64, %ecx
    mov     $NONE, %rax
    rep stosq
    bsf     ST_HEAP_SIZE(%rbp), %rcx        /* the order: log2 of the heap size */
    mov     X23(%rsp), %rdx
    add     %rbp, %rdx
    movl    %ecx, HB_ORDER(%rdx)
    movl    $1, HB_FREE(%rdx)
    movq    $NONE, HB_NEXT(%rdx)
    movq    $NONE, HB_PREV(%rdx)
    movq    $0, ST_HEAP_FREE(%rbp,%rcx,8)
    /* The DRBG key: the seed. */
    lea     ST_DRBG_KEY(%rbp), %rdi
    lea     QUIC_CFG_SEED(%rbx), %rsi
    mov     $32, %edx
    call    quic_copy
    /* The host public key and its protobuf: 0x08 type 0x12 length key. */
    lea     QUIC_CFG_KEY(%rbx), %rdi
    lea     ST_HOST_PUB(%rbp), %rsi
    cmpq    $QUIC_KEY_ED25519, QUIC_CFG_KEY_TYPE(%rbx)
    jne     3f
    CALL_GLOBAL crypto_ed25519_public_key
    movq    $32, X24(%rsp)
    jmp     4f
3:  CALL_GLOBAL crypto_secp256k1_public_key
    movq    $33, X24(%rsp)
4:  movb    $0x08, ST_HOST_PROTO(%rbp)
    mov     QUIC_CFG_KEY_TYPE(%rbx), %rax
    movb    %al, (ST_HOST_PROTO + 1)(%rbp)
    movb    $0x12, (ST_HOST_PROTO + 2)(%rbp)
    mov     X24(%rsp), %rdx
    movb    %dl, (ST_HOST_PROTO + 3)(%rbp)
    lea     (ST_HOST_PROTO + 4)(%rbp), %rdi
    lea     ST_HOST_PUB(%rbp), %rsi
    call    quic_copy
    mov     X24(%rsp), %rax
    add     $4, %rax
    mov     %rax, ST_HOST_PROTO_LEN(%rbp)
    /* The certificate key: drawn until it is from 1 to n - 1. */
5:  lea     ST_CERT_PRIV(%rbp), %rdi
    mov     $32, %esi
    call    quic_random
    lea     ST_CERT_PRIV(%rbp), %rdi
    lea     (32 + IN_PUB)(%rsp), %rsi
    CALL_GLOBAL crypto_p256_public_key
    test    %rax, %rax
    jnz     5b
    call    quic_cert_build
    mov     $QUIC_OK, %eax
9:  LEAVE   0, IN_FRAME
END_FUNCTION quic_init

/* ---------------------------------------------------------------- Event checks */

/* quic_check_addr(addr) -> 1 when the Address is IPv4 or IPv6 with a port below 65536. A leaf. */
LOCAL_FUNCTION quic_check_addr
    UNWIND_END_PROLOGUE
    mov     QUIC_ADDR_FAMILY(%rdi), %rcx
    cmp     $4, %rcx
    je      1f
    cmp     $6, %rcx
    jne     8f
1:  cmpq    $65536, QUIC_ADDR_PORT(%rdi)
    jae     8f
    mov     $1, %eax
    ret
8:  xor     %eax, %eax
    ret
END_FUNCTION quic_check_addr

/*
 * quic_check_event(event, room) -> 1 when the event is well formed within
 * room bytes: its size a multiple of 8 within room, a known kind, and the
 * fields of its kind. rbx event, rbp room, r12 size.
 */
LOCAL_FUNCTION quic_check_event
    ENTER   0
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    cmp     $16, %rbp
    jb      8f
    mov     QUIC_EV_SIZE(%rbx), %r12
    cmp     $16, %r12
    jb      8f
    test    $7, %r12
    jnz     8f
    cmp     %r12, %rbp
    jb      8f
    mov     QUIC_EV_KIND(%rbx), %rax
    cmp     $QUIC_EVENT_DATAGRAM, %rax
    je      1f
    cmp     $QUIC_EVENT_DIAL, %rax
    je      2f
    cmp     $QUIC_EVENT_OPEN_STREAM, %rax
    je      3f
    cmp     $QUIC_EVENT_STREAM_WRITE, %rax
    je      4f
    cmp     $QUIC_EVENT_STREAM_CLOSE, %rax
    je      5f
    cmp     $QUIC_EVENT_STREAM_RESET, %rax
    je      6f
    cmp     $QUIC_EVENT_CLOSE, %rax
    je      6f
    jmp     8f
1:  cmp     $QUIC_EV_DATA, %r12             /* DATAGRAM */
    jb      8f
    mov     QUIC_EV_COUNT(%rbx), %rax
    cmp     $65536, %rax
    jae     8f
    add     $QUIC_EV_DATA, %rax
    cmp     %rax, %r12
    jb      8f
    lea     QUIC_EV_ADDR(%rbx), %rdi
    call    quic_check_addr
    jmp     9f
2:  cmp     $QUIC_EV_DIAL_SIZE, %r12        /* DIAL */
    jne     8f
    cmpq    $QUIC_PEER_MAX, QUIC_EV_PEER_LEN(%rbx)
    ja      8f
    lea     QUIC_EV_DIAL_ADDR(%rbx), %rdi
    call    quic_check_addr
    jmp     9f
3:  cmp     $QUIC_EV_OPEN_SIZE, %r12
    jne     8f
    jmp     7f
4:  cmp     $QUIC_EV_WRITE_DATA, %r12       /* STREAM_WRITE */
    jb      8f
    mov     %r12, %rax
    sub     $QUIC_EV_WRITE_DATA, %rax
    cmp     QUIC_EV_WRITE_COUNT(%rbx), %rax
    jb      8f
    jmp     7f
5:  cmp     $QUIC_EV_STREAM_SIZE, %r12
    jne     8f
    jmp     7f
6:  cmp     $QUIC_EV_CLOSE_SIZE, %r12       /* STREAM_RESET, CLOSE: a code below 2^62 */
    jne     8f
    mov     QUIC_EV_CODE(%rbx), %rax
    shr     $62, %rax
    jnz     8f
7:  mov     $1, %eax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_check_event

/* ---------------------------------------------------------------- The step */

/*
 * quic_step(state, tick, events, scratch, actions, result) -> status: the
 * events in order while the action room allows, the timers, what the
 * application hears, the datagrams, and one WAKEUP last.
 * r15 state, r14 scratch; rbx tick, rbp events, r12 actions, r13 result,
 * X23 position, X24 end, X25 handled.
 */
FUNCTION quic_step
    ENTER   0
    mov     %rdi, %r15
    mov     %rsi, %rbx
    mov     %rdx, %rbp
    mov     %rcx, %r14
    mov     %r8, %r12
    mov     %r9, %r13
    mov     $QUIC_BUFFER_TOO_SMALL, %eax
    cmpq    $QUIC_SCRATCH_SIZE, SC_SIZE(%r14)
    jb      9f
    cmpq    $(QUIC_BL_FIXED + QUIC_ACTIONS_MIN), QUIC_BL_SIZE(%r12)
    jb      9f
    /* Every event first. */
    mov     $QUIC_INVALID_EVENT, %eax
    mov     QUIC_BL_OFFSET(%rbp), %rcx
    mov     QUIC_BL_COUNT(%rbp), %rdx
    mov     QUIC_BL_SIZE(%rbp), %rsi
    cmp     $QUIC_BL_FIXED, %rcx
    jb      9f
    test    $7, %rcx
    jnz     9f
    cmp     %rcx, %rsi
    jb      9f
    sub     %rcx, %rsi
    cmp     %rdx, %rsi
    jb      9f
    add     %rbp, %rcx
    mov     %rcx, X23(%rsp)
    add     %rcx, %rdx
    mov     %rdx, X24(%rsp)
1:  mov     X23(%rsp), %rdi
    mov     X24(%rsp), %rsi
    cmp     %rsi, %rdi
    jae     2f
    sub     %rdi, %rsi
    call    quic_check_event
    test    %rax, %rax
    jz      8f
    mov     X23(%rsp), %rdi
    mov     QUIC_EV_SIZE(%rdi), %rax
    add     %rax, X23(%rsp)
    jmp     1b
2:  /* Commit: nothing fails from here. */
    mov     %r12, SC_ACTIONS(%r14)
    movq    $QUIC_BL_FIXED, QUIC_BL_OFFSET(%r12)
    movq    $0, QUIC_BL_COUNT(%r12)
    movq    $QUIC_ACT_WAKEUP_SIZE, SC_RESERVE(%r14)
    movq    $NONE, SC_WAKE(%r14)
    mov     QUIC_TICK_NOW(%rbx), %rax
    mov     ST_NOW(%r15), %rcx
    cmp     %rax, %rcx
    jb      21f
    mov     %rcx, %rax
21: mov     %rax, ST_NOW(%r15)
    mov     QUIC_TICK_UNIX(%rbx), %rax
    mov     %rax, ST_UNIX(%r15)
    lea     QUIC_TICK_ENTROPY(%rbx), %rdi
    call    quic_reseed
    movq    $0, X25(%rsp)
    mov     QUIC_BL_OFFSET(%rbp), %rax
    add     %rbp, %rax
    mov     %rax, X23(%rsp)
3:  mov     X23(%rsp), %rax
    cmp     X24(%rsp), %rax
    jae     4f
    call    quic_room
    cmp     $EVENT_ROOM, %rax
    jb      4f
    mov     X23(%rsp), %rdi
    call    quic_event
    mov     X23(%rsp), %rdi
    mov     QUIC_EV_SIZE(%rdi), %rax
    add     %rax, X23(%rsp)
    incq    X25(%rsp)
    jmp     3b
4:  mov     X25(%rsp), %rax
    mov     %rax, QUIC_RESULT_HANDLED(%r13)
    call    quic_connections
    mov     X23(%rsp), %rax
    cmp     X24(%rsp), %rax
    jae     5f                              /* events left: the next step is due now */
    mov     ST_NOW(%r15), %rdi
    call    quic_wake_at
5:  movq    $0, SC_RESERVE(%r14)
    mov     $QUIC_ACTION_WAKEUP, %edi
    mov     $QUIC_ACT_WAKEUP_SIZE, %esi
    call    quic_action
    mov     SC_WAKE(%r14), %rcx
    mov     ST_NOW(%r15), %rdx
    add     $60000000, %rdx
    cmp     %rdx, %rcx
    jb      51f
    mov     %rdx, %rcx
51: mov     %rcx, QUIC_ACT_TIME(%rax)
    mov     $QUIC_OK, %eax
    jmp     9f
8:  mov     $QUIC_INVALID_EVENT, %eax
9:  LEAVE   0
END_FUNCTION quic_step

/* quic_event(event): hands one event to the function of its kind. */
LOCAL_FUNCTION quic_event
    FRAME
    mov     QUIC_EV_KIND(%rdi), %rax
    cmp     $QUIC_EVENT_DATAGRAM, %rax
    jne     1f
    call    quic_on_datagram
    jmp     9f
1:  cmp     $QUIC_EVENT_DIAL, %rax
    jne     2f
    call    quic_on_dial
    jmp     9f
2:  cmp     $QUIC_EVENT_OPEN_STREAM, %rax
    jne     3f
    call    quic_on_open_stream
    jmp     9f
3:  cmp     $QUIC_EVENT_STREAM_WRITE, %rax
    jne     4f
    call    quic_on_stream_write
    jmp     9f
4:  cmp     $QUIC_EVENT_STREAM_CLOSE, %rax
    jne     5f
    call    quic_on_stream_close
    jmp     9f
5:  cmp     $QUIC_EVENT_STREAM_RESET, %rax
    jne     6f
    call    quic_on_stream_reset
    jmp     9f
6:  call    quic_on_close
9:  UNFRAME
END_FUNCTION quic_event

/*
 * quic_on_dial(event): a client connection: a random first DCID of 8 bytes,
 * its Initial keys, and a ClientHello; DIAL_FAILED with QUIC_ERR_LIMIT when
 * no slot or heap is free. rbx the connection, rbp the TLS block, X23 the event.
 */
LOCAL_FUNCTION quic_on_dial
    ENTER   0
    mov     %rdi, X23(%rsp)
    xor     %edi, %edi
    call    quic_conn_new
    test    %rax, %rax
    jz      8f
    mov     %rax, %rbx
    mov     X23(%rsp), %rcx
    mov     QUIC_EV_TAG(%rcx), %rax
    mov     %rax, C_TAG(%rbx)
    mov     QUIC_EV_DIAL_SOCKET(%rcx), %rax
    mov     %rax, C_SOCKET(%rbx)
    lea     C_ADDR(%rbx), %rdi
    lea     QUIC_EV_DIAL_ADDR(%rcx), %rsi
    mov     $QUIC_ADDR_SIZE, %edx
    call    quic_copy
    movq    $8, (C_ODCID + QUIC_CID_LENGTH)(%rbx)
    lea     (C_ODCID + QUIC_CID_ID)(%rbx), %rdi
    mov     $8, %esi
    call    quic_random
    lea     C_RCID(%rbx), %rdi
    lea     C_ODCID(%rbx), %rsi
    mov     $QUIC_CID_SIZE, %edx
    call    quic_copy
    lea     C_ODCID(%rbx), %rdi
    call    quic_initial_install
    mov     C_TLS(%rbx), %rbp
    add     %r15, %rbp
    mov     X23(%rsp), %rsi
    mov     QUIC_EV_PEER_LEN(%rsi), %rdx
    mov     %rdx, T_PID_LEN(%rbp)
    lea     T_PID(%rbp), %rdi
    add     $QUIC_EV_PEER, %rsi
    call    quic_copy
    call    quic_tls_start
    test    %rax, %rax
    jz      1f
    mov     %rax, %rsi
    mov     %rbx, %rdi
    mov     $QUIC_ERR_PROTOCOL, %edx
    call    quic_conn_close
1:  call    quic_idle_reset
    jmp     9f
8:  mov     $QUIC_ACTION_DIAL_FAILED, %edi
    mov     $QUIC_ACT_CLOSED_SIZE, %esi
    call    quic_action
    test    %rax, %rax
    jz      9f
    mov     X23(%rsp), %rcx
    mov     QUIC_EV_TAG(%rcx), %rdx
    mov     %rdx, QUIC_ACT_TAG(%rax)
    movq    $QUIC_ERR_LIMIT, QUIC_ACT_REASON(%rax)
9:  LEAVE   0
END_FUNCTION quic_on_dial

/* quic_on_close(event): the application closes the connection with its code. rbx the connection, rbp the event. */
LOCAL_FUNCTION quic_on_close
    ENTER   0
    mov     %rdi, %rbp
    mov     QUIC_EV_CONN(%rbp), %rdi
    call    quic_conn
    test    %rax, %rax
    jz      9f
    mov     %rax, %rbx
    cmpq    $CS_CLOSING, C_STATE(%rbx)
    jae     9f
    orq     $CF_APP_CLOSE, C_FLAGS(%rbx)
    mov     %rbx, %rdi
    mov     QUIC_EV_CODE(%rbp), %rsi
    mov     $QUIC_ERR_LOCAL, %edx
    call    quic_conn_close
9:  LEAVE   0
END_FUNCTION quic_on_close

/* ---------------------------------------------------------------- Connections each step */

/*
 * quic_connections(): for each connection in use: its timers, what the
 * application hears, its datagrams, its deadline; a connection that is over
 * is freed once the application heard it.
 * rbp index, rbx the connection.
 */
LOCAL_FUNCTION quic_connections
    ENTER   0
    xor     %ebp, %ebp
1:  cmp     ST_CONN_COUNT(%r15), %rbp
    jae     9f
    mov     %rbp, %rdi
    call    quic_conn_at
    mov     %rax, %rbx
    inc     %rbp
    cmpl    $0, C_USED(%rbx)
    je      1b
    call    quic_conn_timers
    call    quic_conn_tell
    cmpq    $CS_DONE, C_STATE(%rbx)
    jne     2f
    testq   $CF_GONE, C_FLAGS(%rbx)
    jnz     3f                              /* not heard yet: wait */
    mov     %rbx, %rdi
    call    quic_conn_free
    jmp     1b
2:  call    quic_conn_output
3:  call    quic_conn_deadline
    jmp     1b
9:  LEAVE   0
END_FUNCTION quic_connections

/*
 * quic_conn_timers(): the end of closing or draining, the handshake deadline,
 * the idle timeout, the loss detection timer, the keep-alive and the end of
 * the previous receive keys. rbx the connection, rbp now.
 */
LOCAL_FUNCTION quic_conn_timers
    ENTER   0
    mov     ST_NOW(%r15), %rbp
    mov     C_STATE(%rbx), %rax
    cmp     $CS_DONE, %rax
    je      9f
    cmp     $CS_CLOSING, %rax
    jb      1f
    cmp     C_CLOSE_AT(%rbx), %rbp
    jb      9f
    movq    $CS_DONE, C_STATE(%rbx)
    jmp     9f
1:  testq   $CF_COMPLETE, C_FLAGS(%rbx)
    jnz     2f
    CFG     %rax, QUIC_CFG_HANDSHAKE
    imul    $1000, %rax, %rax
    add     C_START(%rbx), %rax
    cmp     %rax, %rbp
    jb      2f
    mov     $QUIC_ERR_HANDSHAKE_TIMEOUT, %eax
    jmp     5f
2:  cmp     C_IDLE_AT(%rbx), %rbp
    jb      3f
    mov     $QUIC_ERR_IDLE, %eax
5:  cmpq    $0, C_REASON(%rbx)              /* silently over */
    jne     51f
    mov     %rax, C_REASON(%rbx)
51: movq    $CS_DONE, C_STATE(%rbx)
    orq     $CF_GONE, C_FLAGS(%rbx)
    jmp     9f
3:  cmp     C_LOSS_AT(%rbx), %rbp
    jb      4f
    call    quic_on_loss_timer
4:  cmp     C_PING_AT(%rbx), %rbp
    jb      6f
    movq    $NONE, C_PING_AT(%rbx)
    cmpq    $CS_ACTIVE, C_STATE(%rbx)
    jne     6f
    orq     $CF_PING, C_FLAGS(%rbx)
6:  cmp     C_PREV_UNTIL(%rbx), %rbp
    jb      7f
    movq    $NONE, C_PREV_UNTIL(%rbx)
7:  call    quic_maybe_key_update
9:  LEAVE   0
END_FUNCTION quic_conn_timers

/*
 * quic_maybe_key_update(): we start a key update (RFC 9001 section 6) once the
 * current key phase carried QUIC_CFG_KEY_UPDATE packets (1000000 when 0, far
 * below the 2^23 packets AES-128-GCM may protect), the handshake is
 * confirmed, the previous keys are gone, and the peer acknowledged a packet
 * of the current phase. rbx the connection.
 */
LOCAL_FUNCTION quic_maybe_key_update
    FRAME
    cmpq    $CS_ACTIVE, C_STATE(%rbx)
    jne     9f
    testq   $CF_CONFIRMED, C_FLAGS(%rbx)
    jz      9f
    cmpq    $-1, C_PREV_UNTIL(%rbx)
    jne     9f
    CFG     %rcx, QUIC_CFG_KEY_UPDATE
    test    %rcx, %rcx
    jnz     1f
    mov     $1000000, %ecx
1:  cmp     %rcx, C_PHASE_SENT(%rbx)
    jb      9f
    mov     (C_SPACES + 2 * SP_SIZE + SP_LARGEST_ACKED)(%rbx), %rax
    cmp     $-1, %rax
    je      9f
    cmp     C_PHASE_FIRST(%rbx), %rax
    jb      9f
    call    quic_key_update
    call    quic_phase_start
9:  UNFRAME
END_FUNCTION quic_maybe_key_update

/*
 * quic_phase_start(): after a key update: our first packet number of the new
 * phase, and the previous receive keys stay for 3 PTO. rbx the connection.
 */
LOCAL_FUNCTION quic_phase_start
    FRAME
    mov     (C_SPACES + 2 * SP_SIZE + SP_NEXT_PN)(%rbx), %rax
    mov     %rax, C_PHASE_FIRST(%rbx)
    mov     %rbx, %rdi
    mov     $SPACE_APP, %esi
    call    quic_pto_period
    lea     (%rax,%rax,2), %rax
    add     ST_NOW(%r15), %rax
    mov     %rax, C_PREV_UNTIL(%rbx)
    UNFRAME
END_FUNCTION quic_phase_start

/*
 * quic_conn_tell(): CONNECTED, then the stream actions, then CLOSED or
 * DIAL_FAILED, while the action room allows. rbx the connection,
 * rbp the action, then the next stream.
 */
LOCAL_FUNCTION quic_conn_tell
    ENTER   0
    mov     C_FLAGS(%rbx), %rax
    test    $CF_TELL, %rax
    jz      2f
    test    $CF_KNOWN, %rax
    jnz     2f
    cmpq    $CS_ACTIVE, C_STATE(%rbx)
    jne     2f
    call    quic_room
    cmp     $QUIC_ACT_CONNECTED_SIZE, %rax
    jb      9f
    mov     $QUIC_ACTION_CONNECTED, %edi
    mov     $QUIC_ACT_CONNECTED_SIZE, %esi
    call    quic_action
    mov     %rax, %rbp
    mov     %rbx, %rdi
    call    quic_conn_handle
    mov     %rax, QUIC_ACT_CONN(%rbp)
    mov     C_TAG(%rbx), %rax
    mov     %rax, QUIC_ACT_TAG(%rbp)
    mov     C_ROLE(%rbx), %rax
    xor     $1, %rax
    mov     %rax, QUIC_ACT_DIRECTION(%rbp)
    mov     C_SOCKET(%rbx), %rax
    mov     %rax, QUIC_ACT_C_SOCKET(%rbp)
    lea     QUIC_ACT_C_ADDR(%rbp), %rdi
    lea     C_ADDR(%rbx), %rsi
    mov     $QUIC_ADDR_SIZE, %edx
    call    quic_copy
    mov     C_PEER_KEY_LEN(%rbx), %rdx
    mov     %rdx, QUIC_ACT_KEY_LEN(%rbp)
    lea     QUIC_ACT_KEY(%rbp), %rdi
    lea     C_PEER_KEY(%rbx), %rsi
    call    quic_copy
    mov     C_FLAGS(%rbx), %rax
    or      $CF_KNOWN, %rax
    and     $~CF_TELL, %rax
    mov     %rax, C_FLAGS(%rbx)
2:  testq   $CF_KNOWN, C_FLAGS(%rbx)        /* the streams */
    jz      4f
    cmpq    $CS_ACTIVE, C_STATE(%rbx)
    jne     4f
    mov     C_STREAM_HEAD(%rbx), %rbp
3:  cmp     $-1, %rbp
    je      4f
    mov     %rbp, %rdi
    call    quic_stream_at
    mov     S_NEXT(%rax), %rbp
    mov     %rax, %rdi
    call    quic_stream_tell
    jmp     3b
4:  mov     C_FLAGS(%rbx), %rax             /* the end */
    test    $CF_GONE, %rax
    jz      9f
    cmpq    $CS_CLOSING, C_STATE(%rbx)
    jb      9f
    test    $CF_KNOWN, %rax
    jnz     5f
    cmpq    $0, C_ROLE(%rbx)
    jne     7f                              /* a peer's connection that never came up: nothing to tell */
    call    quic_room
    cmp     $QUIC_ACT_CLOSED_SIZE, %rax
    jb      9f
    mov     $QUIC_ACTION_DIAL_FAILED, %edi
    mov     $QUIC_ACT_CLOSED_SIZE, %esi
    call    quic_action
    mov     %rax, %rbp
    mov     C_TAG(%rbx), %rax
    mov     %rax, QUIC_ACT_TAG(%rbp)
    jmp     6f
5:  call    quic_room
    cmp     $QUIC_ACT_CLOSED_SIZE, %rax
    jb      9f
    mov     $QUIC_ACTION_CLOSED, %edi
    mov     $QUIC_ACT_CLOSED_SIZE, %esi
    call    quic_action
    mov     %rax, %rbp
    mov     %rbx, %rdi
    call    quic_conn_handle
    mov     %rax, QUIC_ACT_CONN(%rbp)
    mov     C_TAG(%rbx), %rax
    mov     %rax, QUIC_ACT_TAG(%rbp)
6:  mov     C_REASON(%rbx), %rax
    mov     %rax, QUIC_ACT_REASON(%rbp)
    mov     C_ERROR(%rbx), %rax
    mov     %rax, QUIC_ACT_ERROR(%rbp)
7:  andq    $~CF_GONE, C_FLAGS(%rbx)
9:  LEAVE   0
END_FUNCTION quic_conn_tell

/*
 * quic_conn_deadline(): the earliest timer of the connection becomes a
 * wakeup: loss detection, idle, closing, keep-alive, a delayed ACK, the
 * handshake deadline, and the end of the previous keys. rbx the connection.
 */
LOCAL_FUNCTION quic_conn_deadline
    FRAME
    cmpq    $CS_DONE, C_STATE(%rbx)
    jne     1f
    mov     ST_NOW(%r15), %rdi              /* over, waiting to be heard */
    call    quic_wake_at
    jmp     9f
1:  mov     C_LOSS_AT(%rbx), %rdi
    call    quic_wake_at
    mov     C_IDLE_AT(%rbx), %rdi
    call    quic_wake_at
    mov     C_CLOSE_AT(%rbx), %rdi
    call    quic_wake_at
    mov     C_PING_AT(%rbx), %rdi
    call    quic_wake_at
    mov     C_PREV_UNTIL(%rbx), %rdi
    call    quic_wake_at
    mov     (C_SPACES + 2 * SP_SIZE + SP_ACK_AT)(%rbx), %rdi
    call    quic_wake_at
    testq   $CF_COMPLETE, C_FLAGS(%rbx)
    jnz     9f
    CFG     %rdi, QUIC_CFG_HANDSHAKE
    imul    $1000, %rdi, %rdi
    add     C_START(%rbx), %rdi
    call    quic_wake_at
9:  UNFRAME
END_FUNCTION quic_conn_deadline
