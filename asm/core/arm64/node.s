/*
 * The node: the state size and layout, init, and the step: event checks,
 * events, timers, what the application hears, datagrams out, and the wakeup.
 */

.set EVENT_ROOM, 256                    /* the action bytes an event may add itself */

/* ---------------------------------------------------------------- Layout */

/*
 * quic_layout(config) -> x0 the state size, or 0 when the config breaks a rule;
 * x1 the stream table offset, x2 the heap offset. The connection table is at
 * ST_FIXED; the heap at a multiple of 64.
 */
LOCAL_FUNCTION quic_layout
    UNWIND_END_PROLOGUE
    ldr     x9, [x0, #QUIC_CFG_SIZE_FIELD]
    cmp     x9, #QUIC_CFG_SIZE
    b.lo    8f
    ldr     x9, [x0, #QUIC_CFG_VERSION]
    cmp     x9, #QUIC_VERSION
    b.ne    8f
    ldr     x9, [x0, #QUIC_CFG_KEY_TYPE]
    cmp     x9, #QUIC_KEY_ED25519
    b.eq    1f
    cmp     x9, #QUIC_KEY_SECP256K1
    b.ne    8f
1:  ldr     x9, [x0, #QUIC_CFG_CONNS]
    cbz     x9, 8f
    mov     x10, #65536
    cmp     x9, x10
    b.hs    8f
    ldr     x10, [x0, #QUIC_CFG_STREAMS]
    cbz     x10, 8f
    mov     x11, #(1 << 20)
    cmp     x10, x11
    b.hi    8f
    ldr     x11, [x0, #QUIC_CFG_HEAP]
    mov     x12, #(1 << 16)
    cmp     x11, x12
    b.lo    8f
    mov     x12, #1
    lsl     x12, x12, #40
    cmp     x11, x12
    b.hi    8f
    sub     x12, x11, #1
    tst     x11, x12
    b.ne    8f                              /* a power of two */
    ldr     x12, [x0, #QUIC_CFG_IDLE]
    MOV64   x13, (1 << 40)
    cmp     x12, x13
    b.hs    8f
    ldr     x12, [x0, #QUIC_CFG_HANDSHAKE]
    cbz     x12, 8f
    cmp     x12, x13
    b.hs    8f
    ldr     x12, [x0, #QUIC_CFG_KEEP_ALIVE]
    cmp     x12, x13
    b.hs    8f
    mov     x13, #1
    lsl     x13, x13, #60
    ldr     x12, [x0, #QUIC_CFG_MAX_DATA]
    cmp     x12, x13
    b.hs    8f
    ldr     x12, [x0, #QUIC_CFG_STREAM_DATA]
    cmp     x12, x13
    b.hs    8f
    ldr     x12, [x0, #QUIC_CFG_MAX_STREAMS]
    cmp     x12, x13
    b.hs    8f
    ldr     x12, [x0, #QUIC_CFG_STREAM_QUEUE]
    cbz     x12, 8f
    ldr     x12, [x0, #QUIC_CFG_FLAGS]
    cmp     x12, #QUIC_CFG_ACCEPT
    b.hi    8f
    ldr     x12, [x0, #QUIC_CFG_KEY_UPDATE]
    mov     x13, #(1 << 23)
    cmp     x12, x13
    b.hs    8f
    ldr     x12, [x0, #QUIC_CFG_SENT]
    cmp     x12, #16
    b.lo    8f
    mov     x13, #65536
    cmp     x12, x13
    b.hi    8f
    mov     x13, #C_SIZE
    mul     x1, x9, x13
    add     x1, x1, #ST_FIXED               /* the stream table */
    mov     x13, #S_SIZE
    madd    x2, x10, x13, x1
    add     x2, x2, #63
    and     x2, x2, #~63                    /* the heap */
    add     x0, x2, x11
    ret
8:  mov     x0, #0
    ret
END_FUNCTION quic_layout

/* quic_state_size(config, size) -> status: the bytes of the state quic_init builds. */
FUNCTION quic_state_size
    ENTER   0
    mov     x19, x1
    bl      quic_layout
    cbz     x0, 8f
    str     x0, [x19]
    mov     x0, #QUIC_OK
    b       9f
8:  mov     x0, #QUIC_INVALID_CONFIG
9:  LEAVE   0
END_FUNCTION quic_state_size

/*
 * quic_init(config, state) -> status: a node with no connections: the tables,
 * the heap as one free block, the DRBG from the seed, the host public key and
 * its protobuf, a P-256 key and our certificate.
 * x19 config, x20 state (also x27), x21 size, x22 stream table, x23 heap.
 */
.set IN_PUB, 0                          /* 72 bytes */
.set IN_FRAME, 80
FUNCTION quic_init
    ENTER   0, IN_FRAME
    mov     x19, x0
    mov     x20, x1
    mov     x27, x1
    bl      quic_layout
    mov     x21, x0
    mov     x22, x1
    mov     x23, x2
    mov     x0, #QUIC_INVALID_CONFIG
    cbz     x21, 9f
    ldr     x9, [x20, #ST_SIZE]
    mov     x0, #QUIC_BUFFER_TOO_SMALL
    cmp     x9, x21
    b.lo    9f
    /* The host key: secp256k1 must be from 1 to n - 1. */
    ldr     x9, [x19, #QUIC_CFG_KEY_TYPE]
    cmp     x9, #QUIC_KEY_SECP256K1
    b.ne    1f
    add     x0, x19, #QUIC_CFG_KEY
    add     x1, sp, #IN_PUB
    CALL_GLOBAL crypto_secp256k1_public_key
    mov     x9, x0
    mov     x0, #QUIC_INVALID_KEY
    cbnz    x9, 9f
1:  ldr     x24, [x20, #ST_SIZE]            /* the state: zero, then its fields */
    add     x0, x20, #8
    sub     x1, x23, #8
    bl      quic_zero
    str     x24, [x20, #ST_SIZE]
    mov     x9, #QUIC_VERSION
    str     x9, [x20, #ST_VERSION]
    add     x0, x20, #ST_CONFIG
    mov     x1, x19
    mov     x2, #QUIC_CFG_SIZE
    bl      quic_copy
    mov     x9, #ST_FIXED
    str     x9, [x20, #ST_CONN_OFF]
    ldr     x9, [x19, #QUIC_CFG_CONNS]
    str     x9, [x20, #ST_CONN_COUNT]
    str     x22, [x20, #ST_STREAM_OFF]
    ldr     x9, [x19, #QUIC_CFG_STREAMS]
    str     x9, [x20, #ST_STREAM_COUNT]
    str     x23, [x20, #ST_HEAP_OFF]
    ldr     x9, [x19, #QUIC_CFG_HEAP]
    str     x9, [x20, #ST_HEAP_SIZE]
    add     x10, x20, #ST_HEAP_FREE         /* the heap: one free block of the top order */
    mov     x11, #64
    mov     x12, #NONE
2:  str     x12, [x10], #8
    subs    x11, x11, #1
    b.ne    2b
    rbit    x13, x9
    clz     x13, x13
    add     x14, x20, x23
    str     w13, [x14, #HB_ORDER]
    mov     w15, #1
    str     w15, [x14, #HB_FREE]
    str     x12, [x14, #HB_NEXT]
    str     x12, [x14, #HB_PREV]
    add     x10, x20, #ST_HEAP_FREE
    str     xzr, [x10, x13, lsl #3]
    /* The DRBG key: the seed. */
    ldp     x9, x10, [x19, #QUIC_CFG_SEED]
    stp     x9, x10, [x20, #ST_DRBG_KEY]
    ldp     x9, x10, [x19, #(QUIC_CFG_SEED + 16)]
    stp     x9, x10, [x20, #(ST_DRBG_KEY + 16)]
    /* The host public key and its protobuf: 0x08 type 0x12 length key. */
    ldr     x9, [x19, #QUIC_CFG_KEY_TYPE]
    cmp     x9, #QUIC_KEY_ED25519
    b.ne    3f
    add     x0, x19, #QUIC_CFG_KEY
    add     x1, x20, #ST_HOST_PUB
    CALL_GLOBAL crypto_ed25519_public_key
    mov     x24, #32
    b       4f
3:  add     x0, x19, #QUIC_CFG_KEY
    add     x1, x20, #ST_HOST_PUB
    CALL_GLOBAL crypto_secp256k1_public_key
    mov     x24, #33
4:  mov     w9, #0x08
    strb    w9, [x20, #ST_HOST_PROTO]
    ldr     x9, [x19, #QUIC_CFG_KEY_TYPE]
    strb    w9, [x20, #(ST_HOST_PROTO + 1)]
    mov     w9, #0x12
    strb    w9, [x20, #(ST_HOST_PROTO + 2)]
    strb    w24, [x20, #(ST_HOST_PROTO + 3)]
    add     x0, x20, #(ST_HOST_PROTO + 4)
    add     x1, x20, #ST_HOST_PUB
    mov     x2, x24
    bl      quic_copy
    add     x9, x24, #4
    str     x9, [x20, #ST_HOST_PROTO_LEN]
    /* The certificate key: drawn until it is from 1 to n - 1. */
5:  add     x0, x20, #ST_CERT_PRIV
    mov     x1, #32
    bl      quic_random
    add     x0, x20, #ST_CERT_PRIV
    add     x1, sp, #IN_PUB
    CALL_GLOBAL crypto_p256_public_key
    cbnz    x0, 5b
    bl      quic_cert_build
    mov     x0, #QUIC_OK
9:  LEAVE   0, IN_FRAME
END_FUNCTION quic_init

/* ---------------------------------------------------------------- Event checks */

/* quic_check_addr(addr) -> 1 when the Address is IPv4 or IPv6 with a port below 65536. A leaf. */
LOCAL_FUNCTION quic_check_addr
    UNWIND_END_PROLOGUE
    ldr     x1, [x0, #QUIC_ADDR_FAMILY]
    cmp     x1, #4
    b.eq    1f
    cmp     x1, #6
    b.ne    8f
1:  ldr     x1, [x0, #QUIC_ADDR_PORT]
    mov     x2, #65536
    cmp     x1, x2
    b.hs    8f
    mov     x0, #1
    ret
8:  mov     x0, #0
    ret
END_FUNCTION quic_check_addr

/*
 * quic_check_event(event, room) -> 1 when the event is well formed within
 * room bytes: its size a multiple of 8 within room, a known kind, and the
 * fields of its kind.
 */
LOCAL_FUNCTION quic_check_event
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    cmp     x20, #16
    b.lo    8f
    ldr     x21, [x19, #QUIC_EV_SIZE]
    cmp     x21, #16
    b.lo    8f
    tst     x21, #7
    b.ne    8f
    cmp     x21, x20
    b.hi    8f
    ldr     x9, [x19, #QUIC_EV_KIND]
    cmp     x9, #QUIC_EVENT_DATAGRAM
    b.eq    1f
    cmp     x9, #QUIC_EVENT_DIAL
    b.eq    2f
    cmp     x9, #QUIC_EVENT_OPEN_STREAM
    b.eq    3f
    cmp     x9, #QUIC_EVENT_STREAM_WRITE
    b.eq    4f
    cmp     x9, #QUIC_EVENT_STREAM_CLOSE
    b.eq    5f
    cmp     x9, #QUIC_EVENT_STREAM_RESET
    b.eq    6f
    cmp     x9, #QUIC_EVENT_CLOSE
    b.eq    6f
    b       8f
1:  cmp     x21, #QUIC_EV_DATA              /* DATAGRAM */
    b.lo    8f
    ldr     x9, [x19, #QUIC_EV_COUNT]
    mov     x10, #65536
    cmp     x9, x10
    b.hs    8f
    add     x9, x9, #QUIC_EV_DATA
    cmp     x9, x21
    b.hi    8f
    add     x0, x19, #QUIC_EV_ADDR
    bl      quic_check_addr
    b       9f
2:  cmp     x21, #QUIC_EV_DIAL_SIZE         /* DIAL */
    b.ne    8f
    ldr     x9, [x19, #QUIC_EV_PEER_LEN]
    cmp     x9, #QUIC_PEER_MAX
    b.hi    8f
    add     x0, x19, #QUIC_EV_DIAL_ADDR
    bl      quic_check_addr
    b       9f
3:  cmp     x21, #QUIC_EV_OPEN_SIZE
    b.ne    8f
    b       7f
4:  cmp     x21, #QUIC_EV_WRITE_DATA        /* STREAM_WRITE */
    b.lo    8f
    ldr     x9, [x19, #QUIC_EV_WRITE_COUNT]
    sub     x10, x21, #QUIC_EV_WRITE_DATA
    cmp     x9, x10
    b.hi    8f
    b       7f
5:  cmp     x21, #QUIC_EV_STREAM_SIZE
    b.ne    8f
    b       7f
6:  cmp     x21, #QUIC_EV_CLOSE_SIZE        /* STREAM_RESET, CLOSE: a code below 2^62 */
    b.ne    8f
    ldr     x9, [x19, #QUIC_EV_CODE]
    lsr     x9, x9, #62
    cbnz    x9, 8f
7:  mov     x0, #1
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_check_event

/* ---------------------------------------------------------------- The step */

/*
 * quic_step(state, tick, events, scratch, actions, result) -> status: the
 * events in order while the action room allows, the timers, what the
 * application hears, the datagrams, and one WAKEUP last.
 * x27 state, x28 scratch; x19 tick, x20 events, x21 actions, x22 result,
 * x23 position, x24 end, x25 handled.
 */
FUNCTION quic_step
    ENTER   0
    mov     x27, x0
    mov     x19, x1
    mov     x20, x2
    mov     x28, x3
    mov     x21, x4
    mov     x22, x5
    ldr     x9, [x28, #SC_SIZE]
    MOV64   x10, QUIC_SCRATCH_SIZE
    mov     x0, #QUIC_BUFFER_TOO_SMALL
    cmp     x9, x10
    b.lo    9f
    ldr     x9, [x21, #QUIC_BL_SIZE]
    MOV64   x10, (QUIC_BL_FIXED + QUIC_ACTIONS_MIN)
    cmp     x9, x10
    b.lo    9f
    /* Every event first. */
    mov     x0, #QUIC_INVALID_EVENT
    ldr     x9, [x20, #QUIC_BL_OFFSET]
    ldr     x10, [x20, #QUIC_BL_COUNT]
    ldr     x11, [x20, #QUIC_BL_SIZE]
    cmp     x9, #QUIC_BL_FIXED
    b.lo    9f
    tst     x9, #7
    b.ne    9f
    cmp     x9, x11
    b.hi    9f
    sub     x12, x11, x9
    cmp     x10, x12
    b.hi    9f
    add     x23, x20, x9
    add     x24, x23, x10
1:  cmp     x23, x24
    b.hs    2f
    mov     x0, x23
    sub     x1, x24, x23
    bl      quic_check_event
    cbz     x0, 8f
    ldr     x9, [x23, #QUIC_EV_SIZE]
    add     x23, x23, x9
    b       1b
2:  /* Commit: nothing fails from here. */
    str     x21, [x28, #SC_ACTIONS]
    mov     x9, #QUIC_BL_FIXED
    str     x9, [x21, #QUIC_BL_OFFSET]
    str     xzr, [x21, #QUIC_BL_COUNT]
    mov     x9, #QUIC_ACT_WAKEUP_SIZE
    str     x9, [x28, #SC_RESERVE]
    mov     x9, #NONE
    str     x9, [x28, #SC_WAKE]
    ldr     x9, [x19, #QUIC_TICK_NOW]
    ldr     x10, [x27, #ST_NOW]
    cmp     x9, x10
    csel    x9, x9, x10, hi
    str     x9, [x27, #ST_NOW]
    ldr     x9, [x19, #QUIC_TICK_UNIX]
    str     x9, [x27, #ST_UNIX]
    add     x0, x19, #QUIC_TICK_ENTROPY
    bl      quic_reseed
    mov     x25, #0
    ldr     x9, [x20, #QUIC_BL_OFFSET]
    add     x23, x20, x9
3:  cmp     x23, x24
    b.hs    4f
    bl      quic_room
    cmp     x0, #EVENT_ROOM
    b.lo    4f
    mov     x0, x23
    bl      quic_event
    ldr     x9, [x23, #QUIC_EV_SIZE]
    add     x23, x23, x9
    add     x25, x25, #1
    b       3b
4:  str     x25, [x22, #QUIC_RESULT_HANDLED]
    bl      quic_connections
    cmp     x23, x24                        /* events left: the next step is due now */
    b.hs    5f
    ldr     x0, [x27, #ST_NOW]
    bl      quic_wake_at
5:  str     xzr, [x28, #SC_RESERVE]
    mov     x0, #QUIC_ACTION_WAKEUP
    mov     x1, #QUIC_ACT_WAKEUP_SIZE
    bl      quic_action
    ldr     x9, [x28, #SC_WAKE]
    ldr     x10, [x27, #ST_NOW]
    MOV64   x11, 60000000
    add     x10, x10, x11
    cmp     x9, x10
    csel    x9, x9, x10, lo
    str     x9, [x0, #QUIC_ACT_TIME]
    mov     x0, #QUIC_OK
    b       9f
8:  mov     x0, #QUIC_INVALID_EVENT
9:  LEAVE   0
END_FUNCTION quic_step

/* quic_event(event): hands one event to the function of its kind. */
LOCAL_FUNCTION quic_event
    ENTER   0
    ldr     x9, [x0, #QUIC_EV_KIND]
    cmp     x9, #QUIC_EVENT_DATAGRAM
    b.ne    1f
    bl      quic_on_datagram
    b       9f
1:  cmp     x9, #QUIC_EVENT_DIAL
    b.ne    2f
    bl      quic_on_dial
    b       9f
2:  cmp     x9, #QUIC_EVENT_OPEN_STREAM
    b.ne    3f
    bl      quic_on_open_stream
    b       9f
3:  cmp     x9, #QUIC_EVENT_STREAM_WRITE
    b.ne    4f
    bl      quic_on_stream_write
    b       9f
4:  cmp     x9, #QUIC_EVENT_STREAM_CLOSE
    b.ne    5f
    bl      quic_on_stream_close
    b       9f
5:  cmp     x9, #QUIC_EVENT_STREAM_RESET
    b.ne    6f
    bl      quic_on_stream_reset
    b       9f
6:  bl      quic_on_close
9:  LEAVE   0
END_FUNCTION quic_event

/*
 * quic_on_dial(event): a client connection: a random first DCID of 8 bytes,
 * its Initial keys, and a ClientHello; DIAL_FAILED with QUIC_ERR_LIMIT when
 * no slot or heap is free.
 */
LOCAL_FUNCTION quic_on_dial
    ENTER   0
    mov     x23, x0
    mov     x0, #0
    bl      quic_conn_new
    cbz     x0, 8f
    mov     x19, x0
    ldr     x9, [x23, #QUIC_EV_TAG]
    str     x9, [x19, #C_TAG]
    ldr     x9, [x23, #QUIC_EV_DIAL_SOCKET]
    str     x9, [x19, #C_SOCKET]
    add     x0, x19, #C_ADDR
    add     x1, x23, #QUIC_EV_DIAL_ADDR
    mov     x2, #QUIC_ADDR_SIZE
    bl      quic_copy
    mov     x9, #8
    str     x9, [x19, #(C_ODCID + QUIC_CID_LENGTH)]
    add     x0, x19, #(C_ODCID + QUIC_CID_ID)
    mov     x1, #8
    bl      quic_random
    add     x0, x19, #C_RCID
    add     x1, x19, #C_ODCID
    mov     x2, #QUIC_CID_SIZE
    bl      quic_copy
    add     x0, x19, #C_ODCID
    bl      quic_initial_install
    ldr     x20, [x19, #C_TLS]
    add     x20, x27, x20
    ldr     x2, [x23, #QUIC_EV_PEER_LEN]
    str     x2, [x20, #T_PID_LEN]
    add     x0, x20, #T_PID
    add     x1, x23, #QUIC_EV_PEER
    bl      quic_copy
    bl      quic_tls_start
    cbz     x0, 1f
    mov     x1, x0
    mov     x0, x19
    mov     x2, #QUIC_ERR_PROTOCOL
    bl      quic_conn_close
1:  bl      quic_idle_reset
    b       9f
8:  mov     x0, #QUIC_ACTION_DIAL_FAILED
    mov     x1, #QUIC_ACT_CLOSED_SIZE
    bl      quic_action
    cbz     x0, 9f
    ldr     x9, [x23, #QUIC_EV_TAG]
    str     x9, [x0, #QUIC_ACT_TAG]
    mov     x9, #QUIC_ERR_LIMIT
    str     x9, [x0, #QUIC_ACT_REASON]
9:  LEAVE   0
END_FUNCTION quic_on_dial

/* quic_on_close(event): the application closes the connection with its code. */
LOCAL_FUNCTION quic_on_close
    ENTER   0
    mov     x20, x0
    ldr     x0, [x20, #QUIC_EV_CONN]
    bl      quic_conn
    cbz     x0, 9f
    mov     x19, x0
    ldr     x9, [x19, #C_STATE]
    cmp     x9, #CS_CLOSING
    b.hs    9f
    ldr     x9, [x19, #C_FLAGS]
    orr     x9, x9, #CF_APP_CLOSE
    str     x9, [x19, #C_FLAGS]
    mov     x0, x19
    ldr     x1, [x20, #QUIC_EV_CODE]
    mov     x2, #QUIC_ERR_LOCAL
    bl      quic_conn_close
9:  LEAVE   0
END_FUNCTION quic_on_close

/* ---------------------------------------------------------------- Connections each step */

/*
 * quic_connections(): for each connection in use: its timers, what the
 * application hears, its datagrams, its deadline; a connection that is over
 * is freed once the application heard it.
 * x20 index, x19 the connection.
 */
LOCAL_FUNCTION quic_connections
    ENTER   0
    mov     x20, #0
1:  ldr     x9, [x27, #ST_CONN_COUNT]
    cmp     x20, x9
    b.hs    9f
    mov     x0, x20
    bl      quic_conn_at
    mov     x19, x0
    add     x20, x20, #1
    ldr     w9, [x19, #C_USED]
    cbz     w9, 1b
    bl      quic_conn_timers
    bl      quic_conn_tell
    ldr     x9, [x19, #C_STATE]
    cmp     x9, #CS_DONE
    b.ne    2f
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_GONE
    b.ne    3f                              /* not heard yet: wait */
    mov     x0, x19
    bl      quic_conn_free
    b       1b
2:  bl      quic_conn_output
3:  bl      quic_conn_deadline
    b       1b
9:  LEAVE   0
END_FUNCTION quic_connections

/*
 * quic_conn_timers(): the end of closing or draining, the handshake deadline,
 * the idle timeout, the loss detection timer, the keep-alive and the end of
 * the previous receive keys. x19 the connection.
 */
LOCAL_FUNCTION quic_conn_timers
    ENTER   0
    ldr     x20, [x27, #ST_NOW]
    ldr     x9, [x19, #C_STATE]
    cmp     x9, #CS_DONE
    b.eq    9f
    cmp     x9, #CS_CLOSING
    b.lo    1f
    ldr     x10, [x19, #C_CLOSE_AT]
    cmp     x20, x10
    b.lo    9f
    mov     x9, #CS_DONE
    str     x9, [x19, #C_STATE]
    b       9f
1:  ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_COMPLETE
    b.ne    2f
    ldr     x10, [x27, #(ST_CONFIG + QUIC_CFG_HANDSHAKE)]
    mov     x11, #1000
    mul     x10, x10, x11
    ldr     x11, [x19, #C_START]
    add     x10, x10, x11
    cmp     x20, x10
    b.lo    2f
    mov     x9, #QUIC_ERR_HANDSHAKE_TIMEOUT
    b       5f
2:  ldr     x10, [x19, #C_IDLE_AT]
    cmp     x20, x10
    b.lo    3f
    mov     x9, #QUIC_ERR_IDLE
5:  ldr     x10, [x19, #C_REASON]           /* silently over */
    cbnz    x10, 51f
    str     x9, [x19, #C_REASON]
51: mov     x9, #CS_DONE
    str     x9, [x19, #C_STATE]
    ldr     x9, [x19, #C_FLAGS]
    orr     x9, x9, #CF_GONE
    str     x9, [x19, #C_FLAGS]
    b       9f
3:  ldr     x10, [x19, #C_LOSS_AT]
    cmp     x20, x10
    b.lo    4f
    bl      quic_on_loss_timer
4:  ldr     x10, [x19, #C_PING_AT]
    cmp     x20, x10
    b.lo    6f
    mov     x9, #NONE
    str     x9, [x19, #C_PING_AT]
    ldr     x9, [x19, #C_STATE]
    cmp     x9, #CS_ACTIVE
    b.ne    6f
    ldr     x9, [x19, #C_FLAGS]
    orr     x9, x9, #CF_PING
    str     x9, [x19, #C_FLAGS]
6:  ldr     x10, [x19, #C_PREV_UNTIL]
    cmp     x20, x10
    b.lo    7f
    mov     x9, #NONE
    str     x9, [x19, #C_PREV_UNTIL]
7:  bl      quic_maybe_key_update
9:  LEAVE   0
END_FUNCTION quic_conn_timers

/*
 * quic_maybe_key_update(): we start a key update (RFC 9001 section 6) once the
 * current key phase carried QUIC_CFG_KEY_UPDATE packets (1000000 when 0, far
 * below the 2^23 packets AES-128-GCM may protect), the handshake is
 * confirmed, the previous keys are gone, and the peer acknowledged a packet
 * of the current phase. x19 the connection.
 */
LOCAL_FUNCTION quic_maybe_key_update
    ENTER   0
    ldr     x9, [x19, #C_STATE]
    cmp     x9, #CS_ACTIVE
    b.ne    9f
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_CONFIRMED
    b.eq    9f
    ldr     x9, [x19, #C_PREV_UNTIL]
    cmn     x9, #1
    b.ne    9f
    ldr     x10, [x27, #(ST_CONFIG + QUIC_CFG_KEY_UPDATE)]
    MOV64   x11, 1000000
    cmp     x10, #0
    csel    x10, x11, x10, eq
    ldr     x9, [x19, #C_PHASE_SENT]
    cmp     x9, x10
    b.lo    9f
    ldr     x9, [x19, #(C_SPACES + 2 * SP_SIZE + SP_LARGEST_ACKED)]
    cmn     x9, #1
    b.eq    9f
    ldr     x10, [x19, #C_PHASE_FIRST]
    cmp     x9, x10
    b.lo    9f
    bl      quic_key_update
    bl      quic_phase_start
9:  LEAVE   0
END_FUNCTION quic_maybe_key_update

/*
 * quic_phase_start(): after a key update: our first packet number of the new
 * phase, and the previous receive keys stay for 3 PTO. x19 the connection.
 */
LOCAL_FUNCTION quic_phase_start
    ENTER   0
    ldr     x9, [x19, #(C_SPACES + 2 * SP_SIZE + SP_NEXT_PN)]
    str     x9, [x19, #C_PHASE_FIRST]
    mov     x0, x19
    mov     x1, #SPACE_APP
    bl      quic_pto_period
    add     x0, x0, x0, lsl #1
    ldr     x9, [x27, #ST_NOW]
    add     x9, x9, x0
    str     x9, [x19, #C_PREV_UNTIL]
    LEAVE   0
END_FUNCTION quic_phase_start

/*
 * quic_conn_tell(): CONNECTED, then the stream actions, then CLOSED or
 * DIAL_FAILED, while the action room allows. x19 the connection.
 */
LOCAL_FUNCTION quic_conn_tell
    ENTER   0
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_TELL
    b.eq    2f
    tst     x9, #CF_KNOWN
    b.ne    2f
    ldr     x10, [x19, #C_STATE]
    cmp     x10, #CS_ACTIVE
    b.ne    2f
    bl      quic_room
    cmp     x0, #QUIC_ACT_CONNECTED_SIZE
    b.lo    9f
    mov     x0, #QUIC_ACTION_CONNECTED
    mov     x1, #QUIC_ACT_CONNECTED_SIZE
    bl      quic_action
    mov     x20, x0
    mov     x0, x19
    bl      quic_conn_handle
    str     x0, [x20, #QUIC_ACT_CONN]
    ldr     x9, [x19, #C_TAG]
    str     x9, [x20, #QUIC_ACT_TAG]
    ldr     x9, [x19, #C_ROLE]
    eor     x9, x9, #1
    str     x9, [x20, #QUIC_ACT_DIRECTION]
    ldr     x9, [x19, #C_SOCKET]
    str     x9, [x20, #QUIC_ACT_C_SOCKET]
    add     x0, x20, #QUIC_ACT_C_ADDR
    add     x1, x19, #C_ADDR
    mov     x2, #QUIC_ADDR_SIZE
    bl      quic_copy
    ldr     x2, [x19, #C_PEER_KEY_LEN]
    str     x2, [x20, #QUIC_ACT_KEY_LEN]
    add     x0, x20, #QUIC_ACT_KEY
    add     x1, x19, #C_PEER_KEY
    bl      quic_copy
    ldr     x9, [x19, #C_FLAGS]
    orr     x9, x9, #CF_KNOWN
    bic     x9, x9, #CF_TELL
    str     x9, [x19, #C_FLAGS]
2:  ldr     x9, [x19, #C_FLAGS]             /* the streams */
    tst     x9, #CF_KNOWN
    b.eq    4f
    ldr     x10, [x19, #C_STATE]
    cmp     x10, #CS_ACTIVE
    b.ne    4f
    ldr     x20, [x19, #C_STREAM_HEAD]
3:  cmn     x20, #1
    b.eq    4f
    mov     x0, x20
    bl      quic_stream_at
    ldr     x20, [x0, #S_NEXT]
    bl      quic_stream_tell
    b       3b
4:  ldr     x9, [x19, #C_FLAGS]             /* the end */
    tst     x9, #CF_GONE
    b.eq    9f
    ldr     x10, [x19, #C_STATE]
    cmp     x10, #CS_CLOSING
    b.lo    9f
    tst     x9, #CF_KNOWN
    b.ne    5f
    ldr     x10, [x19, #C_ROLE]
    cbnz    x10, 7f                         /* a peer's connection that never came up: nothing to tell */
    bl      quic_room
    cmp     x0, #QUIC_ACT_CLOSED_SIZE
    b.lo    9f
    mov     x0, #QUIC_ACTION_DIAL_FAILED
    mov     x1, #QUIC_ACT_CLOSED_SIZE
    bl      quic_action
    mov     x20, x0
    ldr     x9, [x19, #C_TAG]
    str     x9, [x20, #QUIC_ACT_TAG]
    b       6f
5:  bl      quic_room
    cmp     x0, #QUIC_ACT_CLOSED_SIZE
    b.lo    9f
    mov     x0, #QUIC_ACTION_CLOSED
    mov     x1, #QUIC_ACT_CLOSED_SIZE
    bl      quic_action
    mov     x20, x0
    mov     x0, x19
    bl      quic_conn_handle
    str     x0, [x20, #QUIC_ACT_CONN]
    ldr     x9, [x19, #C_TAG]
    str     x9, [x20, #QUIC_ACT_TAG]
6:  ldr     x9, [x19, #C_REASON]
    str     x9, [x20, #QUIC_ACT_REASON]
    ldr     x9, [x19, #C_ERROR]
    str     x9, [x20, #QUIC_ACT_ERROR]
7:  ldr     x9, [x19, #C_FLAGS]
    bic     x9, x9, #CF_GONE
    str     x9, [x19, #C_FLAGS]
9:  LEAVE   0
END_FUNCTION quic_conn_tell

/*
 * quic_conn_deadline(): the earliest timer of the connection becomes a
 * wakeup: loss detection, idle, closing, keep-alive, a delayed ACK, the
 * handshake deadline, and the end of the previous keys. x19 the connection.
 */
LOCAL_FUNCTION quic_conn_deadline
    ENTER   0
    ldr     x9, [x19, #C_STATE]
    cmp     x9, #CS_DONE
    b.ne    1f
    ldr     x0, [x27, #ST_NOW]              /* over, waiting to be heard */
    bl      quic_wake_at
    b       9f
1:  ldr     x0, [x19, #C_LOSS_AT]
    bl      quic_wake_at
    ldr     x0, [x19, #C_IDLE_AT]
    bl      quic_wake_at
    ldr     x0, [x19, #C_CLOSE_AT]
    bl      quic_wake_at
    ldr     x0, [x19, #C_PING_AT]
    bl      quic_wake_at
    ldr     x0, [x19, #C_PREV_UNTIL]
    bl      quic_wake_at
    ldr     x0, [x19, #(C_SPACES + 2 * SP_SIZE + SP_ACK_AT)]
    bl      quic_wake_at
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_COMPLETE
    b.ne    9f
    ldr     x10, [x27, #(ST_CONFIG + QUIC_CFG_HANDSHAKE)]
    mov     x11, #1000
    mul     x10, x10, x11
    ldr     x11, [x19, #C_START]
    add     x0, x10, x11
    bl      quic_wake_at
9:  LEAVE   0
END_FUNCTION quic_conn_deadline
