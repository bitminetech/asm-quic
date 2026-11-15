/*
 * The node: the state size and layout, init, and the step: event checks,
 * events, timers, what the application hears, datagrams out, and the wakeup.
 */

.set EVENT_ROOM, 256                    /* the action bytes an event may add itself */

/* ---------------------------------------------------------------- Layout */

/*
 * quic_layout(config) -> a0 the state size, or 0 when the config breaks a rule;
 * a1 the stream table offset, a2 the heap offset. The connection table is at
 * ST_FIXED; the heap at a multiple of 64. A leaf.
 */
LOCAL_FUNCTION quic_layout
    UNWIND_END_PROLOGUE
    ld      t0, QUIC_CFG_SIZE_FIELD(a0)
    li      t1, QUIC_CFG_SIZE
    bltu    t0, t1, 8f
    ld      t0, QUIC_CFG_VERSION(a0)
    li      t1, QUIC_VERSION
    bne     t0, t1, 8f
    ld      t0, QUIC_CFG_KEY_TYPE(a0)
    li      t1, QUIC_KEY_ED25519
    beq     t0, t1, 1f
    li      t1, QUIC_KEY_SECP256K1
    bne     t0, t1, 8f
1:  ld      t0, QUIC_CFG_CONNS(a0)
    beqz    t0, 8f
    li      t4, 65536
    bgeu    t0, t4, 8f
    ld      t1, QUIC_CFG_STREAMS(a0)
    beqz    t1, 8f
    li      t4, (1 << 20)
    bltu    t4, t1, 8f
    ld      t2, QUIC_CFG_HEAP(a0)
    li      t4, (1 << 16)
    bltu    t2, t4, 8f
    li      t4, 1
    slli    t4, t4, 40
    bltu    t4, t2, 8f
    addi    t3, t2, -1
    and     t3, t2, t3
    bnez    t3, 8f                          # a power of two
    ld      t3, QUIC_CFG_IDLE(a0)
    li      t4, 1
    slli    t4, t4, 40
    bgeu    t3, t4, 8f
    ld      t3, QUIC_CFG_HANDSHAKE(a0)
    beqz    t3, 8f
    bgeu    t3, t4, 8f
    ld      t3, QUIC_CFG_KEEP_ALIVE(a0)
    bgeu    t3, t4, 8f
    li      t4, 1
    slli    t4, t4, 60
    ld      t3, QUIC_CFG_MAX_DATA(a0)
    bgeu    t3, t4, 8f
    ld      t3, QUIC_CFG_STREAM_DATA(a0)
    bgeu    t3, t4, 8f
    ld      t3, QUIC_CFG_MAX_STREAMS(a0)
    bgeu    t3, t4, 8f
    ld      t3, QUIC_CFG_STREAM_QUEUE(a0)
    beqz    t3, 8f
    ld      t3, QUIC_CFG_FLAGS(a0)
    li      t4, QUIC_CFG_ACCEPT
    bltu    t4, t3, 8f
    ld      t3, QUIC_CFG_KEY_UPDATE(a0)
    li      t4, (1 << 23)
    bgeu    t3, t4, 8f
    ld      t3, QUIC_CFG_SENT(a0)
    li      t4, 16
    bltu    t3, t4, 8f
    li      t4, 65536
    bltu    t4, t3, 8f
    li      t4, C_SIZE
    mul     a1, t0, t4
    li      t4, ST_FIXED
    add     a1, a1, t4                      # the stream table
    li      t4, S_SIZE
    mul     a2, t1, t4
    add     a2, a2, a1
    addi    a2, a2, 63
    andi    a2, a2, -64                     # the heap
    add     a0, a2, t2
    ret
8:  li      a0, 0
    ret
END_FUNCTION quic_layout

/* quic_state_size(config, size) -> status: the bytes of the state quic_init builds. */
FUNCTION quic_state_size
    ENTER   0
    mv      s1, a1
    call    quic_layout
    beqz    a0, 8f
    sd      a0, 0(s1)
    li      a0, QUIC_OK
    j       9f
8:  li      a0, QUIC_INVALID_CONFIG
9:  LEAVE   0
END_FUNCTION quic_state_size

/*
 * quic_init(config, state) -> status: a node with no connections: the tables,
 * the heap as one free block, the DRBG from the seed, the host public key and
 * its protobuf, a P-256 key and our certificate.
 * s1 config, s2 state (also s9), s3 size, s4 stream table, s5 heap.
 */
.set IN_PUB, 0                          /* 72 bytes */
.set IN_FRAME, 80
FUNCTION quic_init
    ENTER   0, IN_FRAME
    mv      s1, a0
    mv      s2, a1
    mv      s9, a1
    call    quic_layout
    mv      s3, a0
    mv      s4, a1
    mv      s5, a2
    li      a0, QUIC_INVALID_CONFIG
    beqz    s3, 9f
    ld      t0, ST_SIZE(s2)
    li      a0, QUIC_BUFFER_TOO_SMALL
    bltu    t0, s3, 9f
    /* The host key: secp256k1 must be from 1 to n - 1. */
    ld      t0, QUIC_CFG_KEY_TYPE(s1)
    li      t1, QUIC_KEY_SECP256K1
    bne     t0, t1, 1f
    addi    a0, s1, QUIC_CFG_KEY
    addi    a1, sp, (FL + IN_PUB)
    CALL_GLOBAL crypto_secp256k1_public_key
    mv      t0, a0
    li      a0, QUIC_INVALID_KEY
    bnez    t0, 9f
1:  ld      s6, ST_SIZE(s2)                 # the state: zero, then its fields
    addi    a0, s2, 8
    addi    a1, s5, -8
    call    quic_zero
    sd      s6, ST_SIZE(s2)
    li      t0, QUIC_VERSION
    sd      t0, ST_VERSION(s2)
    addi    a0, s2, ST_CONFIG
    mv      a1, s1
    li      a2, QUIC_CFG_SIZE
    call    quic_copy
    li      t0, ST_FIXED
    sd      t0, ST_CONN_OFF(s2)
    ld      t0, QUIC_CFG_CONNS(s1)
    sd      t0, ST_CONN_COUNT(s2)
    sd      s4, ST_STREAM_OFF(s2)
    ld      t0, QUIC_CFG_STREAMS(s1)
    sd      t0, ST_STREAM_COUNT(s2)
    sd      s5, ST_HEAP_OFF(s2)
    ld      t0, QUIC_CFG_HEAP(s1)
    sd      t0, ST_HEAP_SIZE(s2)
    addi    t1, s2, ST_HEAP_FREE            # the heap: one free block of the top order
    li      t2, 64
    li      t3, NONE
2:  sd      t3, 0(t1)
    addi    t1, t1, 8
    addi    t2, t2, -1
    bnez    t2, 2b
    li      t4, 0                           # the order: log2 of the heap size
21: srl     t5, t0, t4
    li      a0, 1
    beq     t5, a0, 22f
    addi    t4, t4, 1
    j       21b
22: add     t5, s2, s5
    sw      t4, HB_ORDER(t5)
    li      a0, 1
    sw      a0, HB_FREE(t5)
    sd      t3, HB_NEXT(t5)
    sd      t3, HB_PREV(t5)
    addi    t1, s2, ST_HEAP_FREE
    slli    a0, t4, 3
    add     t1, t1, a0
    sd      zero, 0(t1)
    /* The DRBG key: the seed. */
    addi    a0, s2, ST_DRBG_KEY
    addi    a1, s1, QUIC_CFG_SEED
    li      a2, 32
    call    quic_copy
    /* The host public key and its protobuf: 0x08 type 0x12 length key. */
    ld      t0, QUIC_CFG_KEY_TYPE(s1)
    li      t1, QUIC_KEY_ED25519
    bne     t0, t1, 3f
    addi    a0, s1, QUIC_CFG_KEY
    addi    a1, s2, ST_HOST_PUB
    CALL_GLOBAL crypto_ed25519_public_key
    li      s6, 32
    j       4f
3:  addi    a0, s1, QUIC_CFG_KEY
    addi    a1, s2, ST_HOST_PUB
    CALL_GLOBAL crypto_secp256k1_public_key
    li      s6, 33
4:  li      t0, 0x08
    sb      t0, ST_HOST_PROTO(s2)
    ld      t0, QUIC_CFG_KEY_TYPE(s1)
    sb      t0, (ST_HOST_PROTO + 1)(s2)
    li      t0, 0x12
    sb      t0, (ST_HOST_PROTO + 2)(s2)
    sb      s6, (ST_HOST_PROTO + 3)(s2)
    addi    a0, s2, (ST_HOST_PROTO + 4)
    addi    a1, s2, ST_HOST_PUB
    mv      a2, s6
    call    quic_copy
    addi    t0, s6, 4
    sd      t0, ST_HOST_PROTO_LEN(s2)
    /* The certificate key: drawn until it is from 1 to n - 1. */
5:  addi    a0, s2, ST_CERT_PRIV
    li      a1, 32
    call    quic_random
    addi    a0, s2, ST_CERT_PRIV
    addi    a1, sp, (FL + IN_PUB)
    CALL_GLOBAL crypto_p256_public_key
    bnez    a0, 5b
    call    quic_cert_build
    li      a0, QUIC_OK
9:  LEAVE   0, IN_FRAME
END_FUNCTION quic_init

/* ---------------------------------------------------------------- Event checks */

/* quic_check_addr(addr) -> 1 when the Address is IPv4 or IPv6 with a port below 65536. A leaf. */
LOCAL_FUNCTION quic_check_addr
    UNWIND_END_PROLOGUE
    ld      a1, QUIC_ADDR_FAMILY(a0)
    li      a2, 4
    beq     a1, a2, 1f
    li      a2, 6
    bne     a1, a2, 8f
1:  ld      a1, QUIC_ADDR_PORT(a0)
    li      a2, 65536
    bgeu    a1, a2, 8f
    li      a0, 1
    ret
8:  li      a0, 0
    ret
END_FUNCTION quic_check_addr

/*
 * quic_check_event(event, room) -> 1 when the event is well formed within
 * room bytes: its size a multiple of 8 within room, a known kind, and the
 * fields of its kind.
 */
LOCAL_FUNCTION quic_check_event
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    li      t0, 16
    bltu    s2, t0, 8f
    ld      s3, QUIC_EV_SIZE(s1)
    bltu    s3, t0, 8f
    andi    t1, s3, 7
    bnez    t1, 8f
    bltu    s2, s3, 8f
    ld      t0, QUIC_EV_KIND(s1)
    li      t1, QUIC_EVENT_DATAGRAM
    beq     t0, t1, 1f
    li      t1, QUIC_EVENT_DIAL
    beq     t0, t1, 2f
    li      t1, QUIC_EVENT_OPEN_STREAM
    beq     t0, t1, 3f
    li      t1, QUIC_EVENT_STREAM_WRITE
    beq     t0, t1, 4f
    li      t1, QUIC_EVENT_STREAM_CLOSE
    beq     t0, t1, 5f
    li      t1, QUIC_EVENT_STREAM_RESET
    beq     t0, t1, 6f
    li      t1, QUIC_EVENT_CLOSE
    beq     t0, t1, 6f
    j       8f
1:  li      t1, QUIC_EV_DATA                # DATAGRAM
    bltu    s3, t1, 8f
    ld      t0, QUIC_EV_COUNT(s1)
    li      t1, 65536
    bgeu    t0, t1, 8f
    addi    t0, t0, QUIC_EV_DATA
    bltu    s3, t0, 8f
    addi    a0, s1, QUIC_EV_ADDR
    call    quic_check_addr
    j       9f
2:  li      t1, QUIC_EV_DIAL_SIZE           # DIAL
    bne     s3, t1, 8f
    ld      t0, QUIC_EV_PEER_LEN(s1)
    li      t1, QUIC_PEER_MAX
    bltu    t1, t0, 8f
    addi    a0, s1, QUIC_EV_DIAL_ADDR
    call    quic_check_addr
    j       9f
3:  li      t1, QUIC_EV_OPEN_SIZE
    bne     s3, t1, 8f
    j       7f
4:  li      t1, QUIC_EV_WRITE_DATA          # STREAM_WRITE
    bltu    s3, t1, 8f
    ld      t0, QUIC_EV_WRITE_COUNT(s1)
    sub     t1, s3, t1
    bltu    t1, t0, 8f
    j       7f
5:  li      t1, QUIC_EV_STREAM_SIZE
    bne     s3, t1, 8f
    j       7f
6:  li      t1, QUIC_EV_CLOSE_SIZE          # STREAM_RESET, CLOSE: a code below 2^62
    bne     s3, t1, 8f
    ld      t0, QUIC_EV_CODE(s1)
    srli    t0, t0, 62
    bnez    t0, 8f
7:  li      a0, 1
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_check_event

/* ---------------------------------------------------------------- The step */

/*
 * quic_step(state, tick, events, scratch, actions, result) -> status: the
 * events in order while the action room allows, the timers, what the
 * application hears, the datagrams, and one WAKEUP last.
 * s9 state, s10 scratch; s1 tick, s2 events, s3 actions, s4 result,
 * s5 position, s6 end, s7 handled.
 */
FUNCTION quic_step
    ENTER   0
    mv      s9, a0
    mv      s1, a1
    mv      s2, a2
    mv      s10, a3
    mv      s3, a4
    mv      s4, a5
    ld      t0, SC_SIZE(s10)
    li      t1, QUIC_SCRATCH_SIZE
    li      a0, QUIC_BUFFER_TOO_SMALL
    bltu    t0, t1, 9f
    ld      t0, QUIC_BL_SIZE(s3)
    li      t1, (QUIC_BL_FIXED + QUIC_ACTIONS_MIN)
    bltu    t0, t1, 9f
    /* Every event first. */
    li      a0, QUIC_INVALID_EVENT
    ld      t0, QUIC_BL_OFFSET(s2)
    ld      t1, QUIC_BL_COUNT(s2)
    ld      t2, QUIC_BL_SIZE(s2)
    li      t3, QUIC_BL_FIXED
    bltu    t0, t3, 9f
    andi    t3, t0, 7
    bnez    t3, 9f
    bltu    t2, t0, 9f
    sub     t3, t2, t0
    bltu    t3, t1, 9f
    add     s5, s2, t0
    add     s6, s5, t1
1:  bgeu    s5, s6, 2f
    mv      a0, s5
    sub     a1, s6, s5
    call    quic_check_event
    beqz    a0, 8f
    ld      t0, QUIC_EV_SIZE(s5)
    add     s5, s5, t0
    j       1b
2:  /* Commit: nothing fails from here. */
    sd      s3, SC_ACTIONS(s10)
    li      t0, QUIC_BL_FIXED
    sd      t0, QUIC_BL_OFFSET(s3)
    sd      zero, QUIC_BL_COUNT(s3)
    li      t0, QUIC_ACT_WAKEUP_SIZE
    sd      t0, SC_RESERVE(s10)
    li      t0, NONE
    sd      t0, SC_WAKE(s10)
    ld      t0, QUIC_TICK_NOW(s1)
    ld      t1, ST_NOW(s9)
    bltu    t1, t0, 21f
    mv      t0, t1
21: sd      t0, ST_NOW(s9)
    ld      t0, QUIC_TICK_UNIX(s1)
    sd      t0, ST_UNIX(s9)
    addi    a0, s1, QUIC_TICK_ENTROPY
    call    quic_reseed
    li      s7, 0
    ld      t0, QUIC_BL_OFFSET(s2)
    add     s5, s2, t0
3:  bgeu    s5, s6, 4f
    call    quic_room
    li      t0, EVENT_ROOM
    bltu    a0, t0, 4f
    mv      a0, s5
    call    quic_event
    ld      t0, QUIC_EV_SIZE(s5)
    add     s5, s5, t0
    addi    s7, s7, 1
    j       3b
4:  sd      s7, QUIC_RESULT_HANDLED(s4)
    call    quic_connections
    bgeu    s5, s6, 5f                      # events left: the next step is due now
    ld      a0, ST_NOW(s9)
    call    quic_wake_at
5:  sd      zero, SC_RESERVE(s10)
    li      a0, QUIC_ACTION_WAKEUP
    li      a1, QUIC_ACT_WAKEUP_SIZE
    call    quic_action
    ld      t0, SC_WAKE(s10)
    ld      t1, ST_NOW(s9)
    li      t2, 60000000
    add     t1, t1, t2
    bltu    t0, t1, 51f
    mv      t0, t1
51: sd      t0, QUIC_ACT_TIME(a0)
    li      a0, QUIC_OK
    j       9f
8:  li      a0, QUIC_INVALID_EVENT
9:  LEAVE   0
END_FUNCTION quic_step

/* quic_event(event): hands one event to the function of its kind. */
LOCAL_FUNCTION quic_event
    ENTER   0
    ld      t0, QUIC_EV_KIND(a0)
    li      t1, QUIC_EVENT_DATAGRAM
    bne     t0, t1, 1f
    call    quic_on_datagram
    j       9f
1:  li      t1, QUIC_EVENT_DIAL
    bne     t0, t1, 2f
    call    quic_on_dial
    j       9f
2:  li      t1, QUIC_EVENT_OPEN_STREAM
    bne     t0, t1, 3f
    call    quic_on_open_stream
    j       9f
3:  li      t1, QUIC_EVENT_STREAM_WRITE
    bne     t0, t1, 4f
    call    quic_on_stream_write
    j       9f
4:  li      t1, QUIC_EVENT_STREAM_CLOSE
    bne     t0, t1, 5f
    call    quic_on_stream_close
    j       9f
5:  li      t1, QUIC_EVENT_STREAM_RESET
    bne     t0, t1, 6f
    call    quic_on_stream_reset
    j       9f
6:  call    quic_on_close
9:  LEAVE   0
END_FUNCTION quic_event

/*
 * quic_on_dial(event): a client connection: a random first DCID of 8 bytes,
 * its Initial keys, and a ClientHello; DIAL_FAILED with QUIC_ERR_LIMIT when
 * no slot or heap is free.
 */
LOCAL_FUNCTION quic_on_dial
    ENTER   0
    mv      s5, a0
    li      a0, 0
    call    quic_conn_new
    beqz    a0, 8f
    mv      s1, a0
    ld      t0, QUIC_EV_TAG(s5)
    sd      t0, C_TAG(s1)
    ld      t0, QUIC_EV_DIAL_SOCKET(s5)
    sd      t0, C_SOCKET(s1)
    addi    a0, s1, C_ADDR
    addi    a1, s5, QUIC_EV_DIAL_ADDR
    li      a2, QUIC_ADDR_SIZE
    call    quic_copy
    li      t0, 8
    sd      t0, (C_ODCID + QUIC_CID_LENGTH)(s1)
    addi    a0, s1, (C_ODCID + QUIC_CID_ID)
    li      a1, 8
    call    quic_random
    addi    a0, s1, C_RCID
    addi    a1, s1, C_ODCID
    li      a2, QUIC_CID_SIZE
    call    quic_copy
    addi    a0, s1, C_ODCID
    call    quic_initial_install
    LDX     s2, s1, C_TLS
    add     s2, s9, s2
    ld      a2, QUIC_EV_PEER_LEN(s5)
    sd      a2, T_PID_LEN(s2)
    addi    a0, s2, T_PID
    addi    a1, s5, QUIC_EV_PEER
    call    quic_copy
    call    quic_tls_start
    beqz    a0, 1f
    mv      a1, a0
    mv      a0, s1
    li      a2, QUIC_ERR_PROTOCOL
    call    quic_conn_close
1:  call    quic_idle_reset
    j       9f
8:  li      a0, QUIC_ACTION_DIAL_FAILED
    li      a1, QUIC_ACT_CLOSED_SIZE
    call    quic_action
    beqz    a0, 9f
    ld      t0, QUIC_EV_TAG(s5)
    sd      t0, QUIC_ACT_TAG(a0)
    li      t0, QUIC_ERR_LIMIT
    sd      t0, QUIC_ACT_REASON(a0)
9:  LEAVE   0
END_FUNCTION quic_on_dial

/* quic_on_close(event): the application closes the connection with its code. */
LOCAL_FUNCTION quic_on_close
    ENTER   0
    mv      s2, a0
    ld      a0, QUIC_EV_CONN(s2)
    call    quic_conn
    beqz    a0, 9f
    mv      s1, a0
    ld      t0, C_STATE(s1)
    li      t1, CS_CLOSING
    bgeu    t0, t1, 9f
    ld      t0, C_FLAGS(s1)
    ori     t0, t0, CF_APP_CLOSE
    sd      t0, C_FLAGS(s1)
    mv      a0, s1
    ld      a1, QUIC_EV_CODE(s2)
    li      a2, QUIC_ERR_LOCAL
    call    quic_conn_close
9:  LEAVE   0
END_FUNCTION quic_on_close

/* ---------------------------------------------------------------- Connections each step */

/*
 * quic_connections(): for each connection in use: its timers, what the
 * application hears, its datagrams, its deadline; a connection that is over
 * is freed once the application heard it.
 * s2 index, s1 the connection.
 */
LOCAL_FUNCTION quic_connections
    ENTER   0
    li      s2, 0
1:  ld      t0, ST_CONN_COUNT(s9)
    bgeu    s2, t0, 9f
    mv      a0, s2
    call    quic_conn_at
    mv      s1, a0
    addi    s2, s2, 1
    lwu     t0, C_USED(s1)
    beqz    t0, 1b
    call    quic_conn_timers
    call    quic_conn_tell
    ld      t0, C_STATE(s1)
    li      t1, CS_DONE
    bne     t0, t1, 2f
    ld      t0, C_FLAGS(s1)
    andi    t0, t0, CF_GONE
    bnez    t0, 3f                          # not heard yet: wait
    mv      a0, s1
    call    quic_conn_free
    j       1b
2:  call    quic_conn_output
3:  call    quic_conn_deadline
    j       1b
9:  LEAVE   0
END_FUNCTION quic_connections

/*
 * quic_conn_timers(): the end of closing or draining, the handshake deadline,
 * the idle timeout, the loss detection timer, the keep-alive and the end of
 * the previous receive keys. s1 the connection.
 */
LOCAL_FUNCTION quic_conn_timers
    ENTER   0
    ld      s2, ST_NOW(s9)
    ld      t0, C_STATE(s1)
    li      t1, CS_DONE
    beq     t0, t1, 9f
    li      t1, CS_CLOSING
    bltu    t0, t1, 1f
    LDX     t1, s1, C_CLOSE_AT
    bltu    s2, t1, 9f
    li      t0, CS_DONE
    sd      t0, C_STATE(s1)
    j       9f
1:  ld      t0, C_FLAGS(s1)
    andi    t0, t0, CF_COMPLETE
    bnez    t0, 2f
    CFG     t1, QUIC_CFG_HANDSHAKE
    li      t2, 1000
    mul     t1, t1, t2
    LDX     t2, s1, C_START
    add     t1, t1, t2
    bltu    s2, t1, 2f
    li      t0, QUIC_ERR_HANDSHAKE_TIMEOUT
    j       5f
2:  LDX     t1, s1, C_IDLE_AT
    bltu    s2, t1, 3f
    li      t0, QUIC_ERR_IDLE
5:  ld      t1, C_REASON(s1)                # silently over
    bnez    t1, 51f
    sd      t0, C_REASON(s1)
51: li      t0, CS_DONE
    sd      t0, C_STATE(s1)
    ld      t0, C_FLAGS(s1)
    ori     t0, t0, CF_GONE
    sd      t0, C_FLAGS(s1)
    j       9f
3:  LDX     t1, s1, C_LOSS_AT
    bltu    s2, t1, 4f
    call    quic_on_loss_timer
4:  LDX     t1, s1, C_PING_AT
    bltu    s2, t1, 6f
    li      t0, NONE
    SDX     t0, s1, C_PING_AT
    ld      t0, C_STATE(s1)
    li      t1, CS_ACTIVE
    bne     t0, t1, 6f
    ld      t0, C_FLAGS(s1)
    ORV     t0, CF_PING
    sd      t0, C_FLAGS(s1)
6:  LDX     t1, s1, C_PREV_UNTIL
    bltu    s2, t1, 7f
    li      t0, NONE
    SDX     t0, s1, C_PREV_UNTIL
7:  call    quic_maybe_key_update
9:  LEAVE   0
END_FUNCTION quic_conn_timers

/*
 * quic_maybe_key_update(): we start a key update (RFC 9001 section 6) once the
 * current key phase carried QUIC_CFG_KEY_UPDATE packets (1000000 when 0, far
 * below the 2^23 packets AES-128-GCM may protect), the handshake is
 * confirmed, the previous keys are gone, and the peer acknowledged a packet
 * of the current phase. s1 the connection.
 */
LOCAL_FUNCTION quic_maybe_key_update
    ENTER   0
    ld      t0, C_STATE(s1)
    li      t1, CS_ACTIVE
    bne     t0, t1, 9f
    ld      t0, C_FLAGS(s1)
    andi    t0, t0, CF_CONFIRMED
    beqz    t0, 9f
    LDX     t0, s1, C_PREV_UNTIL
    li      t1, -1
    bne     t0, t1, 9f
    CFG     t1, QUIC_CFG_KEY_UPDATE
    bnez    t1, 1f
    li      t1, 1000000
1:  LDX     t0, s1, C_PHASE_SENT
    bltu    t0, t1, 9f
    ld      t0, (C_SPACES + 2 * SP_SIZE + SP_LARGEST_ACKED)(s1)
    li      t1, -1
    beq     t0, t1, 9f
    LDX     t1, s1, C_PHASE_FIRST
    bltu    t0, t1, 9f
    call    quic_key_update
    call    quic_phase_start
9:  LEAVE   0
END_FUNCTION quic_maybe_key_update

/*
 * quic_phase_start(): after a key update: our first packet number of the new
 * phase, and the previous receive keys stay for 3 PTO. s1 the connection.
 */
LOCAL_FUNCTION quic_phase_start
    ENTER   0
    ld      t0, (C_SPACES + 2 * SP_SIZE + SP_NEXT_PN)(s1)
    SDX     t0, s1, C_PHASE_FIRST
    mv      a0, s1
    li      a1, SPACE_APP
    call    quic_pto_period
    slli    t0, a0, 1
    add     a0, a0, t0
    ld      t0, ST_NOW(s9)
    add     t0, t0, a0
    SDX     t0, s1, C_PREV_UNTIL
    LEAVE   0
END_FUNCTION quic_phase_start

/*
 * quic_conn_tell(): CONNECTED, then the stream actions, then CLOSED or
 * DIAL_FAILED, while the action room allows. s1 the connection.
 */
LOCAL_FUNCTION quic_conn_tell
    ENTER   0
    ld      t0, C_FLAGS(s1)
    andi    t1, t0, CF_TELL
    beqz    t1, 2f
    andi    t1, t0, CF_KNOWN
    bnez    t1, 2f
    ld      t1, C_STATE(s1)
    li      t2, CS_ACTIVE
    bne     t1, t2, 2f
    call    quic_room
    li      t0, QUIC_ACT_CONNECTED_SIZE
    bltu    a0, t0, 9f
    li      a0, QUIC_ACTION_CONNECTED
    li      a1, QUIC_ACT_CONNECTED_SIZE
    call    quic_action
    mv      s2, a0
    mv      a0, s1
    call    quic_conn_handle
    sd      a0, QUIC_ACT_CONN(s2)
    ld      t0, C_TAG(s1)
    sd      t0, QUIC_ACT_TAG(s2)
    ld      t0, C_ROLE(s1)
    xori    t0, t0, 1
    sd      t0, QUIC_ACT_DIRECTION(s2)
    ld      t0, C_SOCKET(s1)
    sd      t0, QUIC_ACT_C_SOCKET(s2)
    addi    a0, s2, QUIC_ACT_C_ADDR
    addi    a1, s1, C_ADDR
    li      a2, QUIC_ADDR_SIZE
    call    quic_copy
    LDX     a2, s1, C_PEER_KEY_LEN
    sd      a2, QUIC_ACT_KEY_LEN(s2)
    addi    a0, s2, QUIC_ACT_KEY
    ADDX    a1, s1, C_PEER_KEY
    call    quic_copy
    ld      t0, C_FLAGS(s1)
    ori     t0, t0, CF_KNOWN
    andi    t0, t0, ~CF_TELL
    sd      t0, C_FLAGS(s1)
2:  ld      t0, C_FLAGS(s1)                 # the streams
    andi    t0, t0, CF_KNOWN
    beqz    t0, 4f
    ld      t1, C_STATE(s1)
    li      t2, CS_ACTIVE
    bne     t1, t2, 4f
    LDX     s2, s1, C_STREAM_HEAD
3:  li      t0, -1
    beq     s2, t0, 4f
    mv      a0, s2
    call    quic_stream_at
    ld      s2, S_NEXT(a0)
    call    quic_stream_tell
    j       3b
4:  ld      t0, C_FLAGS(s1)                 # the end
    andi    t1, t0, CF_GONE
    beqz    t1, 9f
    ld      t1, C_STATE(s1)
    li      t2, CS_CLOSING
    bltu    t1, t2, 9f
    andi    t1, t0, CF_KNOWN
    bnez    t1, 5f
    ld      t1, C_ROLE(s1)
    bnez    t1, 7f                          # a peer's connection that never came up: nothing to tell
    call    quic_room
    li      t0, QUIC_ACT_CLOSED_SIZE
    bltu    a0, t0, 9f
    li      a0, QUIC_ACTION_DIAL_FAILED
    li      a1, QUIC_ACT_CLOSED_SIZE
    call    quic_action
    mv      s2, a0
    ld      t0, C_TAG(s1)
    sd      t0, QUIC_ACT_TAG(s2)
    j       6f
5:  call    quic_room
    li      t0, QUIC_ACT_CLOSED_SIZE
    bltu    a0, t0, 9f
    li      a0, QUIC_ACTION_CLOSED
    li      a1, QUIC_ACT_CLOSED_SIZE
    call    quic_action
    mv      s2, a0
    mv      a0, s1
    call    quic_conn_handle
    sd      a0, QUIC_ACT_CONN(s2)
    ld      t0, C_TAG(s1)
    sd      t0, QUIC_ACT_TAG(s2)
6:  ld      t0, C_REASON(s1)
    sd      t0, QUIC_ACT_REASON(s2)
    ld      t0, C_ERROR(s1)
    sd      t0, QUIC_ACT_ERROR(s2)
7:  ld      t0, C_FLAGS(s1)
    andi    t0, t0, ~CF_GONE
    sd      t0, C_FLAGS(s1)
9:  LEAVE   0
END_FUNCTION quic_conn_tell

/*
 * quic_conn_deadline(): the earliest timer of the connection becomes a
 * wakeup: loss detection, idle, closing, keep-alive, a delayed ACK, the
 * handshake deadline, and the end of the previous keys. s1 the connection.
 */
LOCAL_FUNCTION quic_conn_deadline
    ENTER   0
    ld      t0, C_STATE(s1)
    li      t1, CS_DONE
    bne     t0, t1, 1f
    ld      a0, ST_NOW(s9)                  # over, waiting to be heard
    call    quic_wake_at
    j       9f
1:  LDX     a0, s1, C_LOSS_AT
    call    quic_wake_at
    LDX     a0, s1, C_IDLE_AT
    call    quic_wake_at
    LDX     a0, s1, C_CLOSE_AT
    call    quic_wake_at
    LDX     a0, s1, C_PING_AT
    call    quic_wake_at
    LDX     a0, s1, C_PREV_UNTIL
    call    quic_wake_at
    ld      a0, (C_SPACES + 2 * SP_SIZE + SP_ACK_AT)(s1)
    call    quic_wake_at
    ld      t0, C_FLAGS(s1)
    andi    t0, t0, CF_COMPLETE
    bnez    t0, 9f
    CFG     t1, QUIC_CFG_HANDSHAKE
    li      t2, 1000
    mul     t1, t1, t2
    LDX     t2, s1, C_START
    add     a0, t1, t2
    call    quic_wake_at
9:  LEAVE   0
END_FUNCTION quic_conn_deadline
