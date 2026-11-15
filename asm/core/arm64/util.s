/*
 * Helpers of the core: the state heap, random bytes, actions, slots and
 * handles, and the variable-length integers of QUIC (RFC 9000 section 16).
 * x27 holds the state and x28 the scratch of the step.
 */

/* ---------------------------------------------------------------- Heap */

/*
 * quic_heap_alloc(n) -> the state offset of a block of at least n bytes, or 0
 * when the heap cannot hold it. A buddy allocator over the heap of the state:
 * a block of order k is 2^k bytes, its first HB_HEADER bytes the header. A leaf.
 * x8 heap base, x9 order wanted, x10 top order, x11 order tried, x12 block, x13 lists.
 */
LOCAL_FUNCTION quic_heap_alloc
    UNWIND_END_PROLOGUE
    ldr     x8, [x27, #ST_HEAP_OFF]
    add     x8, x27, x8
    ldr     x10, [x27, #ST_HEAP_SIZE]
    rbit    x10, x10
    clz     x10, x10
    add     x0, x0, #HB_HEADER
    sub     x1, x0, #1
    clz     x1, x1
    mov     x9, #64
    sub     x9, x9, x1
    cmp     x9, #HEAP_MIN_ORDER
    mov     x1, #HEAP_MIN_ORDER
    csel    x9, x1, x9, lo
    mov     x0, #0
    cmp     x9, x10
    b.hi    9f
    mov     x11, x9
    add     x13, x27, #ST_HEAP_FREE
1:  cmp     x11, x10
    b.hi    9f
    ldr     x12, [x13, x11, lsl #3]
    cmn     x12, #1
    b.ne    2f
    add     x11, x11, #1
    b       1b
2:  add     x14, x8, x12
    ldr     x15, [x14, #HB_NEXT]
    str     x15, [x13, x11, lsl #3]
    cmn     x15, #1
    b.eq    3f
    add     x16, x8, x15
    mov     x17, #NONE
    str     x17, [x16, #HB_PREV]
3:  cmp     x11, x9
    b.ls    4f
    sub     x11, x11, #1
    mov     x15, #1
    lsl     x15, x15, x11
    add     x15, x12, x15
    add     x16, x8, x15
    str     w11, [x16, #HB_ORDER]
    mov     w17, #1
    str     w17, [x16, #HB_FREE]
    ldr     x17, [x13, x11, lsl #3]
    str     x17, [x16, #HB_NEXT]
    mov     x1, #NONE
    str     x1, [x16, #HB_PREV]
    cmn     x17, #1
    b.eq    31f
    add     x1, x8, x17
    str     x15, [x1, #HB_PREV]
31: str     x15, [x13, x11, lsl #3]
    b       3b
4:  str     w9, [x14, #HB_ORDER]
    str     wzr, [x14, #HB_FREE]
    mov     x15, #1
    lsl     x15, x15, x9
    ldr     x16, [x27, #ST_HEAP_USED]
    add     x16, x16, x15
    str     x16, [x27, #ST_HEAP_USED]
    sub     x0, x14, x27
    add     x0, x0, #HB_HEADER
9:  ret
END_FUNCTION quic_heap_alloc

/*
 * quic_heap_free(offset): returns a block of quic_heap_alloc, joining it with
 * its free buddies. Offset 0 does nothing. A leaf.
 */
LOCAL_FUNCTION quic_heap_free
    UNWIND_END_PROLOGUE
    cbz     x0, 9f
    ldr     x8, [x27, #ST_HEAP_OFF]
    sub     x12, x0, x8
    sub     x12, x12, #HB_HEADER
    add     x8, x27, x8
    ldr     x10, [x27, #ST_HEAP_SIZE]
    rbit    x10, x10
    clz     x10, x10
    add     x13, x27, #ST_HEAP_FREE
    add     x14, x8, x12
    ldr     w9, [x14, #HB_ORDER]
    mov     x15, #1
    lsl     x15, x15, x9
    ldr     x16, [x27, #ST_HEAP_USED]
    sub     x16, x16, x15
    str     x16, [x27, #ST_HEAP_USED]
1:  cmp     x9, x10
    b.hs    3f
    mov     x15, #1
    lsl     x15, x15, x9
    eor     x15, x12, x15
    add     x16, x8, x15
    ldr     w17, [x16, #HB_FREE]
    cbz     w17, 3f
    ldr     w17, [x16, #HB_ORDER]
    cmp     x17, x9
    b.ne    3f
    ldr     x1, [x16, #HB_NEXT]
    ldr     x2, [x16, #HB_PREV]
    cmn     x2, #1
    b.eq    11f
    add     x3, x8, x2
    str     x1, [x3, #HB_NEXT]
    b       12f
11: str     x1, [x13, x9, lsl #3]
12: cmn     x1, #1
    b.eq    13f
    add     x3, x8, x1
    str     x2, [x3, #HB_PREV]
13: str     wzr, [x16, #HB_FREE]
    cmp     x15, x12
    csel    x12, x15, x12, lo
    add     x9, x9, #1
    b       1b
3:  add     x14, x8, x12
    str     w9, [x14, #HB_ORDER]
    mov     w17, #1
    str     w17, [x14, #HB_FREE]
    ldr     x17, [x13, x9, lsl #3]
    str     x17, [x14, #HB_NEXT]
    mov     x1, #NONE
    str     x1, [x14, #HB_PREV]
    cmn     x17, #1
    b.eq    4f
    add     x1, x8, x17
    str     x12, [x1, #HB_PREV]
4:  str     x12, [x13, x9, lsl #3]
9:  ret
END_FUNCTION quic_heap_free

/* quic_heap_room(offset) -> the bytes a block of quic_heap_alloc holds after its header. A leaf. */
LOCAL_FUNCTION quic_heap_room
    UNWIND_END_PROLOGUE
    add     x1, x27, x0
    ldr     w2, [x1, #-HB_HEADER + HB_ORDER]
    mov     x0, #1
    lsl     x0, x0, x2
    sub     x0, x0, #HB_HEADER
    ret
END_FUNCTION quic_heap_room

/* ---------------------------------------------------------------- Random bytes */

/*
 * quic_random(dst, n): n bytes from the DRBG: SHA-256(key || counter) for each
 * 32 bytes, the counter one higher each time.
 */
LOCAL_FUNCTION quic_random
    ENTER   0, 96
    mov     x20, x0
    mov     x21, x1
1:  cbz     x21, 9f
    mov     x9, #64
    str     x9, [sp]
    mov     x9, #QUIC_BL_FIXED
    str     x9, [sp, #8]
    mov     x9, #40
    str     x9, [sp, #16]
    ldp     x9, x10, [x27, #ST_DRBG_KEY]
    stp     x9, x10, [sp, #24]
    ldp     x9, x10, [x27, #ST_DRBG_KEY + 16]
    stp     x9, x10, [sp, #40]
    ldr     x9, [x27, #ST_DRBG_COUNT]
    str     x9, [sp, #56]
    add     x9, x9, #1
    str     x9, [x27, #ST_DRBG_COUNT]
    mov     x0, sp
    add     x1, sp, #64
    CALL_GLOBAL crypto_sha256
    mov     x2, #32
    cmp     x21, x2
    csel    x2, x21, x2, lo
    sub     x21, x21, x2
    mov     x0, x20
    add     x1, sp, #64
    bl      quic_copy
    mov     x20, x0
    b       1b
9:  LEAVE   0, 96
END_FUNCTION quic_random

/* quic_reseed(entropy): the DRBG key becomes SHA-256(key || the 32 entropy bytes). */
LOCAL_FUNCTION quic_reseed
    ENTER   0, 96
    mov     x9, #88
    str     x9, [sp]
    mov     x9, #QUIC_BL_FIXED
    str     x9, [sp, #8]
    mov     x9, #64
    str     x9, [sp, #16]
    ldp     x9, x10, [x27, #ST_DRBG_KEY]
    stp     x9, x10, [sp, #24]
    ldp     x9, x10, [x27, #ST_DRBG_KEY + 16]
    stp     x9, x10, [sp, #40]
    ldp     x9, x10, [x0]
    stp     x9, x10, [sp, #56]
    ldp     x9, x10, [x0, #16]
    stp     x9, x10, [sp, #72]
    mov     x0, sp
    add     x1, x27, #ST_DRBG_KEY
    CALL_GLOBAL crypto_sha256
    LEAVE   0, 96
END_FUNCTION quic_reseed

/* ---------------------------------------------------------------- Actions and time */

/*
 * quic_action(kind, size) -> the new action, zeroed, with size and kind set;
 * 0 when the action list has no room. size is a multiple of 8.
 */
LOCAL_FUNCTION quic_action
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    ldr     x21, [x28, #SC_ACTIONS]
    ldr     x9, [x21, #QUIC_BL_COUNT]
    ldr     x10, [x21, #QUIC_BL_SIZE]
    sub     x10, x10, #QUIC_BL_FIXED
    sub     x10, x10, x9
    mov     x0, #0
    cmp     x10, x20
    b.lo    9f
    add     x22, x21, #QUIC_BL_FIXED
    add     x22, x22, x9
    add     x9, x9, x20
    str     x9, [x21, #QUIC_BL_COUNT]
    mov     x0, x22
    mov     x1, x20
    bl      quic_zero
    str     x20, [x22, #QUIC_ACT_SIZE]
    str     x19, [x22, #QUIC_ACT_KIND]
    mov     x0, x22
9:  LEAVE   0
END_FUNCTION quic_action

/* quic_room() -> the action bytes left, beyond the reserve of the step. A leaf. */
LOCAL_FUNCTION quic_room
    UNWIND_END_PROLOGUE
    ldr     x1, [x28, #SC_ACTIONS]
    ldr     x2, [x1, #QUIC_BL_SIZE]
    sub     x2, x2, #QUIC_BL_FIXED
    ldr     x3, [x1, #QUIC_BL_COUNT]
    sub     x2, x2, x3
    ldr     x3, [x28, #SC_RESERVE]
    subs    x0, x2, x3
    csel    x0, xzr, x0, lo
    ret
END_FUNCTION quic_room

/* quic_wake_at(time): the next step is due by time at the latest. NONE does nothing. A leaf. */
LOCAL_FUNCTION quic_wake_at
    UNWIND_END_PROLOGUE
    ldr     x1, [x28, #SC_WAKE]
    cmp     x0, x1
    b.hs    1f
    str     x0, [x28, #SC_WAKE]
1:  ret
END_FUNCTION quic_wake_at

/* ---------------------------------------------------------------- Slots and handles */

/*
 * quic_slot(table field, count field, stride, handle) -> the slot of a live
 * handle, or 0: the index is below the count, the generation matches and
 * the slot is in use. A leaf.
 */
LOCAL_FUNCTION quic_slot
    UNWIND_END_PROLOGUE
    ldr     x4, [x27, x1]
    mov     w5, w3
    cmp     x5, x4
    b.hs    8f
    ldr     x4, [x27, x0]
    add     x4, x27, x4
    madd    x4, x5, x2, x4
    ldr     w6, [x4]
    cmp     x6, x3, lsr #32
    b.ne    8f
    ldr     w6, [x4, #4]
    cbz     w6, 8f
    mov     x0, x4
    ret
8:  mov     x0, #0
    ret
END_FUNCTION quic_slot

/* quic_conn(handle) -> the connection slot, or 0. */
LOCAL_FUNCTION quic_conn
    ENTER   0
    mov     x3, x0
    mov     x0, #ST_CONN_OFF
    mov     x1, #ST_CONN_COUNT
    mov     x2, #C_SIZE
    bl      quic_slot
    LEAVE   0
END_FUNCTION quic_conn

/* quic_stream(handle) -> the stream slot, or 0. */
LOCAL_FUNCTION quic_stream
    ENTER   0
    mov     x3, x0
    mov     x0, #ST_STREAM_OFF
    mov     x1, #ST_STREAM_COUNT
    mov     x2, #S_SIZE
    bl      quic_slot
    LEAVE   0
END_FUNCTION quic_stream

/*
 * quic_handle(table field, stride, slot) -> the handle of a slot: its index,
 * and its generation in the high 32 bits. A leaf.
 */
LOCAL_FUNCTION quic_handle
    UNWIND_END_PROLOGUE
    ldr     x3, [x27, x0]
    add     x3, x27, x3
    sub     x3, x2, x3
    udiv    x3, x3, x1
    ldr     w4, [x2]
    orr     x0, x3, x4, lsl #32
    ret
END_FUNCTION quic_handle

/* quic_conn_handle(conn) -> its handle. */
LOCAL_FUNCTION quic_conn_handle
    ENTER   0
    mov     x2, x0
    mov     x0, #ST_CONN_OFF
    mov     x1, #C_SIZE
    bl      quic_handle
    LEAVE   0
END_FUNCTION quic_conn_handle

/* quic_stream_handle(stream) -> its handle. */
LOCAL_FUNCTION quic_stream_handle
    ENTER   0
    mov     x2, x0
    mov     x0, #ST_STREAM_OFF
    mov     x1, #S_SIZE
    bl      quic_handle
    LEAVE   0
END_FUNCTION quic_stream_handle

/* quic_conn_index(conn) -> the slot index of a connection. A leaf. */
LOCAL_FUNCTION quic_conn_index
    UNWIND_END_PROLOGUE
    ldr     x1, [x27, #ST_CONN_OFF]
    add     x1, x27, x1
    sub     x0, x0, x1
    mov     x1, #C_SIZE
    udiv    x0, x0, x1
    ret
END_FUNCTION quic_conn_index

/* quic_conn_at(index) -> the connection slot of an index. A leaf. */
LOCAL_FUNCTION quic_conn_at
    UNWIND_END_PROLOGUE
    ldr     x1, [x27, #ST_CONN_OFF]
    add     x1, x27, x1
    mov     x2, #C_SIZE
    madd    x0, x0, x2, x1
    ret
END_FUNCTION quic_conn_at

/* quic_stream_at(index) -> the stream slot of an index. A leaf. */
LOCAL_FUNCTION quic_stream_at
    UNWIND_END_PROLOGUE
    ldr     x1, [x27, #ST_STREAM_OFF]
    add     x1, x27, x1
    mov     x2, #S_SIZE
    madd    x0, x0, x2, x1
    ret
END_FUNCTION quic_stream_at

/* quic_stream_index(stream) -> the slot index of a stream. A leaf. */
LOCAL_FUNCTION quic_stream_index
    UNWIND_END_PROLOGUE
    ldr     x1, [x27, #ST_STREAM_OFF]
    add     x1, x27, x1
    sub     x0, x0, x1
    mov     x1, #S_SIZE
    udiv    x0, x0, x1
    ret
END_FUNCTION quic_stream_index

/*
 * quic_alloc_slot(table field, count field, stride) -> a free slot, zeroed
 * after its generation, with the generation one higher and the in-use word
 * set to 1; 0 when every slot is in use.
 */
LOCAL_FUNCTION quic_alloc_slot
    ENTER   0
    ldr     x19, [x27, x0]
    add     x19, x27, x19
    ldr     x20, [x27, x1]
    mov     x21, x2
1:  cbz     x20, 8f
    ldr     w9, [x19, #4]
    cbz     w9, 2f
    add     x19, x19, x21
    sub     x20, x20, #1
    b       1b
2:  ldr     w22, [x19]
    add     x0, x19, #8
    sub     x1, x21, #8
    bl      quic_zero
    add     w22, w22, #1
    str     w22, [x19]
    mov     w9, #1
    str     w9, [x19, #4]
    mov     x0, x19
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_alloc_slot

/* ---------------------------------------------------------------- Variable-length integers */

/* quic_vlen(v) -> the bytes of the varint of v: 1, 2, 4 or 8. v is below 2^62. A leaf. */
LOCAL_FUNCTION quic_vlen
    UNWIND_END_PROLOGUE
    cmp     x0, #64
    b.lo    1f
    mov     x1, #16384
    cmp     x0, x1
    b.lo    2f
    mov     x1, #(1 << 30)
    cmp     x0, x1
    b.lo    4f
    mov     x0, #8
    ret
1:  mov     x0, #1
    ret
2:  mov     x0, #2
    ret
4:  mov     x0, #4
    ret
END_FUNCTION quic_vlen

/* quic_vput(dst, v) -> dst after the varint of v, in its shortest form. v is below 2^62. A leaf. */
LOCAL_FUNCTION quic_vput
    UNWIND_END_PROLOGUE
    cmp     x1, #64
    b.lo    1f
    mov     x2, #16384
    cmp     x1, x2
    b.lo    2f
    mov     x2, #(1 << 30)
    cmp     x1, x2
    b.lo    4f
    orr     x1, x1, #0xC000000000000000
    rev     x1, x1
    str     x1, [x0], #8
    ret
1:  strb    w1, [x0], #1
    ret
2:  orr     w1, w1, #0x4000
    rev16   w1, w1
    strh    w1, [x0], #2
    ret
4:  orr     w1, w1, #0x80000000
    rev     w1, w1
    str     w1, [x0], #4
    ret
END_FUNCTION quic_vput

/* quic_vput2(dst, v) -> dst after the 2-byte varint of v. v is below 16384. A leaf. */
LOCAL_FUNCTION quic_vput2
    UNWIND_END_PROLOGUE
    orr     w1, w1, #0x4000
    rev16   w1, w1
    strh    w1, [x0], #2
    ret
END_FUNCTION quic_vput2

/*
 * quic_vget(p, end) -> x0 the position after the varint at p, or 0 when it
 * does not end by end; x1 its value. A leaf.
 */
LOCAL_FUNCTION quic_vget
    UNWIND_END_PROLOGUE
    cmp     x0, x1
    b.hs    8f
    ldrb    w2, [x0]
    lsr     w3, w2, #6
    mov     x4, #1
    lsl     x4, x4, x3                      /* 1, 2, 4 or 8 bytes */
    sub     x5, x1, x0
    cmp     x4, x5
    b.hi    8f
    and     x6, x2, #0x3F
    mov     x7, #1
1:  cmp     x7, x4
    b.hs    2f
    ldrb    w2, [x0, x7]
    orr     x6, x2, x6, lsl #8
    add     x7, x7, #1
    b       1b
2:  add     x0, x0, x4
    mov     x1, x6
    ret
8:  mov     x0, #0
    mov     x1, #0
    ret
END_FUNCTION quic_vget

/* quic_put16(dst, v) -> dst + 2: v as 2 bytes big endian. A leaf. */
LOCAL_FUNCTION quic_put16
    UNWIND_END_PROLOGUE
    lsr     w2, w1, #8
    strb    w2, [x0]
    strb    w1, [x0, #1]
    add     x0, x0, #2
    ret
END_FUNCTION quic_put16

/* quic_put24(dst, v) -> dst + 3: v as 3 bytes big endian. A leaf. */
LOCAL_FUNCTION quic_put24
    UNWIND_END_PROLOGUE
    lsr     w2, w1, #16
    strb    w2, [x0]
    lsr     w2, w1, #8
    strb    w2, [x0, #1]
    strb    w1, [x0, #2]
    add     x0, x0, #3
    ret
END_FUNCTION quic_put24

/* quic_get24(p) -> the 3 bytes big endian at p. A leaf. */
LOCAL_FUNCTION quic_get24
    UNWIND_END_PROLOGUE
    ldrb    w1, [x0]
    ldrb    w2, [x0, #1]
    ldrb    w3, [x0, #2]
    lsl     w1, w1, #16
    orr     w1, w1, w2, lsl #8
    orr     w0, w1, w3
    ret
END_FUNCTION quic_get24
