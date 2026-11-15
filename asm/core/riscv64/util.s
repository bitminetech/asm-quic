/*
 * Helpers of the core: the state heap, random bytes, actions, slots and
 * handles, and the variable-length integers of QUIC (RFC 9000 section 16).
 * s9 holds the state and s10 the scratch of the step.
 */

/*
 * quic_heap_alloc(n) -> the state offset of n usable bytes, or 0 when no
 * block is free. Blocks are 2^order bytes with a 16-byte header; free
 * blocks sit on one doubly linked list for each order. A leaf.
 * a7 heap base, t0 order, t1 top order, t2 order found, t3 block, t4
 * lists, t5 the block's address, t6 a6 a5 a1 temporaries.
 */
LOCAL_FUNCTION quic_heap_alloc
    UNWIND_END_PROLOGUE
    ld      a7, ST_HEAP_OFF(s9)
    add     a7, s9, a7
    ld      t6, ST_HEAP_SIZE(s9)            # the top order: the size is a power of 2
    li      t1, 0
1:  andi    a6, t6, 1
    bnez    a6, 2f
    srli    t6, t6, 1
    addi    t1, t1, 1
    j       1b
2:  addi    t6, a0, (HB_HEADER - 1)         # the order that holds n + 16: the bit length of n + 15
    li      t0, 0
3:  beqz    t6, 4f
    srli    t6, t6, 1
    addi    t0, t0, 1
    j       3b
4:  li      a6, HEAP_MIN_ORDER
    bgeu    t0, a6, 5f
    mv      t0, a6
5:  li      a0, 0
    bltu    t1, t0, 9f
    mv      t2, t0
    addi    t4, s9, ST_HEAP_FREE
6:  bltu    t1, t2, 9f
    slli    a6, t2, 3
    add     a6, t4, a6
    ld      t3, 0(a6)
    li      a5, NONE
    bne     t3, a5, 7f
    addi    t2, t2, 1
    j       6b
7:  add     t5, a7, t3                      # take the block off its list
    ld      t6, HB_NEXT(t5)
    sd      t6, 0(a6)
    beq     t6, a5, 8f
    add     a6, a7, t6
    sd      a5, HB_PREV(a6)
8:  bgeu    t0, t2, 10f                     # split down to the order asked for
    addi    t2, t2, -1
    li      t6, 1
    sll     t6, t6, t2
    add     t6, t3, t6                      # the upper half becomes free
    add     a6, a7, t6
    sw      t2, HB_ORDER(a6)
    li      a5, 1
    sw      a5, HB_FREE(a6)
    slli    a1, t2, 3
    add     a1, t4, a1
    ld      a5, 0(a1)
    sd      a5, HB_NEXT(a6)
    li      a0, NONE
    sd      a0, HB_PREV(a6)
    beq     a5, a0, 81f
    add     a5, a7, a5
    sd      t6, HB_PREV(a5)
81: sd      t6, 0(a1)
    j       8b
10: sw      t0, HB_ORDER(t5)
    sw      zero, HB_FREE(t5)
    li      t6, 1
    sll     t6, t6, t0
    ld      a6, ST_HEAP_USED(s9)
    add     a6, a6, t6
    sd      a6, ST_HEAP_USED(s9)
    sub     a0, t5, s9
    addi    a0, a0, HB_HEADER
9:  ret
END_FUNCTION quic_heap_alloc

/*
 * quic_heap_free(offset): returns a block from quic_heap_alloc, joining it with
 * its free buddies. Offset 0 does nothing. A leaf.
 * a7 heap base, t0 order, t1 top order, t3 block, t4 lists, t5 address,
 * t6 buddy, a6 its address.
 */
LOCAL_FUNCTION quic_heap_free
    UNWIND_END_PROLOGUE
    beqz    a0, 9f
    ld      a7, ST_HEAP_OFF(s9)
    sub     t3, a0, a7
    addi    t3, t3, -HB_HEADER
    add     a7, s9, a7
    ld      t6, ST_HEAP_SIZE(s9)
    li      t1, 0
1:  andi    a6, t6, 1
    bnez    a6, 2f
    srli    t6, t6, 1
    addi    t1, t1, 1
    j       1b
2:  addi    t4, s9, ST_HEAP_FREE
    add     t5, a7, t3
    lwu     t0, HB_ORDER(t5)
    li      t6, 1
    sll     t6, t6, t0
    ld      a6, ST_HEAP_USED(s9)
    sub     a6, a6, t6
    sd      a6, ST_HEAP_USED(s9)
3:  bgeu    t0, t1, 5f
    li      t6, 1
    sll     t6, t6, t0
    xor     t6, t3, t6                      # the buddy
    add     a6, a7, t6
    lwu     a5, HB_FREE(a6)
    beqz    a5, 5f
    lwu     a5, HB_ORDER(a6)
    bne     a5, t0, 5f
    ld      a1, HB_NEXT(a6)                 # take the buddy off its list
    ld      a2, HB_PREV(a6)
    li      a4, NONE
    beq     a2, a4, 31f
    add     a3, a7, a2
    sd      a1, HB_NEXT(a3)
    j       32f
31: slli    a3, t0, 3
    add     a3, t4, a3
    sd      a1, 0(a3)
32: beq     a1, a4, 33f
    add     a3, a7, a1
    sd      a2, HB_PREV(a3)
33: sw      zero, HB_FREE(a6)
    bgeu    t6, t3, 34f
    mv      t3, t6
34: addi    t0, t0, 1
    j       3b
5:  add     t5, a7, t3                      # push the joined block
    sw      t0, HB_ORDER(t5)
    li      a5, 1
    sw      a5, HB_FREE(t5)
    slli    a3, t0, 3
    add     a3, t4, a3
    ld      a5, 0(a3)
    sd      a5, HB_NEXT(t5)
    li      a1, NONE
    sd      a1, HB_PREV(t5)
    beq     a5, a1, 6f
    add     a1, a7, a5
    sd      t3, HB_PREV(a1)
6:  sd      t3, 0(a3)
9:  ret
END_FUNCTION quic_heap_free

/*
 * quic_random(dst, n): n bytes from the DRBG: SHA-256(key || counter) blocks,
 * the counter going up by one for each block.
 * Extra: sp + FL the ByteList (64 bytes), sp + FL + 64 the block.
 */
LOCAL_FUNCTION quic_random
    ENTER   0, 96
    mv      s2, a0
    mv      s3, a1
1:  beqz    s3, 9f
    li      t0, 64
    sd      t0, FL(sp)
    li      t0, QUIC_BL_FIXED
    sd      t0, (FL + 8)(sp)
    li      t0, 40
    sd      t0, (FL + 16)(sp)
    ld      t0, ST_DRBG_KEY(s9)
    sd      t0, (FL + 24)(sp)
    ld      t0, (ST_DRBG_KEY + 8)(s9)
    sd      t0, (FL + 32)(sp)
    ld      t0, (ST_DRBG_KEY + 16)(s9)
    sd      t0, (FL + 40)(sp)
    ld      t0, (ST_DRBG_KEY + 24)(s9)
    sd      t0, (FL + 48)(sp)
    ld      t0, ST_DRBG_COUNT(s9)
    sd      t0, (FL + 56)(sp)
    addi    t0, t0, 1
    sd      t0, ST_DRBG_COUNT(s9)
    addi    a0, sp, FL
    addi    a1, sp, (FL + 64)
    CALL_GLOBAL crypto_sha256
    li      a2, 32
    bgeu    s3, a2, 2f
    mv      a2, s3
2:  sub     s3, s3, a2
    mv      a0, s2
    addi    a1, sp, (FL + 64)
    call    quic_copy
    mv      s2, a0
    j       1b
9:  LEAVE   0, 96
END_FUNCTION quic_random

/* quic_reseed(entropy): the DRBG key becomes SHA-256(key || the 32 entropy bytes). */
LOCAL_FUNCTION quic_reseed
    ENTER   0, 96
    li      t0, 88
    sd      t0, FL(sp)
    li      t0, QUIC_BL_FIXED
    sd      t0, (FL + 8)(sp)
    li      t0, 64
    sd      t0, (FL + 16)(sp)
    ld      t0, ST_DRBG_KEY(s9)
    sd      t0, (FL + 24)(sp)
    ld      t0, (ST_DRBG_KEY + 8)(s9)
    sd      t0, (FL + 32)(sp)
    ld      t0, (ST_DRBG_KEY + 16)(s9)
    sd      t0, (FL + 40)(sp)
    ld      t0, (ST_DRBG_KEY + 24)(s9)
    sd      t0, (FL + 48)(sp)
    ld      t0, 0(a0)
    sd      t0, (FL + 56)(sp)
    ld      t0, 8(a0)
    sd      t0, (FL + 64)(sp)
    ld      t0, 16(a0)
    sd      t0, (FL + 72)(sp)
    ld      t0, 24(a0)
    sd      t0, (FL + 80)(sp)
    addi    a0, sp, FL
    addi    a1, s9, ST_DRBG_KEY
    CALL_GLOBAL crypto_sha256
    LEAVE   0, 96
END_FUNCTION quic_reseed

/*
 * quic_action(kind, size) -> the new action, zeroed, with size and kind set;
 * 0 when the action list has no room. size is a multiple of 8.
 */
LOCAL_FUNCTION quic_action
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    ld      s3, SC_ACTIONS(s10)
    ld      t0, QUIC_BL_COUNT(s3)
    ld      t1, QUIC_BL_SIZE(s3)
    addi    t1, t1, -QUIC_BL_FIXED
    sub     t1, t1, t0
    li      a0, 0
    bltu    t1, s2, 9f
    addi    s4, s3, QUIC_BL_FIXED
    add     s4, s4, t0
    add     t0, t0, s2
    sd      t0, QUIC_BL_COUNT(s3)
    mv      a0, s4
    mv      a1, s2
    call    quic_zero
    sd      s2, QUIC_ACT_SIZE(s4)
    sd      s1, QUIC_ACT_KIND(s4)
    mv      a0, s4
9:  LEAVE   0
END_FUNCTION quic_action

/* quic_room() -> the action bytes left, beyond the reserve of the step. A leaf. */
LOCAL_FUNCTION quic_room
    UNWIND_END_PROLOGUE
    ld      a1, SC_ACTIONS(s10)
    ld      a2, QUIC_BL_SIZE(a1)
    addi    a2, a2, -QUIC_BL_FIXED
    ld      a3, QUIC_BL_COUNT(a1)
    sub     a2, a2, a3
    ld      a3, SC_RESERVE(s10)
    li      a0, 0
    bltu    a2, a3, 1f
    sub     a0, a2, a3
1:  ret
END_FUNCTION quic_room

/* quic_wake_at(time): the next step is due by time at the latest. A leaf. */
LOCAL_FUNCTION quic_wake_at
    UNWIND_END_PROLOGUE
    ld      a1, SC_WAKE(s10)
    bgeu    a0, a1, 1f
    sd      a0, SC_WAKE(s10)
1:  ret
END_FUNCTION quic_wake_at

/*
 * quic_slot(table field, count field, stride, handle) -> the slot of a live
 * handle, or 0: the index is below the count, the generation matches and
 * the slot is in use (a nonzero u32 at offset 4). A leaf.
 */
LOCAL_FUNCTION quic_slot
    UNWIND_END_PROLOGUE
    add     a4, s9, a1
    ld      a4, 0(a4)
    slli    a5, a3, 32
    srli    a5, a5, 32
    bgeu    a5, a4, 8f
    add     a4, s9, a0
    ld      a4, 0(a4)
    add     a4, s9, a4
    mul     a5, a5, a2
    add     a4, a4, a5
    lwu     a6, 0(a4)
    srli    a7, a3, 32
    bne     a6, a7, 8f
    lwu     a6, 4(a4)
    beqz    a6, 8f
    mv      a0, a4
    ret
8:  li      a0, 0
    ret
END_FUNCTION quic_slot

/* quic_conn(handle) -> the connection slot, or 0. */
LOCAL_FUNCTION quic_conn
    FRAME
    mv      a3, a0
    li      a0, ST_CONN_OFF
    li      a1, ST_CONN_COUNT
    li      a2, C_SIZE
    call    quic_slot
    UNFRAME
END_FUNCTION quic_conn

/* quic_stream(handle) -> the stream slot, or 0. */
LOCAL_FUNCTION quic_stream
    FRAME
    mv      a3, a0
    li      a0, ST_STREAM_OFF
    li      a1, ST_STREAM_COUNT
    li      a2, S_SIZE
    call    quic_slot
    UNFRAME
END_FUNCTION quic_stream

/*
 * quic_handle(table field, stride, slot) -> the handle of a slot: its index,
 * and its generation in the high 32 bits. A leaf.
 */
LOCAL_FUNCTION quic_handle
    UNWIND_END_PROLOGUE
    add     a3, s9, a0
    ld      a3, 0(a3)
    add     a3, s9, a3
    sub     a3, a2, a3
    divu    a3, a3, a1
    lwu     a4, 0(a2)
    slli    a4, a4, 32
    or      a0, a3, a4
    ret
END_FUNCTION quic_handle

/*
 * quic_alloc_slot(table field, count field, stride) -> a free slot, zeroed
 * after its generation, with the generation one higher and the in-use word
 * set to 1; 0 when every slot is in use.
 */
LOCAL_FUNCTION quic_alloc_slot
    ENTER   0
    add     t0, s9, a0
    ld      s1, 0(t0)
    add     s1, s9, s1
    add     t0, s9, a1
    ld      s2, 0(t0)
    mv      s3, a2
1:  beqz    s2, 8f
    lwu     t0, 4(s1)
    beqz    t0, 2f
    add     s1, s1, s3
    addi    s2, s2, -1
    j       1b
2:  lwu     s4, 0(s1)
    addi    a0, s1, 8
    addi    a1, s3, -8
    call    quic_zero
    addiw   s4, s4, 1
    sw      s4, 0(s1)
    li      t0, 1
    sw      t0, 4(s1)
    mv      a0, s1
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_alloc_slot


/* quic_heap_room(offset) -> the bytes a block of quic_heap_alloc holds after its header. A leaf. */
LOCAL_FUNCTION quic_heap_room
    UNWIND_END_PROLOGUE
    add     a1, s9, a0
    lwu     a2, (HB_ORDER - HB_HEADER)(a1)
    li      a0, 1
    sll     a0, a0, a2
    addi    a0, a0, -HB_HEADER
    ret
END_FUNCTION quic_heap_room

/* quic_conn_handle(conn) -> its handle. */
LOCAL_FUNCTION quic_conn_handle
    FRAME
    mv      a2, a0
    li      a0, ST_CONN_OFF
    li      a1, C_SIZE
    call    quic_handle
    UNFRAME
END_FUNCTION quic_conn_handle

/* quic_stream_handle(stream) -> its handle. */
LOCAL_FUNCTION quic_stream_handle
    FRAME
    mv      a2, a0
    li      a0, ST_STREAM_OFF
    li      a1, S_SIZE
    call    quic_handle
    UNFRAME
END_FUNCTION quic_stream_handle

/* quic_conn_index(conn) -> the slot index of a connection. A leaf. */
LOCAL_FUNCTION quic_conn_index
    UNWIND_END_PROLOGUE
    ld      a1, ST_CONN_OFF(s9)
    add     a1, s9, a1
    sub     a0, a0, a1
    li      a1, C_SIZE
    divu    a0, a0, a1
    ret
END_FUNCTION quic_conn_index

/* quic_conn_at(index) -> the connection slot of an index. A leaf. */
LOCAL_FUNCTION quic_conn_at
    UNWIND_END_PROLOGUE
    ld      a1, ST_CONN_OFF(s9)
    add     a1, s9, a1
    li      a2, C_SIZE
    mul     a0, a0, a2
    add     a0, a0, a1
    ret
END_FUNCTION quic_conn_at

/* quic_stream_at(index) -> the stream slot of an index. A leaf. */
LOCAL_FUNCTION quic_stream_at
    UNWIND_END_PROLOGUE
    ld      a1, ST_STREAM_OFF(s9)
    add     a1, s9, a1
    li      a2, S_SIZE
    mul     a0, a0, a2
    add     a0, a0, a1
    ret
END_FUNCTION quic_stream_at

/* quic_stream_index(stream) -> the slot index of a stream. A leaf. */
LOCAL_FUNCTION quic_stream_index
    UNWIND_END_PROLOGUE
    ld      a1, ST_STREAM_OFF(s9)
    add     a1, s9, a1
    sub     a0, a0, a1
    li      a1, S_SIZE
    divu    a0, a0, a1
    ret
END_FUNCTION quic_stream_index

/* ---------------------------------------------------------------- Variable-length integers */

/* quic_vlen(v) -> the bytes of the varint of v: 1, 2, 4 or 8. v is below 2^62. A leaf. */
LOCAL_FUNCTION quic_vlen
    UNWIND_END_PROLOGUE
    li      a1, 64
    bltu    a0, a1, 1f
    li      a1, 16384
    bltu    a0, a1, 2f
    li      a1, (1 << 30)
    bltu    a0, a1, 4f
    li      a0, 8
    ret
1:  li      a0, 1
    ret
2:  li      a0, 2
    ret
4:  li      a0, 4
    ret
END_FUNCTION quic_vlen

/* quic_vput(dst, v) -> dst after the varint of v, in its shortest form, big endian. v is below 2^62. A leaf. */
LOCAL_FUNCTION quic_vput
    UNWIND_END_PROLOGUE
    li      a2, 64
    bltu    a1, a2, 1f
    li      a2, 16384
    bltu    a1, a2, 2f
    li      a2, (1 << 30)
    bltu    a1, a2, 4f
    li      a2, 3
    slli    a2, a2, 62
    or      a1, a1, a2
    li      a3, 56
3:  srl     a4, a1, a3
    sb      a4, 0(a0)
    addi    a0, a0, 1
    addi    a3, a3, -8
    bgez    a3, 3b
    ret
1:  sb      a1, 0(a0)
    addi    a0, a0, 1
    ret
2:  li      a2, 0x4000
    or      a1, a1, a2
    srli    a3, a1, 8
    sb      a3, 0(a0)
    sb      a1, 1(a0)
    addi    a0, a0, 2
    ret
4:  li      a2, 1
    slli    a2, a2, 31
    or      a1, a1, a2
    srli    a3, a1, 24
    sb      a3, 0(a0)
    srli    a3, a1, 16
    sb      a3, 1(a0)
    srli    a3, a1, 8
    sb      a3, 2(a0)
    sb      a1, 3(a0)
    addi    a0, a0, 4
    ret
END_FUNCTION quic_vput

/* quic_vput2(dst, v) -> dst after the 2-byte varint of v. v is below 16384. A leaf. */
LOCAL_FUNCTION quic_vput2
    UNWIND_END_PROLOGUE
    li      a2, 0x4000
    or      a1, a1, a2
    srli    a3, a1, 8
    sb      a3, 0(a0)
    sb      a1, 1(a0)
    addi    a0, a0, 2
    ret
END_FUNCTION quic_vput2

/*
 * quic_vget(p, end) -> a0 the position after the varint at p, or 0 when it
 * does not end by end; a1 its value. A leaf.
 */
LOCAL_FUNCTION quic_vget
    UNWIND_END_PROLOGUE
    bgeu    a0, a1, 8f
    lbu     a2, 0(a0)
    srli    a3, a2, 6
    li      a4, 1
    sll     a4, a4, a3                      # 1, 2, 4 or 8 bytes
    sub     a3, a1, a0
    bltu    a3, a4, 8f
    andi    a5, a2, 0x3F
    li      a6, 1
1:  bgeu    a6, a4, 2f
    add     a7, a0, a6
    lbu     a7, 0(a7)
    slli    a5, a5, 8
    or      a5, a5, a7
    addi    a6, a6, 1
    j       1b
2:  add     a0, a0, a4
    mv      a1, a5
    ret
8:  li      a0, 0
    li      a1, 0
    ret
END_FUNCTION quic_vget

/* quic_put16(dst, v) -> dst + 2: v as 2 bytes big endian. A leaf. */
LOCAL_FUNCTION quic_put16
    UNWIND_END_PROLOGUE
    srli    a2, a1, 8
    sb      a2, 0(a0)
    sb      a1, 1(a0)
    addi    a0, a0, 2
    ret
END_FUNCTION quic_put16

/* quic_put24(dst, v) -> dst + 3: v as 3 bytes big endian. A leaf. */
LOCAL_FUNCTION quic_put24
    UNWIND_END_PROLOGUE
    srli    a2, a1, 16
    sb      a2, 0(a0)
    srli    a2, a1, 8
    sb      a2, 1(a0)
    sb      a1, 2(a0)
    addi    a0, a0, 3
    ret
END_FUNCTION quic_put24

/* quic_get24(p) -> the 3 bytes big endian at p. A leaf. */
LOCAL_FUNCTION quic_get24
    UNWIND_END_PROLOGUE
    lbu     a1, 0(a0)
    lbu     a2, 1(a0)
    lbu     a3, 2(a0)
    slli    a1, a1, 16
    slli    a2, a2, 8
    or      a1, a1, a2
    or      a0, a1, a3
    ret
END_FUNCTION quic_get24
