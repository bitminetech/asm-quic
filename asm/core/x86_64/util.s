/*
 * Helpers of the core: the state heap, random bytes, actions, slots and
 * handles, and the variable-length integers of QUIC (RFC 9000 section 16).
 * r15 holds the state and r14 the scratch of the step.
 */

/* ---------------------------------------------------------------- Heap: a buddy allocator over the heap part */

/*
 * quic_heap_alloc(n) -> the state offset of n usable bytes, or 0 when no
 * block is free. Blocks are 2^order bytes with a 16-byte header; free
 * blocks sit on one doubly linked list for each order. A leaf.
 * r8 heap base, r9 order, r10 top order, r11 order found, rdx block,
 * rsi lists, rdi the block's address.
 */
LOCAL_FUNCTION quic_heap_alloc
    UNWIND_END_PROLOGUE
    mov     ST_HEAP_OFF(%r15), %r8
    add     %r15, %r8
    bsf     ST_HEAP_SIZE(%r15), %r10        /* the top order */
    lea     (HB_HEADER - 1)(%rdi), %rcx
    bsr     %rcx, %r9
    inc     %r9                             /* the order that holds n + 16 */
    mov     $HEAP_MIN_ORDER, %ecx
    cmp     %rcx, %r9
    cmovb   %rcx, %r9
    xor     %eax, %eax
    cmp     %r10, %r9
    ja      9f
    mov     %r9, %r11
    lea     ST_HEAP_FREE(%r15), %rsi
1:  cmp     %r10, %r11
    ja      9f
    mov     (%rsi,%r11,8), %rdx
    cmp     $NONE, %rdx
    jne     2f
    inc     %r11
    jmp     1b
2:  lea     (%r8,%rdx), %rdi                /* take the block off its list */
    mov     HB_NEXT(%rdi), %rcx
    mov     %rcx, (%rsi,%r11,8)
    cmp     $NONE, %rcx
    je      3f
    movq    $NONE, HB_PREV(%r8,%rcx)
3:  cmp     %r9, %r11                       /* split down to the order asked for */
    jbe     4f
    dec     %r11
    mov     %r11, %rcx
    mov     $1, %eax
    shl     %cl, %rax
    add     %rdx, %rax                      /* the upper half becomes free */
    movl    %r11d, HB_ORDER(%r8,%rax)
    movl    $1, HB_FREE(%r8,%rax)
    mov     (%rsi,%r11,8), %rcx
    mov     %rcx, HB_NEXT(%r8,%rax)
    movq    $NONE, HB_PREV(%r8,%rax)
    cmp     $NONE, %rcx
    je      31f
    mov     %rax, HB_PREV(%r8,%rcx)
31: mov     %rax, (%rsi,%r11,8)
    jmp     3b
4:  movl    %r9d, HB_ORDER(%rdi)
    movl    $0, HB_FREE(%rdi)
    mov     %r9, %rcx
    mov     $1, %eax
    shl     %cl, %rax
    add     %rax, ST_HEAP_USED(%r15)
    mov     %rdi, %rax
    sub     %r15, %rax
    add     $HB_HEADER, %rax
9:  ret
END_FUNCTION quic_heap_alloc

/*
 * quic_heap_free(offset): returns a block from quic_heap_alloc, joining it with
 * its free buddies. Offset 0 does nothing. A leaf.
 * r8 heap base, r9 order, r10 top order, rdx block, rsi lists, rax buddy,
 * r11 the buddy's address.
 */
LOCAL_FUNCTION quic_heap_free
    UNWIND_END_PROLOGUE
    test    %rdi, %rdi
    jz      9f
    mov     ST_HEAP_OFF(%r15), %r8
    mov     %rdi, %rdx
    sub     %r8, %rdx
    sub     $HB_HEADER, %rdx
    add     %r15, %r8
    bsf     ST_HEAP_SIZE(%r15), %r10
    lea     ST_HEAP_FREE(%r15), %rsi
    movl    HB_ORDER(%r8,%rdx), %r9d
    mov     %r9, %rcx
    mov     $1, %eax
    shl     %cl, %rax
    sub     %rax, ST_HEAP_USED(%r15)
1:  cmp     %r10, %r9
    jae     3f
    mov     %r9, %rcx
    mov     $1, %eax
    shl     %cl, %rax
    xor     %rdx, %rax                      /* the buddy */
    lea     (%r8,%rax), %r11
    cmpl    $0, HB_FREE(%r11)
    je      3f
    movl    HB_ORDER(%r11), %ecx
    cmp     %r9, %rcx
    jne     3f
    mov     HB_NEXT(%r11), %rcx             /* take the buddy off its list */
    mov     HB_PREV(%r11), %rdi
    cmp     $NONE, %rdi
    je      11f
    mov     %rcx, HB_NEXT(%r8,%rdi)
    jmp     12f
11: mov     %rcx, (%rsi,%r9,8)
12: cmp     $NONE, %rcx
    je      13f
    mov     %rdi, HB_PREV(%r8,%rcx)
13: movl    $0, HB_FREE(%r11)
    cmp     %rdx, %rax
    cmovb   %rax, %rdx
    inc     %r9
    jmp     1b
3:  lea     (%r8,%rdx), %rdi                /* push the joined block */
    movl    %r9d, HB_ORDER(%rdi)
    movl    $1, HB_FREE(%rdi)
    mov     (%rsi,%r9,8), %rcx
    mov     %rcx, HB_NEXT(%rdi)
    movq    $NONE, HB_PREV(%rdi)
    cmp     $NONE, %rcx
    je      4f
    mov     %rdx, HB_PREV(%r8,%rcx)
4:  mov     %rdx, (%rsi,%r9,8)
9:  ret
END_FUNCTION quic_heap_free

/* quic_heap_room(offset) -> the bytes a block of quic_heap_alloc holds after its header. A leaf. */
LOCAL_FUNCTION quic_heap_room
    UNWIND_END_PROLOGUE
    movl    (HB_ORDER - HB_HEADER)(%r15,%rdi), %ecx
    mov     $1, %eax
    shl     %cl, %rax
    sub     $HB_HEADER, %rax
    ret
END_FUNCTION quic_heap_room


/* ---------------------------------------------------------------- Random bytes */

/*
 * quic_random(dst, n): n bytes from the DRBG: SHA-256(key || counter) blocks,
 * the counter going up by one for each block.
 * Extra: 32(%rsp) the ByteList (64 bytes), 96(%rsp) the block.
 */
LOCAL_FUNCTION quic_random
    ENTER   0, 96
    mov     %rdi, %rbp
    mov     %rsi, %r12
1:  test    %r12, %r12
    jz      9f
    movq    $64, 32(%rsp)
    movq    $QUIC_BL_FIXED, 40(%rsp)
    movq    $40, 48(%rsp)
    mov     ST_DRBG_KEY(%r15), %rax
    mov     %rax, 56(%rsp)
    mov     (ST_DRBG_KEY + 8)(%r15), %rax
    mov     %rax, 64(%rsp)
    mov     (ST_DRBG_KEY + 16)(%r15), %rax
    mov     %rax, 72(%rsp)
    mov     (ST_DRBG_KEY + 24)(%r15), %rax
    mov     %rax, 80(%rsp)
    mov     ST_DRBG_COUNT(%r15), %rax
    mov     %rax, 88(%rsp)
    inc     %rax
    mov     %rax, ST_DRBG_COUNT(%r15)
    lea     32(%rsp), %rdi
    lea     96(%rsp), %rsi
    CALL_GLOBAL crypto_sha256
    mov     $32, %edx
    cmp     %rdx, %r12
    cmovb   %r12, %rdx
    sub     %rdx, %r12
    mov     %rbp, %rdi
    lea     96(%rsp), %rsi
    call    quic_copy
    mov     %rax, %rbp
    jmp     1b
9:  LEAVE   0, 96
END_FUNCTION quic_random

/* quic_reseed(entropy): the DRBG key becomes SHA-256(key || the 32 entropy bytes). */
LOCAL_FUNCTION quic_reseed
    ENTER   0, 96
    movq    $88, 32(%rsp)
    movq    $QUIC_BL_FIXED, 40(%rsp)
    movq    $64, 48(%rsp)
    mov     ST_DRBG_KEY(%r15), %rax
    mov     %rax, 56(%rsp)
    mov     (ST_DRBG_KEY + 8)(%r15), %rax
    mov     %rax, 64(%rsp)
    mov     (ST_DRBG_KEY + 16)(%r15), %rax
    mov     %rax, 72(%rsp)
    mov     (ST_DRBG_KEY + 24)(%r15), %rax
    mov     %rax, 80(%rsp)
    mov     (%rdi), %rax
    mov     %rax, 88(%rsp)
    mov     8(%rdi), %rax
    mov     %rax, 96(%rsp)
    mov     16(%rdi), %rax
    mov     %rax, 104(%rsp)
    mov     24(%rdi), %rax
    mov     %rax, 112(%rsp)
    lea     32(%rsp), %rdi
    lea     ST_DRBG_KEY(%r15), %rsi
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
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     SC_ACTIONS(%r14), %r12
    mov     QUIC_BL_COUNT(%r12), %rax
    mov     QUIC_BL_SIZE(%r12), %rcx
    sub     $QUIC_BL_FIXED, %rcx
    sub     %rax, %rcx
    cmp     %rbp, %rcx
    jb      8f
    lea     QUIC_BL_FIXED(%r12,%rax), %r13
    add     %rbp, %rax
    mov     %rax, QUIC_BL_COUNT(%r12)
    mov     %r13, %rdi
    mov     %rbp, %rsi
    call    quic_zero
    mov     %rbp, QUIC_ACT_SIZE(%r13)
    mov     %rbx, QUIC_ACT_KIND(%r13)
    mov     %r13, %rax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_action

/* quic_room() -> the action bytes left, beyond the reserve of the step. A leaf. */
LOCAL_FUNCTION quic_room
    UNWIND_END_PROLOGUE
    mov     SC_ACTIONS(%r14), %rcx
    mov     QUIC_BL_SIZE(%rcx), %rax
    sub     $QUIC_BL_FIXED, %rax
    sub     QUIC_BL_COUNT(%rcx), %rax
    xor     %edx, %edx
    sub     SC_RESERVE(%r14), %rax
    cmovb   %rdx, %rax
    ret
END_FUNCTION quic_room

/* quic_wake_at(time): the next step is due by time at the latest. A leaf. */
LOCAL_FUNCTION quic_wake_at
    UNWIND_END_PROLOGUE
    cmp     SC_WAKE(%r14), %rdi
    jae     1f
    mov     %rdi, SC_WAKE(%r14)
1:  ret
END_FUNCTION quic_wake_at

/* ---------------------------------------------------------------- Slots and handles */

/*
 * quic_slot(table field, count field, stride, handle) -> the slot of a live
 * handle, or 0: the index is below the count, the generation matches and
 * the slot is in use (a nonzero u32 at offset 4). A leaf.
 */
LOCAL_FUNCTION quic_slot
    UNWIND_END_PROLOGUE
    mov     %ecx, %r9d
    cmp     (%r15,%rsi), %r9
    jae     8f
    mov     (%r15,%rdi), %rax
    add     %r15, %rax
    imul    %rdx, %r9
    add     %r9, %rax
    movl    (%rax), %r8d
    shr     $32, %rcx
    cmp     %rcx, %r8
    jne     8f
    cmpl    $0, 4(%rax)
    je      8f
    ret
8:  xor     %eax, %eax
    ret
END_FUNCTION quic_slot

/* quic_conn(handle) -> the connection slot, or 0. */
LOCAL_FUNCTION quic_conn
    FRAME
    mov     %rdi, %rcx
    mov     $ST_CONN_OFF, %edi
    mov     $ST_CONN_COUNT, %esi
    mov     $C_SIZE, %edx
    call    quic_slot
    UNFRAME
END_FUNCTION quic_conn

/* quic_stream(handle) -> the stream slot, or 0. */
LOCAL_FUNCTION quic_stream
    FRAME
    mov     %rdi, %rcx
    mov     $ST_STREAM_OFF, %edi
    mov     $ST_STREAM_COUNT, %esi
    mov     $S_SIZE, %edx
    call    quic_slot
    UNFRAME
END_FUNCTION quic_stream

/*
 * quic_handle(table field, stride, slot) -> the handle of a slot: its index,
 * and its generation in the high 32 bits. A leaf.
 */
LOCAL_FUNCTION quic_handle
    UNWIND_END_PROLOGUE
    mov     %rdx, %rcx
    mov     (%r15,%rdi), %r8
    add     %r15, %r8
    mov     %rcx, %rax
    sub     %r8, %rax
    xor     %edx, %edx
    div     %rsi
    movl    (%rcx), %edx
    shl     $32, %rdx
    or      %rdx, %rax
    ret
END_FUNCTION quic_handle

/*
 * quic_alloc_slot(table field, count field, stride) -> a free slot, zeroed
 * after its generation, with the generation one higher and the in-use word
 * set to 1; 0 when every slot is in use.
 */
LOCAL_FUNCTION quic_alloc_slot
    ENTER   0
    mov     (%r15,%rdi), %rbx
    add     %r15, %rbx
    mov     (%r15,%rsi), %rbp
    mov     %rdx, %r12
1:  test    %rbp, %rbp
    jz      8f
    cmpl    $0, 4(%rbx)
    je      2f
    add     %r12, %rbx
    dec     %rbp
    jmp     1b
2:  movl    (%rbx), %r13d
    lea     8(%rbx), %rdi
    lea     -8(%r12), %rsi
    call    quic_zero
    inc     %r13d
    movl    %r13d, (%rbx)
    movl    $1, 4(%rbx)
    mov     %rbx, %rax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_alloc_slot

/* quic_conn_handle(conn) -> its handle. */
LOCAL_FUNCTION quic_conn_handle
    FRAME
    mov     %rdi, %rdx
    mov     $ST_CONN_OFF, %edi
    mov     $C_SIZE, %esi
    call    quic_handle
    UNFRAME
END_FUNCTION quic_conn_handle

/* quic_stream_handle(stream) -> its handle. */
LOCAL_FUNCTION quic_stream_handle
    FRAME
    mov     %rdi, %rdx
    mov     $ST_STREAM_OFF, %edi
    mov     $S_SIZE, %esi
    call    quic_handle
    UNFRAME
END_FUNCTION quic_stream_handle

/* quic_conn_index(conn) -> the slot index of a connection. A leaf. */
LOCAL_FUNCTION quic_conn_index
    UNWIND_END_PROLOGUE
    mov     %rdi, %rax
    sub     ST_CONN_OFF(%r15), %rax
    sub     %r15, %rax
    xor     %edx, %edx
    mov     $C_SIZE, %ecx
    div     %rcx
    ret
END_FUNCTION quic_conn_index

/* quic_conn_at(index) -> the connection slot of an index. A leaf. */
LOCAL_FUNCTION quic_conn_at
    UNWIND_END_PROLOGUE
    imul    $C_SIZE, %rdi, %rax
    add     ST_CONN_OFF(%r15), %rax
    add     %r15, %rax
    ret
END_FUNCTION quic_conn_at

/* quic_stream_at(index) -> the stream slot of an index. A leaf. */
LOCAL_FUNCTION quic_stream_at
    UNWIND_END_PROLOGUE
    imul    $S_SIZE, %rdi, %rax
    add     ST_STREAM_OFF(%r15), %rax
    add     %r15, %rax
    ret
END_FUNCTION quic_stream_at

/* quic_stream_index(stream) -> the slot index of a stream. A leaf. */
LOCAL_FUNCTION quic_stream_index
    UNWIND_END_PROLOGUE
    mov     %rdi, %rax
    sub     ST_STREAM_OFF(%r15), %rax
    sub     %r15, %rax
    xor     %edx, %edx
    mov     $S_SIZE, %ecx
    div     %rcx
    ret
END_FUNCTION quic_stream_index

/* ---------------------------------------------------------------- Variable-length integers */

/* quic_vlen(v) -> the bytes of the varint of v: 1, 2, 4 or 8. v is below 2^62. A leaf. */
LOCAL_FUNCTION quic_vlen
    UNWIND_END_PROLOGUE
    mov     $1, %eax
    cmp     $64, %rdi
    jb      9f
    mov     $2, %eax
    cmp     $16384, %rdi
    jb      9f
    mov     $4, %eax
    cmp     $(1 << 30), %rdi
    jb      9f
    mov     $8, %eax
9:  ret
END_FUNCTION quic_vlen

/* quic_vput(dst, v) -> dst after the varint of v, in its shortest form, big endian. v is below 2^62. A leaf. */
LOCAL_FUNCTION quic_vput
    UNWIND_END_PROLOGUE
    mov     %rdi, %rax
    cmp     $64, %rsi
    jb      1f
    cmp     $16384, %rsi
    jb      2f
    cmp     $(1 << 30), %rsi
    jb      4f
    movabs  $0xC000000000000000, %rcx
    or      %rcx, %rsi
    bswap   %rsi
    mov     %rsi, (%rax)
    add     $8, %rax
    ret
1:  movb    %sil, (%rax)
    inc     %rax
    ret
2:  or      $0x4000, %esi
    rol     $8, %si
    movw    %si, (%rax)
    add     $2, %rax
    ret
4:  or      $0x80000000, %esi
    bswap   %esi
    movl    %esi, (%rax)
    add     $4, %rax
    ret
END_FUNCTION quic_vput

/* quic_vput2(dst, v) -> dst after the 2-byte varint of v. v is below 16384. A leaf. */
LOCAL_FUNCTION quic_vput2
    UNWIND_END_PROLOGUE
    mov     %rdi, %rax
    or      $0x4000, %esi
    rol     $8, %si
    movw    %si, (%rax)
    add     $2, %rax
    ret
END_FUNCTION quic_vput2

/*
 * quic_vget(p, end) -> rax the position after the varint at p, or 0 when it
 * does not end by end; rdx its value. A leaf.
 */
LOCAL_FUNCTION quic_vget
    UNWIND_END_PROLOGUE
    cmp     %rsi, %rdi
    jae     8f
    movzbl  (%rdi), %ecx
    shr     $6, %ecx
    mov     $1, %r8d
    shl     %cl, %r8                        /* 1, 2, 4 or 8 bytes */
    mov     %rsi, %rax
    sub     %rdi, %rax
    cmp     %r8, %rax
    jb      8f
    movzbl  (%rdi), %edx
    and     $0x3F, %edx
    mov     $1, %r9d
1:  cmp     %r8, %r9
    jae     2f
    shl     $8, %rdx
    movzbl  (%rdi,%r9), %ecx
    or      %rcx, %rdx
    inc     %r9
    jmp     1b
2:  lea     (%rdi,%r8), %rax
    ret
8:  xor     %eax, %eax
    xor     %edx, %edx
    ret
END_FUNCTION quic_vget

/* quic_put16(dst, v) -> dst + 2: v as 2 bytes big endian. A leaf. */
LOCAL_FUNCTION quic_put16
    UNWIND_END_PROLOGUE
    mov     %esi, %ecx
    rol     $8, %cx
    movw    %cx, (%rdi)
    lea     2(%rdi), %rax
    ret
END_FUNCTION quic_put16

/* quic_put24(dst, v) -> dst + 3: v as 3 bytes big endian. A leaf. */
LOCAL_FUNCTION quic_put24
    UNWIND_END_PROLOGUE
    mov     %esi, %ecx
    shr     $16, %ecx
    movb    %cl, (%rdi)
    mov     %esi, %ecx
    shr     $8, %ecx
    movb    %cl, 1(%rdi)
    movb    %sil, 2(%rdi)
    lea     3(%rdi), %rax
    ret
END_FUNCTION quic_put24

/* quic_get24(p) -> the 3 bytes big endian at p. A leaf. */
LOCAL_FUNCTION quic_get24
    UNWIND_END_PROLOGUE
    movzbl  (%rdi), %eax
    shl     $16, %eax
    movzbl  1(%rdi), %ecx
    shl     $8, %ecx
    or      %ecx, %eax
    movzbl  2(%rdi), %ecx
    or      %ecx, %eax
    ret
END_FUNCTION quic_get24
