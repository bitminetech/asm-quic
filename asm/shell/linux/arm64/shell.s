/*
 * asm-quic shell for Linux on ARM64: UDP sockets, the clock and random bytes,
 * through direct system calls. Requirements: docs/reference/shell.md.
 * Layouts: include/quic.inc.
 *
 * System calls: the number in x8, arguments in x0 to x5, "svc #0"; x0 holds
 * the result, or minus the error number (-4095 to -1).
 */
.set ISA_ARM64, 1
.include "quic.inc"
.include "platform.inc"

/* Linux numbers: asm-generic/unistd.h and the uapi headers. */
.set SYS_CLOSE, 57
.set SYS_PPOLL, 73
.set SYS_CLOCK_GETTIME, 113
.set SYS_SOCKET, 198
.set SYS_BIND, 200
.set SYS_GETSOCKNAME, 204
.set SYS_SENDTO, 206
.set SYS_RECVFROM, 207
.set SYS_SETSOCKOPT, 208
.set SYS_GETRANDOM, 278
.set OS_AF_INET, 2
.set OS_AF_INET6, 10
.set OS_SOCK_DGRAM, 2
.set OS_SOCK_NONBLOCK, 0x800
.set OS_SOCK_CLOEXEC, 0x80000
.set OS_SOL_SOCKET, 1
.set OS_SO_SNDBUF, 7
.set OS_SO_RCVBUF, 8
.set OS_IPPROTO_IPV6, 41
.set OS_IPV6_V6ONLY, 26
.set OS_MSG_DONTWAIT, 0x40
.set OS_POLLIN, 1
.set OS_EAGAIN, 11
.set OS_EINTR, 4
.set OS_CLOCK_REALTIME, 0
.set OS_CLOCK_MONOTONIC, 1
.set SOCKET_BUFFER, 4194304             /* bytes asked for each socket buffer */

.macro SYSCALL number
    mov     x8, #\number
    svc     #0
.endm

/* The frame of a shell function: x29, x30, x19-x28, then locals at sp + 96. */
.macro SENTER locals
    stp     x29, x30, [sp, #-(96 + \locals)]!
    UNWIND_SAVE_FPLR_X (96 + \locals)
    mov     x29, sp
    UNWIND_SET_FP
    stp     x19, x20, [sp, #16]
    UNWIND_SAVE_REGP x19, x20, 16, (96 + \locals)
    stp     x21, x22, [sp, #32]
    UNWIND_SAVE_REGP x21, x22, 32, (96 + \locals)
    stp     x23, x24, [sp, #48]
    UNWIND_SAVE_REGP x23, x24, 48, (96 + \locals)
    stp     x25, x26, [sp, #64]
    UNWIND_SAVE_REGP x25, x26, 64, (96 + \locals)
    stp     x27, x28, [sp, #80]
    UNWIND_SAVE_REGP x27, x28, 80, (96 + \locals)
    UNWIND_END_PROLOGUE
.endm

.macro SLEAVE locals
    UNWIND_BEGIN_EPILOGUE
    ldp     x27, x28, [sp, #80]
    UNWIND_RESTORE_REGP x27, x28, 80
    ldp     x25, x26, [sp, #64]
    UNWIND_RESTORE_REGP x25, x26, 64
    ldp     x23, x24, [sp, #48]
    UNWIND_RESTORE_REGP x23, x24, 48
    ldp     x21, x22, [sp, #32]
    UNWIND_RESTORE_REGP x21, x22, 32
    ldp     x19, x20, [sp, #16]
    UNWIND_RESTORE_REGP x19, x20, 16
    ldp     x29, x30, [sp], #(96 + \locals)
    UNWIND_RESTORE_FPLR_X (96 + \locals)
    UNWIND_END_EPILOGUE
    ret
.endm

/* ---------------------------------------------------------------- Addresses */

/*
 * quic_shell_sockaddr(dst, addr) -> the length of the native socket address
 * of an Address: sockaddr_in (16 bytes) or sockaddr_in6 (28 bytes). A leaf.
 */
LOCAL_FUNCTION quic_shell_sockaddr
    UNWIND_END_PROLOGUE
    stp     xzr, xzr, [x0]
    stp     xzr, xzr, [x0, #16]
    ldr     x2, [x1, #QUIC_ADDR_PORT]
    rev16   w2, w2
    strh    w2, [x0, #2]
    ldr     x3, [x1, #QUIC_ADDR_FAMILY]
    cmp     x3, #6
    b.eq    1f
    mov     w4, #OS_AF_INET
    strh    w4, [x0]
    ldr     w4, [x1, #QUIC_ADDR_IP]
    str     w4, [x0, #4]
    mov     x0, #16
    ret
1:  mov     w4, #OS_AF_INET6
    strh    w4, [x0]
    ldr     x4, [x1, #QUIC_ADDR_IP]
    ldr     x5, [x1, #(QUIC_ADDR_IP + 8)]
    str     x4, [x0, #8]
    str     x5, [x0, #16]
    mov     x0, #28
    ret
END_FUNCTION quic_shell_sockaddr

/* quic_shell_address(dst, sockaddr): the Address of a native socket address. A leaf. */
LOCAL_FUNCTION quic_shell_address
    UNWIND_END_PROLOGUE
    stp     xzr, xzr, [x0]
    stp     xzr, xzr, [x0, #16]
    ldrh    w2, [x1, #2]
    rev16   w2, w2
    str     x2, [x0, #QUIC_ADDR_PORT]
    ldrh    w3, [x1]
    cmp     w3, #OS_AF_INET6
    b.eq    1f
    mov     x3, #4
    str     x3, [x0, #QUIC_ADDR_FAMILY]
    ldr     w4, [x1, #4]
    str     w4, [x0, #QUIC_ADDR_IP]
    ret
1:  mov     x3, #6
    str     x3, [x0, #QUIC_ADDR_FAMILY]
    ldr     x4, [x1, #8]
    ldr     x5, [x1, #16]
    str     x4, [x0, #QUIC_ADDR_IP]
    str     x5, [x0, #(QUIC_ADDR_IP + 8)]
    ret
END_FUNCTION quic_shell_address

/* ---------------------------------------------------------------- Functions */

/* quic_shell_init(ctx) -> status: a context with no socket. */
FUNCTION quic_shell_init
    SENTER  0
    ldr     x9, [x0, #QUIC_SH_SIZE]
    mov     x10, #QUIC_SHELL_SIZE
    cmp     x9, x10
    mov     x1, x0
    mov     x0, #QUIC_BUFFER_TOO_SMALL
    b.lo    9f
    str     xzr, [x1, #QUIC_SH_COUNT]
    mov     x0, #QUIC_OK
9:  SLEAVE  0
END_FUNCTION quic_shell_init

/*
 * quic_shell_bind(ctx, addr, result) -> status: a non-blocking UDP socket bound
 * to the address (port 0 picks one), IPv6 only for an IPv6 address, with big
 * buffers; result gets its socket ID and local address.
 * x19 ctx, x20 addr, x21 result, x22 fd, x23 the entry.
 */
.set SB_SA, 0                           /* 32 bytes */
.set SB_LEN, 32
.set SB_OPT, 40
.set SB_FRAME, 48
FUNCTION quic_shell_bind
    SENTER  SB_FRAME
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    ldr     x9, [x19, #QUIC_SH_COUNT]
    mov     x0, #QUIC_BUFFER_TOO_SMALL
    cmp     x9, #QUIC_SH_MAX
    b.hs    9f
    ldr     x9, [x20, #QUIC_ADDR_FAMILY]
    mov     x0, #OS_AF_INET
    cmp     x9, #6
    mov     x10, #OS_AF_INET6
    csel    x0, x10, x0, eq
    mov     x1, #(OS_SOCK_DGRAM | OS_SOCK_NONBLOCK)
    orr     x1, x1, #OS_SOCK_CLOEXEC
    mov     x2, #0
    SYSCALL SYS_SOCKET
    cmn     x0, #4095
    b.hi    8f
    mov     x22, x0
    ldr     x9, [x20, #QUIC_ADDR_FAMILY]
    cmp     x9, #6
    b.ne    1f
    mov     w9, #1
    str     w9, [sp, #(96 + SB_OPT)]
    mov     x0, x22
    mov     x1, #OS_IPPROTO_IPV6
    mov     x2, #OS_IPV6_V6ONLY
    add     x3, sp, #(96 + SB_OPT)
    mov     x4, #4
    SYSCALL SYS_SETSOCKOPT
1:  movz    w9, #(SOCKET_BUFFER >> 16), lsl #16
    str     w9, [sp, #(96 + SB_OPT)]
    mov     x0, x22
    mov     x1, #OS_SOL_SOCKET
    mov     x2, #OS_SO_RCVBUF
    add     x3, sp, #(96 + SB_OPT)
    mov     x4, #4
    SYSCALL SYS_SETSOCKOPT                  /* the kernel may give less: not an error */
    mov     x0, x22
    mov     x1, #OS_SOL_SOCKET
    mov     x2, #OS_SO_SNDBUF
    add     x3, sp, #(96 + SB_OPT)
    mov     x4, #4
    SYSCALL SYS_SETSOCKOPT
    add     x0, sp, #(96 + SB_SA)
    mov     x1, x20
    bl      quic_shell_sockaddr
    mov     x2, x0
    mov     x0, x22
    add     x1, sp, #(96 + SB_SA)
    SYSCALL SYS_BIND
    cmn     x0, #4095
    b.hi    7f
    mov     x9, #32
    str     w9, [sp, #(96 + SB_LEN)]
    mov     x0, x22
    add     x1, sp, #(96 + SB_SA)
    add     x2, sp, #(96 + SB_LEN)
    SYSCALL SYS_GETSOCKNAME
    cmn     x0, #4095
    b.hi    7f
    ldr     x9, [x19, #QUIC_SH_COUNT]
    mov     x10, #QUIC_SH_STRIDE
    madd    x23, x9, x10, x19
    add     x23, x23, #QUIC_SH_SOCKETS
    str     x22, [x23, #QUIC_SH_FD]
    add     x0, x23, #QUIC_SH_LOCAL
    add     x1, sp, #(96 + SB_SA)
    bl      quic_shell_address
    ldr     x9, [x19, #QUIC_SH_COUNT]
    str     x9, [x21, #QUIC_BR_SOCKET]
    add     x9, x9, #1
    str     x9, [x19, #QUIC_SH_COUNT]
    add     x0, x21, #QUIC_BR_LOCAL
    add     x1, sp, #(96 + SB_SA)
    bl      quic_shell_address
    mov     x0, #QUIC_OK
    b       9f
7:  mov     x0, x22
    SYSCALL SYS_CLOSE
8:  mov     x0, #QUIC_OS_ERROR
9:  SLEAVE  SB_FRAME
END_FUNCTION quic_shell_bind

/*
 * quic_shell_send(ctx, actions) -> status: each SEND action of the list goes
 * out with sendto; a datagram the OS does not take is lost, as UDP allows.
 * x19 ctx, x20 position, x21 end, x22 the action.
 */
.set SS_SA, 0
.set SS_FRAME, 32
FUNCTION quic_shell_send
    SENTER  SS_FRAME
    mov     x19, x0
    ldr     x9, [x1, #8]
    add     x20, x1, x9
    ldr     x10, [x1, #16]
    add     x21, x20, x10
1:  cmp     x20, x21
    b.hs    8f
    mov     x22, x20
    ldr     x9, [x22, #QUIC_ACT_SIZE]
    add     x20, x20, x9
    ldr     x9, [x22, #QUIC_ACT_KIND]
    cmp     x9, #QUIC_ACTION_SEND
    b.ne    1b
    ldr     x9, [x22, #QUIC_ACT_SOCKET]
    ldr     x10, [x19, #QUIC_SH_COUNT]
    cmp     x9, x10
    b.hs    1b
    mov     x10, #QUIC_SH_STRIDE
    madd    x23, x9, x10, x19
    ldr     x24, [x23, #(QUIC_SH_SOCKETS + QUIC_SH_FD)]
    add     x0, sp, #(96 + SS_SA)
    add     x1, x22, #QUIC_ACT_ADDR
    bl      quic_shell_sockaddr
    mov     x5, x0
    mov     x0, x24
    add     x1, x22, #QUIC_ACT_DATA
    ldr     x2, [x22, #QUIC_ACT_COUNT]
    mov     x3, #OS_MSG_DONTWAIT
    add     x4, sp, #(96 + SS_SA)
    SYSCALL SYS_SENDTO
    b       1b
8:  mov     x0, #QUIC_OK
    SLEAVE  SS_FRAME
END_FUNCTION quic_shell_send

/*
 * quic_shell_receive(ctx, events) -> status: DATAGRAM events for the
 * datagrams waiting on each socket, while the list has room for one of
 * QUIC_RECEIVE_MAX bytes.
 * x19 ctx, x20 events, x21 socket index, x22 fd, x23 the event.
 */
.set SR_SA, 0
.set SR_LEN, 32
.set SR_FRAME, 48
FUNCTION quic_shell_receive
    SENTER  SR_FRAME
    mov     x19, x0
    mov     x20, x1
    mov     x21, #0
1:  ldr     x9, [x19, #QUIC_SH_COUNT]
    cmp     x21, x9
    b.hs    8f
    mov     x10, #QUIC_SH_STRIDE
    madd    x9, x21, x10, x19
    ldr     x22, [x9, #(QUIC_SH_SOCKETS + QUIC_SH_FD)]
2:  ldr     x9, [x20, #QUIC_BL_SIZE]        /* room for one more */
    ldr     x10, [x20, #QUIC_BL_COUNT]
    sub     x9, x9, #QUIC_BL_FIXED
    sub     x9, x9, x10
    mov     x11, #(QUIC_EV_DATA + QUIC_RECEIVE_MAX + 8)
    cmp     x9, x11
    b.lo    8f
    add     x23, x20, #QUIC_BL_FIXED
    add     x23, x23, x10
    mov     x9, #32
    str     w9, [sp, #(96 + SR_LEN)]
    mov     x0, x22
    add     x1, x23, #QUIC_EV_DATA
    mov     x2, #QUIC_RECEIVE_MAX
    mov     x3, #OS_MSG_DONTWAIT
    add     x4, sp, #(96 + SR_SA)
    add     x5, sp, #(96 + SR_LEN)
    SYSCALL SYS_RECVFROM
    cmn     x0, #4095
    b.hi    3f
    str     x0, [x23, #QUIC_EV_COUNT]
    add     x9, x0, #(QUIC_EV_DATA + 7)
    and     x9, x9, #~7
    str     x9, [x23, #QUIC_EV_SIZE]
    mov     x10, #QUIC_EVENT_DATAGRAM
    str     x10, [x23, #QUIC_EV_KIND]
    str     x21, [x23, #QUIC_EV_SOCKET]
    ldr     x10, [x20, #QUIC_BL_COUNT]
    add     x10, x10, x9
    str     x10, [x20, #QUIC_BL_COUNT]
    add     x0, x23, #QUIC_EV_ADDR
    add     x1, sp, #(96 + SR_SA)
    bl      quic_shell_address
    b       2b
3:  add     x21, x21, #1                    /* EAGAIN or an error: the next socket */
    b       1b
8:  mov     x0, #QUIC_OK
    SLEAVE  SR_FRAME
END_FUNCTION quic_shell_receive

/*
 * quic_shell_wait(ctx, until) -> status: waits with ppoll until a socket can
 * be read or the monotonic time in microseconds at until, at most 60 s.
 * x19 ctx, x20 until.
 */
.set SW_FDS, 0                          /* QUIC_SH_MAX pollfd of 8 bytes */
.set SW_TS, 32
.set SW_NOW, 48
.set SW_FRAME, 64
FUNCTION quic_shell_wait
    SENTER  SW_FRAME
    mov     x19, x0
    ldr     x20, [x1]
    mov     x0, #OS_CLOCK_MONOTONIC
    add     x1, sp, #(96 + SW_NOW)
    SYSCALL SYS_CLOCK_GETTIME
    ldp     x9, x10, [sp, #(96 + SW_NOW)]
    movz    x11, #0x4240
    movk    x11, #0xF, lsl #16              /* 1000000 */
    mul     x9, x9, x11
    mov     x12, #1000
    udiv    x10, x10, x12
    add     x9, x9, x10                     /* now in microseconds */
    subs    x13, x20, x9
    csel    x13, xzr, x13, lo
    movz    x14, #0x8700
    movk    x14, #0x0393, lsl #16           /* 60000000 */
    cmp     x13, x14
    csel    x13, x13, x14, lo
    udiv    x15, x13, x11
    msub    x16, x15, x11, x13
    mul     x16, x16, x12
    stp     x15, x16, [sp, #(96 + SW_TS)]
    ldr     x21, [x19, #QUIC_SH_COUNT]
    mov     x22, #0
1:  cmp     x22, x21
    b.hs    2f
    mov     x10, #QUIC_SH_STRIDE
    madd    x9, x22, x10, x19
    ldr     x9, [x9, #(QUIC_SH_SOCKETS + QUIC_SH_FD)]
    add     x10, sp, #(96 + SW_FDS)
    add     x10, x10, x22, lsl #3
    str     w9, [x10]
    mov     w11, #OS_POLLIN
    str     w11, [x10, #4]
    add     x22, x22, #1
    b       1b
2:  add     x0, sp, #(96 + SW_FDS)
    mov     x1, x21
    add     x2, sp, #(96 + SW_TS)
    mov     x3, #0
    mov     x4, #8
    SYSCALL SYS_PPOLL
    mov     x0, #QUIC_OK
    SLEAVE  SW_FRAME
END_FUNCTION quic_shell_wait

/*
 * quic_shell_clock(tick) -> status: the monotonic time in microseconds, the
 * Unix time in seconds, and 32 bytes of getrandom.
 * x19 tick, x20 bytes so far.
 */
.set SC_TS, 0
.set SC_FRAME, 16
FUNCTION quic_shell_clock
    SENTER  SC_FRAME
    mov     x19, x0
    mov     x0, #OS_CLOCK_MONOTONIC
    add     x1, sp, #(96 + SC_TS)
    SYSCALL SYS_CLOCK_GETTIME
    cmn     x0, #4095
    b.hi    8f
    ldp     x9, x10, [sp, #(96 + SC_TS)]
    movz    x11, #0x4240
    movk    x11, #0xF, lsl #16
    mul     x9, x9, x11
    mov     x12, #1000
    udiv    x10, x10, x12
    add     x9, x9, x10
    str     x9, [x19, #QUIC_TICK_NOW]
    mov     x0, #OS_CLOCK_REALTIME
    add     x1, sp, #(96 + SC_TS)
    SYSCALL SYS_CLOCK_GETTIME
    cmn     x0, #4095
    b.hi    8f
    ldr     x9, [sp, #(96 + SC_TS)]
    str     x9, [x19, #QUIC_TICK_UNIX]
    mov     x20, #0
1:  cmp     x20, #32
    b.hs    2f
    add     x0, x19, #QUIC_TICK_ENTROPY
    add     x0, x0, x20
    mov     x1, #32
    sub     x1, x1, x20
    mov     x2, #0
    SYSCALL SYS_GETRANDOM
    cmn     x0, #4095
    b.hi    8f
    add     x20, x20, x0
    b       1b
2:  mov     x0, #QUIC_OK
    b       9f
8:  mov     x0, #QUIC_OS_ERROR
9:  SLEAVE  SC_FRAME
END_FUNCTION quic_shell_clock

/* quic_shell_close(ctx) -> status: every socket is closed. x19 ctx, x20 index. */
FUNCTION quic_shell_close
    SENTER  0
    mov     x19, x0
    mov     x20, #0
1:  ldr     x9, [x19, #QUIC_SH_COUNT]
    cmp     x20, x9
    b.hs    2f
    mov     x10, #QUIC_SH_STRIDE
    madd    x9, x20, x10, x19
    ldr     x0, [x9, #(QUIC_SH_SOCKETS + QUIC_SH_FD)]
    SYSCALL SYS_CLOSE
    add     x20, x20, #1
    b       1b
2:  str     xzr, [x19, #QUIC_SH_COUNT]
    mov     x0, #QUIC_OK
    SLEAVE  0
END_FUNCTION quic_shell_close
