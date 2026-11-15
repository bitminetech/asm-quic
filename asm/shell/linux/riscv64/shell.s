/*
 * asm-quic shell for Linux on RISC-V: UDP sockets, the clock and random bytes,
 * through direct system calls. Requirements: docs/reference/shell.md.
 * Layouts: include/quic.inc.
 *
 * System calls: the number in a7, arguments in a0 to a5, "ecall"; a0 holds
 * the result, or minus the error number (-4095 to -1). The steps follow the
 * ARM64 shell one for one, with its x19-x28 as s1-s10 and x9-x15 as t0-t6.
 * 8-byte loads and stores only touch 8-byte aligned addresses.
 */
.set ISA_RISCV64, 1
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
.set OS_SOCK_NONBLOCK, 0x800            /* O_NONBLOCK of asm-generic/fcntl.h */
.set OS_SOCK_CLOEXEC, 0x80000
.set OS_SOL_SOCKET, 1
.set OS_SO_SNDBUF, 7
.set OS_SO_RCVBUF, 8
.set OS_IPPROTO_IPV6, 41
.set OS_IPV6_V6ONLY, 26
.set OS_MSG_DONTWAIT, 0x40
.set OS_POLLIN, 1
.set OS_CLOCK_REALTIME, 0
.set OS_CLOCK_MONOTONIC, 1
.set SOCKET_BUFFER, 4194304             /* bytes asked for each socket buffer */

.set FL, 112                            /* ra, s0-s11; locals at sp + FL */

.macro SYSCALL number
    li      a7, \number
    ecall
.endm

/* Branch to label when a0 is minus an error number (-4095 to -1). Uses t6. */
.macro IF_ERROR_NEG label
    li      t6, -4095
    bgeu    a0, t6, \label
.endm

/* The frame of a shell function: ra, s0-s11, then locals at sp + FL. */
.macro SENTER locals
    addi    sp, sp, -(FL + \locals)
    UNWIND_ALLOC (FL + \locals)
    sd      ra, 0(sp)
    UNWIND_SAVE ra, 0
    sd      s0, 8(sp)
    UNWIND_SAVE s0, 8
    sd      s1, 16(sp)
    UNWIND_SAVE s1, 16
    sd      s2, 24(sp)
    UNWIND_SAVE s2, 24
    sd      s3, 32(sp)
    UNWIND_SAVE s3, 32
    sd      s4, 40(sp)
    UNWIND_SAVE s4, 40
    sd      s5, 48(sp)
    UNWIND_SAVE s5, 48
    sd      s6, 56(sp)
    UNWIND_SAVE s6, 56
    sd      s7, 64(sp)
    UNWIND_SAVE s7, 64
    sd      s8, 72(sp)
    UNWIND_SAVE s8, 72
    sd      s9, 80(sp)
    UNWIND_SAVE s9, 80
    sd      s10, 88(sp)
    UNWIND_SAVE s10, 88
    sd      s11, 96(sp)
    UNWIND_SAVE s11, 96
    UNWIND_END_PROLOGUE
.endm

.macro SLEAVE locals
    UNWIND_BEGIN_EPILOGUE
    ld      ra, 0(sp)
    UNWIND_RESTORE ra
    ld      s0, 8(sp)
    UNWIND_RESTORE s0
    ld      s1, 16(sp)
    UNWIND_RESTORE s1
    ld      s2, 24(sp)
    UNWIND_RESTORE s2
    ld      s3, 32(sp)
    UNWIND_RESTORE s3
    ld      s4, 40(sp)
    UNWIND_RESTORE s4
    ld      s5, 48(sp)
    UNWIND_RESTORE s5
    ld      s6, 56(sp)
    UNWIND_RESTORE s6
    ld      s7, 64(sp)
    UNWIND_RESTORE s7
    ld      s8, 72(sp)
    UNWIND_RESTORE s8
    ld      s9, 80(sp)
    UNWIND_RESTORE s9
    ld      s10, 88(sp)
    UNWIND_RESTORE s10
    ld      s11, 96(sp)
    UNWIND_RESTORE s11
    addi    sp, sp, (FL + \locals)
    UNWIND_FREE (FL + \locals)
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
    sd      zero, 0(a0)
    sd      zero, 8(a0)
    sd      zero, 16(a0)
    sd      zero, 24(a0)
    ld      a2, QUIC_ADDR_PORT(a1)
    srli    a3, a2, 8                       # the port in network order
    andi    a3, a3, 0xFF
    andi    a4, a2, 0xFF
    slli    a4, a4, 8
    or      a2, a3, a4
    sh      a2, 2(a0)
    ld      a3, QUIC_ADDR_FAMILY(a1)
    li      a4, 6
    beq     a3, a4, 1f
    li      a4, OS_AF_INET
    sh      a4, 0(a0)
    lwu     a4, QUIC_ADDR_IP(a1)
    sw      a4, 4(a0)
    li      a0, 16
    ret
1:  li      a4, OS_AF_INET6
    sh      a4, 0(a0)
    ld      a4, QUIC_ADDR_IP(a1)
    ld      a5, (QUIC_ADDR_IP + 8)(a1)
    sd      a4, 8(a0)
    sd      a5, 16(a0)
    li      a0, 28
    ret
END_FUNCTION quic_shell_sockaddr

/* quic_shell_address(dst, sockaddr): the Address of a native socket address. A leaf. */
LOCAL_FUNCTION quic_shell_address
    UNWIND_END_PROLOGUE
    sd      zero, 0(a0)
    sd      zero, 8(a0)
    sd      zero, 16(a0)
    sd      zero, 24(a0)
    lhu     a2, 2(a1)
    srli    a3, a2, 8
    andi    a4, a2, 0xFF
    slli    a4, a4, 8
    or      a2, a3, a4
    sd      a2, QUIC_ADDR_PORT(a0)
    lhu     a3, 0(a1)
    li      a4, OS_AF_INET6
    beq     a3, a4, 1f
    li      a3, 4
    sd      a3, QUIC_ADDR_FAMILY(a0)
    lwu     a4, 4(a1)
    sw      a4, QUIC_ADDR_IP(a0)
    ret
1:  li      a3, 6
    sd      a3, QUIC_ADDR_FAMILY(a0)
    ld      a4, 8(a1)
    ld      a5, 16(a1)
    sd      a4, QUIC_ADDR_IP(a0)
    sd      a5, (QUIC_ADDR_IP + 8)(a0)
    ret
END_FUNCTION quic_shell_address

/* ---------------------------------------------------------------- Functions */

/* quic_shell_init(ctx) -> status: a context with no socket. */
FUNCTION quic_shell_init
    SENTER  0
    ld      t0, QUIC_SH_SIZE(a0)
    li      t1, QUIC_SHELL_SIZE
    mv      a1, a0
    li      a0, QUIC_BUFFER_TOO_SMALL
    bltu    t0, t1, 9f
    sd      zero, QUIC_SH_COUNT(a1)
    li      a0, QUIC_OK
9:  SLEAVE  0
END_FUNCTION quic_shell_init

/*
 * quic_shell_bind(ctx, addr, result) -> status: a non-blocking UDP socket bound
 * to the address (port 0 picks one), IPv6 only for an IPv6 address, with big
 * buffers; result gets its socket ID and local address.
 * s1 ctx, s2 addr, s3 result, s4 fd, s5 the entry.
 */
.set SB_SA, 0                           /* 32 bytes */
.set SB_LEN, 32
.set SB_OPT, 40
.set SB_FRAME, 48
FUNCTION quic_shell_bind
    SENTER  SB_FRAME
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    ld      t0, QUIC_SH_COUNT(s1)
    li      a0, QUIC_BUFFER_TOO_SMALL
    li      t1, QUIC_SH_MAX
    bgeu    t0, t1, 9f
    ld      t0, QUIC_ADDR_FAMILY(s2)
    li      a0, OS_AF_INET
    li      t1, 6
    bne     t0, t1, 10f
    li      a0, OS_AF_INET6
10: li      a1, (OS_SOCK_DGRAM | OS_SOCK_NONBLOCK | OS_SOCK_CLOEXEC)
    li      a2, 0
    SYSCALL SYS_SOCKET
    IF_ERROR_NEG 8f
    mv      s4, a0
    ld      t0, QUIC_ADDR_FAMILY(s2)
    li      t1, 6
    bne     t0, t1, 1f
    li      t0, 1
    sw      t0, (FL + SB_OPT)(sp)
    mv      a0, s4
    li      a1, OS_IPPROTO_IPV6
    li      a2, OS_IPV6_V6ONLY
    addi    a3, sp, (FL + SB_OPT)
    li      a4, 4
    SYSCALL SYS_SETSOCKOPT
1:  li      t0, SOCKET_BUFFER
    sw      t0, (FL + SB_OPT)(sp)
    mv      a0, s4
    li      a1, OS_SOL_SOCKET
    li      a2, OS_SO_RCVBUF
    addi    a3, sp, (FL + SB_OPT)
    li      a4, 4
    SYSCALL SYS_SETSOCKOPT                  # the kernel may give less: not an error
    mv      a0, s4
    li      a1, OS_SOL_SOCKET
    li      a2, OS_SO_SNDBUF
    addi    a3, sp, (FL + SB_OPT)
    li      a4, 4
    SYSCALL SYS_SETSOCKOPT
    addi    a0, sp, (FL + SB_SA)
    mv      a1, s2
    call    quic_shell_sockaddr
    mv      a2, a0
    mv      a0, s4
    addi    a1, sp, (FL + SB_SA)
    SYSCALL SYS_BIND
    IF_ERROR_NEG 7f
    li      t0, 32
    sw      t0, (FL + SB_LEN)(sp)
    mv      a0, s4
    addi    a1, sp, (FL + SB_SA)
    addi    a2, sp, (FL + SB_LEN)
    SYSCALL SYS_GETSOCKNAME
    IF_ERROR_NEG 7f
    ld      t0, QUIC_SH_COUNT(s1)
    li      t1, QUIC_SH_STRIDE
    mul     s5, t0, t1
    add     s5, s5, s1
    addi    s5, s5, QUIC_SH_SOCKETS
    sd      s4, QUIC_SH_FD(s5)
    addi    a0, s5, QUIC_SH_LOCAL
    addi    a1, sp, (FL + SB_SA)
    call    quic_shell_address
    ld      t0, QUIC_SH_COUNT(s1)
    sd      t0, QUIC_BR_SOCKET(s3)
    addi    t0, t0, 1
    sd      t0, QUIC_SH_COUNT(s1)
    addi    a0, s3, QUIC_BR_LOCAL
    addi    a1, sp, (FL + SB_SA)
    call    quic_shell_address
    li      a0, QUIC_OK
    j       9f
7:  mv      a0, s4
    SYSCALL SYS_CLOSE
8:  li      a0, QUIC_OS_ERROR
9:  SLEAVE  SB_FRAME
END_FUNCTION quic_shell_bind

/*
 * quic_shell_send(ctx, actions) -> status: each SEND action of the list goes
 * out with sendto; a datagram the OS does not take is lost, as UDP allows.
 * s1 ctx, s2 position, s3 end, s4 the action, s5 the entry, s6 fd.
 */
.set SS_SA, 0
.set SS_FRAME, 32
FUNCTION quic_shell_send
    SENTER  SS_FRAME
    mv      s1, a0
    ld      t0, 8(a1)
    add     s2, a1, t0
    ld      t1, 16(a1)
    add     s3, s2, t1
1:  bgeu    s2, s3, 8f
    mv      s4, s2
    ld      t0, QUIC_ACT_SIZE(s4)
    add     s2, s2, t0
    ld      t0, QUIC_ACT_KIND(s4)
    li      t1, QUIC_ACTION_SEND
    bne     t0, t1, 1b
    ld      t0, QUIC_ACT_SOCKET(s4)
    ld      t1, QUIC_SH_COUNT(s1)
    bgeu    t0, t1, 1b
    li      t1, QUIC_SH_STRIDE
    mul     s5, t0, t1
    add     s5, s5, s1
    ld      s6, (QUIC_SH_SOCKETS + QUIC_SH_FD)(s5)
    addi    a0, sp, (FL + SS_SA)
    addi    a1, s4, QUIC_ACT_ADDR
    call    quic_shell_sockaddr
    mv      a5, a0
    mv      a0, s6
    addi    a1, s4, QUIC_ACT_DATA
    ld      a2, QUIC_ACT_COUNT(s4)
    li      a3, OS_MSG_DONTWAIT
    addi    a4, sp, (FL + SS_SA)
    SYSCALL SYS_SENDTO
    j       1b
8:  li      a0, QUIC_OK
    SLEAVE  SS_FRAME
END_FUNCTION quic_shell_send

/*
 * quic_shell_receive(ctx, events) -> status: DATAGRAM events for the
 * datagrams waiting on each socket, while the list has room for one of
 * QUIC_RECEIVE_MAX bytes.
 * s1 ctx, s2 events, s3 socket index, s4 fd, s5 the event.
 */
.set SR_SA, 0
.set SR_LEN, 32
.set SR_FRAME, 48
FUNCTION quic_shell_receive
    SENTER  SR_FRAME
    mv      s1, a0
    mv      s2, a1
    li      s3, 0
1:  ld      t0, QUIC_SH_COUNT(s1)
    bgeu    s3, t0, 8f
    li      t1, QUIC_SH_STRIDE
    mul     t0, s3, t1
    add     t0, t0, s1
    ld      s4, (QUIC_SH_SOCKETS + QUIC_SH_FD)(t0)
2:  ld      t0, QUIC_BL_SIZE(s2)            # room for one more
    ld      t1, QUIC_BL_COUNT(s2)
    addi    t0, t0, -QUIC_BL_FIXED
    sub     t0, t0, t1
    li      t2, (QUIC_EV_DATA + QUIC_RECEIVE_MAX + 8)
    bltu    t0, t2, 8f
    addi    s5, s2, QUIC_BL_FIXED
    add     s5, s5, t1
    li      t0, 32
    sw      t0, (FL + SR_LEN)(sp)
    mv      a0, s4
    addi    a1, s5, QUIC_EV_DATA
    li      a2, QUIC_RECEIVE_MAX
    li      a3, OS_MSG_DONTWAIT
    addi    a4, sp, (FL + SR_SA)
    addi    a5, sp, (FL + SR_LEN)
    SYSCALL SYS_RECVFROM
    IF_ERROR_NEG 3f
    sd      a0, QUIC_EV_COUNT(s5)
    addi    t0, a0, (QUIC_EV_DATA + 7)
    andi    t0, t0, -8
    sd      t0, QUIC_EV_SIZE(s5)
    li      t1, QUIC_EVENT_DATAGRAM
    sd      t1, QUIC_EV_KIND(s5)
    sd      s3, QUIC_EV_SOCKET(s5)
    ld      t1, QUIC_BL_COUNT(s2)
    add     t1, t1, t0
    sd      t1, QUIC_BL_COUNT(s2)
    addi    a0, s5, QUIC_EV_ADDR
    addi    a1, sp, (FL + SR_SA)
    call    quic_shell_address
    j       2b
3:  addi    s3, s3, 1                       # EAGAIN or an error: the next socket
    j       1b
8:  li      a0, QUIC_OK
    SLEAVE  SR_FRAME
END_FUNCTION quic_shell_receive

/*
 * quic_shell_wait(ctx, until) -> status: waits with ppoll until a socket can
 * be read or the monotonic time in microseconds at until, at most 60 s.
 * s1 ctx, s2 until, s3 sockets, s4 index.
 */
.set SW_FDS, 0                          /* QUIC_SH_MAX pollfd of 8 bytes */
.set SW_TS, 32
.set SW_NOW, 48
.set SW_FRAME, 64
FUNCTION quic_shell_wait
    SENTER  SW_FRAME
    mv      s1, a0
    ld      s2, 0(a1)
    li      a0, OS_CLOCK_MONOTONIC
    addi    a1, sp, (FL + SW_NOW)
    SYSCALL SYS_CLOCK_GETTIME
    ld      t0, (FL + SW_NOW)(sp)
    ld      t1, (FL + SW_NOW + 8)(sp)
    li      t2, 1000000
    mul     t0, t0, t2
    li      t3, 1000
    divu    t1, t1, t3
    add     t0, t0, t1                      # now in microseconds
    sub     t4, s2, t0
    bgeu    s2, t0, 1f
    li      t4, 0
1:  li      t5, 60000000
    bltu    t4, t5, 2f
    mv      t4, t5
2:  divu    t5, t4, t2
    remu    t6, t4, t2
    mul     t6, t6, t3
    sd      t5, (FL + SW_TS)(sp)
    sd      t6, (FL + SW_TS + 8)(sp)
    ld      s3, QUIC_SH_COUNT(s1)
    li      s4, 0
3:  bgeu    s4, s3, 4f
    li      t1, QUIC_SH_STRIDE
    mul     t0, s4, t1
    add     t0, t0, s1
    ld      t0, (QUIC_SH_SOCKETS + QUIC_SH_FD)(t0)
    addi    t1, sp, (FL + SW_FDS)
    slli    t2, s4, 3
    add     t1, t1, t2
    sw      t0, 0(t1)
    li      t2, OS_POLLIN
    sw      t2, 4(t1)
    addi    s4, s4, 1
    j       3b
4:  addi    a0, sp, (FL + SW_FDS)
    mv      a1, s3
    addi    a2, sp, (FL + SW_TS)
    li      a3, 0
    li      a4, 8
    SYSCALL SYS_PPOLL
    li      a0, QUIC_OK
    SLEAVE  SW_FRAME
END_FUNCTION quic_shell_wait

/*
 * quic_shell_clock(tick) -> status: the monotonic time in microseconds, the
 * Unix time in seconds, and 32 bytes of getrandom.
 * s1 tick, s2 bytes so far.
 */
.set SC_TS, 0
.set SC_FRAME, 16
FUNCTION quic_shell_clock
    SENTER  SC_FRAME
    mv      s1, a0
    li      a0, OS_CLOCK_MONOTONIC
    addi    a1, sp, (FL + SC_TS)
    SYSCALL SYS_CLOCK_GETTIME
    IF_ERROR_NEG 8f
    ld      t0, (FL + SC_TS)(sp)
    ld      t1, (FL + SC_TS + 8)(sp)
    li      t2, 1000000
    mul     t0, t0, t2
    li      t3, 1000
    divu    t1, t1, t3
    add     t0, t0, t1
    sd      t0, QUIC_TICK_NOW(s1)
    li      a0, OS_CLOCK_REALTIME
    addi    a1, sp, (FL + SC_TS)
    SYSCALL SYS_CLOCK_GETTIME
    IF_ERROR_NEG 8f
    ld      t0, (FL + SC_TS)(sp)
    sd      t0, QUIC_TICK_UNIX(s1)
    li      s2, 0
1:  li      t0, 32
    bgeu    s2, t0, 2f
    addi    a0, s1, QUIC_TICK_ENTROPY
    add     a0, a0, s2
    li      a1, 32
    sub     a1, a1, s2
    li      a2, 0
    SYSCALL SYS_GETRANDOM
    IF_ERROR_NEG 8f
    add     s2, s2, a0
    j       1b
2:  li      a0, QUIC_OK
    j       9f
8:  li      a0, QUIC_OS_ERROR
9:  SLEAVE  SC_FRAME
END_FUNCTION quic_shell_clock

/* quic_shell_close(ctx) -> status: every socket is closed. s1 ctx, s2 index. */
FUNCTION quic_shell_close
    SENTER  0
    mv      s1, a0
    li      s2, 0
1:  ld      t0, QUIC_SH_COUNT(s1)
    bgeu    s2, t0, 2f
    li      t1, QUIC_SH_STRIDE
    mul     t0, s2, t1
    add     t0, t0, s1
    ld      a0, (QUIC_SH_SOCKETS + QUIC_SH_FD)(t0)
    SYSCALL SYS_CLOSE
    addi    s2, s2, 1
    j       1b
2:  sd      zero, QUIC_SH_COUNT(s1)
    li      a0, QUIC_OK
    SLEAVE  0
END_FUNCTION quic_shell_close
