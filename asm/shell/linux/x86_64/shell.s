/*
 * asm-quic shell for Linux on x86-64: UDP sockets, the clock and random
 * bytes, through direct system calls. AT&T syntax.
 * Requirements: docs/reference/shell.md. Layouts: include/quic.inc.
 *
 * The functions use the System V AMD64 psABI like the core. System calls:
 * the number in rax, arguments in rdi, rsi, rdx, r10, r8, r9, "syscall";
 * rax holds the result, or minus the error number (-4095 to -1); rcx and
 * r11 change. The steps follow the ARM64 shell one for one, with its x19 to
 * x24 as rbx, rbp, r12, r13, r14 and r15.
 *
 * Constants in macros are written $(n): in a macro without named
 * parameters, the Mach-O assembler reads $0 to $9 as positional arguments.
 */
.set ISA_X86_64, 1
.include "quic.inc"
.include "platform.inc"

/* Linux numbers: arch/x86/entry/syscalls/syscall_64.tbl and the uapi headers. */
.set SYS_CLOSE, 3
.set SYS_SOCKET, 41
.set SYS_SENDTO, 44
.set SYS_RECVFROM, 45
.set SYS_BIND, 49
.set SYS_GETSOCKNAME, 51
.set SYS_SETSOCKOPT, 54
.set SYS_CLOCK_GETTIME, 228
.set SYS_PPOLL, 271
.set SYS_GETRANDOM, 318
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
.set OS_CLOCK_REALTIME, 0
.set OS_CLOCK_MONOTONIC, 1
.set SOCKET_BUFFER, 4194304             /* bytes asked for each socket buffer */

.macro SYSCALL number
    mov     $\number, %eax
    syscall
.endm

/* Branch to label when rax is minus an error number (-4095 to -1). */
.macro IF_ERROR_NEG label
    cmp     $(-4095), %rax
    jae     \label
.endm

/* Frame: rbx, rbp, r12-r15, then bytes of locals at rsp. bytes is 8 more than a multiple of 16. */
.macro SENTER bytes
    push    %rbx
    UNWIND_PUSH %rbx
    push    %rbp
    UNWIND_PUSH %rbp
    push    %r12
    UNWIND_PUSH %r12
    push    %r13
    UNWIND_PUSH %r13
    push    %r14
    UNWIND_PUSH %r14
    push    %r15
    UNWIND_PUSH %r15
    sub     $\bytes, %rsp
    UNWIND_ALLOC \bytes
    UNWIND_END_PROLOGUE
.endm

.macro SLEAVE bytes
    UNWIND_BEGIN_EPILOGUE
    add     $\bytes, %rsp
    UNWIND_FREE \bytes
    pop     %r15
    UNWIND_POP %r15
    pop     %r14
    UNWIND_POP %r14
    pop     %r13
    UNWIND_POP %r13
    pop     %r12
    UNWIND_POP %r12
    pop     %rbp
    UNWIND_POP %rbp
    pop     %rbx
    UNWIND_POP %rbx
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
    xor     %eax, %eax
    mov     %rax, (%rdi)
    mov     %rax, 8(%rdi)
    mov     %rax, 16(%rdi)
    mov     %rax, 24(%rdi)
    mov     QUIC_ADDR_PORT(%rsi), %rdx
    rolw    $8, %dx
    movw    %dx, 2(%rdi)
    cmpq    $6, QUIC_ADDR_FAMILY(%rsi)
    je      1f
    movw    $OS_AF_INET, (%rdi)
    movl    QUIC_ADDR_IP(%rsi), %eax
    movl    %eax, 4(%rdi)
    mov     $16, %eax
    ret
1:  movw    $OS_AF_INET6, (%rdi)
    mov     QUIC_ADDR_IP(%rsi), %rax
    mov     %rax, 8(%rdi)
    mov     (QUIC_ADDR_IP + 8)(%rsi), %rax
    mov     %rax, 16(%rdi)
    mov     $28, %eax
    ret
END_FUNCTION quic_shell_sockaddr

/* quic_shell_address(dst, sockaddr): the Address of a native socket address. A leaf. */
LOCAL_FUNCTION quic_shell_address
    UNWIND_END_PROLOGUE
    xor     %eax, %eax
    mov     %rax, (%rdi)
    mov     %rax, 8(%rdi)
    mov     %rax, 16(%rdi)
    mov     %rax, 24(%rdi)
    movzwl  2(%rsi), %edx
    rolw    $8, %dx
    mov     %rdx, QUIC_ADDR_PORT(%rdi)
    cmpw    $OS_AF_INET6, (%rsi)
    je      1f
    movq    $4, QUIC_ADDR_FAMILY(%rdi)
    movl    4(%rsi), %eax
    movl    %eax, QUIC_ADDR_IP(%rdi)
    ret
1:  movq    $6, QUIC_ADDR_FAMILY(%rdi)
    mov     8(%rsi), %rax
    mov     %rax, QUIC_ADDR_IP(%rdi)
    mov     16(%rsi), %rax
    mov     %rax, (QUIC_ADDR_IP + 8)(%rdi)
    ret
END_FUNCTION quic_shell_address

/* ---------------------------------------------------------------- Functions */

/* quic_shell_init(ctx) -> status: a context with no socket. A leaf. */
FUNCTION quic_shell_init
    UNWIND_END_PROLOGUE
    mov     $QUIC_BUFFER_TOO_SMALL, %eax
    cmpq    $QUIC_SHELL_SIZE, QUIC_SH_SIZE(%rdi)
    jb      9f
    movq    $0, QUIC_SH_COUNT(%rdi)
    mov     $QUIC_OK, %eax
9:  ret
END_FUNCTION quic_shell_init

/*
 * quic_shell_bind(ctx, addr, result) -> status: a non-blocking UDP socket bound
 * to the address (port 0 picks one), IPv6 only for an IPv6 address, with big
 * buffers; result gets its socket ID and local address.
 * rbx ctx, rbp addr, r12 result, r13 fd, r14 the entry.
 */
.set SB_SA, 0                           /* 32 bytes */
.set SB_LEN, 32
.set SB_OPT, 40
.set SB_FRAME, 56
FUNCTION quic_shell_bind
    SENTER  SB_FRAME
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     $QUIC_BUFFER_TOO_SMALL, %eax
    cmpq    $QUIC_SH_MAX, QUIC_SH_COUNT(%rbx)
    jae     9f
    mov     $OS_AF_INET, %edi
    mov     $OS_AF_INET6, %eax
    cmpq    $6, QUIC_ADDR_FAMILY(%rbp)
    cmove   %eax, %edi
    mov     $(OS_SOCK_DGRAM | OS_SOCK_NONBLOCK | OS_SOCK_CLOEXEC), %esi
    xor     %edx, %edx
    SYSCALL SYS_SOCKET
    IF_ERROR_NEG 8f
    mov     %rax, %r13
    cmpq    $6, QUIC_ADDR_FAMILY(%rbp)
    jne     1f
    movl    $1, SB_OPT(%rsp)
    mov     %r13, %rdi
    mov     $OS_IPPROTO_IPV6, %esi
    mov     $OS_IPV6_V6ONLY, %edx
    lea     SB_OPT(%rsp), %r10
    mov     $4, %r8d
    SYSCALL SYS_SETSOCKOPT
1:  movl    $SOCKET_BUFFER, SB_OPT(%rsp)
    mov     %r13, %rdi
    mov     $OS_SOL_SOCKET, %esi
    mov     $OS_SO_RCVBUF, %edx
    lea     SB_OPT(%rsp), %r10
    mov     $4, %r8d
    SYSCALL SYS_SETSOCKOPT                  /* the kernel may give less: not an error */
    mov     %r13, %rdi
    mov     $OS_SOL_SOCKET, %esi
    mov     $OS_SO_SNDBUF, %edx
    lea     SB_OPT(%rsp), %r10
    mov     $4, %r8d
    SYSCALL SYS_SETSOCKOPT
    lea     SB_SA(%rsp), %rdi
    mov     %rbp, %rsi
    call    quic_shell_sockaddr
    mov     %rax, %rdx
    mov     %r13, %rdi
    lea     SB_SA(%rsp), %rsi
    SYSCALL SYS_BIND
    IF_ERROR_NEG 7f
    movl    $32, SB_LEN(%rsp)
    mov     %r13, %rdi
    lea     SB_SA(%rsp), %rsi
    lea     SB_LEN(%rsp), %rdx
    SYSCALL SYS_GETSOCKNAME
    IF_ERROR_NEG 7f
    mov     QUIC_SH_COUNT(%rbx), %rax
    imul    $QUIC_SH_STRIDE, %rax, %r14
    lea     QUIC_SH_SOCKETS(%rbx,%r14), %r14
    mov     %r13, QUIC_SH_FD(%r14)
    lea     QUIC_SH_LOCAL(%r14), %rdi
    lea     SB_SA(%rsp), %rsi
    call    quic_shell_address
    mov     QUIC_SH_COUNT(%rbx), %rax
    mov     %rax, QUIC_BR_SOCKET(%r12)
    inc     %rax
    mov     %rax, QUIC_SH_COUNT(%rbx)
    lea     QUIC_BR_LOCAL(%r12), %rdi
    lea     SB_SA(%rsp), %rsi
    call    quic_shell_address
    mov     $QUIC_OK, %eax
    jmp     9f
7:  mov     %r13, %rdi
    SYSCALL SYS_CLOSE
8:  mov     $QUIC_OS_ERROR, %eax
9:  SLEAVE  SB_FRAME
END_FUNCTION quic_shell_bind

/*
 * quic_shell_send(ctx, actions) -> status: each SEND action of the list goes
 * out with sendto; a datagram the OS does not take is lost, as UDP allows.
 * rbx ctx, rbp position, r12 end, r13 the action, r14 fd.
 */
.set SS_SA, 0
.set SS_FRAME, 40
FUNCTION quic_shell_send
    SENTER  SS_FRAME
    mov     %rdi, %rbx
    mov     QUIC_BL_OFFSET(%rsi), %rbp
    add     %rsi, %rbp
    mov     QUIC_BL_COUNT(%rsi), %r12
    add     %rbp, %r12
1:  cmp     %r12, %rbp
    jae     8f
    mov     %rbp, %r13
    add     QUIC_ACT_SIZE(%r13), %rbp
    cmpq    $QUIC_ACTION_SEND, QUIC_ACT_KIND(%r13)
    jne     1b
    mov     QUIC_ACT_SOCKET(%r13), %rax
    cmp     QUIC_SH_COUNT(%rbx), %rax
    jae     1b
    imul    $QUIC_SH_STRIDE, %rax, %rax
    mov     (QUIC_SH_SOCKETS + QUIC_SH_FD)(%rbx,%rax), %r14
    lea     SS_SA(%rsp), %rdi
    lea     QUIC_ACT_ADDR(%r13), %rsi
    call    quic_shell_sockaddr
    mov     %rax, %r9
    mov     %r14, %rdi
    lea     QUIC_ACT_DATA(%r13), %rsi
    mov     QUIC_ACT_COUNT(%r13), %rdx
    mov     $OS_MSG_DONTWAIT, %r10d
    lea     SS_SA(%rsp), %r8
    SYSCALL SYS_SENDTO
    jmp     1b
8:  mov     $QUIC_OK, %eax
    SLEAVE  SS_FRAME
END_FUNCTION quic_shell_send

/*
 * quic_shell_receive(ctx, events) -> status: DATAGRAM events for the
 * datagrams waiting on each socket, while the list has room for one of
 * QUIC_RECEIVE_MAX bytes.
 * rbx ctx, rbp events, r12 socket index, r13 fd, r14 the event.
 */
.set SR_SA, 0
.set SR_LEN, 32
.set SR_FRAME, 40
FUNCTION quic_shell_receive
    SENTER  SR_FRAME
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    xor     %r12d, %r12d
1:  cmp     QUIC_SH_COUNT(%rbx), %r12
    jae     8f
    imul    $QUIC_SH_STRIDE, %r12, %rax
    mov     (QUIC_SH_SOCKETS + QUIC_SH_FD)(%rbx,%rax), %r13
2:  mov     QUIC_BL_SIZE(%rbp), %rax        /* room for one more */
    mov     QUIC_BL_COUNT(%rbp), %rcx
    sub     $QUIC_BL_FIXED, %rax
    sub     %rcx, %rax
    cmp     $(QUIC_EV_DATA + QUIC_RECEIVE_MAX + 8), %rax
    jb      8f
    lea     QUIC_BL_FIXED(%rbp,%rcx), %r14
    movl    $32, SR_LEN(%rsp)
    mov     %r13, %rdi
    lea     QUIC_EV_DATA(%r14), %rsi
    mov     $QUIC_RECEIVE_MAX, %edx
    mov     $OS_MSG_DONTWAIT, %r10d
    lea     SR_SA(%rsp), %r8
    lea     SR_LEN(%rsp), %r9
    SYSCALL SYS_RECVFROM
    IF_ERROR_NEG 3f
    mov     %rax, QUIC_EV_COUNT(%r14)
    add     $(QUIC_EV_DATA + 7), %rax
    and     $-8, %rax
    mov     %rax, QUIC_EV_SIZE(%r14)
    movq    $QUIC_EVENT_DATAGRAM, QUIC_EV_KIND(%r14)
    mov     %r12, QUIC_EV_SOCKET(%r14)
    add     %rax, QUIC_BL_COUNT(%rbp)
    lea     QUIC_EV_ADDR(%r14), %rdi
    lea     SR_SA(%rsp), %rsi
    call    quic_shell_address
    jmp     2b
3:  inc     %r12                            /* EAGAIN or an error: the next socket */
    jmp     1b
8:  mov     $QUIC_OK, %eax
    SLEAVE  SR_FRAME
END_FUNCTION quic_shell_receive

/*
 * quic_shell_wait(ctx, until) -> status: waits with ppoll until a socket can
 * be read or the monotonic time in microseconds at until, at most 60 s.
 * rbx ctx, rbp until, r12 the socket count, r13 index.
 */
.set SW_FDS, 0                          /* QUIC_SH_MAX pollfd of 8 bytes */
.set SW_TS, 32
.set SW_NOW, 48
.set SW_FRAME, 72
FUNCTION quic_shell_wait
    SENTER  SW_FRAME
    mov     %rdi, %rbx
    mov     (%rsi), %rbp
    mov     $OS_CLOCK_MONOTONIC, %edi
    lea     SW_NOW(%rsp), %rsi
    SYSCALL SYS_CLOCK_GETTIME
    imul    $1000000, SW_NOW(%rsp), %rcx
    mov     (SW_NOW + 8)(%rsp), %rax
    xor     %edx, %edx
    mov     $1000, %r8d
    div     %r8
    add     %rax, %rcx                      /* now in microseconds */
    mov     %rbp, %rax
    sub     %rcx, %rax
    jae     1f
    xor     %eax, %eax
1:  cmp     $60000000, %rax
    jb      2f
    mov     $60000000, %eax
2:  xor     %edx, %edx
    mov     $1000000, %ecx
    div     %rcx
    mov     %rax, SW_TS(%rsp)
    imul    $1000, %rdx, %rdx
    mov     %rdx, (SW_TS + 8)(%rsp)
    mov     QUIC_SH_COUNT(%rbx), %r12
    xor     %r13d, %r13d
3:  cmp     %r12, %r13
    jae     4f
    imul    $QUIC_SH_STRIDE, %r13, %rax
    mov     (QUIC_SH_SOCKETS + QUIC_SH_FD)(%rbx,%rax), %rax
    movl    %eax, SW_FDS(%rsp,%r13,8)
    movl    $OS_POLLIN, (SW_FDS + 4)(%rsp,%r13,8)
    inc     %r13
    jmp     3b
4:  lea     SW_FDS(%rsp), %rdi
    mov     %r12, %rsi
    lea     SW_TS(%rsp), %rdx
    xor     %r10d, %r10d
    mov     $8, %r8d
    SYSCALL SYS_PPOLL
    mov     $QUIC_OK, %eax
    SLEAVE  SW_FRAME
END_FUNCTION quic_shell_wait

/*
 * quic_shell_clock(tick) -> status: the monotonic time in microseconds, the
 * Unix time in seconds, and 32 bytes of getrandom.
 * rbx tick, rbp bytes so far.
 */
.set SC_TS, 0
.set SC_FRAME, 24
FUNCTION quic_shell_clock
    SENTER  SC_FRAME
    mov     %rdi, %rbx
    mov     $OS_CLOCK_MONOTONIC, %edi
    lea     SC_TS(%rsp), %rsi
    SYSCALL SYS_CLOCK_GETTIME
    IF_ERROR_NEG 8f
    imul    $1000000, SC_TS(%rsp), %rcx
    mov     (SC_TS + 8)(%rsp), %rax
    xor     %edx, %edx
    mov     $1000, %r8d
    div     %r8
    add     %rcx, %rax
    mov     %rax, QUIC_TICK_NOW(%rbx)
    mov     $OS_CLOCK_REALTIME, %edi
    lea     SC_TS(%rsp), %rsi
    SYSCALL SYS_CLOCK_GETTIME
    IF_ERROR_NEG 8f
    mov     SC_TS(%rsp), %rax
    mov     %rax, QUIC_TICK_UNIX(%rbx)
    xor     %ebp, %ebp
1:  cmp     $32, %rbp
    jae     2f
    lea     QUIC_TICK_ENTROPY(%rbx,%rbp), %rdi
    mov     $32, %esi
    sub     %rbp, %rsi
    xor     %edx, %edx
    SYSCALL SYS_GETRANDOM
    IF_ERROR_NEG 8f
    add     %rax, %rbp
    jmp     1b
2:  mov     $QUIC_OK, %eax
    jmp     9f
8:  mov     $QUIC_OS_ERROR, %eax
9:  SLEAVE  SC_FRAME
END_FUNCTION quic_shell_clock

/* quic_shell_close(ctx) -> status: every socket is closed. rbx ctx, rbp index. */
FUNCTION quic_shell_close
    SENTER  8
    mov     %rdi, %rbx
    xor     %ebp, %ebp
1:  cmp     QUIC_SH_COUNT(%rbx), %rbp
    jae     2f
    imul    $QUIC_SH_STRIDE, %rbp, %rax
    mov     (QUIC_SH_SOCKETS + QUIC_SH_FD)(%rbx,%rax), %rdi
    SYSCALL SYS_CLOSE
    inc     %rbp
    jmp     1b
2:  movq    $0, QUIC_SH_COUNT(%rbx)
    mov     $QUIC_OK, %eax
    SLEAVE  8
END_FUNCTION quic_shell_close
