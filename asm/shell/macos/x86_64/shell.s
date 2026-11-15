/*
 * asm-quic shell for macOS on x86-64: UDP sockets, the clock and random
 * bytes, through libSystem. AT&T syntax.
 * Requirements: docs/reference/shell.md. Layouts: include/quic.inc.
 *
 * The functions use the System V AMD64 psABI like the core, and call
 * libSystem with it; a call may change rax, rcx, rdx, rsi, rdi and r8-r11.
 * The variadic fcntl gets al 0: no vector registers. A libSystem call that
 * fails returns -1. The steps follow the Linux x86-64 shell; the socket
 * addresses carry their length in their first byte.
 *
 * Constants in macros are written $(n): in a macro without named
 * parameters, the Mach-O assembler reads $0 to $9 as positional arguments.
 */
.set ISA_X86_64, 1
.include "quic.inc"
.include "platform.inc"

/* libSystem numbers: the macOS SDK headers. */
.set OS_AF_INET, 2                      /* sys/socket.h */
.set OS_AF_INET6, 30                    /* sys/socket.h */
.set OS_SOCK_DGRAM, 2                   /* sys/socket.h */
.set OS_SOL_SOCKET, 0xFFFF              /* sys/socket.h */
.set OS_SO_SNDBUF, 0x1001               /* sys/socket.h */
.set OS_SO_RCVBUF, 0x1002               /* sys/socket.h */
.set OS_MSG_DONTWAIT, 0x80              /* sys/socket.h */
.set OS_IPPROTO_IPV6, 41                /* netinet/in.h */
.set OS_IPV6_V6ONLY, 27                 /* netinet6/in6.h */
.set OS_POLLIN, 1                       /* sys/poll.h */
.set OS_F_SETFD, 2                      /* sys/fcntl.h */
.set OS_F_SETFL, 4                      /* sys/fcntl.h */
.set OS_FD_CLOEXEC, 1                   /* sys/fcntl.h */
.set OS_O_NONBLOCK, 4                   /* sys/fcntl.h */
.set OS_CLOCK_REALTIME, 0               /* time.h */
.set OS_CLOCK_MONOTONIC, 6              /* time.h */
.set SOCKET_BUFFER, 4194304             /* bytes asked for each socket buffer */

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

/* ---------------------------------------------------------------- libSystem */

/* quic_shell_fcntl(socket, command, value) -> the int result of fcntl, a variadic call. */
LOCAL_FUNCTION quic_shell_fcntl
    sub     $8, %rsp
    UNWIND_ALLOC 8
    UNWIND_END_PROLOGUE
    xor     %eax, %eax
    CALL_GLOBAL fcntl
    UNWIND_BEGIN_EPILOGUE
    add     $8, %rsp
    UNWIND_FREE 8
    UNWIND_END_EPILOGUE
    ret
END_FUNCTION quic_shell_fcntl

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
    movb    $16, (%rdi)                     /* sin_len */
    movb    $OS_AF_INET, 1(%rdi)
    movl    QUIC_ADDR_IP(%rsi), %eax
    movl    %eax, 4(%rdi)
    mov     $16, %eax
    ret
1:  movb    $28, (%rdi)                     /* sin6_len */
    movb    $OS_AF_INET6, 1(%rdi)
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
    cmpb    $OS_AF_INET6, 1(%rsi)
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
    mov     $OS_SOCK_DGRAM, %esi
    xor     %edx, %edx
    CALL_GLOBAL socket
    test    %eax, %eax
    js      8f
    mov     %eax, %r13d
    mov     %r13d, %edi
    mov     $OS_F_SETFL, %esi
    mov     $OS_O_NONBLOCK, %edx
    call    quic_shell_fcntl
    test    %eax, %eax
    js      7f
    mov     %r13d, %edi
    mov     $OS_F_SETFD, %esi
    mov     $OS_FD_CLOEXEC, %edx
    call    quic_shell_fcntl
    test    %eax, %eax
    js      7f
    cmpq    $6, QUIC_ADDR_FAMILY(%rbp)
    jne     1f
    movl    $1, SB_OPT(%rsp)
    mov     %r13d, %edi
    mov     $OS_IPPROTO_IPV6, %esi
    mov     $OS_IPV6_V6ONLY, %edx
    lea     SB_OPT(%rsp), %rcx
    mov     $4, %r8d
    CALL_GLOBAL setsockopt
1:  movl    $SOCKET_BUFFER, SB_OPT(%rsp)
    mov     %r13d, %edi
    mov     $OS_SOL_SOCKET, %esi
    mov     $OS_SO_RCVBUF, %edx
    lea     SB_OPT(%rsp), %rcx
    mov     $4, %r8d
    CALL_GLOBAL setsockopt                  /* the kernel may refuse the size: not an error */
    mov     %r13d, %edi
    mov     $OS_SOL_SOCKET, %esi
    mov     $OS_SO_SNDBUF, %edx
    lea     SB_OPT(%rsp), %rcx
    mov     $4, %r8d
    CALL_GLOBAL setsockopt
    lea     SB_SA(%rsp), %rdi
    mov     %rbp, %rsi
    call    quic_shell_sockaddr
    mov     %eax, %edx
    mov     %r13d, %edi
    lea     SB_SA(%rsp), %rsi
    CALL_GLOBAL bind
    test    %eax, %eax
    js      7f
    movl    $32, SB_LEN(%rsp)
    mov     %r13d, %edi
    lea     SB_SA(%rsp), %rsi
    lea     SB_LEN(%rsp), %rdx
    CALL_GLOBAL getsockname
    test    %eax, %eax
    js      7f
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
7:  mov     %r13d, %edi
    CALL_GLOBAL close
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
    mov     %eax, %r9d
    mov     %r14d, %edi
    lea     QUIC_ACT_DATA(%r13), %rsi
    mov     QUIC_ACT_COUNT(%r13), %rdx
    mov     $OS_MSG_DONTWAIT, %ecx
    lea     SS_SA(%rsp), %r8
    CALL_GLOBAL sendto
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
    mov     %r13d, %edi
    lea     QUIC_EV_DATA(%r14), %rsi
    mov     $QUIC_RECEIVE_MAX, %edx
    mov     $OS_MSG_DONTWAIT, %ecx
    lea     SR_SA(%rsp), %r8
    lea     SR_LEN(%rsp), %r9
    CALL_GLOBAL recvfrom
    test    %rax, %rax
    js      3f
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
 * quic_shell_wait(ctx, until) -> status: waits with poll until a socket can be
 * read or the monotonic time in microseconds at until, at most 60 s; poll
 * counts whole milliseconds, so the wait rounds up.
 * rbx ctx, rbp until, r12 the socket count, r13 index, r14 milliseconds.
 */
.set SW_FDS, 0                          /* QUIC_SH_MAX pollfd of 8 bytes */
.set SW_FRAME, 40
FUNCTION quic_shell_wait
    SENTER  SW_FRAME
    mov     %rdi, %rbx
    mov     (%rsi), %rbp
    mov     $OS_CLOCK_MONOTONIC, %edi
    CALL_GLOBAL clock_gettime_nsec_np
    xor     %edx, %edx
    mov     $1000, %ecx
    div     %rcx                            /* now in microseconds */
    mov     %rbp, %rcx
    sub     %rax, %rcx
    jae     1f
    xor     %ecx, %ecx
1:  cmp     $60000000, %rcx
    jb      2f
    mov     $60000000, %ecx
2:  lea     999(%rcx), %rax
    xor     %edx, %edx
    mov     $1000, %ecx
    div     %rcx
    mov     %rax, %r14                      /* milliseconds */
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
    mov     %r12d, %esi
    mov     %r14d, %edx
    CALL_GLOBAL poll
    mov     $QUIC_OK, %eax
    SLEAVE  SW_FRAME
END_FUNCTION quic_shell_wait

/*
 * quic_shell_clock(tick) -> status: the monotonic time in microseconds and
 * the Unix time in seconds (clock_gettime_nsec_np), and 32 bytes of
 * getentropy. rbx tick.
 */
FUNCTION quic_shell_clock
    SENTER  8
    mov     %rdi, %rbx
    mov     $OS_CLOCK_MONOTONIC, %edi
    CALL_GLOBAL clock_gettime_nsec_np
    test    %rax, %rax
    jz      8f
    xor     %edx, %edx
    mov     $1000, %ecx
    div     %rcx
    mov     %rax, QUIC_TICK_NOW(%rbx)
    mov     $OS_CLOCK_REALTIME, %edi
    CALL_GLOBAL clock_gettime_nsec_np
    test    %rax, %rax
    jz      8f
    xor     %edx, %edx
    mov     $1000000000, %ecx
    div     %rcx
    mov     %rax, QUIC_TICK_UNIX(%rbx)
    lea     QUIC_TICK_ENTROPY(%rbx), %rdi
    mov     $32, %esi
    CALL_GLOBAL getentropy
    test    %eax, %eax
    jnz     8f
    mov     $QUIC_OK, %eax
    jmp     9f
8:  mov     $QUIC_OS_ERROR, %eax
9:  SLEAVE  8
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
    CALL_GLOBAL close
    inc     %rbp
    jmp     1b
2:  movq    $0, QUIC_SH_COUNT(%rbx)
    mov     $QUIC_OK, %eax
    SLEAVE  8
END_FUNCTION quic_shell_close
