/*
 * asm-quic shell for Windows on x86-64: UDP sockets, the clock and random
 * bytes, through Winsock 2, kernel32 and bcrypt. AT&T syntax.
 * Requirements: docs/reference/shell.md. Layouts: include/quic.inc.
 *
 * The functions use the System V AMD64 psABI like the core, and call the
 * Windows APIs with the Windows x64 convention: arguments in rcx, rdx, r8,
 * r9, then on the stack after 32 bytes of shadow space. Those APIs keep
 * rbx, rbp, rdi, rsi and r12-r15, so they keep what System V callers need.
 * Each socket holds one WSAStartup, which its close ends with WSACleanup.
 * The steps follow the Linux x86-64 shell.
 *
 * Constants in macros are written $(n): in a macro without named
 * parameters, the Mach-O assembler reads $0 to $9 as positional arguments.
 */
.set ISA_X86_64, 1
.include "quic.inc"
.include "platform.inc"

/* Windows numbers: the llvm-mingw headers. */
.set OS_AF_INET, 2                      /* winsock2.h */
.set OS_AF_INET6, 23                    /* winsock2.h */
.set OS_SOCK_DGRAM, 2                   /* winsock2.h */
.set OS_IPPROTO_UDP, 17                 /* winsock2.h */
.set OS_SOL_SOCKET, 0xFFFF              /* winsock2.h */
.set OS_SO_SNDBUF, 0x1001               /* winsock2.h */
.set OS_SO_RCVBUF, 0x1002               /* winsock2.h */
.set OS_IPPROTO_IPV6, 41                /* winsock2.h */
.set OS_IPV6_V6ONLY, 27                 /* ws2ipdef.h */
.set OS_POLLIN, 0x0100                  /* POLLRDNORM, winsock2.h */
.set OS_FIONBIO, 0x8004667E             /* winsock2.h */
.set OS_SIO_UDP_CONNRESET, 0x9800000C   /* _WSAIOW(IOC_VENDOR, 12), mstcpip.h */
.set OS_RNG_FLAGS, 2                    /* bcrypt.h: BCRYPT_USE_SYSTEM_PREFERRED_RNG */
.set OS_WINSOCK_VERSION, 0x0202
.set OS_WSADATA_SIZE, 416               /* sizeof(WSADATA) on 64-bit Windows: 408 */
.set OS_UNIX_EPOCH, 116444736000000000  /* 1970-01-01 in 100 ns units since 1601 */
.set SOCKET_BUFFER, 4194304             /* bytes asked for each socket buffer */
.set ARG5, 32                           /* the stack arguments of a Windows call, after the shadow space */
.set ARG6, 40
.set ARG7, 48
.set ARG8, 56
.set ARG9, 64

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

/* ---------------------------------------------------------------- Winsock */

/* quic_shell_wsa_start() -> the WSAStartup result: 0 when Winsock 2.2 started. */
.set WS_DATA, 32
.set WS_FRAME, WS_DATA + OS_WSADATA_SIZE + 8
LOCAL_FUNCTION quic_shell_wsa_start
    sub     $WS_FRAME, %rsp
    UNWIND_ALLOC WS_FRAME
    UNWIND_END_PROLOGUE
    mov     $OS_WINSOCK_VERSION, %ecx
    lea     WS_DATA(%rsp), %rdx
    CALL_GLOBAL WSAStartup
    UNWIND_BEGIN_EPILOGUE
    add     $WS_FRAME, %rsp
    UNWIND_FREE WS_FRAME
    UNWIND_END_EPILOGUE
    ret
END_FUNCTION quic_shell_wsa_start

/*
 * quic_shell_no_connreset(socket): WSAIoctl SIO_UDP_CONNRESET FALSE, so an
 * ICMP port unreachable gives no WSAECONNRESET on reads. A System V argument.
 */
.set NC_IN, 72
.set NC_BYTES, 76
.set NC_FRAME, 88
LOCAL_FUNCTION quic_shell_no_connreset
    sub     $NC_FRAME, %rsp
    UNWIND_ALLOC NC_FRAME
    UNWIND_END_PROLOGUE
    movl    $0, NC_IN(%rsp)                 /* FALSE */
    mov     %rdi, %rcx
    mov     $OS_SIO_UDP_CONNRESET, %edx
    lea     NC_IN(%rsp), %r8
    mov     $4, %r9d
    movq    $0, ARG5(%rsp)
    movq    $0, ARG6(%rsp)
    lea     NC_BYTES(%rsp), %rax
    mov     %rax, ARG7(%rsp)
    movq    $0, ARG8(%rsp)
    movq    $0, ARG9(%rsp)                  /* no completion routine */
    CALL_GLOBAL WSAIoctl
    UNWIND_BEGIN_EPILOGUE
    add     $NC_FRAME, %rsp
    UNWIND_FREE NC_FRAME
    UNWIND_END_EPILOGUE
    ret
END_FUNCTION quic_shell_no_connreset

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

/* ---------------------------------------------------------------- Time */

/*
 * quic_shell_now() -> the monotonic time in microseconds:
 * QueryPerformanceCounter scaled by QueryPerformanceFrequency.
 */
.set QN_COUNT, 32
.set QN_FREQ, 40
.set QN_FRAME, 56
LOCAL_FUNCTION quic_shell_now
    SENTER  QN_FRAME
    lea     QN_COUNT(%rsp), %rcx
    CALL_GLOBAL QueryPerformanceCounter
    lea     QN_FREQ(%rsp), %rcx
    CALL_GLOBAL QueryPerformanceFrequency
    mov     QN_COUNT(%rsp), %rax
    mov     $1000000, %ecx
    mul     %rcx
    divq    QN_FREQ(%rsp)
    SLEAVE  QN_FRAME
END_FUNCTION quic_shell_now

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
 * buffers and no WSAECONNRESET from ICMP port unreachable; result gets its
 * socket ID and local address.
 * rbx ctx, rbp addr, r12 result, r13 the socket, r14 the entry.
 */
.set SB_SA, 48                          /* 32 bytes */
.set SB_LEN, 80
.set SB_OPT, 84
.set SB_FRAME, 88
FUNCTION quic_shell_bind
    SENTER  SB_FRAME
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     $QUIC_BUFFER_TOO_SMALL, %eax
    cmpq    $QUIC_SH_MAX, QUIC_SH_COUNT(%rbx)
    jae     9f
    call    quic_shell_wsa_start
    test    %eax, %eax
    jnz     8f
    mov     $OS_AF_INET, %ecx
    mov     $OS_AF_INET6, %eax
    cmpq    $6, QUIC_ADDR_FAMILY(%rbp)
    cmove   %eax, %ecx
    mov     $OS_SOCK_DGRAM, %edx
    mov     $OS_IPPROTO_UDP, %r8d
    CALL_GLOBAL socket
    cmp     $-1, %rax                       /* INVALID_SOCKET */
    je      6f
    mov     %rax, %r13
    movl    $1, SB_OPT(%rsp)
    mov     %r13, %rcx
    mov     $OS_FIONBIO, %edx
    lea     SB_OPT(%rsp), %r8
    CALL_GLOBAL ioctlsocket
    test    %eax, %eax
    jnz     7f
    mov     %r13, %rdi
    call    quic_shell_no_connreset         /* reads still work without it: not an error */
    cmpq    $6, QUIC_ADDR_FAMILY(%rbp)
    jne     1f
    movl    $1, SB_OPT(%rsp)
    mov     %r13, %rcx
    mov     $OS_IPPROTO_IPV6, %edx
    mov     $OS_IPV6_V6ONLY, %r8d
    lea     SB_OPT(%rsp), %r9
    movq    $4, ARG5(%rsp)
    CALL_GLOBAL setsockopt
1:  movl    $SOCKET_BUFFER, SB_OPT(%rsp)
    mov     %r13, %rcx
    mov     $OS_SOL_SOCKET, %edx
    mov     $OS_SO_RCVBUF, %r8d
    lea     SB_OPT(%rsp), %r9
    movq    $4, ARG5(%rsp)
    CALL_GLOBAL setsockopt                  /* the OS may refuse the size: not an error */
    mov     %r13, %rcx
    mov     $OS_SOL_SOCKET, %edx
    mov     $OS_SO_SNDBUF, %r8d
    lea     SB_OPT(%rsp), %r9
    movq    $4, ARG5(%rsp)
    CALL_GLOBAL setsockopt
    lea     SB_SA(%rsp), %rdi
    mov     %rbp, %rsi
    call    quic_shell_sockaddr
    mov     %r13, %rcx
    lea     SB_SA(%rsp), %rdx
    mov     %eax, %r8d
    CALL_GLOBAL bind
    test    %eax, %eax
    jnz     7f
    movl    $32, SB_LEN(%rsp)
    mov     %r13, %rcx
    lea     SB_SA(%rsp), %rdx
    lea     SB_LEN(%rsp), %r8
    CALL_GLOBAL getsockname
    test    %eax, %eax
    jnz     7f
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
7:  mov     %r13, %rcx
    CALL_GLOBAL closesocket
6:  CALL_GLOBAL WSACleanup
8:  mov     $QUIC_OS_ERROR, %eax
9:  SLEAVE  SB_FRAME
END_FUNCTION quic_shell_bind

/*
 * quic_shell_send(ctx, actions) -> status: each SEND action of the list goes
 * out with sendto; a datagram the OS does not take is lost, as UDP allows.
 * rbx ctx, rbp position, r12 end, r13 the action, r14 the socket.
 */
.set SS_SA, 48
.set SS_FRAME, 88
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
    mov     %rax, ARG6(%rsp)
    lea     SS_SA(%rsp), %rax
    mov     %rax, ARG5(%rsp)
    mov     %r14, %rcx
    lea     QUIC_ACT_DATA(%r13), %rdx
    mov     QUIC_ACT_COUNT(%r13), %r8
    xor     %r9d, %r9d
    CALL_GLOBAL sendto
    jmp     1b
8:  mov     $QUIC_OK, %eax
    SLEAVE  SS_FRAME
END_FUNCTION quic_shell_send

/*
 * quic_shell_receive(ctx, events) -> status: DATAGRAM events for the
 * datagrams waiting on each socket, while the list has room for one of
 * QUIC_RECEIVE_MAX bytes.
 * rbx ctx, rbp events, r12 socket index, r13 the socket, r14 the event.
 */
.set SR_SA, 48
.set SR_LEN, 80
.set SR_FRAME, 88
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
    mov     %r13, %rcx
    lea     QUIC_EV_DATA(%r14), %rdx
    mov     $QUIC_RECEIVE_MAX, %r8d
    xor     %r9d, %r9d
    lea     SR_SA(%rsp), %rax
    mov     %rax, ARG5(%rsp)
    lea     SR_LEN(%rsp), %rax
    mov     %rax, ARG6(%rsp)
    CALL_GLOBAL recvfrom
    cmp     $-1, %eax                       /* SOCKET_ERROR */
    je      3f
    mov     %eax, %eax
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
3:  inc     %r12                            /* WSAEWOULDBLOCK or an error: the next socket */
    jmp     1b
8:  mov     $QUIC_OK, %eax
    SLEAVE  SR_FRAME
END_FUNCTION quic_shell_receive

/*
 * quic_shell_wait(ctx, until) -> status: waits with WSAPoll until a socket
 * can be read or the monotonic time in microseconds at until, at most 60 s;
 * WSAPoll counts whole milliseconds, so the wait rounds up. With no socket,
 * or when WSAPoll fails, it sleeps instead.
 * rbx ctx, rbp until, r12 the socket count, r13 index, r14 milliseconds.
 */
.set SW_FDS, 48                         /* QUIC_SH_MAX WSAPOLLFD of 16 bytes */
.set SW_FRAME, 120
FUNCTION quic_shell_wait
    SENTER  SW_FRAME
    mov     %rdi, %rbx
    mov     (%rsi), %rbp
    call    quic_shell_now
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
    mov     %r13, %rcx
    shl     $4, %rcx
    mov     %rax, SW_FDS(%rsp,%rcx)
    movl    $OS_POLLIN, (SW_FDS + 8)(%rsp,%rcx) /* events, and revents 0 */
    inc     %r13
    jmp     3b
4:  test    %r12, %r12
    jz      5f
    lea     SW_FDS(%rsp), %rcx
    mov     %r12d, %edx
    mov     %r14d, %r8d
    CALL_GLOBAL WSAPoll
    cmp     $-1, %eax
    jne     9f
5:  mov     %r14d, %ecx
    CALL_GLOBAL Sleep
9:  mov     $QUIC_OK, %eax
    SLEAVE  SW_FRAME
END_FUNCTION quic_shell_wait

/*
 * quic_shell_clock(tick) -> status: the monotonic time in microseconds, the
 * Unix time in seconds (GetSystemTimeAsFileTime), and 32 bytes of
 * BCryptGenRandom. rbx tick.
 */
.set CK_FT, 32
.set CK_FRAME, 40
FUNCTION quic_shell_clock
    SENTER  CK_FRAME
    mov     %rdi, %rbx
    call    quic_shell_now
    mov     %rax, QUIC_TICK_NOW(%rbx)
    lea     CK_FT(%rsp), %rcx
    CALL_GLOBAL GetSystemTimeAsFileTime
    mov     CK_FT(%rsp), %rax
    movabs  $OS_UNIX_EPOCH, %rcx
    sub     %rcx, %rax
    xor     %edx, %edx
    mov     $10000000, %ecx
    div     %rcx
    mov     %rax, QUIC_TICK_UNIX(%rbx)
    xor     %ecx, %ecx
    lea     QUIC_TICK_ENTROPY(%rbx), %rdx
    mov     $32, %r8d
    mov     $OS_RNG_FLAGS, %r9d
    CALL_GLOBAL BCryptGenRandom
    test    %eax, %eax
    jnz     8f
    mov     $QUIC_OK, %eax
    jmp     9f
8:  mov     $QUIC_OS_ERROR, %eax
9:  SLEAVE  CK_FRAME
END_FUNCTION quic_shell_clock

/* quic_shell_close(ctx) -> status: every socket is closed, and its WSAStartup ended. rbx ctx, rbp index. */
FUNCTION quic_shell_close
    SENTER  40
    mov     %rdi, %rbx
    xor     %ebp, %ebp
1:  cmp     QUIC_SH_COUNT(%rbx), %rbp
    jae     2f
    imul    $QUIC_SH_STRIDE, %rbp, %rax
    mov     (QUIC_SH_SOCKETS + QUIC_SH_FD)(%rbx,%rax), %rcx
    CALL_GLOBAL closesocket
    CALL_GLOBAL WSACleanup
    inc     %rbp
    jmp     1b
2:  movq    $0, QUIC_SH_COUNT(%rbx)
    mov     $QUIC_OK, %eax
    SLEAVE  40
END_FUNCTION quic_shell_close
