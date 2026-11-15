/*
 * Frame and helper macros of the x86-64 core (System V AMD64 psABI), AT&T
 * syntax. The functions and their steps follow the ARM64 core one for one.
 *
 * Inside quic_step, r15 holds the state and r14 the scratch; no function
 * changes them. The ARM64 x19 to x22 are rbx, rbp, r12 and r13 here; x23 to
 * x26 sit in the frame at X23(%rsp) to X26(%rsp).
 *
 * Constants in macros are written $(n): in a macro without named
 * parameters, the Mach-O assembler reads $0 to $9 as positional arguments.
 */

.set X23, 0
.set X24, 8
.set X25, 16
.set X26, 24

/*
 * Frame of a non-leaf function: rbx, rbp, r12-r15 pushed, then from rsp:
 * the x23-x26 slots (32 bytes), extra bytes at 32(%rsp) (ARM64 [sp, k] for
 * k below extra), then locals at 32 + extra (ARM64 [sp, extra + 96 + k]),
 * then 8 bytes so that rsp is 16-byte aligned at each call.
 */
.macro ENTER locals, extra=0
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
    sub     $(40 + \extra + \locals), %rsp
    UNWIND_ALLOC (40 + \extra + \locals)
    UNWIND_END_PROLOGUE
.endm

.macro LEAVE locals, extra=0
    UNWIND_BEGIN_EPILOGUE
    add     $(40 + \extra + \locals), %rsp
    UNWIND_FREE (40 + \extra + \locals)
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

/* Frame of a function that keeps no register: 8 bytes, so rsp is 16-byte aligned at each call. */
.macro FRAME
    sub     $(8), %rsp
    UNWIND_ALLOC 8
    UNWIND_END_PROLOGUE
.endm

.macro UNFRAME
    UNWIND_BEGIN_EPILOGUE
    add     $(8), %rsp
    UNWIND_FREE 8
    UNWIND_END_EPILOGUE
    ret
.endm

/* reg = state + the u64 at state + field: a table base. */
.macro TABLE reg, field
    mov     \field(%r15), \reg
    add     %r15, \reg
.endm

/* reg = the config field of the state. */
.macro CFG reg, field
    mov     (ST_CONFIG + \field)(%r15), \reg
.endm

/* reg = scratch + off. */
.macro SCR reg, off
    lea     \off(%r14), \reg
.endm

/* A ByteList header at off(base): size, offset 24, count (a register). */
.macro BYTELIST base, off, size, count
    mov     \count, (\off + 16)(\base)
    movq    $\size, \off(\base)
    movq    $QUIC_BL_FIXED, (\off + 8)(\base)
.endm

/*
 * Scratch words of the x86-64 core for values that ARM64 callees read from
 * their caller's x23 to x26, which are frame slots here (ARM64 never uses
 * scratch 32 to 63).
 */
.set SC_PACKET, 32                      /* the packet of quic_packet_build (ARM64 x23) */
.set SC_SLOT, 40                        /* the stream slot of quic_stream_out (ARM64 x25) */
.set SC_SPREC, 48                       /* the space record of quic_packet_build (ARM64 x26) */
.set SC_X86_END, 56
.if SC_X86_END > SC_FRAME
.error "x86-64 scratch words overlap SC_FRAME"
.endif

