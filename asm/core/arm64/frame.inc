/*
 * Frame and helper macros of the ARM64 core (AAPCS64). x18 is never used.
 * Every function that calls keeps an x29 frame record.
 *
 * Inside quic_step, x27 holds the state and x28 the scratch; no function
 * changes them.
 */

/*
 * Frame of a non-leaf function: x29, x30, x19-x28 at sp + extra, then
 * locals at sp + extra + 96. extra bytes of locals sit below at sp.
 */
.macro ENTER locals, extra=0
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
    .if \extra
    sub     sp, sp, #\extra
    UNWIND_ALLOC \extra
    .endif
    UNWIND_END_PROLOGUE
.endm

.macro LEAVE locals, extra=0
    UNWIND_BEGIN_EPILOGUE
    .if \extra
    add     sp, sp, #\extra
    UNWIND_FREE \extra
    .endif
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

/* reg = the 64-bit constant v. */
.macro MOV64 reg, v
    movz    \reg, #((\v) & 0xFFFF)
    movk    \reg, #(((\v) >> 16) & 0xFFFF), lsl #16
    movk    \reg, #(((\v) >> 32) & 0xFFFF), lsl #32
    movk    \reg, #(((\v) >> 48) & 0xFFFF), lsl #48
.endm

/* A ByteList header at base + off: size, offset 24, count. Uses x17; count is not x17. */
.macro BYTELIST base, off, size, count
    str     \count, [\base, #(\off) + 16]
    MOV64   x17, \size
    str     x17, [\base, #\off]
    mov     x17, #QUIC_BL_FIXED
    str     x17, [\base, #(\off) + 8]
.endm

/* reg = scratch + off, for any offset. */
.macro SCR reg, off
    MOV64   \reg, \off
    add     \reg, x28, \reg
.endm
