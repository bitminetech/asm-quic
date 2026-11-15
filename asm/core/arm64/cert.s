/*
 * The certificate of the libp2p TLS handshake (libp2p/specs tls/tls.md):
 * DER reading, the checks of a peer certificate, and the host key signature
 * of the libp2p Public Key Extension.
 */

/* ---------------------------------------------------------------- DER */

/*
 * quic_der_next(p, end, tlv) -> 1 when one DER element with a one-byte tag
 * and a length of at most 0xFFFF starts at p and ends by end; tlv gets the
 * tag, the start and the end of its content. Else 0. A leaf.
 */
LOCAL_FUNCTION quic_der_next
    UNWIND_END_PROLOGUE
    sub     x3, x1, x0
    cmp     x0, x1
    b.hs    8f
    cmp     x3, #2
    b.lo    8f
    ldrb    w4, [x0]
    and     w5, w4, #0x1F
    cmp     w5, #0x1F
    b.eq    8f
    ldrb    w5, [x0, #1]
    add     x6, x0, #2
    tbz     w5, #7, 1f
    cmp     w5, #0x81
    b.eq    2f
    cmp     w5, #0x82
    b.ne    8f
    cmp     x3, #4
    b.lo    8f
    ldrb    w5, [x0, #2]
    ldrb    w7, [x0, #3]
    orr     w5, w7, w5, lsl #8
    add     x6, x0, #4
    b       1f
2:  cmp     x3, #3
    b.lo    8f
    ldrb    w5, [x0, #2]
    add     x6, x0, #3
1:  add     x7, x6, x5
    cmp     x7, x1
    b.hi    8f
    str     x4, [x2]
    str     x6, [x2, #8]
    str     x7, [x2, #16]
    mov     x0, #1
    ret
8:  mov     x0, #0
    ret
END_FUNCTION quic_der_next

/*
 * quic_der_take(p, end, tlv, tag) -> the end of the element at p when it is
 * one with that tag, its fields in tlv; else 0.
 */
LOCAL_FUNCTION quic_der_take
    ENTER   0
    mov     x19, x2
    mov     x20, x3
    bl      quic_der_next
    cbz     x0, 9f
    ldr     x9, [x19]
    cmp     x9, x20
    b.ne    8f
    ldr     x0, [x19, #16]
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_der_take

/* quic_bytes_is(p, n, q, m) -> 1 when the n bytes at p are the m bytes at q. A leaf. */
LOCAL_FUNCTION quic_bytes_is
    UNWIND_END_PROLOGUE
    cmp     x1, x3
    b.ne    8f
1:  cbz     x1, 2f
    ldrb    w4, [x0], #1
    ldrb    w5, [x2], #1
    cmp     w4, w5
    b.ne    8f
    sub     x1, x1, #1
    b       1b
2:  mov     x0, #1
    ret
8:  mov     x0, #0
    ret
END_FUNCTION quic_bytes_is

/*
 * quic_der_digits(p, n) -> the number of the n ASCII digits at p, or -1 when
 * one is not a digit. A leaf.
 */
LOCAL_FUNCTION quic_der_digits
    UNWIND_END_PROLOGUE
    mov     x2, #0
1:  cbz     x1, 2f
    ldrb    w3, [x0], #1
    sub     w3, w3, #'0'
    cmp     w3, #9
    b.hi    8f
    mov     x4, #10
    madd    x2, x2, x4, x3
    sub     x1, x1, #1
    b       1b
2:  mov     x0, x2
    ret
8:  mov     x0, #-1
    ret
END_FUNCTION quic_der_digits

/*
 * quic_der_time(tag, p, n) -> the Unix time in seconds of a UTCTime
 * YYMMDDHHMMSSZ (years 1950 to 2049) or a GeneralizedTime YYYYMMDDHHMMSSZ
 * (RFC 5280 section 4.1.2.5), as a signed number; or the NONE value
 * (all ones) when the time is malformed.
 * x19 p, x20 the year, x21 month, x22 day, x23 seconds of the day.
 */
LOCAL_FUNCTION quic_der_time
    ENTER   0
    mov     x19, x1
    cmp     x0, #0x17
    b.eq    1f
    cmp     x0, #0x18
    b.ne    8f
    cmp     x2, #15
    b.ne    8f
    ldrb    w9, [x19, #14]
    cmp     w9, #'Z'
    b.ne    8f
    mov     x0, x19
    mov     x1, #4
    bl      quic_der_digits
    cmn     x0, #1
    b.eq    8f
    mov     x20, x0
    add     x19, x19, #4
    b       2f
1:  cmp     x2, #13
    b.ne    8f
    ldrb    w9, [x19, #12]
    cmp     w9, #'Z'
    b.ne    8f
    mov     x0, x19
    mov     x1, #2
    bl      quic_der_digits
    cmn     x0, #1
    b.eq    8f
    add     x20, x0, #1900
    cmp     x0, #50
    b.hs    3f
    add     x20, x0, #2000
3:  add     x19, x19, #2
2:  mov     x0, x19                         /* MM */
    mov     x1, #2
    bl      quic_der_digits
    sub     x21, x0, #1
    cmp     x21, #11
    b.hi    8f
    add     x21, x21, #1
    add     x0, x19, #2                     /* DD */
    mov     x1, #2
    bl      quic_der_digits
    sub     x22, x0, #1
    cmp     x22, #30
    b.hi    8f
    add     x22, x22, #1
    add     x0, x19, #4                     /* HH */
    mov     x1, #2
    bl      quic_der_digits
    cmp     x0, #23
    b.hi    8f
    mov     x9, #3600
    mul     x23, x0, x9
    add     x0, x19, #6                     /* MM */
    mov     x1, #2
    bl      quic_der_digits
    cmp     x0, #59
    b.hi    8f
    mov     x9, #60
    madd    x23, x0, x9, x23
    add     x0, x19, #8                     /* SS */
    mov     x1, #2
    bl      quic_der_digits
    cmp     x0, #60
    b.hi    8f
    add     x23, x23, x0
    /* Days from 1970-01-01 (H. Hinnant's days_from_civil), for years 0 and later. */
    cmp     x21, #2
    cset    x9, ls
    sub     x20, x20, x9                    /* y */
    mov     x9, #400
    udiv    x10, x20, x9                    /* era */
    msub    x11, x10, x9, x20               /* yoe */
    add     x12, x21, #9
    mov     x13, #12
    udiv    x14, x12, x13
    msub    x12, x14, x13, x12              /* mp = (m + 9) mod 12 */
    mov     x13, #153
    mul     x12, x12, x13
    add     x12, x12, #2
    mov     x13, #5
    udiv    x12, x12, x13
    add     x12, x12, x22
    sub     x12, x12, #1                    /* doy */
    mov     x13, #365
    mul     x14, x11, x13
    add     x14, x14, x11, lsr #2
    mov     x13, #100
    udiv    x15, x11, x13
    sub     x14, x14, x15
    add     x14, x14, x12                   /* doe */
    MOV64   x13, 146097
    mul     x15, x10, x13
    add     x15, x15, x14
    MOV64   x13, 719468
    sub     x15, x15, x13                   /* days, signed */
    MOV64   x13, 86400
    madd    x0, x15, x13, x23
    b       9f
8:  mov     x0, #-1
9:  LEAVE   0
END_FUNCTION quic_der_time

/* ---------------------------------------------------------------- ECDSA signatures in DER */

/*
 * quic_der_int_get(dst, p, end) -> the position after a DER INTEGER at p, its
 * value written as 32 bytes big endian at dst; 0 when it is not a positive
 * INTEGER of at most 32 bytes of value.
 */
LOCAL_FUNCTION quic_der_int_get
    ENTER   0
    mov     x19, x0
    sub     x9, x2, x1
    cmp     x9, #2
    b.lo    8f
    ldrb    w10, [x1]
    cmp     w10, #2
    b.ne    8f
    ldrb    w11, [x1, #1]
    add     x20, x1, #2
    sub     x9, x9, #2
    cmp     x11, x9
    b.hi    8f
    cbz     x11, 8f
    ldrb    w12, [x20]
    tbnz    w12, #7, 8f
    add     x21, x20, x11
1:  cmp     x11, #32
    b.ls    2f
    ldrb    w12, [x20]
    cbnz    w12, 8f
    add     x20, x20, #1
    sub     x11, x11, #1
    b       1b
2:  mov     x22, x11
    mov     x0, x19
    mov     x1, #32
    bl      quic_zero
    mov     x9, #32
    sub     x9, x9, x22
    add     x0, x19, x9
    mov     x1, x20
    mov     x2, x22
    bl      quic_copy
    mov     x0, x21
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_der_int_get

/*
 * quic_der_sig_get(sig, p, n) -> 1 when the n bytes at p are a DER SEQUENCE of
 * two positive INTEGERs r and s, written as 64 bytes big endian at sig;
 * else 0. The length of the SEQUENCE is at most 127.
 */
LOCAL_FUNCTION quic_der_sig_get
    ENTER   0
    mov     x19, x0
    add     x20, x1, x2
    cmp     x2, #8
    b.lo    8f
    ldrb    w9, [x1]
    cmp     w9, #0x30
    b.ne    8f
    ldrb    w10, [x1, #1]
    sub     x11, x2, #2
    cmp     x10, x11
    b.ne    8f
    add     x1, x1, #2
    mov     x0, x19
    mov     x2, x20
    bl      quic_der_int_get
    cbz     x0, 8f
    mov     x1, x0
    add     x0, x19, #32
    mov     x2, x20
    bl      quic_der_int_get
    cmp     x0, x20
    b.ne    8f
    mov     x0, #1
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_der_sig_get

/* quic_der_int_put(dst, src) -> dst after a DER INTEGER of the 32-byte big-endian number at src. */
LOCAL_FUNCTION quic_der_int_put
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    mov     x21, #32
1:  cmp     x21, #1
    b.ls    2f
    ldrb    w9, [x20]
    cbnz    w9, 2f
    add     x20, x20, #1
    sub     x21, x21, #1
    b       1b
2:  ldrb    w9, [x20]
    lsr     w10, w9, #7
    mov     w11, #2
    strb    w11, [x19]
    add     w12, w21, w10
    strb    w12, [x19, #1]
    add     x0, x19, #2
    cbz     w10, 3f
    strb    wzr, [x0], #1
3:  mov     x1, x20
    mov     x2, x21
    bl      quic_copy
    LEAVE   0
END_FUNCTION quic_der_int_put

/* quic_der_sig_put(dst, sig) -> the length of the DER SEQUENCE of r and s (64 bytes big endian at sig). */
LOCAL_FUNCTION quic_der_sig_put
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    add     x0, x19, #2
    bl      quic_der_int_put
    add     x1, x20, #32
    bl      quic_der_int_put
    sub     x9, x0, x19
    mov     w10, #0x30
    strb    w10, [x19]
    sub     w11, w9, #2
    strb    w11, [x19, #1]
    mov     x0, x9
    LEAVE   0
END_FUNCTION quic_der_sig_put

/*
 * quic_low_s(s): when the 32-byte big-endian s is above n / 2 of secp256k1,
 * replaces it with n - s. A leaf. x2 to x5 s as big-endian limbs, most
 * significant first.
 */
LOCAL_FUNCTION quic_low_s
    UNWIND_END_PROLOGUE
    ldp     x2, x3, [x0]
    ldp     x4, x5, [x0, #16]
    rev     x2, x2
    rev     x3, x3
    rev     x4, x4
    rev     x5, x5
    /* n / 2 = 7FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 5D576E73 57A4501D DFE92F46 681B20A0 */
    MOV64   x6, 0x7FFFFFFFFFFFFFFF
    mov     x7, #-1
    MOV64   x8, 0x5D576E7357A4501D
    MOV64   x9, 0xDFE92F46681B20A0
    cmp     x2, x6
    b.hi    1f
    b.lo    9f
    cmp     x3, x7
    b.hi    1f
    b.lo    9f
    cmp     x4, x8
    b.hi    1f
    b.lo    9f
    cmp     x5, x9
    b.ls    9f
1:  /* s = n - s, with n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141 */
    MOV64   x9, 0xBFD25E8CD0364141
    MOV64   x8, 0xBAAEDCE6AF48A03B
    mov     x7, #-2
    mov     x6, #-1
    subs    x5, x9, x5
    sbcs    x4, x8, x4
    sbcs    x3, x7, x3
    sbc     x2, x6, x2
    rev     x2, x2
    rev     x3, x3
    rev     x4, x4
    rev     x5, x5
    stp     x2, x3, [x0]
    stp     x4, x5, [x0, #16]
9:  ret
END_FUNCTION quic_low_s

/* ---------------------------------------------------------------- Peer certificates */

/* The work area of quic_cert_check: CW_SIZE bytes at a multiple of 8. */
.set CW_TBS, 0                          /* ByteList: 24 + QUIC_CERT_MAX */
.set CW_MSG, 2072                       /* ByteList: 24 + 128 */
.set CW_HASH, 2224
.set CW_SIG, 2256
.set CW_KEY, 2320                       /* 72 bytes */
.set CW_VALID, 2392
.set CW_CTX, 2400                       /* the fields below */
.set CW_SIZE, 2624

/* Fields of the context of one check, at CW_CTX. */
.set X_TLV, 0                           /* tag, start, end */
.set X_TBS, 24                          /* the tbsCertificate element */
.set X_TBS_END, 32
.set X_SIG, 40                          /* the signature bytes */
.set X_SIG_LEN, 48
.set X_SIGALG, 56                       /* QUIC_CERT_P256 or QUIC_CERT_ED25519 */
.set X_SPKI, 64                         /* the SubjectPublicKeyInfo element */
.set X_SPKI_END, 72
.set X_KIND, 80                         /* the key of the certificate */
.set X_KEYP, 88
.set X_EXT, 96                          /* the value of the libp2p extension, or 0 */
.set X_EXT_END, 104
.set X_POS, 112                         /* the tbsCertificate content */
.set X_END, 120
.set X_TLV2, 128                        /* tag, start, end */
.set X_HOST_TYPE, 152
.set X_HOST_DATA, 160
.set X_HOST_LEN, 168
.set X_PROTO, 176                       /* the PublicKey protobuf */
.set X_PROTO_LEN, 184
.set X_HSIG, 192                        /* the host key signature */
.set X_HSIG_LEN, 200
.set X_SAVE_KIND, 208                   /* X_KIND and X_KEYP while an ECDSA host key is read */
.set X_SAVE_KEYP, 216
.set X_SIZE, 224

/*
 * quic_cert_alg(p, end) -> QUIC_CERT_P256 when the AlgorithmIdentifier content
 * at p is ecdsa-with-SHA256 with no parameters, QUIC_CERT_ED25519 when it is
 * Ed25519, else 0. x24 the context.
 */
LOCAL_FUNCTION quic_cert_alg
    ENTER   0
    mov     x20, x1
    add     x2, x24, #X_TLV2
    mov     x3, #0x06
    bl      quic_der_take
    cbz     x0, 8f
    cmp     x0, x20
    b.ne    8f
    ldr     x0, [x24, #X_TLV2 + 8]
    sub     x1, x20, x0
    adr     x2, 410f
    mov     x3, #8
    bl      quic_bytes_is
    mov     x19, #QUIC_CERT_P256
    cbnz    x0, 7f
    ldr     x0, [x24, #X_TLV2 + 8]
    sub     x1, x20, x0
    adr     x2, 411f
    mov     x3, #3
    bl      quic_bytes_is
    mov     x19, #QUIC_CERT_ED25519
    cbnz    x0, 7f
8:  mov     x0, #0
    b       9f
7:  mov     x0, x19
9:  LEAVE   0
END_FUNCTION quic_cert_alg

/*
 * quic_cert_spki(p, end) -> 1 when the SubjectPublicKeyInfo content at p is a
 * P-256 key (id-ecPublicKey, prime256v1, 65 bytes from 0x04) or an Ed25519
 * key (32 bytes); X_KIND and X_KEYP get its kind and bytes. Else 0.
 * x24 the context; x19 the end, x20 the end of the AlgorithmIdentifier.
 */
LOCAL_FUNCTION quic_cert_spki
    ENTER   0
    mov     x19, x1
    add     x2, x24, #X_TLV
    mov     x3, #0x30
    bl      quic_der_take
    cbz     x0, 8f
    mov     x21, x0                         /* after the AlgorithmIdentifier */
    ldr     x22, [x24, #X_TLV + 8]
    ldr     x20, [x24, #X_TLV + 16]
    mov     x0, x22
    mov     x1, x20
    add     x2, x24, #X_TLV
    mov     x3, #0x06
    bl      quic_der_take
    cbz     x0, 8f
    mov     x22, x0                         /* after the OID */
    ldr     x0, [x24, #X_TLV + 8]
    ldr     x1, [x24, #X_TLV + 16]
    sub     x1, x1, x0
    adr     x2, 412f
    mov     x3, #7
    bl      quic_bytes_is
    cbnz    x0, 1f
    ldr     x0, [x24, #X_TLV + 8]
    ldr     x1, [x24, #X_TLV + 16]
    sub     x1, x1, x0
    adr     x2, 411f
    mov     x3, #3
    bl      quic_bytes_is
    cbz     x0, 8f
    cmp     x22, x20                        /* Ed25519: no parameters */
    b.ne    8f
    mov     x23, #QUIC_CERT_ED25519
    mov     x25, #33
    b       2f
1:  mov     x0, x22                         /* id-ecPublicKey: the curve */
    mov     x1, x20
    add     x2, x24, #X_TLV
    mov     x3, #0x06
    bl      quic_der_take
    cmp     x0, x20
    b.ne    8f
    ldr     x0, [x24, #X_TLV + 8]
    sub     x1, x20, x0
    adr     x2, 413f
    mov     x3, #8
    bl      quic_bytes_is
    cbz     x0, 8f
    mov     x23, #QUIC_CERT_P256
    mov     x25, #66
2:  mov     x0, x21                         /* the BIT STRING */
    mov     x1, x19
    add     x2, x24, #X_TLV
    mov     x3, #0x03
    bl      quic_der_take
    cmp     x0, x19
    b.ne    8f
    ldr     x9, [x24, #X_TLV + 8]
    ldr     x10, [x24, #X_TLV + 16]
    sub     x10, x10, x9
    cmp     x10, x25
    b.ne    8f
    ldrb    w11, [x9]
    cbnz    w11, 8f                         /* no unused bits */
    add     x9, x9, #1
    cmp     x23, #QUIC_CERT_P256
    b.ne    3f
    ldrb    w11, [x9]
    cmp     w11, #4
    b.ne    8f
3:  str     x23, [x24, #X_KIND]
    str     x9, [x24, #X_KEYP]
    mov     x0, #1
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_cert_spki

/*
 * quic_cert_exts(p, end) -> 1 when the Extensions content at p is a SEQUENCE
 * of Extension elements with one libp2p extension (X_EXT, X_EXT_END) and no
 * other critical extension; else 0. x24 the context.
 * x19 the end of the list, x20 the position, x21 the end of one Extension,
 * x22 critical.
 */
LOCAL_FUNCTION quic_cert_exts
    ENTER   0
    mov     x9, x1
    add     x2, x24, #X_TLV
    mov     x3, #0x30
    bl      quic_der_take
    cbz     x0, 8f
    ldr     x20, [x24, #X_TLV + 8]
    ldr     x19, [x24, #X_TLV + 16]
1:  cmp     x20, x19
    b.hs    5f
    mov     x0, x20
    mov     x1, x19
    add     x2, x24, #X_TLV
    mov     x3, #0x30
    bl      quic_der_take
    cbz     x0, 8f
    mov     x21, x0
    ldr     x0, [x24, #X_TLV + 8]
    mov     x1, x21
    add     x2, x24, #X_TLV2
    mov     x3, #0x06
    bl      quic_der_take
    cbz     x0, 8f
    mov     x20, x0                         /* after the OID */
    mov     x22, #0
    mov     x0, x20
    mov     x1, x21
    add     x2, x24, #X_TLV
    bl      quic_der_next
    cbz     x0, 8f
    ldr     x9, [x24, #X_TLV]
    cmp     x9, #0x01                       /* critical BOOLEAN */
    b.ne    2f
    ldr     x10, [x24, #X_TLV + 8]
    ldr     x11, [x24, #X_TLV + 16]
    sub     x12, x11, x10
    cmp     x12, #1
    b.ne    8f
    ldrb    w22, [x10]
    mov     x20, x11
    mov     x0, x20
    mov     x1, x21
    add     x2, x24, #X_TLV
    bl      quic_der_next
    cbz     x0, 8f
    ldr     x9, [x24, #X_TLV]
2:  cmp     x9, #0x04                       /* extnValue */
    b.ne    8f
    ldr     x9, [x24, #X_TLV + 16]
    cmp     x9, x21
    b.ne    8f
    ldr     x0, [x24, #X_TLV2 + 8]
    ldr     x1, [x24, #X_TLV2 + 16]
    sub     x1, x1, x0
    adr     x2, 414f
    mov     x3, #10
    bl      quic_bytes_is
    cbz     x0, 3f
    ldr     x9, [x24, #X_EXT]
    cbnz    x9, 8f                          /* two libp2p extensions */
    ldr     x9, [x24, #X_TLV + 8]
    ldr     x10, [x24, #X_TLV + 16]
    str     x9, [x24, #X_EXT]
    str     x10, [x24, #X_EXT_END]
    b       4f
3:  cbz     x22, 4f                         /* a critical extension: one go-libp2p understands */
    ldr     x0, [x24, #X_TLV2 + 8]
    ldr     x1, [x24, #X_TLV2 + 16]
    sub     x1, x1, x0
    bl      quic_ext_understood
    cbz     x0, 8f
4:  mov     x20, x21
    b       1b
5:  mov     x0, #1
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_cert_exts

/*
 * quic_ext_understood(oid, n) -> 1 when the OID of n bytes is one of the
 * extensions that the x509 parser of go-libp2p handles, so it may be
 * critical: subjectKeyIdentifier, keyUsage, subjectAltName, basicConstraints,
 * authorityKeyIdentifier, extKeyUsage (2.5.29.14, 15, 17, 19, 35, 37). A leaf.
 */
LOCAL_FUNCTION quic_ext_understood
    UNWIND_END_PROLOGUE
    cmp     x1, #3
    b.ne    8f
    ldrb    w2, [x0]
    cmp     w2, #0x55
    b.ne    8f
    ldrb    w2, [x0, #1]
    cmp     w2, #0x1D
    b.ne    8f
    ldrb    w2, [x0, #2]
    cmp     w2, #0x25
    b.hi    8f
    mov     x3, #1
    lsl     x3, x3, x2
    MOV64   x4, ((1 << 0x0E) | (1 << 0x0F) | (1 << 0x11) | (1 << 0x13) | (1 << 0x23) | (1 << 0x25))
    tst     x3, x4
    cset    x0, ne
    ret
8:  mov     x0, #0
    ret
END_FUNCTION quic_ext_understood

/*
 * quic_pb_key(p, n) -> 1 when the n bytes at p are a PublicKey protobuf: Type
 * (field 1, a varint below 128) and Data (field 2, below 128 bytes), each
 * once; X_HOST_TYPE, X_HOST_DATA and X_HOST_LEN get them. Else 0. A leaf.
 * x24 the context.
 */
LOCAL_FUNCTION quic_pb_key
    UNWIND_END_PROLOGUE
    add     x1, x0, x1                      /* end */
    mov     x6, #0                          /* fields seen */
1:  cmp     x0, x1
    b.hs    5f
    ldrb    w2, [x0], #1
    cmp     w2, #0x08
    b.ne    2f
    tbnz    x6, #0, 8f
    cmp     x0, x1
    b.hs    8f
    ldrb    w3, [x0], #1
    tbnz    w3, #7, 8f
    str     x3, [x24, #X_HOST_TYPE]
    orr     x6, x6, #1
    b       1b
2:  cmp     w2, #0x12
    b.ne    8f
    tbnz    x6, #1, 8f
    cmp     x0, x1
    b.hs    8f
    ldrb    w3, [x0], #1
    tbnz    w3, #7, 8f
    sub     x4, x1, x0
    cmp     x3, x4
    b.hi    8f
    str     x0, [x24, #X_HOST_DATA]
    str     x3, [x24, #X_HOST_LEN]
    add     x0, x0, x3
    orr     x6, x6, #2
    b       1b
5:  cmp     x6, #3
    b.ne    8f
    mov     x0, #1
    ret
8:  mov     x0, #0
    ret
END_FUNCTION quic_pb_key

/*
 * quic_cert_selfsig() -> 1 when the signature of the certificate verifies
 * with its own key: ECDSA P-256 over the SHA-256 of tbsCertificate, or
 * Ed25519 over tbsCertificate. x23 the work area, x24 the context.
 */
LOCAL_FUNCTION quic_cert_selfsig
    ENTER   0
    ldr     x1, [x24, #X_TBS]
    ldr     x2, [x24, #X_TBS_END]
    sub     x19, x2, x1
    MOV64   x9, (QUIC_BL_FIXED + QUIC_CERT_MAX)
    BYTELIST x23, CW_TBS, (QUIC_BL_FIXED + QUIC_CERT_MAX), x19
    add     x0, x23, #(CW_TBS + QUIC_BL_FIXED)
    mov     x2, x19
    bl      quic_copy
    ldr     x9, [x24, #X_KIND]
    cmp     x9, #QUIC_CERT_ED25519
    b.ne    1f
    ldr     x9, [x24, #X_SIG_LEN]
    cmp     x9, #64
    b.ne    8f
    add     x0, x23, #CW_SIG
    ldr     x1, [x24, #X_SIG]
    mov     x2, #64
    bl      quic_copy
    add     x0, x23, #CW_KEY
    ldr     x1, [x24, #X_KEYP]
    mov     x2, #32
    bl      quic_copy
    add     x0, x23, #CW_KEY
    add     x1, x23, #CW_TBS
    add     x2, x23, #CW_SIG
    add     x3, x23, #CW_VALID
    CALL_GLOBAL crypto_ed25519_verify
    b       2f
1:  add     x0, x23, #CW_SIG
    ldr     x1, [x24, #X_SIG]
    ldr     x2, [x24, #X_SIG_LEN]
    bl      quic_der_sig_get
    cbz     x0, 8f
    add     x0, x23, #CW_TBS
    add     x1, x23, #CW_HASH
    CALL_GLOBAL crypto_sha256
    add     x0, x23, #CW_KEY
    ldr     x1, [x24, #X_KEYP]
    mov     x2, #65
    bl      quic_copy
    add     x0, x23, #CW_KEY
    add     x1, x23, #CW_HASH
    add     x2, x23, #CW_SIG
    add     x3, x23, #CW_VALID
    CALL_GLOBAL crypto_p256_verify
2:  cbnz    x0, 8f
    ldr     x0, [x23, #CW_VALID]
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_cert_selfsig

/*
 * quic_host_verify() -> 1 when the SignedKey of the libp2p extension holds a
 * PublicKey of type Ed25519, Secp256k1 or ECDSA (P-256), and its signature of
 * "libp2p-tls-handshake:" || the SubjectPublicKeyInfo of the certificate
 * verifies with that key: Ed25519 over the message; ECDSA over its SHA-256,
 * in DER, a secp256k1 s above n / 2 taken as n - s. x23 the work area,
 * x24 the context. x19 the SignedKey end, x20 the message length.
 */
LOCAL_FUNCTION quic_host_verify
    ENTER   0
    ldr     x0, [x24, #X_EXT]
    ldr     x1, [x24, #X_EXT_END]
    add     x2, x24, #X_TLV
    mov     x3, #0x30
    bl      quic_der_take
    ldr     x9, [x24, #X_EXT_END]
    cmp     x0, x9
    b.ne    8f
    ldr     x0, [x24, #X_TLV + 8]
    ldr     x19, [x24, #X_TLV + 16]
    mov     x1, x19
    add     x2, x24, #X_TLV2
    mov     x3, #0x04
    bl      quic_der_take
    cbz     x0, 8f
    mov     x20, x0
    ldr     x9, [x24, #X_TLV2 + 8]
    ldr     x10, [x24, #X_TLV2 + 16]
    sub     x10, x10, x9
    str     x9, [x24, #X_PROTO]
    str     x10, [x24, #X_PROTO_LEN]
    cmp     x10, #QUIC_HOST_MAX
    b.hi    8f
    mov     x0, x20
    mov     x1, x19
    add     x2, x24, #X_TLV2
    mov     x3, #0x04
    bl      quic_der_take
    cmp     x0, x19
    b.ne    8f
    ldr     x9, [x24, #X_TLV2 + 8]
    ldr     x10, [x24, #X_TLV2 + 16]
    sub     x10, x10, x9
    str     x9, [x24, #X_HSIG]
    str     x10, [x24, #X_HSIG_LEN]
    ldr     x0, [x24, #X_PROTO]
    ldr     x1, [x24, #X_PROTO_LEN]
    bl      quic_pb_key
    cbz     x0, 8f
    /* The message: "libp2p-tls-handshake:" || SubjectPublicKeyInfo. */
    ldr     x9, [x24, #X_SPKI]
    ldr     x10, [x24, #X_SPKI_END]
    sub     x21, x10, x9
    add     x20, x21, #21
    BYTELIST x23, CW_MSG, 152, x20
    add     x0, x23, #(CW_MSG + QUIC_BL_FIXED)
    adr     x1, 415f
    mov     x2, #21
    bl      quic_copy
    ldr     x1, [x24, #X_SPKI]
    mov     x2, x21
    bl      quic_copy
    ldr     x9, [x24, #X_HOST_TYPE]
    cmp     x9, #QUIC_KEY_ED25519
    b.ne    1f
    ldr     x9, [x24, #X_HOST_LEN]
    cmp     x9, #32
    b.ne    8f
    ldr     x9, [x24, #X_HSIG_LEN]
    cmp     x9, #64
    b.ne    8f
    add     x0, x23, #CW_SIG
    ldr     x1, [x24, #X_HSIG]
    mov     x2, #64
    bl      quic_copy
    add     x0, x23, #CW_KEY
    ldr     x1, [x24, #X_HOST_DATA]
    mov     x2, #32
    bl      quic_copy
    add     x0, x23, #CW_KEY
    add     x1, x23, #CW_MSG
    add     x2, x23, #CW_SIG
    add     x3, x23, #CW_VALID
    CALL_GLOBAL crypto_ed25519_verify
    b       5f
1:  add     x0, x23, #CW_SIG                /* ECDSA: the DER signature */
    ldr     x1, [x24, #X_HSIG]
    ldr     x2, [x24, #X_HSIG_LEN]
    bl      quic_der_sig_get
    cbz     x0, 8f
    add     x0, x23, #CW_MSG
    add     x1, x23, #CW_HASH
    CALL_GLOBAL crypto_sha256
    ldr     x9, [x24, #X_HOST_TYPE]
    cmp     x9, #QUIC_KEY_SECP256K1
    b.ne    2f
    ldr     x9, [x24, #X_HOST_LEN]
    cmp     x9, #33
    b.ne    8f
    add     x0, x23, #(CW_SIG + 32)
    bl      quic_low_s
    add     x0, x23, #CW_KEY
    ldr     x1, [x24, #X_HOST_DATA]
    mov     x2, #33
    bl      quic_copy
    add     x0, x23, #CW_KEY
    add     x1, x23, #CW_HASH
    add     x2, x23, #CW_SIG
    add     x3, x23, #CW_VALID
    CALL_GLOBAL crypto_secp256k1_verify
    b       5f
2:  cmp     x9, #QUIC_KEY_ECDSA
    b.ne    8f
    /* An ECDSA host key: a P-256 SubjectPublicKeyInfo, read with the SPKI steps. */
    ldr     x9, [x24, #X_KIND]
    ldr     x10, [x24, #X_KEYP]
    str     x9, [x24, #X_SAVE_KIND]
    str     x10, [x24, #X_SAVE_KEYP]
    ldr     x0, [x24, #X_HOST_DATA]
    ldr     x1, [x24, #X_HOST_LEN]
    add     x1, x0, x1
    add     x2, x24, #X_TLV2
    mov     x3, #0x30
    bl      quic_der_take
    ldr     x9, [x24, #X_HOST_DATA]
    ldr     x10, [x24, #X_HOST_LEN]
    add     x9, x9, x10
    cmp     x0, x9
    b.ne    7f
    ldr     x0, [x24, #X_TLV2 + 8]
    ldr     x1, [x24, #X_TLV2 + 16]
    bl      quic_cert_spki
    cbz     x0, 7f
    ldr     x9, [x24, #X_KIND]
    cmp     x9, #QUIC_CERT_P256
    b.ne    7f
    add     x0, x23, #CW_KEY
    ldr     x1, [x24, #X_KEYP]
    mov     x2, #65
    bl      quic_copy
    ldr     x9, [x24, #X_SAVE_KIND]
    ldr     x10, [x24, #X_SAVE_KEYP]
    str     x9, [x24, #X_KIND]
    str     x10, [x24, #X_KEYP]
    add     x0, x23, #CW_KEY
    add     x1, x23, #CW_HASH
    add     x2, x23, #CW_SIG
    add     x3, x23, #CW_VALID
    CALL_GLOBAL crypto_p256_verify
    b       5f
7:  ldr     x9, [x24, #X_SAVE_KIND]
    ldr     x10, [x24, #X_SAVE_KEYP]
    str     x9, [x24, #X_KIND]
    str     x10, [x24, #X_KEYP]
    b       8f
5:  cbnz    x0, 8f
    ldr     x0, [x23, #CW_VALID]
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_host_verify

/*
 * quic_cert_check(cert, len, now, info, work) -> QUIC_OK when the DER
 * certificate of len bytes meets the libp2p TLS spec at Unix time now, with
 * info filled; else QUIC_INVALID_CERT. work: CW_SIZE bytes at a multiple of 8.
 * The checks: one Certificate with nothing after it; valid at now; a P-256
 * or Ed25519 key that verifies its own signature; no unique IDs; exactly one
 * libp2p extension and no other critical extension; a host key signature
 * that verifies (quic_host_verify).
 * x19 the certificate, x20 its end, x21 now, x22 info, x23 work, x24 the context.
 */
LOCAL_FUNCTION quic_cert_check
    ENTER   0
    mov     x19, x0
    add     x20, x0, x1
    mov     x21, x2
    mov     x22, x3
    mov     x23, x4
    add     x24, x23, #CW_CTX
    cmp     x1, #QUIC_CERT_MAX
    b.hi    8f
    mov     x0, x24
    mov     x1, #X_SIZE
    bl      quic_zero
    /* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue } */
    mov     x0, x19
    mov     x1, x20
    add     x2, x24, #X_TLV
    mov     x3, #0x30
    bl      quic_der_take
    cmp     x0, x20
    b.ne    8f
    ldr     x25, [x24, #X_TLV + 8]          /* position */
    str     x25, [x24, #X_TBS]
    mov     x0, x25
    mov     x1, x20
    add     x2, x24, #X_TLV2
    mov     x3, #0x30
    bl      quic_der_take
    cbz     x0, 8f
    str     x0, [x24, #X_TBS_END]
    ldr     x9, [x24, #X_TLV2 + 8]          /* the tbsCertificate content */
    ldr     x10, [x24, #X_TLV2 + 16]
    str     x9, [x24, #X_POS]
    str     x10, [x24, #X_END]
    mov     x25, x0
    mov     x1, x20
    add     x2, x24, #X_TLV
    mov     x3, #0x30
    bl      quic_der_take
    cbz     x0, 8f
    mov     x25, x0
    ldr     x0, [x24, #X_TLV + 8]
    ldr     x1, [x24, #X_TLV + 16]
    bl      quic_cert_alg
    cbz     x0, 8f
    str     x0, [x24, #X_SIGALG]
    mov     x0, x25
    mov     x1, x20
    add     x2, x24, #X_TLV
    mov     x3, #0x03
    bl      quic_der_take
    cmp     x0, x20
    b.ne    8f
    ldr     x9, [x24, #X_TLV + 8]
    ldr     x10, [x24, #X_TLV + 16]
    cmp     x9, x10
    b.hs    8f
    ldrb    w11, [x9]
    cbnz    w11, 8f
    add     x9, x9, #1
    sub     x10, x10, x9
    str     x9, [x24, #X_SIG]
    str     x10, [x24, #X_SIG_LEN]
    /* tbsCertificate */
    ldr     x25, [x24, #X_POS]
    ldr     x26, [x24, #X_END]
    mov     x0, x25
    mov     x1, x26
    add     x2, x24, #X_TLV
    bl      quic_der_next
    cbz     x0, 8f
    ldr     x9, [x24, #X_TLV]
    cmp     x9, #0xA0                       /* version, optional */
    b.ne    1f
    ldr     x25, [x24, #X_TLV + 16]
1:  mov     x0, x25                         /* serialNumber */
    mov     x1, x26
    add     x2, x24, #X_TLV
    mov     x3, #0x02
    bl      quic_der_take
    cbz     x0, 8f
    mov     x1, x26                         /* signature */
    add     x2, x24, #X_TLV
    mov     x3, #0x30
    bl      quic_der_take
    cbz     x0, 8f
    mov     x1, x26                         /* issuer */
    add     x2, x24, #X_TLV
    mov     x3, #0x30
    bl      quic_der_take
    cbz     x0, 8f
    mov     x1, x26                         /* validity */
    add     x2, x24, #X_TLV2
    mov     x3, #0x30
    bl      quic_der_take
    cbz     x0, 8f
    mov     x25, x0
    ldr     x0, [x24, #X_TLV2 + 8]
    ldr     x1, [x24, #X_TLV2 + 16]
    add     x2, x24, #X_TLV
    bl      quic_der_next
    cbz     x0, 8f
    ldr     x0, [x24, #X_TLV]
    ldr     x1, [x24, #X_TLV + 8]
    ldr     x2, [x24, #X_TLV + 16]
    sub     x2, x2, x1
    bl      quic_der_time
    cmn     x0, #1
    b.eq    8f
    cmp     x21, x0                         /* not before */
    b.lt    8f
    ldr     x0, [x24, #X_TLV + 16]
    ldr     x1, [x24, #X_TLV2 + 16]
    add     x2, x24, #X_TLV
    bl      quic_der_next
    cbz     x0, 8f
    ldr     x9, [x24, #X_TLV + 16]
    ldr     x10, [x24, #X_TLV2 + 16]
    cmp     x9, x10
    b.ne    8f
    ldr     x0, [x24, #X_TLV]
    ldr     x1, [x24, #X_TLV + 8]
    ldr     x2, [x24, #X_TLV + 16]
    sub     x2, x2, x1
    bl      quic_der_time
    cmn     x0, #1
    b.eq    8f
    cmp     x21, x0                         /* not after */
    b.gt    8f
    mov     x0, x25                         /* subject */
    mov     x1, x26
    add     x2, x24, #X_TLV
    mov     x3, #0x30
    bl      quic_der_take
    cbz     x0, 8f
    mov     x25, x0
    str     x25, [x24, #X_SPKI]             /* subjectPublicKeyInfo */
    mov     x1, x26
    add     x2, x24, #X_TLV2
    mov     x3, #0x30
    bl      quic_der_take
    cbz     x0, 8f
    str     x0, [x24, #X_SPKI_END]
    mov     x25, x0
    ldr     x0, [x24, #X_TLV2 + 8]
    ldr     x1, [x24, #X_TLV2 + 16]
    bl      quic_cert_spki
    cbz     x0, 8f
2:  cmp     x25, x26                        /* issuerUniqueID, subjectUniqueID, extensions */
    b.hs    3f
    mov     x0, x25
    mov     x1, x26
    add     x2, x24, #X_TLV2
    bl      quic_der_next
    cbz     x0, 8f
    ldr     x9, [x24, #X_TLV2]
    cmp     x9, #0xA3
    b.ne    8f
    ldr     x9, [x24, #X_EXT]
    cbnz    x9, 8f
    ldr     x0, [x24, #X_TLV2 + 8]
    ldr     x1, [x24, #X_TLV2 + 16]
    mov     x25, x1                         /* after the extensions */
    bl      quic_cert_exts
    cbz     x0, 8f
    ldr     x9, [x24, #X_EXT]
    cbz     x9, 8f
    b       2b
3:  ldr     x9, [x24, #X_EXT]
    cbz     x9, 8f
    ldr     x9, [x24, #X_KIND]
    ldr     x10, [x24, #X_SIGALG]
    cmp     x9, x10
    b.ne    8f
    bl      quic_cert_selfsig
    cbz     x0, 8f
    bl      quic_host_verify
    cbz     x0, 8f
    /* CertInfo */
    add     x0, x22, #8
    mov     x1, #(QUIC_CI_FIXED - 8)
    bl      quic_zero
    ldr     x9, [x24, #X_KIND]
    str     x9, [x22, #QUIC_CI_KIND]
    add     x0, x22, #QUIC_CI_KEY
    ldr     x1, [x24, #X_KEYP]
    mov     x2, #65
    cmp     x9, #QUIC_CERT_P256
    mov     x3, #32
    csel    x2, x2, x3, eq
    bl      quic_copy
    ldr     x2, [x24, #X_PROTO_LEN]
    str     x2, [x22, #QUIC_CI_HOST_LEN]
    add     x0, x22, #QUIC_CI_HOST
    ldr     x1, [x24, #X_PROTO]
    bl      quic_copy
    mov     x0, #QUIC_OK
    b       9f
8:  mov     x0, #QUIC_INVALID_CERT
9:  LEAVE   0
END_FUNCTION quic_cert_check

/*
 * quic_cert_verify(cert, now, scratch, info) -> status: quic_cert_check of a
 * ByteList certificate at the Unix time at now. The scratch: its size,
 * then the work area.
 */
FUNCTION quic_cert_verify
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x22, x3
    ldr     x9, [x21]
    MOV64   x10, QUIC_CERT_SCRATCH
    mov     x0, #QUIC_BUFFER_TOO_SMALL
    cmp     x9, x10
    b.lo    9f
    ldr     x9, [x22]
    cmp     x9, #QUIC_CI_FIXED
    b.lo    9f
    ldr     x0, [x19, #QUIC_BL_OFFSET]
    add     x0, x19, x0
    ldr     x1, [x19, #QUIC_BL_COUNT]
    ldr     x2, [x20]
    mov     x3, x22
    add     x4, x21, #8
    bl      quic_cert_check
9:  LEAVE   0
END_FUNCTION quic_cert_verify

/* ---------------------------------------------------------------- Our certificate */

/*
 * quic_der_wrap(dst, tag, src, n) -> dst after one DER element: the tag, the
 * length of n (below 65536), then a copy of the n bytes at src. src does not
 * overlap dst.
 */
LOCAL_FUNCTION quic_der_wrap
    ENTER   0
    mov     x19, x2
    mov     x20, x3
    strb    w1, [x0], #1
    cmp     x20, #128
    b.lo    1f
    cmp     x20, #256
    b.lo    2f
    mov     w9, #0x82
    strb    w9, [x0], #1
    lsr     x9, x20, #8
    strb    w9, [x0], #1
    b       1f
2:  mov     w9, #0x81
    strb    w9, [x0], #1
1:  strb    w20, [x0], #1
    mov     x1, x19
    mov     x2, x20
    bl      quic_copy
    LEAVE   0
END_FUNCTION quic_der_wrap

/*
 * quic_cert_build(): our self-signed certificate in ST_CERT (libp2p TLS
 * spec): the template of the spec's test vectors (version 3, a random
 * serial, ecdsa-with-SHA256, issuer and subject O=libp2p.io serialNumber=1,
 * valid from 1975 to 4096), the P-256 key of ST_CERT_PRIV, and the libp2p
 * extension: the host key protobuf and its signature of
 * "libp2p-tls-handshake:" || the SubjectPublicKeyInfo. The host signs with
 * Ed25519, or with secp256k1 ECDSA over SHA-256 in DER.
 * x19 area A, x20 area B, x21 length, x22 the key type.
 */
.set CB_A, 0                            /* 512 bytes */
.set CB_B, 512                          /* 512 bytes */
.set CB_MSG, 1024                       /* ByteList: 24 + 112 */
.set CB_HASH, 1160
.set CB_SIG, 1192                       /* 64 bytes */
.set CB_DER, 1256                       /* 80 bytes */
.set CB_PUB, 1336                       /* 72 bytes */
.set CB_FRAME, 1408
LOCAL_FUNCTION quic_cert_build
    ENTER   0, CB_FRAME
    add     x19, sp, #CB_A
    add     x20, sp, #CB_B
    ldr     x22, [x27, #(ST_CONFIG + QUIC_CFG_KEY_TYPE)]
    add     x0, x27, #ST_CERT_PRIV
    add     x1, sp, #CB_PUB
    CALL_GLOBAL crypto_p256_public_key
    /* The message the host key signs: the prefix, then the SPKI. */
    mov     x9, #112
    BYTELIST sp, CB_MSG, 136, x9
    add     x0, sp, #(CB_MSG + QUIC_BL_FIXED)
    adr     x1, 415f
    mov     x2, #21
    bl      quic_copy
    adr     x1, 417f
    mov     x2, #26
    bl      quic_copy
    add     x1, sp, #CB_PUB
    mov     x2, #65
    bl      quic_copy
    cmp     x22, #QUIC_KEY_ED25519
    b.ne    1f
    add     x0, x27, #(ST_CONFIG + QUIC_CFG_KEY)
    add     x1, sp, #CB_MSG
    add     x2, sp, #CB_SIG
    CALL_GLOBAL crypto_ed25519_sign
    add     x0, sp, #CB_DER
    add     x1, sp, #CB_SIG
    mov     x2, #64
    bl      quic_copy
    mov     x21, #64
    b       2f
1:  add     x0, sp, #CB_MSG
    add     x1, sp, #CB_HASH
    CALL_GLOBAL crypto_sha256
    add     x0, x27, #(ST_CONFIG + QUIC_CFG_KEY)
    add     x1, sp, #CB_HASH
    add     x2, sp, #CB_SIG
    CALL_GLOBAL crypto_secp256k1_sign
    add     x0, sp, #CB_DER
    add     x1, sp, #CB_SIG
    bl      quic_der_sig_put
    mov     x21, x0
2:  /* SignedKey ::= SEQUENCE { publicKey OCTET STRING, signature OCTET STRING } */
    mov     x0, x19
    mov     x1, #0x04
    add     x2, x27, #ST_HOST_PROTO
    ldr     x3, [x27, #ST_HOST_PROTO_LEN]
    bl      quic_der_wrap
    mov     x1, #0x04
    add     x2, sp, #CB_DER
    mov     x3, x21
    bl      quic_der_wrap
    sub     x3, x0, x19
    mov     x0, x20
    mov     x1, #0x30
    mov     x2, x19
    bl      quic_der_wrap                   /* B: SignedKey */
    sub     x21, x0, x20
    /* Extension ::= SEQUENCE { extnID, extnValue OCTET STRING } */
    mov     x0, x19
    mov     x1, #0x06
    adr     x2, 414f
    mov     x3, #10
    bl      quic_der_wrap
    mov     x1, #0x04
    mov     x2, x20
    mov     x3, x21
    bl      quic_der_wrap
    sub     x3, x0, x19
    mov     x0, x20
    mov     x1, #0x30
    mov     x2, x19
    bl      quic_der_wrap                   /* B: Extension */
    sub     x3, x0, x20
    mov     x0, x19
    mov     x1, #0x30
    mov     x2, x20
    bl      quic_der_wrap                   /* A: Extensions */
    sub     x3, x0, x19
    mov     x0, x20
    mov     x1, #0xA3
    mov     x2, x19
    bl      quic_der_wrap                   /* B: [3] Extensions */
    sub     x21, x0, x20
    /* tbsCertificate: the template, the serial, the key, then [3]. */
    mov     x0, x19
    adr     x1, 416f
    mov     x2, #5
    bl      quic_copy
    mov     w9, #0x02
    strb    w9, [x0], #1
    mov     w9, #8
    strb    w9, [x0], #1
    mov     x23, x0
    mov     x1, #8
    bl      quic_random
    ldrb    w9, [x23]
    and     w9, w9, #0x3F
    orr     w9, w9, #0x40                   /* a positive INTEGER with no leading zero */
    strb    w9, [x23]
    add     x0, x23, #8
    adr     x1, 418f
    mov     x2, #(12 + 34 + 34 + 34)
    bl      quic_copy
    adr     x1, 417f
    mov     x2, #26
    bl      quic_copy
    add     x1, sp, #CB_PUB
    mov     x2, #65
    bl      quic_copy
    mov     x1, x20
    mov     x2, x21
    bl      quic_copy
    sub     x3, x0, x19
    mov     x0, x20
    mov     x1, #0x30
    mov     x2, x19
    bl      quic_der_wrap                   /* B: tbsCertificate */
    sub     x21, x0, x20
    /* signatureValue: ECDSA P-256 over the SHA-256 of tbsCertificate. */
    sub     x9, x20, #QUIC_BL_FIXED         /* a ByteList header before B: in A, unused now */
    mov     x10, #(512 + QUIC_BL_FIXED)
    str     x10, [x9, #QUIC_BL_SIZE]
    mov     x10, #QUIC_BL_FIXED
    str     x10, [x9, #QUIC_BL_OFFSET]
    str     x21, [x9, #QUIC_BL_COUNT]
    mov     x0, x9
    add     x1, sp, #CB_HASH
    CALL_GLOBAL crypto_sha256
    add     x0, x27, #ST_CERT_PRIV
    add     x1, sp, #CB_HASH
    add     x2, sp, #CB_SIG
    CALL_GLOBAL crypto_p256_sign
    mov     w9, #0
    strb    w9, [sp, #CB_DER]
    add     x0, sp, #(CB_DER + 1)
    add     x1, sp, #CB_SIG
    bl      quic_der_sig_put
    add     x22, x0, #1                     /* the BIT STRING content */
    /* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue } */
    mov     x0, x19
    mov     x1, x20
    mov     x2, x21
    bl      quic_copy
    adr     x1, 418f
    mov     x2, #12
    bl      quic_copy
    mov     x1, #0x03
    add     x2, sp, #CB_DER
    mov     x3, x22
    bl      quic_der_wrap
    sub     x3, x0, x19
    add     x0, x27, #ST_CERT
    mov     x1, #0x30
    mov     x2, x19
    bl      quic_der_wrap
    add     x9, x27, #ST_CERT
    sub     x9, x0, x9
    str     x9, [x27, #ST_CERT_LEN]
    LEAVE   0, CB_FRAME
END_FUNCTION quic_cert_build

/* ---------------------------------------------------------------- Constants of the certificate */

    .p2align 3
/* ecdsa-with-SHA256: 1.2.840.10045.4.3.2 */
410:
    .byte   0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02
/* Ed25519: 1.3.101.112 */
411:
    .byte   0x2B, 0x65, 0x70
/* id-ecPublicKey: 1.2.840.10045.2.1 */
412:
    .byte   0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
/* prime256v1: 1.2.840.10045.3.1.7 */
413:
    .byte   0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
/* The libp2p Public Key Extension: 1.3.6.1.4.1.53594.1.1 */
414:
    .byte   0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xA2, 0x5A, 0x01, 0x01
415:
    .ascii  "libp2p-tls-handshake:"
/* tbsCertificate up to the serial: version [0] INTEGER 2. */
416:
    .byte   0xA0, 0x03, 0x02, 0x01, 0x02
/* SubjectPublicKeyInfo of a P-256 key, up to the point. */
417:
    .byte   0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
    .byte   0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
/* signature ecdsa-with-SHA256, issuer, validity (1975 to 4096), subject: as the test vectors of tls.md. */
418:
    .byte   0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02
    .byte   0x30, 0x20, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x09
    .ascii  "libp2p.io"
    .byte   0x31, 0x0A, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x01, 0x31
    .byte   0x30, 0x20, 0x17, 0x0D
    .ascii  "750101130000Z"
    .byte   0x18, 0x0F
    .ascii  "40960101130000Z"
    .byte   0x30, 0x20, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x09
    .ascii  "libp2p.io"
    .byte   0x31, 0x0A, 0x30, 0x08, 0x06, 0x03, 0x55, 0x04, 0x05, 0x13, 0x01, 0x31
    .p2align 2
