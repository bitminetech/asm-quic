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
    sub     a3, a1, a0
    bgeu    a0, a1, 8f
    li      a7, 2
    bltu    a3, a7, 8f
    lbu     a4, 0(a0)
    andi    a7, a4, 0x1F
    li      a6, 0x1F
    beq     a7, a6, 8f
    lbu     a5, 1(a0)
    addi    a6, a0, 2
    andi    a7, a5, 0x80
    beqz    a7, 1f
    li      a7, 0x81
    beq     a5, a7, 2f
    li      a7, 0x82
    bne     a5, a7, 8f
    li      a7, 4
    bltu    a3, a7, 8f
    lbu     a5, 2(a0)
    lbu     a7, 3(a0)
    slli    a5, a5, 8
    or      a5, a5, a7
    addi    a6, a0, 4
    j       1f
2:  li      a7, 3
    bltu    a3, a7, 8f
    lbu     a5, 2(a0)
    addi    a6, a0, 3
1:  add     a7, a6, a5
    bltu    a1, a7, 8f
    sd      a4, 0(a2)
    sd      a6, 8(a2)
    sd      a7, 16(a2)
    li      a0, 1
    ret
8:  li      a0, 0
    ret
END_FUNCTION quic_der_next

/*
 * quic_der_take(p, end, tlv, tag) -> the end of the element at p when it is
 * one with that tag, its fields in tlv; else 0.
 */
LOCAL_FUNCTION quic_der_take
    ENTER   0
    mv      s1, a2
    mv      s2, a3
    call    quic_der_next
    beqz    a0, 9f
    ld      t0, 0(s1)
    bne     t0, s2, 8f
    ld      a0, 16(s1)
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_der_take

/* quic_bytes_is(p, n, q, m) -> 1 when the n bytes at p are the m bytes at q. A leaf. */
LOCAL_FUNCTION quic_bytes_is
    UNWIND_END_PROLOGUE
    bne     a1, a3, 8f
1:  beqz    a1, 2f
    lbu     a4, 0(a0)
    lbu     a5, 0(a2)
    bne     a4, a5, 8f
    addi    a0, a0, 1
    addi    a2, a2, 1
    addi    a1, a1, -1
    j       1b
2:  li      a0, 1
    ret
8:  li      a0, 0
    ret
END_FUNCTION quic_bytes_is

/*
 * quic_der_digits(p, n) -> the number of the n ASCII digits at p, or -1 when
 * one is not a digit. A leaf.
 */
LOCAL_FUNCTION quic_der_digits
    UNWIND_END_PROLOGUE
    li      a2, 0
    li      a5, 10
1:  beqz    a1, 2f
    lbu     a3, 0(a0)
    addi    a3, a3, -48
    li      a4, 9
    bltu    a4, a3, 8f
    mul     a2, a2, a5
    add     a2, a2, a3
    addi    a0, a0, 1
    addi    a1, a1, -1
    j       1b
2:  mv      a0, a2
    ret
8:  li      a0, -1
    ret
END_FUNCTION quic_der_digits

/*
 * quic_der_time(tag, p, n) -> the Unix time in seconds of a UTCTime
 * YYMMDDHHMMSSZ (years 1950 to 2049) or a GeneralizedTime YYYYMMDDHHMMSSZ
 * (RFC 5280 section 4.1.2.5), as a signed number; or the NONE value
 * (all ones) when the time is malformed.
 * s1 p, s2 the year, s3 month, s4 day, s5 seconds of the day.
 */
LOCAL_FUNCTION quic_der_time
    ENTER   0
    mv      s1, a1
    li      t0, 0x17
    beq     a0, t0, 1f
    li      t0, 0x18
    bne     a0, t0, 8f
    li      t0, 15
    bne     a2, t0, 8f
    lbu     t1, 14(s1)
    li      t0, 'Z'
    bne     t1, t0, 8f
    mv      a0, s1
    li      a1, 4
    call    quic_der_digits
    li      t0, -1
    beq     a0, t0, 8f
    mv      s2, a0
    addi    s1, s1, 4
    j       2f
1:  li      t0, 13
    bne     a2, t0, 8f
    lbu     t1, 12(s1)
    li      t0, 'Z'
    bne     t1, t0, 8f
    mv      a0, s1
    li      a1, 2
    call    quic_der_digits
    li      t0, -1
    beq     a0, t0, 8f
    addi    s2, a0, 1900
    li      t0, 50
    bgeu    a0, t0, 3f
    addi    s2, a0, 2000
3:  addi    s1, s1, 2
2:  mv      a0, s1                          # MM
    li      a1, 2
    call    quic_der_digits
    addi    s3, a0, -1
    li      t0, 11
    bltu    t0, s3, 8f
    addi    s3, s3, 1
    addi    a0, s1, 2                       # DD
    li      a1, 2
    call    quic_der_digits
    addi    s4, a0, -1
    li      t0, 30
    bltu    t0, s4, 8f
    addi    s4, s4, 1
    addi    a0, s1, 4                       # HH
    li      a1, 2
    call    quic_der_digits
    li      t0, 23
    bltu    t0, a0, 8f
    li      t1, 3600
    mul     s5, a0, t1
    addi    a0, s1, 6                       # MM
    li      a1, 2
    call    quic_der_digits
    li      t0, 59
    bltu    t0, a0, 8f
    li      t1, 60
    mul     t1, a0, t1
    add     s5, s5, t1
    addi    a0, s1, 8                       # SS
    li      a1, 2
    call    quic_der_digits
    li      t0, 60
    bltu    t0, a0, 8f
    add     s5, s5, a0
    /* Days from 1970-01-01 (H. Hinnant's days_from_civil), for years 0 and later. */
    li      t0, 2
    bltu    t0, s3, 4f
    addi    s2, s2, -1                      # y
4:  li      t0, 400
    divu    t1, s2, t0                      # era
    mul     t2, t1, t0
    sub     t2, s2, t2                      # yoe
    addi    t3, s3, 9
    li      t0, 12
    remu    t3, t3, t0                      # mp = (m + 9) mod 12
    li      t0, 153
    mul     t3, t3, t0
    addi    t3, t3, 2
    li      t0, 5
    divu    t3, t3, t0
    add     t3, t3, s4
    addi    t3, t3, -1                      # doy
    li      t0, 365
    mul     t4, t2, t0
    srli    t5, t2, 2
    add     t4, t4, t5
    li      t0, 100
    divu    t5, t2, t0
    sub     t4, t4, t5
    add     t4, t4, t3                      # doe
    li      t0, 146097
    mul     t5, t1, t0
    add     t5, t5, t4
    li      t0, 719468
    sub     t5, t5, t0                      # days, signed
    li      t0, 86400
    mul     a0, t5, t0
    add     a0, a0, s5
    j       9f
8:  li      a0, -1
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
    mv      s1, a0
    sub     t0, a2, a1
    li      t1, 2
    bltu    t0, t1, 8f
    lbu     t2, 0(a1)
    li      t1, 2
    bne     t2, t1, 8f
    lbu     t3, 1(a1)
    addi    s2, a1, 2
    addi    t0, t0, -2
    bltu    t0, t3, 8f
    beqz    t3, 8f
    lbu     t4, 0(s2)
    andi    t4, t4, 0x80
    bnez    t4, 8f
    add     s3, s2, t3
1:  li      t1, 32
    bgeu    t1, t3, 2f
    lbu     t4, 0(s2)
    bnez    t4, 8f
    addi    s2, s2, 1
    addi    t3, t3, -1
    j       1b
2:  mv      s4, t3
    mv      a0, s1
    li      a1, 32
    call    quic_zero
    li      t0, 32
    sub     t0, t0, s4
    add     a0, s1, t0
    mv      a1, s2
    mv      a2, s4
    call    quic_copy
    mv      a0, s3
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_der_int_get

/*
 * quic_der_sig_get(sig, p, n) -> 1 when the n bytes at p are a DER SEQUENCE of
 * two positive INTEGERs r and s, written as 64 bytes big endian at sig;
 * else 0. The length of the SEQUENCE is at most 127.
 */
LOCAL_FUNCTION quic_der_sig_get
    ENTER   0
    mv      s1, a0
    add     s2, a1, a2
    li      t0, 8
    bltu    a2, t0, 8f
    lbu     t1, 0(a1)
    li      t0, 0x30
    bne     t1, t0, 8f
    lbu     t2, 1(a1)
    addi    t3, a2, -2
    bne     t2, t3, 8f
    addi    a1, a1, 2
    mv      a0, s1
    mv      a2, s2
    call    quic_der_int_get
    beqz    a0, 8f
    mv      a1, a0
    addi    a0, s1, 32
    mv      a2, s2
    call    quic_der_int_get
    bne     a0, s2, 8f
    li      a0, 1
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_der_sig_get

/* quic_der_int_put(dst, src) -> dst after a DER INTEGER of the 32-byte big-endian number at src. */
LOCAL_FUNCTION quic_der_int_put
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    li      s3, 32
1:  li      t0, 1
    bgeu    t0, s3, 2f
    lbu     t1, 0(s2)
    bnez    t1, 2f
    addi    s2, s2, 1
    addi    s3, s3, -1
    j       1b
2:  lbu     t1, 0(s2)
    srli    t2, t1, 7
    li      t3, 2
    sb      t3, 0(s1)
    add     t4, s3, t2
    sb      t4, 1(s1)
    addi    a0, s1, 2
    beqz    t2, 3f
    sb      zero, 0(a0)
    addi    a0, a0, 1
3:  mv      a1, s2
    mv      a2, s3
    call    quic_copy
    LEAVE   0
END_FUNCTION quic_der_int_put

/* quic_der_sig_put(dst, sig) -> the length of the DER SEQUENCE of r and s (64 bytes big endian at sig). */
LOCAL_FUNCTION quic_der_sig_put
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    addi    a0, s1, 2
    call    quic_der_int_put
    addi    a1, s2, 32
    call    quic_der_int_put
    sub     t0, a0, s1
    li      t1, 0x30
    sb      t1, 0(s1)
    addi    t2, t0, -2
    sb      t2, 1(s1)
    mv      a0, t0
    LEAVE   0
END_FUNCTION quic_der_sig_put

/*
 * quic_low_s(s): when the 32-byte big-endian s is above n / 2 of secp256k1,
 * replaces it with n - s. A leaf: byte by byte, from the tables of n / 2 and n.
 */
LOCAL_FUNCTION quic_low_s
    UNWIND_END_PROLOGUE
    lla     a1, 420f                        # n / 2
    li      a2, 0
1:  li      t0, 32
    bgeu    a2, t0, 9f                      # equal: not above
    add     a6, a0, a2
    lbu     a3, 0(a6)
    add     a6, a1, a2
    lbu     a4, 0(a6)
    bltu    a4, a3, 2f                      # above
    bltu    a3, a4, 9f                      # below
    addi    a2, a2, 1
    j       1b
2:  lla     a1, 421f                        # s = n - s, from the last byte
    li      a2, 31
    li      a5, 0                           # borrow
3:  add     a6, a0, a2
    lbu     a3, 0(a6)
    add     a7, a1, a2
    lbu     a4, 0(a7)
    sub     a4, a4, a3
    sub     a4, a4, a5
    sltz    a5, a4
    sb      a4, 0(a6)
    addi    a2, a2, -1
    bgez    a2, 3b
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
 * Ed25519, else 0. s6 the context.
 */
LOCAL_FUNCTION quic_cert_alg
    ENTER   0
    mv      s2, a1
    addi    a2, s6, X_TLV2
    li      a3, 0x06
    call    quic_der_take
    beqz    a0, 8f
    bne     a0, s2, 8f
    ld      a0, (X_TLV2 + 8)(s6)
    sub     a1, s2, a0
    lla     a2, 410f
    li      a3, 8
    call    quic_bytes_is
    li      s1, QUIC_CERT_P256
    bnez    a0, 7f
    ld      a0, (X_TLV2 + 8)(s6)
    sub     a1, s2, a0
    lla     a2, 411f
    li      a3, 3
    call    quic_bytes_is
    li      s1, QUIC_CERT_ED25519
    bnez    a0, 7f
8:  li      a0, 0
    j       9f
7:  mv      a0, s1
9:  LEAVE   0
END_FUNCTION quic_cert_alg

/*
 * quic_cert_spki(p, end) -> 1 when the SubjectPublicKeyInfo content at p is a
 * P-256 key (id-ecPublicKey, prime256v1, 65 bytes from 0x04) or an Ed25519
 * key (32 bytes); X_KIND and X_KEYP get its kind and bytes. Else 0.
 * s6 the context; s1 the end, s2 the end of the AlgorithmIdentifier.
 */
LOCAL_FUNCTION quic_cert_spki
    ENTER   0
    mv      s1, a1
    addi    a2, s6, X_TLV
    li      a3, 0x30
    call    quic_der_take
    beqz    a0, 8f
    mv      s3, a0                          # after the AlgorithmIdentifier
    ld      s4, (X_TLV + 8)(s6)
    ld      s2, (X_TLV + 16)(s6)
    mv      a0, s4
    mv      a1, s2
    addi    a2, s6, X_TLV
    li      a3, 0x06
    call    quic_der_take
    beqz    a0, 8f
    mv      s4, a0                          # after the OID
    ld      a0, (X_TLV + 8)(s6)
    ld      a1, (X_TLV + 16)(s6)
    sub     a1, a1, a0
    lla     a2, 412f
    li      a3, 7
    call    quic_bytes_is
    bnez    a0, 1f
    ld      a0, (X_TLV + 8)(s6)
    ld      a1, (X_TLV + 16)(s6)
    sub     a1, a1, a0
    lla     a2, 411f
    li      a3, 3
    call    quic_bytes_is
    beqz    a0, 8f
    bne     s4, s2, 8f                      # Ed25519: no parameters
    li      s5, QUIC_CERT_ED25519
    li      s7, 33
    j       2f
1:  mv      a0, s4                          # id-ecPublicKey: the curve
    mv      a1, s2
    addi    a2, s6, X_TLV
    li      a3, 0x06
    call    quic_der_take
    bne     a0, s2, 8f
    ld      a0, (X_TLV + 8)(s6)
    sub     a1, s2, a0
    lla     a2, 413f
    li      a3, 8
    call    quic_bytes_is
    beqz    a0, 8f
    li      s5, QUIC_CERT_P256
    li      s7, 66
2:  mv      a0, s3                          # the BIT STRING
    mv      a1, s1
    addi    a2, s6, X_TLV
    li      a3, 0x03
    call    quic_der_take
    bne     a0, s1, 8f
    ld      t0, (X_TLV + 8)(s6)
    ld      t1, (X_TLV + 16)(s6)
    sub     t1, t1, t0
    bne     t1, s7, 8f
    lbu     t2, 0(t0)
    bnez    t2, 8f                          # no unused bits
    addi    t0, t0, 1
    li      t3, QUIC_CERT_P256
    bne     s5, t3, 3f
    lbu     t2, 0(t0)
    li      t3, 4
    bne     t2, t3, 8f
3:  sd      s5, X_KIND(s6)
    sd      t0, X_KEYP(s6)
    li      a0, 1
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_cert_spki

/*
 * quic_ext_understood(oid, n) -> 1 when the OID of n bytes is one of the
 * extensions that the x509 parser of go-libp2p handles, so it may be
 * critical: subjectKeyIdentifier, keyUsage, subjectAltName, basicConstraints,
 * authorityKeyIdentifier, extKeyUsage (2.5.29.14, 15, 17, 19, 35, 37). A leaf.
 */
LOCAL_FUNCTION quic_ext_understood
    UNWIND_END_PROLOGUE
    li      a2, 3
    bne     a1, a2, 8f
    lbu     a3, 0(a0)
    li      a2, 0x55
    bne     a3, a2, 8f
    lbu     a3, 1(a0)
    li      a2, 0x1D
    bne     a3, a2, 8f
    lbu     a3, 2(a0)
    li      a2, 0x25
    bltu    a2, a3, 8f
    li      a4, 1
    sll     a4, a4, a3
    li      a5, ((1 << 0x0E) | (1 << 0x0F) | (1 << 0x11) | (1 << 0x13) | (1 << 0x23) | (1 << 0x25))
    and     a4, a4, a5
    snez    a0, a4
    ret
8:  li      a0, 0
    ret
END_FUNCTION quic_ext_understood

/*
 * quic_cert_exts(p, end) -> 1 when the Extensions content at p is a SEQUENCE
 * of Extension elements with one libp2p extension (X_EXT, X_EXT_END) and no
 * other critical extension that go-libp2p does not understand; else 0.
 * s6 the context. s1 the end of the list, s2 the position, s3 the end of one
 * Extension, s4 critical.
 */
LOCAL_FUNCTION quic_cert_exts
    ENTER   0
    addi    a2, s6, X_TLV
    li      a3, 0x30
    call    quic_der_take
    beqz    a0, 8f
    ld      s2, (X_TLV + 8)(s6)
    ld      s1, (X_TLV + 16)(s6)
1:  bgeu    s2, s1, 5f
    mv      a0, s2
    mv      a1, s1
    addi    a2, s6, X_TLV
    li      a3, 0x30
    call    quic_der_take
    beqz    a0, 8f
    mv      s3, a0
    ld      a0, (X_TLV + 8)(s6)
    mv      a1, s3
    addi    a2, s6, X_TLV2
    li      a3, 0x06
    call    quic_der_take
    beqz    a0, 8f
    mv      s2, a0                          # after the OID
    li      s4, 0
    mv      a0, s2
    mv      a1, s3
    addi    a2, s6, X_TLV
    call    quic_der_next
    beqz    a0, 8f
    ld      t0, X_TLV(s6)
    li      t1, 0x01                        # critical BOOLEAN
    bne     t0, t1, 2f
    ld      t2, (X_TLV + 8)(s6)
    ld      t3, (X_TLV + 16)(s6)
    sub     t4, t3, t2
    li      t1, 1
    bne     t4, t1, 8f
    lbu     s4, 0(t2)
    mv      s2, t3
    mv      a0, s2
    mv      a1, s3
    addi    a2, s6, X_TLV
    call    quic_der_next
    beqz    a0, 8f
    ld      t0, X_TLV(s6)
2:  li      t1, 0x04                        # extnValue
    bne     t0, t1, 8f
    ld      t0, (X_TLV + 16)(s6)
    bne     t0, s3, 8f
    ld      a0, (X_TLV2 + 8)(s6)
    ld      a1, (X_TLV2 + 16)(s6)
    sub     a1, a1, a0
    lla     a2, 414f
    li      a3, 10
    call    quic_bytes_is
    beqz    a0, 3f
    ld      t0, X_EXT(s6)
    bnez    t0, 8f                          # two libp2p extensions
    ld      t0, (X_TLV + 8)(s6)
    ld      t1, (X_TLV + 16)(s6)
    sd      t0, X_EXT(s6)
    sd      t1, X_EXT_END(s6)
    j       4f
3:  beqz    s4, 4f                          # a critical extension: one go-libp2p understands
    ld      a0, (X_TLV2 + 8)(s6)
    ld      a1, (X_TLV2 + 16)(s6)
    sub     a1, a1, a0
    call    quic_ext_understood
    beqz    a0, 8f
4:  mv      s2, s3
    j       1b
5:  li      a0, 1
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_cert_exts

/*
 * quic_pb_key(p, n) -> 1 when the n bytes at p are a PublicKey protobuf: Type
 * (field 1, a varint below 128) and Data (field 2, below 128 bytes), each
 * once; X_HOST_TYPE, X_HOST_DATA and X_HOST_LEN get them. Else 0. A leaf.
 * s6 the context.
 */
LOCAL_FUNCTION quic_pb_key
    UNWIND_END_PROLOGUE
    add     a1, a0, a1                      # end
    li      a6, 0                           # fields seen
1:  bgeu    a0, a1, 5f
    lbu     a2, 0(a0)
    addi    a0, a0, 1
    li      a7, 0x08
    bne     a2, a7, 2f
    andi    a5, a6, 1
    bnez    a5, 8f
    bgeu    a0, a1, 8f
    lbu     a3, 0(a0)
    addi    a0, a0, 1
    andi    a5, a3, 0x80
    bnez    a5, 8f
    sd      a3, X_HOST_TYPE(s6)
    ori     a6, a6, 1
    j       1b
2:  li      a7, 0x12
    bne     a2, a7, 8f
    andi    a5, a6, 2
    bnez    a5, 8f
    bgeu    a0, a1, 8f
    lbu     a3, 0(a0)
    addi    a0, a0, 1
    andi    a5, a3, 0x80
    bnez    a5, 8f
    sub     a4, a1, a0
    bltu    a4, a3, 8f
    sd      a0, X_HOST_DATA(s6)
    sd      a3, X_HOST_LEN(s6)
    add     a0, a0, a3
    ori     a6, a6, 2
    j       1b
5:  li      a7, 3
    bne     a6, a7, 8f
    li      a0, 1
    ret
8:  li      a0, 0
    ret
END_FUNCTION quic_pb_key

/*
 * quic_cert_selfsig() -> 1 when the signature of the certificate verifies
 * with its own key: ECDSA P-256 over the SHA-256 of tbsCertificate, or
 * Ed25519 over tbsCertificate. s5 the work area, s6 the context.
 */
LOCAL_FUNCTION quic_cert_selfsig
    ENTER   0
    ld      a1, X_TBS(s6)
    ld      a2, X_TBS_END(s6)
    sub     s1, a2, a1
    BYTELIST s5, CW_TBS, (QUIC_BL_FIXED + QUIC_CERT_MAX), s1
    addi    a0, s5, (CW_TBS + QUIC_BL_FIXED)
    mv      a2, s1
    call    quic_copy
    ld      t0, X_KIND(s6)
    li      t1, QUIC_CERT_ED25519
    bne     t0, t1, 1f
    ld      t0, X_SIG_LEN(s6)
    li      t1, 64
    bne     t0, t1, 8f
    li      t2, CW_SIG
    add     a0, s5, t2
    ld      a1, X_SIG(s6)
    li      a2, 64
    call    quic_copy
    li      t2, CW_KEY
    add     a0, s5, t2
    ld      a1, X_KEYP(s6)
    li      a2, 32
    call    quic_copy
    li      t2, CW_KEY
    add     a0, s5, t2
    mv      a1, s5                          # CW_TBS is 0
    li      t2, CW_SIG
    add     a2, s5, t2
    li      t2, CW_VALID
    add     a3, s5, t2
    CALL_GLOBAL crypto_ed25519_verify
    j       2f
1:  li      t2, CW_SIG
    add     a0, s5, t2
    ld      a1, X_SIG(s6)
    ld      a2, X_SIG_LEN(s6)
    call    quic_der_sig_get
    beqz    a0, 8f
    mv      a0, s5
    li      t2, CW_HASH
    add     a1, s5, t2
    CALL_GLOBAL crypto_sha256
    li      t2, CW_KEY
    add     a0, s5, t2
    ld      a1, X_KEYP(s6)
    li      a2, 65
    call    quic_copy
    li      t2, CW_KEY
    add     a0, s5, t2
    li      t2, CW_HASH
    add     a1, s5, t2
    li      t2, CW_SIG
    add     a2, s5, t2
    li      t2, CW_VALID
    add     a3, s5, t2
    CALL_GLOBAL crypto_p256_verify
2:  bnez    a0, 8f
    li      t2, CW_VALID
    add     t2, s5, t2
    ld      a0, 0(t2)
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_cert_selfsig

/*
 * quic_host_verify() -> 1 when the SignedKey of the libp2p extension holds a
 * PublicKey of type Ed25519, Secp256k1 or ECDSA (P-256), and its signature of
 * "libp2p-tls-handshake:" || the SubjectPublicKeyInfo of the certificate
 * verifies with that key: Ed25519 over the message; ECDSA over its SHA-256,
 * in DER, a secp256k1 s above n / 2 taken as n - s. s5 the work area,
 * s6 the context. s1 the SignedKey end, s2 the message length, s3 the SPKI length.
 */
LOCAL_FUNCTION quic_host_verify
    ENTER   0
    ld      a0, X_EXT(s6)
    ld      a1, X_EXT_END(s6)
    addi    a2, s6, X_TLV
    li      a3, 0x30
    call    quic_der_take
    ld      t0, X_EXT_END(s6)
    bne     a0, t0, 8f
    ld      a0, (X_TLV + 8)(s6)
    ld      s1, (X_TLV + 16)(s6)
    mv      a1, s1
    addi    a2, s6, X_TLV2
    li      a3, 0x04
    call    quic_der_take
    beqz    a0, 8f
    mv      s2, a0
    ld      t0, (X_TLV2 + 8)(s6)
    ld      t1, (X_TLV2 + 16)(s6)
    sub     t1, t1, t0
    sd      t0, X_PROTO(s6)
    sd      t1, X_PROTO_LEN(s6)
    li      t2, QUIC_HOST_MAX
    bltu    t2, t1, 8f
    mv      a0, s2
    mv      a1, s1
    addi    a2, s6, X_TLV2
    li      a3, 0x04
    call    quic_der_take
    bne     a0, s1, 8f
    ld      t0, (X_TLV2 + 8)(s6)
    ld      t1, (X_TLV2 + 16)(s6)
    sub     t1, t1, t0
    sd      t0, X_HSIG(s6)
    sd      t1, X_HSIG_LEN(s6)
    ld      a0, X_PROTO(s6)
    ld      a1, X_PROTO_LEN(s6)
    call    quic_pb_key
    beqz    a0, 8f
    /* The message: "libp2p-tls-handshake:" || SubjectPublicKeyInfo. */
    ld      t0, X_SPKI(s6)
    ld      t1, X_SPKI_END(s6)
    sub     s3, t1, t0
    addi    s2, s3, 21
    li      t2, CW_MSG
    add     t3, s5, t2
    BYTELIST t3, 0, 152, s2
    li      t2, (CW_MSG + QUIC_BL_FIXED)
    add     a0, s5, t2
    lla     a1, 415f
    li      a2, 21
    call    quic_copy
    ld      a1, X_SPKI(s6)
    mv      a2, s3
    call    quic_copy
    ld      t0, X_HOST_TYPE(s6)
    li      t1, QUIC_KEY_ED25519
    bne     t0, t1, 1f
    ld      t0, X_HOST_LEN(s6)
    li      t1, 32
    bne     t0, t1, 8f
    ld      t0, X_HSIG_LEN(s6)
    li      t1, 64
    bne     t0, t1, 8f
    li      t2, CW_SIG
    add     a0, s5, t2
    ld      a1, X_HSIG(s6)
    li      a2, 64
    call    quic_copy
    li      t2, CW_KEY
    add     a0, s5, t2
    ld      a1, X_HOST_DATA(s6)
    li      a2, 32
    call    quic_copy
    li      t2, CW_KEY
    add     a0, s5, t2
    li      t2, CW_MSG
    add     a1, s5, t2
    li      t2, CW_SIG
    add     a2, s5, t2
    li      t2, CW_VALID
    add     a3, s5, t2
    CALL_GLOBAL crypto_ed25519_verify
    j       5f
1:  li      t2, CW_SIG                      # ECDSA: the DER signature
    add     a0, s5, t2
    ld      a1, X_HSIG(s6)
    ld      a2, X_HSIG_LEN(s6)
    call    quic_der_sig_get
    beqz    a0, 8f
    li      t2, CW_MSG
    add     a0, s5, t2
    li      t2, CW_HASH
    add     a1, s5, t2
    CALL_GLOBAL crypto_sha256
    ld      t0, X_HOST_TYPE(s6)
    li      t1, QUIC_KEY_SECP256K1
    bne     t0, t1, 2f
    ld      t0, X_HOST_LEN(s6)
    li      t1, 33
    bne     t0, t1, 8f
    li      t2, (CW_SIG + 32)
    add     a0, s5, t2
    call    quic_low_s
    li      t2, CW_KEY
    add     a0, s5, t2
    ld      a1, X_HOST_DATA(s6)
    li      a2, 33
    call    quic_copy
    li      t2, CW_KEY
    add     a0, s5, t2
    li      t2, CW_HASH
    add     a1, s5, t2
    li      t2, CW_SIG
    add     a2, s5, t2
    li      t2, CW_VALID
    add     a3, s5, t2
    CALL_GLOBAL crypto_secp256k1_verify
    j       5f
2:  li      t1, QUIC_KEY_ECDSA
    bne     t0, t1, 8f
    /* An ECDSA host key: a P-256 SubjectPublicKeyInfo, read with the SPKI steps. */
    ld      t0, X_KIND(s6)
    ld      t1, X_KEYP(s6)
    sd      t0, X_SAVE_KIND(s6)
    sd      t1, X_SAVE_KEYP(s6)
    ld      a0, X_HOST_DATA(s6)
    ld      a1, X_HOST_LEN(s6)
    add     a1, a0, a1
    addi    a2, s6, X_TLV2
    li      a3, 0x30
    call    quic_der_take
    ld      t0, X_HOST_DATA(s6)
    ld      t1, X_HOST_LEN(s6)
    add     t0, t0, t1
    bne     a0, t0, 7f
    ld      a0, (X_TLV2 + 8)(s6)
    ld      a1, (X_TLV2 + 16)(s6)
    call    quic_cert_spki
    beqz    a0, 7f
    ld      t0, X_KIND(s6)
    li      t1, QUIC_CERT_P256
    bne     t0, t1, 7f
    li      t2, CW_KEY
    add     a0, s5, t2
    ld      a1, X_KEYP(s6)
    li      a2, 65
    call    quic_copy
    ld      t0, X_SAVE_KIND(s6)
    ld      t1, X_SAVE_KEYP(s6)
    sd      t0, X_KIND(s6)
    sd      t1, X_KEYP(s6)
    li      t2, CW_KEY
    add     a0, s5, t2
    li      t2, CW_HASH
    add     a1, s5, t2
    li      t2, CW_SIG
    add     a2, s5, t2
    li      t2, CW_VALID
    add     a3, s5, t2
    CALL_GLOBAL crypto_p256_verify
    j       5f
7:  ld      t0, X_SAVE_KIND(s6)
    ld      t1, X_SAVE_KEYP(s6)
    sd      t0, X_KIND(s6)
    sd      t1, X_KEYP(s6)
    j       8f
5:  bnez    a0, 8f
    li      t2, CW_VALID
    add     t2, s5, t2
    ld      a0, 0(t2)
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_host_verify

/*
 * quic_cert_check(cert, len, now, info, work) -> QUIC_OK when the DER
 * certificate of len bytes meets the libp2p TLS spec at Unix time now, with
 * info filled; else QUIC_INVALID_CERT. work: CW_SIZE bytes at a multiple of 8.
 * s1 the certificate, s2 its end, s3 now, s4 info, s5 work, s6 the context,
 * s7 the position, s8 the tbsCertificate end.
 */
LOCAL_FUNCTION quic_cert_check
    ENTER   0
    mv      s1, a0
    add     s2, a0, a1
    mv      s3, a2
    mv      s4, a3
    mv      s5, a4
    li      t0, CW_CTX
    add     s6, s5, t0
    li      t0, QUIC_CERT_MAX
    bltu    t0, a1, 8f
    mv      a0, s6
    li      a1, X_SIZE
    call    quic_zero
    /* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue } */
    mv      a0, s1
    mv      a1, s2
    addi    a2, s6, X_TLV
    li      a3, 0x30
    call    quic_der_take
    bne     a0, s2, 8f
    ld      s7, (X_TLV + 8)(s6)             # position
    sd      s7, X_TBS(s6)
    mv      a0, s7
    mv      a1, s2
    addi    a2, s6, X_TLV2
    li      a3, 0x30
    call    quic_der_take
    beqz    a0, 8f
    sd      a0, X_TBS_END(s6)
    ld      t0, (X_TLV2 + 8)(s6)            # the tbsCertificate content
    ld      t1, (X_TLV2 + 16)(s6)
    sd      t0, X_POS(s6)
    sd      t1, X_END(s6)
    mv      s7, a0
    mv      a1, s2
    addi    a2, s6, X_TLV
    li      a3, 0x30
    call    quic_der_take
    beqz    a0, 8f
    mv      s7, a0
    ld      a0, (X_TLV + 8)(s6)
    ld      a1, (X_TLV + 16)(s6)
    call    quic_cert_alg
    beqz    a0, 8f
    sd      a0, X_SIGALG(s6)
    mv      a0, s7
    mv      a1, s2
    addi    a2, s6, X_TLV
    li      a3, 0x03
    call    quic_der_take
    bne     a0, s2, 8f
    ld      t0, (X_TLV + 8)(s6)
    ld      t1, (X_TLV + 16)(s6)
    bgeu    t0, t1, 8f
    lbu     t2, 0(t0)
    bnez    t2, 8f
    addi    t0, t0, 1
    sub     t1, t1, t0
    sd      t0, X_SIG(s6)
    sd      t1, X_SIG_LEN(s6)
    /* tbsCertificate */
    ld      s7, X_POS(s6)
    ld      s8, X_END(s6)
    mv      a0, s7
    mv      a1, s8
    addi    a2, s6, X_TLV
    call    quic_der_next
    beqz    a0, 8f
    ld      t0, X_TLV(s6)
    li      t1, 0xA0                        # version, optional
    bne     t0, t1, 1f
    ld      s7, (X_TLV + 16)(s6)
1:  mv      a0, s7                          # serialNumber
    mv      a1, s8
    addi    a2, s6, X_TLV
    li      a3, 0x02
    call    quic_der_take
    beqz    a0, 8f
    mv      a1, s8                          # signature
    addi    a2, s6, X_TLV
    li      a3, 0x30
    call    quic_der_take
    beqz    a0, 8f
    mv      a1, s8                          # issuer
    addi    a2, s6, X_TLV
    li      a3, 0x30
    call    quic_der_take
    beqz    a0, 8f
    mv      a1, s8                          # validity
    addi    a2, s6, X_TLV2
    li      a3, 0x30
    call    quic_der_take
    beqz    a0, 8f
    mv      s7, a0
    ld      a0, (X_TLV2 + 8)(s6)
    ld      a1, (X_TLV2 + 16)(s6)
    addi    a2, s6, X_TLV
    call    quic_der_next
    beqz    a0, 8f
    ld      a0, X_TLV(s6)
    ld      a1, (X_TLV + 8)(s6)
    ld      a2, (X_TLV + 16)(s6)
    sub     a2, a2, a1
    call    quic_der_time
    li      t0, -1
    beq     a0, t0, 8f
    blt     s3, a0, 8f                      # not before
    ld      a0, (X_TLV + 16)(s6)
    ld      a1, (X_TLV2 + 16)(s6)
    addi    a2, s6, X_TLV
    call    quic_der_next
    beqz    a0, 8f
    ld      t0, (X_TLV + 16)(s6)
    ld      t1, (X_TLV2 + 16)(s6)
    bne     t0, t1, 8f
    ld      a0, X_TLV(s6)
    ld      a1, (X_TLV + 8)(s6)
    ld      a2, (X_TLV + 16)(s6)
    sub     a2, a2, a1
    call    quic_der_time
    li      t0, -1
    beq     a0, t0, 8f
    blt     a0, s3, 8f                      # not after
    mv      a0, s7                          # subject
    mv      a1, s8
    addi    a2, s6, X_TLV
    li      a3, 0x30
    call    quic_der_take
    beqz    a0, 8f
    mv      s7, a0
    sd      s7, X_SPKI(s6)                  # subjectPublicKeyInfo
    mv      a1, s8
    addi    a2, s6, X_TLV2
    li      a3, 0x30
    call    quic_der_take
    beqz    a0, 8f
    sd      a0, X_SPKI_END(s6)
    mv      s7, a0
    ld      a0, (X_TLV2 + 8)(s6)
    ld      a1, (X_TLV2 + 16)(s6)
    call    quic_cert_spki
    beqz    a0, 8f
2:  bgeu    s7, s8, 3f                      # issuerUniqueID, subjectUniqueID, extensions
    mv      a0, s7
    mv      a1, s8
    addi    a2, s6, X_TLV2
    call    quic_der_next
    beqz    a0, 8f
    ld      t0, X_TLV2(s6)
    li      t1, 0xA3
    bne     t0, t1, 8f
    ld      t0, X_EXT(s6)
    bnez    t0, 8f
    ld      a0, (X_TLV2 + 8)(s6)
    ld      a1, (X_TLV2 + 16)(s6)
    mv      s7, a1                          # after the extensions
    call    quic_cert_exts
    beqz    a0, 8f
    ld      t0, X_EXT(s6)
    beqz    t0, 8f
    j       2b
3:  ld      t0, X_EXT(s6)
    beqz    t0, 8f
    ld      t0, X_KIND(s6)
    ld      t1, X_SIGALG(s6)
    bne     t0, t1, 8f
    call    quic_cert_selfsig
    beqz    a0, 8f
    call    quic_host_verify
    beqz    a0, 8f
    /* CertInfo */
    addi    a0, s4, 8
    li      a1, (QUIC_CI_FIXED - 8)
    call    quic_zero
    ld      t0, X_KIND(s6)
    sd      t0, QUIC_CI_KIND(s4)
    addi    a0, s4, QUIC_CI_KEY
    ld      a1, X_KEYP(s6)
    li      a2, 32
    li      t1, QUIC_CERT_P256
    bne     t0, t1, 4f
    li      a2, 65
4:  call    quic_copy
    ld      a2, X_PROTO_LEN(s6)
    sd      a2, QUIC_CI_HOST_LEN(s4)
    addi    a0, s4, QUIC_CI_HOST
    ld      a1, X_PROTO(s6)
    call    quic_copy
    li      a0, QUIC_OK
    j       9f
8:  li      a0, QUIC_INVALID_CERT
9:  LEAVE   0
END_FUNCTION quic_cert_check

/*
 * quic_cert_verify(cert, now, scratch, info) -> status: quic_cert_check of a
 * ByteList certificate at the Unix time at now. The scratch: its size,
 * then the work area.
 */
FUNCTION quic_cert_verify
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    mv      s4, a3
    ld      t0, 0(s3)
    li      t1, QUIC_CERT_SCRATCH
    li      a0, QUIC_BUFFER_TOO_SMALL
    bltu    t0, t1, 9f
    ld      t0, 0(s4)
    li      t1, QUIC_CI_FIXED
    bltu    t0, t1, 9f
    ld      a0, QUIC_BL_OFFSET(s1)
    add     a0, s1, a0
    ld      a1, QUIC_BL_COUNT(s1)
    ld      a2, 0(s2)
    mv      a3, s4
    addi    a4, s3, 8
    call    quic_cert_check
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
    mv      s1, a2
    mv      s2, a3
    sb      a1, 0(a0)
    addi    a0, a0, 1
    li      t0, 128
    bltu    s2, t0, 1f
    li      t0, 256
    bltu    s2, t0, 2f
    li      t1, 0x82
    sb      t1, 0(a0)
    srli    t1, s2, 8
    sb      t1, 1(a0)
    addi    a0, a0, 2
    j       1f
2:  li      t1, 0x81
    sb      t1, 0(a0)
    addi    a0, a0, 1
1:  sb      s2, 0(a0)
    addi    a0, a0, 1
    mv      a1, s1
    mv      a2, s2
    call    quic_copy
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
 * s1 area A, s2 area B, s3 length, s4 the key type, s5 the serial.
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
    addi    s1, sp, (FL + CB_A)
    addi    s2, sp, (FL + CB_B)
    ld      s4, (ST_CONFIG + QUIC_CFG_KEY_TYPE)(s9)
    li      t0, ST_CERT_PRIV
    add     a0, s9, t0
    addi    a1, sp, (FL + CB_PUB)
    CALL_GLOBAL crypto_p256_public_key
    /* The message the host key signs: the prefix, then the SPKI. */
    li      t0, 112
    addi    t1, sp, (FL + CB_MSG)
    BYTELIST t1, 0, 136, t0
    addi    a0, sp, (FL + CB_MSG + QUIC_BL_FIXED)
    lla     a1, 415f
    li      a2, 21
    call    quic_copy
    lla     a1, 417f
    li      a2, 26
    call    quic_copy
    addi    a1, sp, (FL + CB_PUB)
    li      a2, 65
    call    quic_copy
    li      t0, QUIC_KEY_ED25519
    bne     s4, t0, 1f
    addi    a0, s9, (ST_CONFIG + QUIC_CFG_KEY)
    addi    a1, sp, (FL + CB_MSG)
    addi    a2, sp, (FL + CB_SIG)
    CALL_GLOBAL crypto_ed25519_sign
    addi    a0, sp, (FL + CB_DER)
    addi    a1, sp, (FL + CB_SIG)
    li      a2, 64
    call    quic_copy
    li      s3, 64
    j       2f
1:  addi    a0, sp, (FL + CB_MSG)
    addi    a1, sp, (FL + CB_HASH)
    CALL_GLOBAL crypto_sha256
    addi    a0, s9, (ST_CONFIG + QUIC_CFG_KEY)
    addi    a1, sp, (FL + CB_HASH)
    addi    a2, sp, (FL + CB_SIG)
    CALL_GLOBAL crypto_secp256k1_sign
    addi    a0, sp, (FL + CB_DER)
    addi    a1, sp, (FL + CB_SIG)
    call    quic_der_sig_put
    mv      s3, a0
2:  /* SignedKey ::= SEQUENCE { publicKey OCTET STRING, signature OCTET STRING } */
    mv      a0, s1
    li      a1, 0x04
    li      t0, ST_HOST_PROTO
    add     a2, s9, t0
    ld      a3, ST_HOST_PROTO_LEN(s9)
    call    quic_der_wrap
    li      a1, 0x04
    addi    a2, sp, (FL + CB_DER)
    mv      a3, s3
    call    quic_der_wrap
    sub     a3, a0, s1
    mv      a0, s2
    li      a1, 0x30
    mv      a2, s1
    call    quic_der_wrap                   # B: SignedKey
    sub     s3, a0, s2
    /* Extension ::= SEQUENCE { extnID, extnValue OCTET STRING } */
    mv      a0, s1
    li      a1, 0x06
    lla     a2, 414f
    li      a3, 10
    call    quic_der_wrap
    li      a1, 0x04
    mv      a2, s2
    mv      a3, s3
    call    quic_der_wrap
    sub     a3, a0, s1
    mv      a0, s2
    li      a1, 0x30
    mv      a2, s1
    call    quic_der_wrap                   # B: Extension
    sub     a3, a0, s2
    mv      a0, s1
    li      a1, 0x30
    mv      a2, s2
    call    quic_der_wrap                   # A: Extensions
    sub     a3, a0, s1
    mv      a0, s2
    li      a1, 0xA3
    mv      a2, s1
    call    quic_der_wrap                   # B: [3] Extensions
    sub     s3, a0, s2
    /* tbsCertificate: the template, the serial, the key, then [3]. */
    mv      a0, s1
    lla     a1, 416f
    li      a2, 5
    call    quic_copy
    li      t0, 0x02
    sb      t0, 0(a0)
    li      t0, 8
    sb      t0, 1(a0)
    addi    s5, a0, 2
    mv      a0, s5
    li      a1, 8
    call    quic_random
    lbu     t0, 0(s5)
    andi    t0, t0, 0x3F
    ori     t0, t0, 0x40                    # a positive INTEGER with no leading zero
    sb      t0, 0(s5)
    addi    a0, s5, 8
    lla     a1, 418f
    li      a2, (12 + 34 + 34 + 34)
    call    quic_copy
    lla     a1, 417f
    li      a2, 26
    call    quic_copy
    addi    a1, sp, (FL + CB_PUB)
    li      a2, 65
    call    quic_copy
    mv      a1, s2
    mv      a2, s3
    call    quic_copy
    sub     a3, a0, s1
    mv      a0, s2
    li      a1, 0x30
    mv      a2, s1
    call    quic_der_wrap                   # B: tbsCertificate
    sub     s3, a0, s2
    /* signatureValue: ECDSA P-256 over the SHA-256 of tbsCertificate. */
    addi    t0, s2, -QUIC_BL_FIXED          # a ByteList header before B: in A, unused now
    li      t1, (512 + QUIC_BL_FIXED)
    sd      t1, QUIC_BL_SIZE(t0)
    li      t1, QUIC_BL_FIXED
    sd      t1, QUIC_BL_OFFSET(t0)
    sd      s3, QUIC_BL_COUNT(t0)
    mv      a0, t0
    addi    a1, sp, (FL + CB_HASH)
    CALL_GLOBAL crypto_sha256
    li      t0, ST_CERT_PRIV
    add     a0, s9, t0
    addi    a1, sp, (FL + CB_HASH)
    addi    a2, sp, (FL + CB_SIG)
    CALL_GLOBAL crypto_p256_sign
    sb      zero, (FL + CB_DER)(sp)
    addi    a0, sp, (FL + CB_DER + 1)
    addi    a1, sp, (FL + CB_SIG)
    call    quic_der_sig_put
    addi    s4, a0, 1                       # the BIT STRING content
    /* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue } */
    mv      a0, s1
    mv      a1, s2
    mv      a2, s3
    call    quic_copy
    lla     a1, 418f
    li      a2, 12
    call    quic_copy
    li      a1, 0x03
    addi    a2, sp, (FL + CB_DER)
    mv      a3, s4
    call    quic_der_wrap
    sub     a3, a0, s1
    li      t0, ST_CERT
    add     a0, s9, t0
    li      a1, 0x30
    mv      a2, s1
    call    quic_der_wrap
    li      t0, ST_CERT
    add     t0, s9, t0
    sub     t0, a0, t0
    sd      t0, ST_CERT_LEN(s9)
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
/* n / 2 and n of secp256k1, big endian. */
420:
    .byte   0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    .byte   0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0
421:
    .byte   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE
    .byte   0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
    .p2align 2
