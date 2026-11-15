/*
 * The certificate of the libp2p TLS handshake (libp2p/specs tls/tls.md):
 * DER reading, the checks of a peer certificate, and the host key signature
 * of the libp2p Public Key Extension. In the checks, r12 holds the work area
 * and r13 the context (ARM64 x23 and x24), so the helpers read them.
 */

/* ---------------------------------------------------------------- DER */

/*
 * quic_der_next(p, end, tlv) -> 1 when one DER element with a one-byte tag
 * and a length of at most 0xFFFF starts at p and ends by end; tlv gets the
 * tag, the start and the end of its content. Else 0. A leaf.
 */
LOCAL_FUNCTION quic_der_next
    UNWIND_END_PROLOGUE
    mov     %rsi, %rcx
    sub     %rdi, %rcx
    cmp     %rsi, %rdi
    jae     8f
    cmp     $2, %rcx
    jb      8f
    movzbl  (%rdi), %r8d                    /* the tag */
    mov     %r8d, %eax
    and     $0x1F, %eax
    cmp     $0x1F, %eax
    je      8f
    movzbl  1(%rdi), %r9d                   /* the length */
    lea     2(%rdi), %r10                   /* the content */
    test    $0x80, %r9d
    jz      1f
    cmp     $0x81, %r9d
    je      2f
    cmp     $0x82, %r9d
    jne     8f
    cmp     $4, %rcx
    jb      8f
    movzbl  2(%rdi), %r9d
    shl     $8, %r9d
    movzbl  3(%rdi), %eax
    or      %eax, %r9d
    lea     4(%rdi), %r10
    jmp     1f
2:  cmp     $3, %rcx
    jb      8f
    movzbl  2(%rdi), %r9d
    lea     3(%rdi), %r10
1:  lea     (%r10,%r9), %r11
    cmp     %rsi, %r11
    ja      8f
    mov     %r8, (%rdx)
    mov     %r10, 8(%rdx)
    mov     %r11, 16(%rdx)
    mov     $1, %eax
    ret
8:  xor     %eax, %eax
    ret
END_FUNCTION quic_der_next

/*
 * quic_der_take(p, end, tlv, tag) -> the end of the element at p when it is
 * one with that tag, its fields in tlv; else 0.
 */
LOCAL_FUNCTION quic_der_take
    ENTER   0
    mov     %rdx, %rbx
    mov     %rcx, %rbp
    call    quic_der_next
    test    %rax, %rax
    jz      9f
    cmp     %rbp, (%rbx)
    jne     8f
    mov     16(%rbx), %rax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_der_take

/* quic_bytes_is(p, n, q, m) -> 1 when the n bytes at p are the m bytes at q. A leaf. */
LOCAL_FUNCTION quic_bytes_is
    UNWIND_END_PROLOGUE
    cmp     %rcx, %rsi
    jne     8f
1:  test    %rsi, %rsi
    jz      2f
    movzbl  (%rdi), %eax
    cmpb    (%rdx), %al
    jne     8f
    inc     %rdi
    inc     %rdx
    dec     %rsi
    jmp     1b
2:  mov     $1, %eax
    ret
8:  xor     %eax, %eax
    ret
END_FUNCTION quic_bytes_is

/*
 * quic_der_digits(p, n) -> the number of the n ASCII digits at p, or -1 when
 * one is not a digit. A leaf.
 */
LOCAL_FUNCTION quic_der_digits
    UNWIND_END_PROLOGUE
    xor     %eax, %eax
1:  test    %rsi, %rsi
    jz      2f
    movzbl  (%rdi), %ecx
    sub     $48, %ecx                       /* '0' */
    cmp     $9, %ecx
    ja      8f
    imul    $10, %rax, %rax
    add     %rcx, %rax
    inc     %rdi
    dec     %rsi
    jmp     1b
2:  ret
8:  mov     $-1, %rax
    ret
END_FUNCTION quic_der_digits

/*
 * quic_der_time(tag, p, n) -> the Unix time in seconds of a UTCTime
 * YYMMDDHHMMSSZ (years 1950 to 2049) or a GeneralizedTime YYYYMMDDHHMMSSZ
 * (RFC 5280 section 4.1.2.5), as a signed number; or the NONE value
 * (all ones) when the time is malformed.
 * rbx p, rbp the year, r12 month, r13 day, X23 seconds of the day.
 */
LOCAL_FUNCTION quic_der_time
    ENTER   0
    mov     %rsi, %rbx
    cmp     $0x17, %rdi
    je      1f
    cmp     $0x18, %rdi
    jne     8f
    cmp     $15, %rdx
    jne     8f
    cmpb    $90, 14(%rbx)                   /* 'Z' */
    jne     8f
    mov     %rbx, %rdi
    mov     $4, %esi
    call    quic_der_digits
    cmp     $-1, %rax
    je      8f
    mov     %rax, %rbp
    add     $4, %rbx
    jmp     2f
1:  cmp     $13, %rdx
    jne     8f
    cmpb    $90, 12(%rbx)
    jne     8f
    mov     %rbx, %rdi
    mov     $2, %esi
    call    quic_der_digits
    cmp     $-1, %rax
    je      8f
    lea     1900(%rax), %rbp
    cmp     $50, %rax
    jae     3f
    lea     2000(%rax), %rbp
3:  add     $2, %rbx
2:  mov     %rbx, %rdi                      /* MM */
    mov     $2, %esi
    call    quic_der_digits
    lea     -1(%rax), %r12
    cmp     $11, %r12
    ja      8f
    inc     %r12
    lea     2(%rbx), %rdi                   /* DD */
    mov     $2, %esi
    call    quic_der_digits
    lea     -1(%rax), %r13
    cmp     $30, %r13
    ja      8f
    inc     %r13
    lea     4(%rbx), %rdi                   /* HH */
    mov     $2, %esi
    call    quic_der_digits
    cmp     $23, %rax
    ja      8f
    imul    $3600, %rax, %rax
    mov     %rax, X23(%rsp)
    lea     6(%rbx), %rdi                   /* MM */
    mov     $2, %esi
    call    quic_der_digits
    cmp     $59, %rax
    ja      8f
    imul    $60, %rax, %rax
    add     %rax, X23(%rsp)
    lea     8(%rbx), %rdi                   /* SS */
    mov     $2, %esi
    call    quic_der_digits
    cmp     $60, %rax
    ja      8f
    add     %rax, X23(%rsp)
    /* Days from 1970-01-01 (H. Hinnant's days_from_civil), for years 0 and later. */
    cmp     $2, %r12
    ja      4f
    dec     %rbp                            /* y */
4:  mov     %rbp, %rax
    xor     %edx, %edx
    mov     $400, %ecx
    div     %rcx
    mov     %rax, %r8                       /* era */
    mov     %rdx, %r9                       /* yoe */
    lea     9(%r12), %rax
    xor     %edx, %edx
    mov     $12, %ecx
    div     %rcx                            /* rdx: mp = (m + 9) mod 12 */
    imul    $153, %rdx, %rax
    add     $2, %rax
    xor     %edx, %edx
    mov     $5, %ecx
    div     %rcx
    add     %r13, %rax
    dec     %rax                            /* doy */
    mov     %rax, %r10
    imul    $365, %r9, %r11
    mov     %r9, %rax
    shr     $2, %rax
    add     %rax, %r11
    mov     %r9, %rax
    xor     %edx, %edx
    mov     $100, %ecx
    div     %rcx
    sub     %rax, %r11
    add     %r10, %r11                      /* doe */
    imul    $146097, %r8, %rax
    add     %r11, %rax
    sub     $719468, %rax                   /* days, signed */
    imul    $86400, %rax, %rax
    add     X23(%rsp), %rax
    jmp     9f
8:  mov     $-1, %rax
9:  LEAVE   0
END_FUNCTION quic_der_time

/* ---------------------------------------------------------------- ECDSA signatures in DER */

/*
 * quic_der_int_get(dst, p, end) -> the position after a DER INTEGER at p, its
 * value written as 32 bytes big endian at dst; 0 when it is not a positive
 * INTEGER of at most 32 bytes of value. rbx dst, rbp the value, r12 the end, r13 its length.
 */
LOCAL_FUNCTION quic_der_int_get
    ENTER   0
    mov     %rdi, %rbx
    mov     %rdx, %rax
    sub     %rsi, %rax
    cmp     $2, %rax
    jb      8f
    cmpb    $2, (%rsi)
    jne     8f
    movzbl  1(%rsi), %ecx
    lea     2(%rsi), %rbp
    sub     $2, %rax
    cmp     %rax, %rcx
    ja      8f
    test    %rcx, %rcx
    jz      8f
    testb   $0x80, (%rbp)
    jnz     8f
    lea     (%rbp,%rcx), %r12
1:  cmp     $32, %rcx
    jbe     2f
    cmpb    $0, (%rbp)
    jne     8f
    inc     %rbp
    dec     %rcx
    jmp     1b
2:  mov     %rcx, %r13
    mov     %rbx, %rdi
    mov     $32, %esi
    call    quic_zero
    mov     $32, %edi
    sub     %r13, %rdi
    add     %rbx, %rdi
    mov     %rbp, %rsi
    mov     %r13, %rdx
    call    quic_copy
    mov     %r12, %rax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_der_int_get

/*
 * quic_der_sig_get(sig, p, n) -> 1 when the n bytes at p are a DER SEQUENCE of
 * two positive INTEGERs r and s, written as 64 bytes big endian at sig;
 * else 0. The length of the SEQUENCE is at most 127.
 */
LOCAL_FUNCTION quic_der_sig_get
    ENTER   0
    mov     %rdi, %rbx
    lea     (%rsi,%rdx), %rbp
    cmp     $8, %rdx
    jb      8f
    cmpb    $0x30, (%rsi)
    jne     8f
    movzbl  1(%rsi), %eax
    lea     -2(%rdx), %rcx
    cmp     %rcx, %rax
    jne     8f
    add     $2, %rsi
    mov     %rbx, %rdi
    mov     %rbp, %rdx
    call    quic_der_int_get
    test    %rax, %rax
    jz      8f
    mov     %rax, %rsi
    lea     32(%rbx), %rdi
    mov     %rbp, %rdx
    call    quic_der_int_get
    cmp     %rbp, %rax
    jne     8f
    mov     $1, %eax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_der_sig_get

/* quic_der_int_put(dst, src) -> dst after a DER INTEGER of the 32-byte big-endian number at src. */
LOCAL_FUNCTION quic_der_int_put
    ENTER   0
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     $32, %r12d
1:  cmp     $1, %r12
    jbe     2f
    cmpb    $0, (%rbp)
    jne     2f
    inc     %rbp
    dec     %r12
    jmp     1b
2:  movzbl  (%rbp), %eax
    shr     $7, %eax
    movb    $2, (%rbx)
    lea     (%r12,%rax), %ecx
    movb    %cl, 1(%rbx)
    lea     2(%rbx), %rdi
    test    %eax, %eax
    jz      3f
    movb    $0, (%rdi)
    inc     %rdi
3:  mov     %rbp, %rsi
    mov     %r12, %rdx
    call    quic_copy
    LEAVE   0
END_FUNCTION quic_der_int_put

/* quic_der_sig_put(dst, sig) -> the length of the DER SEQUENCE of r and s (64 bytes big endian at sig). */
LOCAL_FUNCTION quic_der_sig_put
    ENTER   0
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    lea     2(%rbx), %rdi
    call    quic_der_int_put
    mov     %rax, %rdi
    lea     32(%rbp), %rsi
    call    quic_der_int_put
    sub     %rbx, %rax
    movb    $0x30, (%rbx)
    lea     -2(%rax), %ecx
    movb    %cl, 1(%rbx)
    LEAVE   0
END_FUNCTION quic_der_sig_put

/*
 * quic_low_s(s): when the 32-byte big-endian s is above n / 2 of secp256k1,
 * replaces it with n - s. A leaf. rax, rcx, rdx, rsi s as big-endian limbs,
 * most significant first.
 */
LOCAL_FUNCTION quic_low_s
    UNWIND_END_PROLOGUE
    mov     (%rdi), %rax
    mov     8(%rdi), %rcx
    mov     16(%rdi), %rdx
    mov     24(%rdi), %rsi
    bswap   %rax
    bswap   %rcx
    bswap   %rdx
    bswap   %rsi
    /* n / 2 = 7FFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 5D576E73 57A4501D DFE92F46 681B20A0 */
    movabs  $0x7FFFFFFFFFFFFFFF, %r8
    cmp     %r8, %rax
    ja      1f
    jb      9f
    cmp     $-1, %rcx
    jb      9f
    movabs  $0x5D576E7357A4501D, %r8
    cmp     %r8, %rdx
    ja      1f
    jb      9f
    movabs  $0xDFE92F46681B20A0, %r8
    cmp     %r8, %rsi
    jbe     9f
1:  /* s = n - s, with n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141 */
    movabs  $0xBFD25E8CD0364141, %r8
    movabs  $0xBAAEDCE6AF48A03B, %r9
    mov     $-2, %r10
    mov     $-1, %r11
    sub     %rsi, %r8
    sbb     %rdx, %r9
    sbb     %rcx, %r10
    sbb     %rax, %r11
    bswap   %r11
    bswap   %r10
    bswap   %r9
    bswap   %r8
    mov     %r11, (%rdi)
    mov     %r10, 8(%rdi)
    mov     %r9, 16(%rdi)
    mov     %r8, 24(%rdi)
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
 * Ed25519, else 0. r13 the context; rbx the result, rbp the end.
 */
LOCAL_FUNCTION quic_cert_alg
    ENTER   0
    mov     %rsi, %rbp
    lea     X_TLV2(%r13), %rdx
    mov     $0x06, %ecx
    call    quic_der_take
    test    %rax, %rax
    jz      8f
    cmp     %rbp, %rax
    jne     8f
    mov     (X_TLV2 + 8)(%r13), %rdi
    mov     %rbp, %rsi
    sub     %rdi, %rsi
    lea     410f(%rip), %rdx
    mov     $8, %ecx
    call    quic_bytes_is
    mov     $QUIC_CERT_P256, %ebx
    test    %rax, %rax
    jnz     7f
    mov     (X_TLV2 + 8)(%r13), %rdi
    mov     %rbp, %rsi
    sub     %rdi, %rsi
    lea     411f(%rip), %rdx
    mov     $3, %ecx
    call    quic_bytes_is
    mov     $QUIC_CERT_ED25519, %ebx
    test    %rax, %rax
    jnz     7f
8:  xor     %eax, %eax
    jmp     9f
7:  mov     %rbx, %rax
9:  LEAVE   0
END_FUNCTION quic_cert_alg

/*
 * quic_cert_spki(p, end) -> 1 when the SubjectPublicKeyInfo content at p is a
 * P-256 key (id-ecPublicKey, prime256v1, 65 bytes from 0x04) or an Ed25519
 * key (32 bytes); X_KIND and X_KEYP get its kind and bytes. Else 0.
 * r13 the context; rbx the end, rbp the end of the AlgorithmIdentifier,
 * X23 after it, X24 after the OID, X25 the kind, X26 the BIT STRING length.
 */
LOCAL_FUNCTION quic_cert_spki
    ENTER   0
    mov     %rsi, %rbx
    lea     X_TLV(%r13), %rdx
    mov     $0x30, %ecx
    call    quic_der_take
    test    %rax, %rax
    jz      8f
    mov     %rax, X23(%rsp)                 /* after the AlgorithmIdentifier */
    mov     (X_TLV + 8)(%r13), %rdi
    mov     (X_TLV + 16)(%r13), %rbp
    mov     %rbp, %rsi
    lea     X_TLV(%r13), %rdx
    mov     $0x06, %ecx
    call    quic_der_take
    test    %rax, %rax
    jz      8f
    mov     %rax, X24(%rsp)                 /* after the OID */
    mov     (X_TLV + 8)(%r13), %rdi
    mov     (X_TLV + 16)(%r13), %rsi
    sub     %rdi, %rsi
    lea     412f(%rip), %rdx
    mov     $7, %ecx
    call    quic_bytes_is
    test    %rax, %rax
    jnz     1f
    mov     (X_TLV + 8)(%r13), %rdi
    mov     (X_TLV + 16)(%r13), %rsi
    sub     %rdi, %rsi
    lea     411f(%rip), %rdx
    mov     $3, %ecx
    call    quic_bytes_is
    test    %rax, %rax
    jz      8f
    cmp     %rbp, X24(%rsp)                 /* Ed25519: no parameters */
    jne     8f
    movq    $QUIC_CERT_ED25519, X25(%rsp)
    movq    $33, X26(%rsp)
    jmp     2f
1:  mov     X24(%rsp), %rdi                 /* id-ecPublicKey: the curve */
    mov     %rbp, %rsi
    lea     X_TLV(%r13), %rdx
    mov     $0x06, %ecx
    call    quic_der_take
    cmp     %rbp, %rax
    jne     8f
    mov     (X_TLV + 8)(%r13), %rdi
    mov     %rbp, %rsi
    sub     %rdi, %rsi
    lea     413f(%rip), %rdx
    mov     $8, %ecx
    call    quic_bytes_is
    test    %rax, %rax
    jz      8f
    movq    $QUIC_CERT_P256, X25(%rsp)
    movq    $66, X26(%rsp)
2:  mov     X23(%rsp), %rdi                 /* the BIT STRING */
    mov     %rbx, %rsi
    lea     X_TLV(%r13), %rdx
    mov     $0x03, %ecx
    call    quic_der_take
    cmp     %rbx, %rax
    jne     8f
    mov     (X_TLV + 8)(%r13), %rax
    mov     (X_TLV + 16)(%r13), %rcx
    sub     %rax, %rcx
    cmp     X26(%rsp), %rcx
    jne     8f
    cmpb    $0, (%rax)                      /* no unused bits */
    jne     8f
    inc     %rax
    cmpq    $QUIC_CERT_P256, X25(%rsp)
    jne     3f
    cmpb    $4, (%rax)
    jne     8f
3:  mov     X25(%rsp), %rcx
    mov     %rcx, X_KIND(%r13)
    mov     %rax, X_KEYP(%r13)
    mov     $1, %eax
    jmp     9f
8:  xor     %eax, %eax
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
    cmp     $3, %rsi
    jne     8f
    cmpb    $0x55, (%rdi)
    jne     8f
    cmpb    $0x1D, 1(%rdi)
    jne     8f
    movzbl  2(%rdi), %ecx
    cmp     $0x25, %ecx
    ja      8f
    mov     $1, %eax
    shl     %cl, %rax
    movabs  $((1 << 0x0E) | (1 << 0x0F) | (1 << 0x11) | (1 << 0x13) | (1 << 0x23) | (1 << 0x25)), %rdx
    and     %rdx, %rax
    setnz   %al
    movzbl  %al, %eax
    ret
8:  xor     %eax, %eax
    ret
END_FUNCTION quic_ext_understood

/*
 * quic_cert_exts(p, end) -> 1 when the Extensions content at p is a SEQUENCE
 * of Extension elements with one libp2p extension (X_EXT, X_EXT_END) and no
 * other critical extension that go-libp2p does not understand; else 0.
 * r13 the context. rbx the end of the list, rbp the position, X23 the end of
 * one Extension, X24 critical.
 */
LOCAL_FUNCTION quic_cert_exts
    ENTER   0
    lea     X_TLV(%r13), %rdx
    mov     $0x30, %ecx
    call    quic_der_take
    test    %rax, %rax
    jz      8f
    mov     (X_TLV + 8)(%r13), %rbp
    mov     (X_TLV + 16)(%r13), %rbx
1:  cmp     %rbx, %rbp
    jae     5f
    mov     %rbp, %rdi
    mov     %rbx, %rsi
    lea     X_TLV(%r13), %rdx
    mov     $0x30, %ecx
    call    quic_der_take
    test    %rax, %rax
    jz      8f
    mov     %rax, X23(%rsp)
    mov     (X_TLV + 8)(%r13), %rdi
    mov     %rax, %rsi
    lea     X_TLV2(%r13), %rdx
    mov     $0x06, %ecx
    call    quic_der_take
    test    %rax, %rax
    jz      8f
    mov     %rax, %rbp                      /* after the OID */
    movq    $0, X24(%rsp)
    mov     %rbp, %rdi
    mov     X23(%rsp), %rsi
    lea     X_TLV(%r13), %rdx
    call    quic_der_next
    test    %rax, %rax
    jz      8f
    mov     X_TLV(%r13), %rax
    cmp     $0x01, %rax                     /* critical BOOLEAN */
    jne     2f
    mov     (X_TLV + 8)(%r13), %rcx
    mov     (X_TLV + 16)(%r13), %rdx
    mov     %rdx, %rax
    sub     %rcx, %rax
    cmp     $1, %rax
    jne     8f
    movzbl  (%rcx), %eax
    mov     %rax, X24(%rsp)
    mov     %rdx, %rbp
    mov     %rbp, %rdi
    mov     X23(%rsp), %rsi
    lea     X_TLV(%r13), %rdx
    call    quic_der_next
    test    %rax, %rax
    jz      8f
    mov     X_TLV(%r13), %rax
2:  cmp     $0x04, %rax                     /* extnValue */
    jne     8f
    mov     X23(%rsp), %rax
    cmp     %rax, (X_TLV + 16)(%r13)
    jne     8f
    mov     (X_TLV2 + 8)(%r13), %rdi
    mov     (X_TLV2 + 16)(%r13), %rsi
    sub     %rdi, %rsi
    lea     414f(%rip), %rdx
    mov     $10, %ecx
    call    quic_bytes_is
    test    %rax, %rax
    jz      3f
    cmpq    $0, X_EXT(%r13)
    jne     8f                              /* two libp2p extensions */
    mov     (X_TLV + 8)(%r13), %rax
    mov     (X_TLV + 16)(%r13), %rcx
    mov     %rax, X_EXT(%r13)
    mov     %rcx, X_EXT_END(%r13)
    jmp     4f
3:  cmpq    $0, X24(%rsp)                   /* a critical extension: one go-libp2p understands */
    je      4f
    mov     (X_TLV2 + 8)(%r13), %rdi
    mov     (X_TLV2 + 16)(%r13), %rsi
    sub     %rdi, %rsi
    call    quic_ext_understood
    test    %rax, %rax
    jz      8f
4:  mov     X23(%rsp), %rbp
    jmp     1b
5:  mov     $1, %eax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_cert_exts

/*
 * quic_pb_key(p, n) -> 1 when the n bytes at p are a PublicKey protobuf: Type
 * (field 1, a varint below 128) and Data (field 2, below 128 bytes), each
 * once; X_HOST_TYPE, X_HOST_DATA and X_HOST_LEN get them. Else 0. A leaf.
 * r13 the context.
 */
LOCAL_FUNCTION quic_pb_key
    UNWIND_END_PROLOGUE
    lea     (%rdi,%rsi), %rsi               /* end */
    xor     %r8d, %r8d                      /* fields seen */
1:  cmp     %rsi, %rdi
    jae     5f
    movzbl  (%rdi), %eax
    inc     %rdi
    cmp     $0x08, %eax
    jne     2f
    test    $1, %r8d
    jnz     8f
    cmp     %rsi, %rdi
    jae     8f
    movzbl  (%rdi), %ecx
    inc     %rdi
    test    $0x80, %ecx
    jnz     8f
    mov     %rcx, X_HOST_TYPE(%r13)
    or      $1, %r8d
    jmp     1b
2:  cmp     $0x12, %eax
    jne     8f
    test    $2, %r8d
    jnz     8f
    cmp     %rsi, %rdi
    jae     8f
    movzbl  (%rdi), %ecx
    inc     %rdi
    test    $0x80, %ecx
    jnz     8f
    mov     %rsi, %rdx
    sub     %rdi, %rdx
    cmp     %rcx, %rdx
    jb      8f
    mov     %rdi, X_HOST_DATA(%r13)
    mov     %rcx, X_HOST_LEN(%r13)
    add     %rcx, %rdi
    or      $2, %r8d
    jmp     1b
5:  cmp     $3, %r8d
    jne     8f
    mov     $1, %eax
    ret
8:  xor     %eax, %eax
    ret
END_FUNCTION quic_pb_key

/*
 * quic_cert_selfsig() -> 1 when the signature of the certificate verifies
 * with its own key: ECDSA P-256 over the SHA-256 of tbsCertificate, or
 * Ed25519 over tbsCertificate. r12 the work area, r13 the context; rbx the length.
 */
LOCAL_FUNCTION quic_cert_selfsig
    ENTER   0
    mov     X_TBS(%r13), %rsi
    mov     X_TBS_END(%r13), %rbx
    sub     %rsi, %rbx
    BYTELIST %r12, CW_TBS, (QUIC_BL_FIXED + QUIC_CERT_MAX), %rbx
    lea     (CW_TBS + QUIC_BL_FIXED)(%r12), %rdi
    mov     %rbx, %rdx
    call    quic_copy
    cmpq    $QUIC_CERT_ED25519, X_KIND(%r13)
    jne     1f
    cmpq    $64, X_SIG_LEN(%r13)
    jne     8f
    lea     CW_SIG(%r12), %rdi
    mov     X_SIG(%r13), %rsi
    mov     $64, %edx
    call    quic_copy
    lea     CW_KEY(%r12), %rdi
    mov     X_KEYP(%r13), %rsi
    mov     $32, %edx
    call    quic_copy
    lea     CW_KEY(%r12), %rdi
    lea     CW_TBS(%r12), %rsi
    lea     CW_SIG(%r12), %rdx
    lea     CW_VALID(%r12), %rcx
    CALL_GLOBAL crypto_ed25519_verify
    jmp     2f
1:  lea     CW_SIG(%r12), %rdi
    mov     X_SIG(%r13), %rsi
    mov     X_SIG_LEN(%r13), %rdx
    call    quic_der_sig_get
    test    %rax, %rax
    jz      8f
    lea     CW_TBS(%r12), %rdi
    lea     CW_HASH(%r12), %rsi
    CALL_GLOBAL crypto_sha256
    lea     CW_KEY(%r12), %rdi
    mov     X_KEYP(%r13), %rsi
    mov     $65, %edx
    call    quic_copy
    lea     CW_KEY(%r12), %rdi
    lea     CW_HASH(%r12), %rsi
    lea     CW_SIG(%r12), %rdx
    lea     CW_VALID(%r12), %rcx
    CALL_GLOBAL crypto_p256_verify
2:  test    %rax, %rax
    jnz     8f
    mov     CW_VALID(%r12), %rax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_cert_selfsig

/*
 * quic_host_verify() -> 1 when the SignedKey of the libp2p extension holds a
 * PublicKey of type Ed25519, Secp256k1 or ECDSA (P-256), and its signature of
 * "libp2p-tls-handshake:" || the SubjectPublicKeyInfo of the certificate
 * verifies with that key: Ed25519 over the message; ECDSA over its SHA-256,
 * in DER, a secp256k1 s above n / 2 taken as n - s. r12 the work area,
 * r13 the context. rbx the SignedKey end, rbp the message length, X23 the SPKI length.
 */
LOCAL_FUNCTION quic_host_verify
    ENTER   0
    mov     X_EXT(%r13), %rdi
    mov     X_EXT_END(%r13), %rsi
    lea     X_TLV(%r13), %rdx
    mov     $0x30, %ecx
    call    quic_der_take
    cmp     X_EXT_END(%r13), %rax
    jne     8f
    mov     (X_TLV + 8)(%r13), %rdi
    mov     (X_TLV + 16)(%r13), %rbx
    mov     %rbx, %rsi
    lea     X_TLV2(%r13), %rdx
    mov     $0x04, %ecx
    call    quic_der_take
    test    %rax, %rax
    jz      8f
    mov     %rax, %rbp
    mov     (X_TLV2 + 8)(%r13), %rax
    mov     (X_TLV2 + 16)(%r13), %rcx
    sub     %rax, %rcx
    mov     %rax, X_PROTO(%r13)
    mov     %rcx, X_PROTO_LEN(%r13)
    cmp     $QUIC_HOST_MAX, %rcx
    ja      8f
    mov     %rbp, %rdi
    mov     %rbx, %rsi
    lea     X_TLV2(%r13), %rdx
    mov     $0x04, %ecx
    call    quic_der_take
    cmp     %rbx, %rax
    jne     8f
    mov     (X_TLV2 + 8)(%r13), %rax
    mov     (X_TLV2 + 16)(%r13), %rcx
    sub     %rax, %rcx
    mov     %rax, X_HSIG(%r13)
    mov     %rcx, X_HSIG_LEN(%r13)
    mov     X_PROTO(%r13), %rdi
    mov     X_PROTO_LEN(%r13), %rsi
    call    quic_pb_key
    test    %rax, %rax
    jz      8f
    /* The message: "libp2p-tls-handshake:" || SubjectPublicKeyInfo. */
    mov     X_SPKI_END(%r13), %rax
    sub     X_SPKI(%r13), %rax
    mov     %rax, X23(%rsp)
    lea     21(%rax), %rbp
    lea     CW_MSG(%r12), %rax
    BYTELIST %rax, 0, 152, %rbp
    lea     (CW_MSG + QUIC_BL_FIXED)(%r12), %rdi
    lea     415f(%rip), %rsi
    mov     $21, %edx
    call    quic_copy
    mov     %rax, %rdi
    mov     X_SPKI(%r13), %rsi
    mov     X23(%rsp), %rdx
    call    quic_copy
    cmpq    $QUIC_KEY_ED25519, X_HOST_TYPE(%r13)
    jne     1f
    cmpq    $32, X_HOST_LEN(%r13)
    jne     8f
    cmpq    $64, X_HSIG_LEN(%r13)
    jne     8f
    lea     CW_SIG(%r12), %rdi
    mov     X_HSIG(%r13), %rsi
    mov     $64, %edx
    call    quic_copy
    lea     CW_KEY(%r12), %rdi
    mov     X_HOST_DATA(%r13), %rsi
    mov     $32, %edx
    call    quic_copy
    lea     CW_KEY(%r12), %rdi
    lea     CW_MSG(%r12), %rsi
    lea     CW_SIG(%r12), %rdx
    lea     CW_VALID(%r12), %rcx
    CALL_GLOBAL crypto_ed25519_verify
    jmp     5f
1:  lea     CW_SIG(%r12), %rdi              /* ECDSA: the DER signature */
    mov     X_HSIG(%r13), %rsi
    mov     X_HSIG_LEN(%r13), %rdx
    call    quic_der_sig_get
    test    %rax, %rax
    jz      8f
    lea     CW_MSG(%r12), %rdi
    lea     CW_HASH(%r12), %rsi
    CALL_GLOBAL crypto_sha256
    cmpq    $QUIC_KEY_SECP256K1, X_HOST_TYPE(%r13)
    jne     2f
    cmpq    $33, X_HOST_LEN(%r13)
    jne     8f
    lea     (CW_SIG + 32)(%r12), %rdi
    call    quic_low_s
    lea     CW_KEY(%r12), %rdi
    mov     X_HOST_DATA(%r13), %rsi
    mov     $33, %edx
    call    quic_copy
    lea     CW_KEY(%r12), %rdi
    lea     CW_HASH(%r12), %rsi
    lea     CW_SIG(%r12), %rdx
    lea     CW_VALID(%r12), %rcx
    CALL_GLOBAL crypto_secp256k1_verify
    jmp     5f
2:  cmpq    $QUIC_KEY_ECDSA, X_HOST_TYPE(%r13)
    jne     8f
    /* An ECDSA host key: a P-256 SubjectPublicKeyInfo, read with the SPKI steps. */
    mov     X_KIND(%r13), %rax
    mov     X_KEYP(%r13), %rcx
    mov     %rax, X_SAVE_KIND(%r13)
    mov     %rcx, X_SAVE_KEYP(%r13)
    mov     X_HOST_DATA(%r13), %rdi
    mov     X_HOST_LEN(%r13), %rsi
    add     %rdi, %rsi
    lea     X_TLV2(%r13), %rdx
    mov     $0x30, %ecx
    call    quic_der_take
    mov     X_HOST_DATA(%r13), %rcx
    add     X_HOST_LEN(%r13), %rcx
    cmp     %rcx, %rax
    jne     7f
    mov     (X_TLV2 + 8)(%r13), %rdi
    mov     (X_TLV2 + 16)(%r13), %rsi
    call    quic_cert_spki
    test    %rax, %rax
    jz      7f
    cmpq    $QUIC_CERT_P256, X_KIND(%r13)
    jne     7f
    lea     CW_KEY(%r12), %rdi
    mov     X_KEYP(%r13), %rsi
    mov     $65, %edx
    call    quic_copy
    mov     X_SAVE_KIND(%r13), %rax
    mov     X_SAVE_KEYP(%r13), %rcx
    mov     %rax, X_KIND(%r13)
    mov     %rcx, X_KEYP(%r13)
    lea     CW_KEY(%r12), %rdi
    lea     CW_HASH(%r12), %rsi
    lea     CW_SIG(%r12), %rdx
    lea     CW_VALID(%r12), %rcx
    CALL_GLOBAL crypto_p256_verify
    jmp     5f
7:  mov     X_SAVE_KIND(%r13), %rax
    mov     X_SAVE_KEYP(%r13), %rcx
    mov     %rax, X_KIND(%r13)
    mov     %rcx, X_KEYP(%r13)
    jmp     8f
5:  test    %rax, %rax
    jnz     8f
    mov     CW_VALID(%r12), %rax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_host_verify

/*
 * quic_cert_check(cert, len, now, info, work) -> QUIC_OK when the DER
 * certificate of len bytes meets the libp2p TLS spec at Unix time now, with
 * info filled; else QUIC_INVALID_CERT. work: CW_SIZE bytes at a multiple of 8.
 * rbx the certificate, rbp its end, X23 now, X24 info, r12 work, r13 the
 * context, X25 the position, X26 the tbsCertificate end.
 */
LOCAL_FUNCTION quic_cert_check
    ENTER   0
    mov     %rdi, %rbx
    lea     (%rdi,%rsi), %rbp
    mov     %rdx, X23(%rsp)
    mov     %rcx, X24(%rsp)
    mov     %r8, %r12
    lea     CW_CTX(%r12), %r13
    cmp     $QUIC_CERT_MAX, %rsi
    ja      8f
    mov     %r13, %rdi
    mov     $X_SIZE, %esi
    call    quic_zero
    /* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue } */
    mov     %rbx, %rdi
    mov     %rbp, %rsi
    lea     X_TLV(%r13), %rdx
    mov     $0x30, %ecx
    call    quic_der_take
    cmp     %rbp, %rax
    jne     8f
    mov     (X_TLV + 8)(%r13), %rdi
    mov     %rdi, X_TBS(%r13)
    mov     %rbp, %rsi
    lea     X_TLV2(%r13), %rdx
    mov     $0x30, %ecx
    call    quic_der_take
    test    %rax, %rax
    jz      8f
    mov     %rax, X_TBS_END(%r13)
    mov     (X_TLV2 + 8)(%r13), %rcx        /* the tbsCertificate content */
    mov     (X_TLV2 + 16)(%r13), %rdx
    mov     %rcx, X_POS(%r13)
    mov     %rdx, X_END(%r13)
    mov     %rax, %rdi
    mov     %rbp, %rsi
    lea     X_TLV(%r13), %rdx
    mov     $0x30, %ecx
    call    quic_der_take
    test    %rax, %rax
    jz      8f
    mov     %rax, X25(%rsp)
    mov     (X_TLV + 8)(%r13), %rdi
    mov     (X_TLV + 16)(%r13), %rsi
    call    quic_cert_alg
    test    %rax, %rax
    jz      8f
    mov     %rax, X_SIGALG(%r13)
    mov     X25(%rsp), %rdi
    mov     %rbp, %rsi
    lea     X_TLV(%r13), %rdx
    mov     $0x03, %ecx
    call    quic_der_take
    cmp     %rbp, %rax
    jne     8f
    mov     (X_TLV + 8)(%r13), %rax
    mov     (X_TLV + 16)(%r13), %rcx
    cmp     %rcx, %rax
    jae     8f
    cmpb    $0, (%rax)
    jne     8f
    inc     %rax
    sub     %rax, %rcx
    mov     %rax, X_SIG(%r13)
    mov     %rcx, X_SIG_LEN(%r13)
    /* tbsCertificate */
    mov     X_POS(%r13), %rax
    mov     %rax, X25(%rsp)
    mov     X_END(%r13), %rax
    mov     %rax, X26(%rsp)
    mov     X25(%rsp), %rdi
    mov     X26(%rsp), %rsi
    lea     X_TLV(%r13), %rdx
    call    quic_der_next
    test    %rax, %rax
    jz      8f
    cmpq    $0xA0, X_TLV(%r13)              /* version, optional */
    jne     1f
    mov     (X_TLV + 16)(%r13), %rax
    mov     %rax, X25(%rsp)
1:  mov     X25(%rsp), %rdi                 /* serialNumber */
    mov     X26(%rsp), %rsi
    lea     X_TLV(%r13), %rdx
    mov     $0x02, %ecx
    call    quic_der_take
    test    %rax, %rax
    jz      8f
    mov     %rax, %rdi                      /* signature */
    mov     X26(%rsp), %rsi
    lea     X_TLV(%r13), %rdx
    mov     $0x30, %ecx
    call    quic_der_take
    test    %rax, %rax
    jz      8f
    mov     %rax, %rdi                      /* issuer */
    mov     X26(%rsp), %rsi
    lea     X_TLV(%r13), %rdx
    mov     $0x30, %ecx
    call    quic_der_take
    test    %rax, %rax
    jz      8f
    mov     %rax, %rdi                      /* validity */
    mov     X26(%rsp), %rsi
    lea     X_TLV2(%r13), %rdx
    mov     $0x30, %ecx
    call    quic_der_take
    test    %rax, %rax
    jz      8f
    mov     %rax, X25(%rsp)
    mov     (X_TLV2 + 8)(%r13), %rdi
    mov     (X_TLV2 + 16)(%r13), %rsi
    lea     X_TLV(%r13), %rdx
    call    quic_der_next
    test    %rax, %rax
    jz      8f
    mov     X_TLV(%r13), %rdi
    mov     (X_TLV + 8)(%r13), %rsi
    mov     (X_TLV + 16)(%r13), %rdx
    sub     %rsi, %rdx
    call    quic_der_time
    cmp     $-1, %rax
    je      8f
    cmp     %rax, X23(%rsp)                 /* not before */
    jl      8f
    mov     (X_TLV + 16)(%r13), %rdi
    mov     (X_TLV2 + 16)(%r13), %rsi
    lea     X_TLV(%r13), %rdx
    call    quic_der_next
    test    %rax, %rax
    jz      8f
    mov     (X_TLV + 16)(%r13), %rax
    cmp     (X_TLV2 + 16)(%r13), %rax
    jne     8f
    mov     X_TLV(%r13), %rdi
    mov     (X_TLV + 8)(%r13), %rsi
    mov     (X_TLV + 16)(%r13), %rdx
    sub     %rsi, %rdx
    call    quic_der_time
    cmp     $-1, %rax
    je      8f
    cmp     X23(%rsp), %rax                 /* not after */
    jl      8f
    mov     X25(%rsp), %rdi                 /* subject */
    mov     X26(%rsp), %rsi
    lea     X_TLV(%r13), %rdx
    mov     $0x30, %ecx
    call    quic_der_take
    test    %rax, %rax
    jz      8f
    mov     %rax, X25(%rsp)
    mov     %rax, X_SPKI(%r13)              /* subjectPublicKeyInfo */
    mov     %rax, %rdi
    mov     X26(%rsp), %rsi
    lea     X_TLV2(%r13), %rdx
    mov     $0x30, %ecx
    call    quic_der_take
    test    %rax, %rax
    jz      8f
    mov     %rax, X_SPKI_END(%r13)
    mov     %rax, X25(%rsp)
    mov     (X_TLV2 + 8)(%r13), %rdi
    mov     (X_TLV2 + 16)(%r13), %rsi
    call    quic_cert_spki
    test    %rax, %rax
    jz      8f
2:  mov     X25(%rsp), %rax                 /* issuerUniqueID, subjectUniqueID, extensions */
    cmp     X26(%rsp), %rax
    jae     3f
    mov     %rax, %rdi
    mov     X26(%rsp), %rsi
    lea     X_TLV2(%r13), %rdx
    call    quic_der_next
    test    %rax, %rax
    jz      8f
    cmpq    $0xA3, X_TLV2(%r13)
    jne     8f
    cmpq    $0, X_EXT(%r13)
    jne     8f
    mov     (X_TLV2 + 8)(%r13), %rdi
    mov     (X_TLV2 + 16)(%r13), %rsi
    mov     %rsi, X25(%rsp)                 /* after the extensions */
    call    quic_cert_exts
    test    %rax, %rax
    jz      8f
    cmpq    $0, X_EXT(%r13)
    je      8f
    jmp     2b
3:  cmpq    $0, X_EXT(%r13)
    je      8f
    mov     X_KIND(%r13), %rax
    cmp     X_SIGALG(%r13), %rax
    jne     8f
    call    quic_cert_selfsig
    test    %rax, %rax
    jz      8f
    call    quic_host_verify
    test    %rax, %rax
    jz      8f
    /* CertInfo */
    mov     X24(%rsp), %rdi
    add     $8, %rdi
    mov     $(QUIC_CI_FIXED - 8), %esi
    call    quic_zero
    mov     X24(%rsp), %rbx
    mov     X_KIND(%r13), %rax
    mov     %rax, QUIC_CI_KIND(%rbx)
    lea     QUIC_CI_KEY(%rbx), %rdi
    mov     X_KEYP(%r13), %rsi
    mov     $32, %edx
    cmp     $QUIC_CERT_P256, %rax
    jne     4f
    mov     $65, %edx
4:  call    quic_copy
    mov     X_PROTO_LEN(%r13), %rdx
    mov     %rdx, QUIC_CI_HOST_LEN(%rbx)
    lea     QUIC_CI_HOST(%rbx), %rdi
    mov     X_PROTO(%r13), %rsi
    call    quic_copy
    mov     $QUIC_OK, %eax
    jmp     9f
8:  mov     $QUIC_INVALID_CERT, %eax
9:  LEAVE   0
END_FUNCTION quic_cert_check

/*
 * quic_cert_verify(cert, now, scratch, info) -> status: quic_cert_check of a
 * ByteList certificate at the Unix time at now. The scratch: its size,
 * then the work area.
 */
FUNCTION quic_cert_verify
    ENTER   0
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     %rcx, %r13
    mov     $QUIC_BUFFER_TOO_SMALL, %eax
    cmpq    $QUIC_CERT_SCRATCH, (%r12)
    jb      9f
    cmpq    $QUIC_CI_FIXED, (%r13)
    jb      9f
    mov     QUIC_BL_OFFSET(%rbx), %rdi
    add     %rbx, %rdi
    mov     QUIC_BL_COUNT(%rbx), %rsi
    mov     (%rbp), %rdx
    mov     %r13, %rcx
    lea     8(%r12), %r8
    call    quic_cert_check
9:  LEAVE   0
END_FUNCTION quic_cert_verify

/* ---------------------------------------------------------------- Our certificate */

/*
 * quic_der_wrap(dst, tag, src, n) -> dst after one DER element: the tag, the
 * length of n (below 65536), then a copy of the n bytes at src. src does not
 * overlap dst. rbx src, rbp n.
 */
LOCAL_FUNCTION quic_der_wrap
    ENTER   0
    mov     %rdx, %rbx
    mov     %rcx, %rbp
    movb    %sil, (%rdi)
    inc     %rdi
    cmp     $128, %rbp
    jb      1f
    cmp     $256, %rbp
    jb      2f
    movb    $0x82, (%rdi)
    mov     %rbp, %rax
    shr     $8, %rax
    movb    %al, 1(%rdi)
    add     $2, %rdi
    jmp     1f
2:  movb    $0x81, (%rdi)
    inc     %rdi
1:  movb    %bpl, (%rdi)
    inc     %rdi
    mov     %rbx, %rsi
    mov     %rbp, %rdx
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
 * rbx area A, rbp area B, r12 length, r13 the key type, X23 the serial.
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
    lea     (32 + CB_A)(%rsp), %rbx
    lea     (32 + CB_B)(%rsp), %rbp
    mov     (ST_CONFIG + QUIC_CFG_KEY_TYPE)(%r15), %r13
    lea     ST_CERT_PRIV(%r15), %rdi
    lea     (32 + CB_PUB)(%rsp), %rsi
    CALL_GLOBAL crypto_p256_public_key
    /* The message the host key signs: the prefix, then the SPKI. */
    mov     $112, %eax
    lea     (32 + CB_MSG)(%rsp), %rcx
    BYTELIST %rcx, 0, 136, %rax
    lea     (32 + CB_MSG + QUIC_BL_FIXED)(%rsp), %rdi
    lea     415f(%rip), %rsi
    mov     $21, %edx
    call    quic_copy
    mov     %rax, %rdi
    lea     417f(%rip), %rsi
    mov     $26, %edx
    call    quic_copy
    mov     %rax, %rdi
    lea     (32 + CB_PUB)(%rsp), %rsi
    mov     $65, %edx
    call    quic_copy
    cmp     $QUIC_KEY_ED25519, %r13
    jne     1f
    lea     (ST_CONFIG + QUIC_CFG_KEY)(%r15), %rdi
    lea     (32 + CB_MSG)(%rsp), %rsi
    lea     (32 + CB_SIG)(%rsp), %rdx
    CALL_GLOBAL crypto_ed25519_sign
    lea     (32 + CB_DER)(%rsp), %rdi
    lea     (32 + CB_SIG)(%rsp), %rsi
    mov     $64, %edx
    call    quic_copy
    mov     $64, %r12d
    jmp     2f
1:  lea     (32 + CB_MSG)(%rsp), %rdi
    lea     (32 + CB_HASH)(%rsp), %rsi
    CALL_GLOBAL crypto_sha256
    lea     (ST_CONFIG + QUIC_CFG_KEY)(%r15), %rdi
    lea     (32 + CB_HASH)(%rsp), %rsi
    lea     (32 + CB_SIG)(%rsp), %rdx
    CALL_GLOBAL crypto_secp256k1_sign
    lea     (32 + CB_DER)(%rsp), %rdi
    lea     (32 + CB_SIG)(%rsp), %rsi
    call    quic_der_sig_put
    mov     %rax, %r12
2:  /* SignedKey ::= SEQUENCE { publicKey OCTET STRING, signature OCTET STRING } */
    mov     %rbx, %rdi
    mov     $0x04, %esi
    lea     ST_HOST_PROTO(%r15), %rdx
    mov     ST_HOST_PROTO_LEN(%r15), %rcx
    call    quic_der_wrap
    mov     %rax, %rdi
    mov     $0x04, %esi
    lea     (32 + CB_DER)(%rsp), %rdx
    mov     %r12, %rcx
    call    quic_der_wrap
    mov     %rax, %rcx
    sub     %rbx, %rcx
    mov     %rbp, %rdi
    mov     $0x30, %esi
    mov     %rbx, %rdx
    call    quic_der_wrap                   /* B: SignedKey */
    mov     %rax, %r12
    sub     %rbp, %r12
    /* Extension ::= SEQUENCE { extnID, extnValue OCTET STRING } */
    mov     %rbx, %rdi
    mov     $0x06, %esi
    lea     414f(%rip), %rdx
    mov     $10, %ecx
    call    quic_der_wrap
    mov     %rax, %rdi
    mov     $0x04, %esi
    mov     %rbp, %rdx
    mov     %r12, %rcx
    call    quic_der_wrap
    mov     %rax, %rcx
    sub     %rbx, %rcx
    mov     %rbp, %rdi
    mov     $0x30, %esi
    mov     %rbx, %rdx
    call    quic_der_wrap                   /* B: Extension */
    mov     %rax, %rcx
    sub     %rbp, %rcx
    mov     %rbx, %rdi
    mov     $0x30, %esi
    mov     %rbp, %rdx
    call    quic_der_wrap                   /* A: Extensions */
    mov     %rax, %rcx
    sub     %rbx, %rcx
    mov     %rbp, %rdi
    mov     $0xA3, %esi
    mov     %rbx, %rdx
    call    quic_der_wrap                   /* B: [3] Extensions */
    mov     %rax, %r12
    sub     %rbp, %r12
    /* tbsCertificate: the template, the serial, the key, then [3]. */
    mov     %rbx, %rdi
    lea     416f(%rip), %rsi
    mov     $5, %edx
    call    quic_copy
    movb    $0x02, (%rax)
    movb    $8, 1(%rax)
    lea     2(%rax), %rdi
    mov     %rdi, X23(%rsp)
    mov     $8, %esi
    call    quic_random
    mov     X23(%rsp), %rax
    movzbl  (%rax), %ecx
    and     $0x3F, %ecx
    or      $0x40, %ecx                     /* a positive INTEGER with no leading zero */
    movb    %cl, (%rax)
    lea     8(%rax), %rdi
    lea     418f(%rip), %rsi
    mov     $(12 + 34 + 34 + 34), %edx
    call    quic_copy
    mov     %rax, %rdi
    lea     417f(%rip), %rsi
    mov     $26, %edx
    call    quic_copy
    mov     %rax, %rdi
    lea     (32 + CB_PUB)(%rsp), %rsi
    mov     $65, %edx
    call    quic_copy
    mov     %rax, %rdi
    mov     %rbp, %rsi
    mov     %r12, %rdx
    call    quic_copy
    mov     %rax, %rcx
    sub     %rbx, %rcx
    mov     %rbp, %rdi
    mov     $0x30, %esi
    mov     %rbx, %rdx
    call    quic_der_wrap                   /* B: tbsCertificate */
    mov     %rax, %r12
    sub     %rbp, %r12
    /* signatureValue: ECDSA P-256 over the SHA-256 of tbsCertificate. */
    lea     -QUIC_BL_FIXED(%rbp), %rdi      /* a ByteList header before B: in A, unused now */
    movq    $(512 + QUIC_BL_FIXED), QUIC_BL_SIZE(%rdi)
    movq    $QUIC_BL_FIXED, QUIC_BL_OFFSET(%rdi)
    mov     %r12, QUIC_BL_COUNT(%rdi)
    lea     (32 + CB_HASH)(%rsp), %rsi
    CALL_GLOBAL crypto_sha256
    lea     ST_CERT_PRIV(%r15), %rdi
    lea     (32 + CB_HASH)(%rsp), %rsi
    lea     (32 + CB_SIG)(%rsp), %rdx
    CALL_GLOBAL crypto_p256_sign
    movb    $0, (32 + CB_DER)(%rsp)
    lea     (32 + CB_DER + 1)(%rsp), %rdi
    lea     (32 + CB_SIG)(%rsp), %rsi
    call    quic_der_sig_put
    lea     1(%rax), %r13                   /* the BIT STRING content */
    /* Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue } */
    mov     %rbx, %rdi
    mov     %rbp, %rsi
    mov     %r12, %rdx
    call    quic_copy
    mov     %rax, %rdi
    lea     418f(%rip), %rsi
    mov     $12, %edx
    call    quic_copy
    mov     %rax, %rdi
    mov     $0x03, %esi
    lea     (32 + CB_DER)(%rsp), %rdx
    mov     %r13, %rcx
    call    quic_der_wrap
    mov     %rax, %rcx
    sub     %rbx, %rcx
    lea     ST_CERT(%r15), %rdi
    mov     $0x30, %esi
    mov     %rbx, %rdx
    call    quic_der_wrap
    lea     ST_CERT(%r15), %rcx
    sub     %rcx, %rax
    mov     %rax, ST_CERT_LEN(%r15)
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
