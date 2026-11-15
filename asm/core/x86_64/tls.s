/*
 * The TLS 1.3 handshake of QUIC (RFC 8446, RFC 9001 section 4) in the libp2p
 * TLS profile: TLS_AES_128_GCM_SHA256 only, key shares x25519 and secp256r1,
 * a self-signed certificate checked with quic_cert_check, the ALPN
 * "libp2p", and client certificates required. No PSK, no 0-RTT, no session
 * tickets of our own.
 *
 * The TLS block of a connection holds the transcript and the secrets until
 * the handshake ends. Messages go out on the CRYPTO stream of their space.
 * Functions give 0, or the QUIC error code to close with: CRYPTO_ERROR
 * 0x100 + the TLS alert, or a transport error.
 * rbx the connection, rbp the TLS block, in the functions that take them.
 */

.set TLS_ERR, 0x100
.set ALERT_UNEXPECTED, 10
.set ALERT_HANDSHAKE, 40
.set ALERT_BAD_CERT, 42
.set ALERT_ILLEGAL, 47
.set ALERT_DECODE, 50
.set ALERT_DECRYPT, 51
.set ALERT_VERSION, 70
.set ALERT_INTERNAL, 80
.set ALERT_MISSING_EXT, 109
.set ALERT_CERT_REQUIRED, 116
.set ALERT_NO_ALPN, 120
.set ERR_INTERNAL, 0x01
.set ERR_TP, 0x08
.set ERR_PROTOCOL, 0x0A
.set ERR_CRYPTO_BUFFER, 0x0D

.set GROUP_X25519, 0x001D
.set GROUP_P256, 0x0017

/* ---------------------------------------------------------------- Readers */

/* quic_rd8(p, end) -> rax p + 1, or 0 past end; rdx the byte (0 past end). A leaf. */
LOCAL_FUNCTION quic_rd8
    UNWIND_END_PROLOGUE
    xor     %edx, %edx
    xor     %eax, %eax
    cmp     %rsi, %rdi
    jae     9f
    movzbl  (%rdi), %edx
    lea     1(%rdi), %rax
9:  ret
END_FUNCTION quic_rd8

/* quic_rd16(p, end) -> rax p + 2, or 0 past end; rdx the big-endian value (0 past end). A leaf. */
LOCAL_FUNCTION quic_rd16
    UNWIND_END_PROLOGUE
    xor     %edx, %edx
    xor     %eax, %eax
    mov     %rsi, %rcx
    sub     %rdi, %rcx
    cmp     %rsi, %rdi
    jae     9f
    cmp     $2, %rcx
    jb      9f
    movzwl  (%rdi), %edx
    rol     $8, %dx
    lea     2(%rdi), %rax
9:  ret
END_FUNCTION quic_rd16

/* quic_rd24(p, end) -> rax p + 3, or 0 past end; rdx the big-endian value (0 past end). A leaf. */
LOCAL_FUNCTION quic_rd24
    UNWIND_END_PROLOGUE
    xor     %edx, %edx
    xor     %eax, %eax
    mov     %rsi, %rcx
    sub     %rdi, %rcx
    cmp     %rsi, %rdi
    jae     9f
    cmp     $3, %rcx
    jb      9f
    movzbl  (%rdi), %edx
    shl     $16, %edx
    movzbl  1(%rdi), %ecx
    shl     $8, %ecx
    or      %ecx, %edx
    movzbl  2(%rdi), %ecx
    or      %ecx, %edx
    lea     3(%rdi), %rax
9:  ret
END_FUNCTION quic_rd24

/* ---------------------------------------------------------------- Transcript and key schedule */

/* quic_tls_append(msg, n) -> 0, or an error when the transcript has no room. rbp the TLS block. */
LOCAL_FUNCTION quic_tls_append
    ENTER   0
    mov     %rdi, %rbx
    mov     T_LEN(%rbp), %rax
    lea     (%rax,%rsi), %rcx
    cmp     $TRANSCRIPT_ROOM, %rcx
    ja      8f
    mov     %rcx, T_LEN(%rbp)
    lea     T_TRANSCRIPT(%rbp,%rax), %rdi
    mov     %rsi, %rdx
    mov     %rbx, %rsi
    call    quic_copy
    xor     %eax, %eax
    jmp     9f
8:  mov     $(TLS_ERR + ALERT_INTERNAL), %eax
9:  LEAVE   0
END_FUNCTION quic_tls_append

/* quic_tls_hash(): T_HASH = SHA-256 of the transcript. rbp the TLS block. */
LOCAL_FUNCTION quic_tls_hash
    ENTER   0
    lea     T_LIST(%rbp), %rdi
    lea     T_HASH(%rbp), %rsi
    CALL_GLOBAL crypto_sha256
    LEAVE   0
END_FUNCTION quic_tls_hash

/*
 * quic_hkdf_extract(salt, ikm, out): out = HKDF-Extract(salt, ikm), three
 * 32-byte values. A zero salt pointer means 32 zero bytes, and so does a zero
 * ikm pointer.
 */
.set HX_SALT, 0                         /* ByteList: 24 + 32 */
.set HX_IKM, 56                         /* ByteList: 24 + 32 */
.set HX_SCRATCH, 112                    /* HmacScratch: 160 bytes */
.set HX_FRAME, 272
LOCAL_FUNCTION quic_hkdf_extract
    ENTER   0, HX_FRAME
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     $32, %eax
    BYTELIST %rsp, (32 + HX_SALT), 56, %rax
    BYTELIST %rsp, (32 + HX_IKM), 56, %rax
    lea     (32 + HX_SALT + 24)(%rsp), %rdi
    mov     $32, %esi
    call    quic_zero
    lea     (32 + HX_IKM + 24)(%rsp), %rdi
    mov     $32, %esi
    call    quic_zero
    test    %rbx, %rbx
    jz      1f
    lea     (32 + HX_SALT + 24)(%rsp), %rdi
    mov     %rbx, %rsi
    mov     $32, %edx
    call    quic_copy
1:  test    %rbp, %rbp
    jz      2f
    lea     (32 + HX_IKM + 24)(%rsp), %rdi
    mov     %rbp, %rsi
    mov     $32, %edx
    call    quic_copy
2:  movq    $160, (32 + HX_SCRATCH)(%rsp)
    lea     (32 + HX_SALT)(%rsp), %rdi
    lea     (32 + HX_IKM)(%rsp), %rsi
    lea     (32 + HX_SCRATCH)(%rsp), %rdx
    mov     %r12, %rcx
    CALL_GLOBAL crypto_hkdf_extract
    LEAVE   0, HX_FRAME
END_FUNCTION quic_hkdf_extract

/*
 * quic_derive_secret(secret, label, label_len, out): Derive-Secret of RFC 8446
 * section 7.1 with the hash of the transcript as it is. rbp the TLS block.
 */
LOCAL_FUNCTION quic_derive_secret
    ENTER   0
    mov     %rdi, %r12
    mov     %rsi, %r13
    mov     %rdx, X23(%rsp)
    mov     %rcx, X24(%rsp)
    call    quic_tls_hash
    mov     %r12, %rdi
    mov     %r13, %rsi
    mov     X23(%rsp), %rdx
    lea     T_HASH(%rbp), %rcx
    mov     $32, %r8d
    mov     $32, %r9d
    mov     X24(%rsp), %r10
    call    quic_expand_label
    LEAVE   0
END_FUNCTION quic_derive_secret

/*
 * quic_finished_mac(secret, out): out = HMAC(finished_key, the transcript
 * hash), with finished_key = HKDF-Expand-Label(secret, "finished", "", 32).
 * rbp the TLS block.
 */
.set FM_KEY, 0                          /* ByteList: 24 + 32 */
.set FM_MSG, 56                         /* ByteList: 24 + 32 */
.set FM_SCRATCH, 112                    /* HmacScratch: 160 bytes */
.set FM_FRAME, 272
LOCAL_FUNCTION quic_finished_mac
    ENTER   0, FM_FRAME
    mov     %rdi, %r12
    mov     %rsi, %r13
    mov     $32, %eax
    BYTELIST %rsp, (32 + FM_KEY), 56, %rax
    BYTELIST %rsp, (32 + FM_MSG), 56, %rax
    mov     %r12, %rdi
    lea     608f(%rip), %rsi
    mov     $8, %edx
    xor     %ecx, %ecx
    xor     %r8d, %r8d
    mov     $32, %r9d
    lea     (32 + FM_KEY + 24)(%rsp), %r10
    call    quic_expand_label
    call    quic_tls_hash
    lea     (32 + FM_MSG + 24)(%rsp), %rdi
    lea     T_HASH(%rbp), %rsi
    mov     $32, %edx
    call    quic_copy
    movq    $160, (32 + FM_SCRATCH)(%rsp)
    lea     (32 + FM_KEY)(%rsp), %rdi
    lea     (32 + FM_MSG)(%rsp), %rsi
    lea     (32 + FM_SCRATCH)(%rsp), %rdx
    mov     %r13, %rcx
    CALL_GLOBAL crypto_hmac_sha256
    LEAVE   0, FM_FRAME
END_FUNCTION quic_finished_mac

/*
 * quic_handshake_keys(): after ServerHello: the handshake secret from the
 * shared secret, the two handshake traffic secrets, and the Handshake keys
 * of both directions. rbx the connection, rbp the TLS block.
 */
LOCAL_FUNCTION quic_handshake_keys
    ENTER   0
    lea     600f(%rip), %rdi
    lea     T_SHARED(%rbp), %rsi
    lea     T_HS_SECRET(%rbp), %rdx
    call    quic_hkdf_extract
    lea     T_HS_SECRET(%rbp), %rdi
    lea     603f(%rip), %rsi
    mov     $12, %edx
    lea     T_C_HS(%rbp), %rcx
    call    quic_derive_secret
    lea     T_HS_SECRET(%rbp), %rdi
    lea     604f(%rip), %rsi
    mov     $12, %edx
    lea     T_S_HS(%rbp), %rcx
    call    quic_derive_secret
    mov     $SPACE_HANDSHAKE, %edi
    lea     T_C_HS(%rbp), %rsi
    lea     T_S_HS(%rbp), %rdx
    call    quic_install_keys
    /* The master secret, for later. */
    lea     T_HS_SECRET(%rbp), %rdi
    lea     607f(%rip), %rsi
    mov     $7, %edx
    lea     601f(%rip), %rcx
    mov     $32, %r8d
    mov     $32, %r9d
    lea     T_MASTER(%rbp), %r10
    call    quic_expand_label
    lea     T_MASTER(%rbp), %rdi
    xor     %esi, %esi
    lea     T_MASTER(%rbp), %rdx
    call    quic_hkdf_extract
    LEAVE   0
END_FUNCTION quic_handshake_keys

/*
 * quic_app_keys(): after the server Finished is in the transcript: the
 * application traffic secrets, kept in C_APP_SECRETS, and the 1-RTT keys.
 * rbx the connection, rbp the TLS block.
 */
LOCAL_FUNCTION quic_app_keys
    ENTER   0
    lea     T_MASTER(%rbp), %rdi
    lea     605f(%rip), %rsi
    mov     $12, %edx
    lea     C_APP_SECRETS(%rbx), %rcx
    call    quic_derive_secret
    lea     T_MASTER(%rbp), %rdi
    lea     606f(%rip), %rsi
    mov     $12, %edx
    lea     (C_APP_SECRETS + 32)(%rbx), %rcx
    call    quic_derive_secret
    mov     $SPACE_APP, %edi
    lea     C_APP_SECRETS(%rbx), %rsi
    lea     (C_APP_SECRETS + 32)(%rbx), %rdx
    call    quic_install_keys
    call    quic_next_rx_keys
    LEAVE   0
END_FUNCTION quic_app_keys

/*
 * quic_install_keys(space, client_secret, server_secret): the receive and send
 * keys of a space for our role. rbx the connection. r12 the space, r13 the
 * receive secret, X23 the send secret.
 */
LOCAL_FUNCTION quic_install_keys
    ENTER   0
    imul    $SP_SIZE, %rdi, %r12
    lea     C_SPACES(%rbx,%r12), %r12
    mov     %rsi, %r13                      /* receive: the peer's secret */
    mov     %rdx, X23(%rsp)                 /* send: ours */
    cmpq    $0, C_ROLE(%rbx)
    jne     1f
    mov     %rdx, %r13
    mov     %rsi, X23(%rsp)
1:  mov     %r13, %rdi
    lea     SP_RX_KEYS(%r12), %rsi
    call    quic_derive_keys
    mov     X23(%rsp), %rdi
    lea     SP_TX_KEYS(%r12), %rsi
    call    quic_derive_keys
    orq     $(SPF_RX | SPF_TX), SP_FLAGS(%r12)
    LEAVE   0
END_FUNCTION quic_install_keys

/*
 * quic_next_rx_keys(): C_NEXT_RX = the receive keys of the next key phase:
 * the key and IV of HKDF-Expand-Label(the peer's secret, "quic ku", "", 32),
 * and the same header protection key (RFC 9001 section 6). rbx the connection.
 */
.set NK_SECRET, 0
.set NK_KEYS, 32
.set NK_FRAME, 80
LOCAL_FUNCTION quic_next_rx_keys
    ENTER   0, NK_FRAME
    lea     C_APP_SECRETS(%rbx), %rdi
    cmpq    $0, C_ROLE(%rbx)
    jne     1f
    add     $32, %rdi                       /* the peer's secret */
1:  lea     609f(%rip), %rsi
    mov     $7, %edx
    xor     %ecx, %ecx
    xor     %r8d, %r8d
    mov     $32, %r9d
    lea     (32 + NK_SECRET)(%rsp), %r10
    call    quic_expand_label
    lea     (32 + NK_SECRET)(%rsp), %rdi
    lea     C_NEXT_RX(%rbx), %rsi
    call    quic_derive_keys
    mov     (C_SPACES + 2 * SP_SIZE + SP_RX_KEYS + QUIC_KEYS_HP)(%rbx), %rax
    mov     (C_SPACES + 2 * SP_SIZE + SP_RX_KEYS + QUIC_KEYS_HP + 8)(%rbx), %rcx
    mov     %rax, (C_NEXT_RX + QUIC_KEYS_HP)(%rbx)
    mov     %rcx, (C_NEXT_RX + QUIC_KEYS_HP + 8)(%rbx)
    LEAVE   0, NK_FRAME
END_FUNCTION quic_next_rx_keys

/*
 * quic_key_update(): moves to the next key phase. The peer's secret steps
 * on: the current receive keys become the previous ones and C_NEXT_RX the
 * current ones. Our secret steps on with it, and the send keys follow. rbx the connection.
 * r12 the Application space, r13 the secret index, X23 the secret.
 */
.set KU_SECRET, 0
.set KU_FRAME, 32
LOCAL_FUNCTION quic_key_update
    ENTER   0, KU_FRAME
    lea     (C_SPACES + 2 * SP_SIZE)(%rbx), %r12
    lea     C_PREV_RX(%rbx), %rdi
    lea     SP_RX_KEYS(%r12), %rsi
    mov     $QUIC_KEYS_SIZE, %edx
    call    quic_copy
    lea     SP_RX_KEYS(%r12), %rdi
    lea     C_NEXT_RX(%rbx), %rsi
    mov     $QUIC_KEYS_SIZE, %edx
    call    quic_copy
    xor     %r13d, %r13d                    /* each secret steps: client 0, server 1 */
1:  mov     %r13, %rax
    shl     $5, %rax
    lea     C_APP_SECRETS(%rbx,%rax), %rax
    mov     %rax, X23(%rsp)
    mov     %rax, %rdi
    lea     609f(%rip), %rsi
    mov     $7, %edx
    xor     %ecx, %ecx
    xor     %r8d, %r8d
    mov     $32, %r9d
    lea     (32 + KU_SECRET)(%rsp), %r10
    call    quic_expand_label
    mov     X23(%rsp), %rdi
    lea     (32 + KU_SECRET)(%rsp), %rsi
    mov     $32, %edx
    call    quic_copy
    inc     %r13
    cmp     $2, %r13
    jb      1b
    /* The send keys from our new secret; the header protection key stays. */
    lea     C_APP_SECRETS(%rbx), %rdi
    cmpq    $0, C_ROLE(%rbx)
    je      2f
    add     $32, %rdi
2:  mov     (SP_TX_KEYS + QUIC_KEYS_HP)(%r12), %rax
    mov     (SP_TX_KEYS + QUIC_KEYS_HP + 8)(%r12), %rcx
    mov     %rax, (32 + KU_SECRET)(%rsp)
    mov     %rcx, (32 + KU_SECRET + 8)(%rsp)
    lea     SP_TX_KEYS(%r12), %rsi
    call    quic_derive_keys
    mov     (32 + KU_SECRET)(%rsp), %rax
    mov     (32 + KU_SECRET + 8)(%rsp), %rcx
    mov     %rax, (SP_TX_KEYS + QUIC_KEYS_HP)(%r12)
    mov     %rcx, (SP_TX_KEYS + QUIC_KEYS_HP + 8)(%r12)
    /* The next receive keys from the peer's new secret. */
    call    quic_next_rx_keys
    xorq    $1, C_KEY_PHASE(%rbx)
    movq    $0, C_PHASE_SENT(%rbx)
    movq    $NONE, C_PHASE_PN(%rbx)
    LEAVE   0, KU_FRAME
END_FUNCTION quic_key_update

/* ---------------------------------------------------------------- Output */

/*
 * quic_crypto_out(space, msg, n) -> 0, or an error: appends a handshake
 * message to the CRYPTO stream of the space and to the transcript.
 * rbx the connection, rbp the TLS block. r12 the space, r13 msg, X23 n.
 */
LOCAL_FUNCTION quic_crypto_out
    ENTER   0
    imul    $SP_SIZE, %rdi, %r12
    lea     C_SPACES(%rbx,%r12), %r12
    mov     %rsi, %r13
    mov     %rdx, X23(%rsp)
    mov     SP_CTX(%r12), %rax
    test    %rax, %rax
    jnz     1f
    mov     $CRYPTO_ROOM, %edi
    call    quic_heap_alloc
    test    %rax, %rax
    jz      8f
    mov     %rax, SP_CTX(%r12)
    movq    $0, SP_CTX_LEN(%r12)
    movq    $0, SP_CTX_SENT(%r12)
1:  mov     SP_CTX_LEN(%r12), %rcx
    mov     X23(%rsp), %rdx
    lea     (%rcx,%rdx), %r8
    cmp     $CRYPTO_ROOM, %r8
    ja      8f
    mov     %r8, SP_CTX_LEN(%r12)
    lea     (%r15,%rax), %rdi
    add     %rcx, %rdi
    mov     %r13, %rsi
    call    quic_copy
    mov     %r13, %rdi
    mov     X23(%rsp), %rsi
    call    quic_tls_append
    jmp     9f
8:  mov     $(TLS_ERR + ALERT_INTERNAL), %eax
9:  LEAVE   0
END_FUNCTION quic_crypto_out

/*
 * quic_key_share(group, dst) -> dst after our public key for the group: a new
 * private key in T_X25519, and the X25519 key of 32 bytes or the P-256 point
 * of 65. rbp the TLS block. r12 group, r13 dst, X23 the key length.
 */
.set KS_BASE, 0
.set KS_PUB, 32                         /* 72 bytes */
.set KS_FRAME, 112
LOCAL_FUNCTION quic_key_share
    ENTER   0, KS_FRAME
    mov     %rdi, %r12
    mov     %rsi, %r13
1:  lea     T_X25519(%rbp), %rdi
    mov     $32, %esi
    call    quic_random
    cmp     $GROUP_X25519, %r12
    jne     2f
    lea     (32 + KS_BASE)(%rsp), %rdi
    lea     613f(%rip), %rsi
    mov     $32, %edx
    call    quic_copy
    lea     T_X25519(%rbp), %rdi
    lea     (32 + KS_BASE)(%rsp), %rsi
    lea     (32 + KS_PUB)(%rsp), %rdx
    CALL_GLOBAL crypto_x25519
    movq    $32, X23(%rsp)
    jmp     3f
2:  lea     T_X25519(%rbp), %rdi
    lea     (32 + KS_PUB)(%rsp), %rsi
    CALL_GLOBAL crypto_p256_public_key
    test    %rax, %rax
    jnz     1b                              /* 0 or n or more: draw again */
    movq    $65, X23(%rsp)
3:  mov     %r13, %rdi
    lea     (32 + KS_PUB)(%rsp), %rsi
    mov     X23(%rsp), %rdx
    call    quic_copy
    LEAVE   0, KS_FRAME
END_FUNCTION quic_key_share

/*
 * quic_shared(key, n) -> 0 when T_SHARED holds the ECDHE secret of our key and
 * the peer's key of n bytes for T_GROUP; else the alert error.
 * rbp the TLS block. r12 key, r13 n.
 */
.set SH_KEY, 0                          /* 72 bytes */
.set SH_FRAME, 80
LOCAL_FUNCTION quic_shared
    ENTER   0, SH_FRAME
    mov     %rdi, %r12
    mov     %rsi, %r13
    mov     $65, %eax
    cmpq    $GROUP_X25519, T_GROUP(%rbp)
    jne     1f
    mov     $32, %eax
1:  cmp     %rax, %r13
    jne     8f
    lea     (32 + SH_KEY)(%rsp), %rdi
    mov     %r12, %rsi
    mov     %r13, %rdx
    call    quic_copy
    cmpq    $GROUP_X25519, T_GROUP(%rbp)
    jne     2f
    lea     T_X25519(%rbp), %rdi
    lea     (32 + SH_KEY)(%rsp), %rsi
    lea     T_SHARED(%rbp), %rdx
    CALL_GLOBAL crypto_x25519
    test    %rax, %rax
    jnz     8f
    jmp     9f
2:  lea     (32 + SH_KEY)(%rsp), %rdi
    lea     T_X25519(%rbp), %rsi
    lea     T_SHARED(%rbp), %rdx
    CALL_GLOBAL crypto_p256_ecdh
    test    %rax, %rax
    jnz     8f
    jmp     9f
8:  mov     $(TLS_ERR + ALERT_ILLEGAL), %eax
9:  LEAVE   0, SH_FRAME
END_FUNCTION quic_shared

/*
 * quic_cert_message(dst) -> dst after a Certificate message with our
 * certificate and an empty context. r15 the state. rbx dst, rbp the length.
 */
LOCAL_FUNCTION quic_cert_message
    ENTER   0
    mov     %rdi, %rbx
    mov     ST_CERT_LEN(%r15), %rbp
    movb    $11, (%rbx)
    lea     1(%rbx), %rdi
    lea     9(%rbp), %rsi                   /* context, list length, entry length, extensions */
    call    quic_put24
    movb    $0, (%rax)
    lea     1(%rax), %rdi
    lea     5(%rbp), %rsi
    call    quic_put24
    mov     %rax, %rdi
    mov     %rbp, %rsi
    call    quic_put24
    mov     %rax, %rdi
    lea     ST_CERT(%r15), %rsi
    mov     %rbp, %rdx
    call    quic_copy
    movb    $0, (%rax)
    movb    $0, 1(%rax)
    add     $2, %rax
    LEAVE   0
END_FUNCTION quic_cert_message

/*
 * quic_cv_message(dst, server) -> dst after our CertificateVerify: ECDSA P-256
 * of the SHA-256 of 64 spaces, the context string of the side, a zero byte
 * and the transcript hash, in DER. rbp the TLS block, r15 the state.
 * r12 dst, r13 server, X23 the signature length.
 */
.set CV_MSG, 0                          /* ByteList: 24 + 64 + 34 + 32 */
.set CV_HASH, 160
.set CV_SIG, 192
.set CV_FRAME, 256
LOCAL_FUNCTION quic_cv_message
    ENTER   0, CV_FRAME
    mov     %rdi, %r12
    mov     %rsi, %r13
    call    quic_tls_hash
    lea     (32 + CV_MSG)(%rsp), %rdi
    mov     %r13, %rsi
    lea     T_HASH(%rbp), %rdx
    call    quic_cv_put
    lea     (32 + CV_MSG)(%rsp), %rdi
    lea     (32 + CV_HASH)(%rsp), %rsi
    CALL_GLOBAL crypto_sha256
    lea     ST_CERT_PRIV(%r15), %rdi
    lea     (32 + CV_HASH)(%rsp), %rsi
    lea     (32 + CV_SIG)(%rsp), %rdx
    CALL_GLOBAL crypto_p256_sign
    movb    $15, (%r12)
    movb    $0x04, 4(%r12)                  /* ecdsa_secp256r1_sha256 */
    movb    $0x03, 5(%r12)
    lea     8(%r12), %rdi
    lea     (32 + CV_SIG)(%rsp), %rsi
    call    quic_der_sig_put
    mov     %rax, X23(%rsp)
    mov     %rax, %rcx
    shr     $8, %rcx
    movb    %cl, 6(%r12)
    movb    %al, 7(%r12)
    lea     1(%r12), %rdi
    lea     4(%rax), %rsi
    call    quic_put24
    mov     X23(%rsp), %rax
    lea     8(%r12,%rax), %rax
    LEAVE   0, CV_FRAME
END_FUNCTION quic_cv_message

/*
 * quic_cv_put(list, server, hash): the ByteList of the content a
 * CertificateVerify signs (RFC 8446 section 4.4.3). rbx list, rbp server, r12 hash.
 */
LOCAL_FUNCTION quic_cv_put
    ENTER   0
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     $130, %eax
    BYTELIST %rbx, 0, 160, %rax
    lea     24(%rbx), %rdi
    movabs  $0x2020202020202020, %rax
    mov     $8, %ecx
1:  mov     %rax, (%rdi)
    add     $8, %rdi
    dec     %ecx
    jnz     1b
    lea     610f(%rip), %rsi
    test    %rbp, %rbp
    jnz     2f
    lea     611f(%rip), %rsi
2:  mov     $33, %edx
    call    quic_copy
    movb    $0, (%rax)
    lea     1(%rax), %rdi
    mov     %r12, %rsi
    mov     $32, %edx
    call    quic_copy
    LEAVE   0
END_FUNCTION quic_cv_put

/* quic_fin_message(dst, secret) -> dst after a Finished message with the MAC of the secret. rbp the TLS block. */
LOCAL_FUNCTION quic_fin_message
    ENTER   0
    mov     %rdi, %r12
    movb    $20, (%r12)
    movb    $0, 1(%r12)
    movb    $0, 2(%r12)
    movb    $32, 3(%r12)
    mov     %rsi, %rdi
    lea     4(%r12), %rsi
    call    quic_finished_mac
    lea     36(%r12), %rax
    LEAVE   0
END_FUNCTION quic_fin_message

/* ---------------------------------------------------------------- Transport parameters */

/* quic_tp_int(dst, id, v) -> dst after one integer transport parameter. r12 v, r13 the position. */
LOCAL_FUNCTION quic_tp_int
    ENTER   0
    mov     %rdx, %r12
    call    quic_vput
    mov     %rax, %r13
    mov     %r12, %rdi
    call    quic_vlen
    mov     %r13, %rdi
    mov     %rax, %rsi
    call    quic_vput
    mov     %rax, %rdi
    mov     %r12, %rsi
    call    quic_vput
    LEAVE   0
END_FUNCTION quic_tp_int

/*
 * quic_tp_write(dst) -> dst after our transport parameters (RFC 9000 section
 * 18): max_idle_timeout, max_udp_payload_size 1452, the flow control limits,
 * initial_max_streams_bidi, disable_active_migration and
 * initial_source_connection_id; a server adds original_destination_connection_id.
 * rbx the connection.
 */
LOCAL_FUNCTION quic_tp_write
    ENTER   0
    mov     $0x01, %esi
    CFG     %rdx, QUIC_CFG_IDLE
    call    quic_tp_int
    mov     %rax, %rdi
    mov     $0x03, %esi
    mov     $1452, %edx
    call    quic_tp_int
    mov     %rax, %rdi
    mov     $0x04, %esi
    CFG     %rdx, QUIC_CFG_MAX_DATA
    call    quic_tp_int
    mov     %rax, %rdi
    mov     $0x05, %esi
    CFG     %rdx, QUIC_CFG_STREAM_DATA
    call    quic_tp_int
    mov     %rax, %rdi
    mov     $0x06, %esi
    CFG     %rdx, QUIC_CFG_STREAM_DATA
    call    quic_tp_int
    mov     %rax, %rdi
    mov     $0x08, %esi
    CFG     %rdx, QUIC_CFG_MAX_STREAMS
    call    quic_tp_int
    movb    $0x0C, (%rax)                   /* disable_active_migration, empty */
    movb    $0, 1(%rax)
    movb    $0x0F, 2(%rax)                  /* initial_source_connection_id */
    movb    $8, 3(%rax)
    lea     4(%rax), %rdi
    lea     C_LCID(%rbx), %rsi
    mov     $8, %edx
    call    quic_copy
    cmpq    $0, C_ROLE(%rbx)
    je      9f
    movb    $0, (%rax)                      /* original_destination_connection_id */
    mov     (C_ODCID + QUIC_CID_LENGTH)(%rbx), %rdx
    movb    %dl, 1(%rax)
    lea     2(%rax), %rdi
    lea     (C_ODCID + QUIC_CID_ID)(%rbx), %rsi
    call    quic_copy
9:  LEAVE   0
END_FUNCTION quic_tp_write

/* quic_cid_is(p, n, cid) -> 1 when the n bytes at p are the ConnectionId cid. */
LOCAL_FUNCTION quic_cid_is
    ENTER   0
    mov     QUIC_CID_LENGTH(%rdx), %rcx
    add     $QUIC_CID_ID, %rdx
    call    quic_bytes_is
    LEAVE   0
END_FUNCTION quic_cid_is

/*
 * quic_tp_read(p, end) -> 0 when the transport parameters of the peer are
 * valid, with their values in the C_P_* fields; else TRANSPORT_PARAMETER_ERROR.
 * Unknown parameters are skipped; each known one may appear once.
 * rbx the connection; r12 position, r13 end, X23 seen bits, X24 id, X25 length, X26 the value end.
 */
LOCAL_FUNCTION quic_tp_read
    ENTER   0
    mov     %rdi, %r12
    mov     %rsi, %r13
    movq    $0, X23(%rsp)
    /* Defaults (RFC 9000 section 18.2). */
    movq    $0, C_P_IDLE(%rbx)
    movq    $65527, C_P_UDP(%rbx)
    movq    $0, C_P_MAX_DATA(%rbx)
    movq    $0, C_P_SD_LOCAL(%rbx)
    movq    $0, C_P_SD_REMOTE(%rbx)
    movq    $0, C_P_STREAMS(%rbx)
    movq    $3, C_P_ACK_EXP(%rbx)
    movq    $25000, C_P_ACK_DELAY(%rbx)
    movq    $2, C_P_CID_LIMIT(%rbx)
1:  cmp     %r13, %r12
    jae     7f
    mov     %r12, %rdi
    mov     %r13, %rsi
    call    quic_vget
    test    %rax, %rax
    jz      8f
    mov     %rdx, X24(%rsp)
    mov     %rax, %rdi
    mov     %r13, %rsi
    call    quic_vget
    test    %rax, %rax
    jz      8f
    mov     %rdx, X25(%rsp)
    mov     %r13, %rcx
    sub     %rax, %rcx
    cmp     %rcx, %rdx
    ja      8f
    mov     %rax, %r12
    lea     (%r12,%rdx), %rcx
    mov     %rcx, X26(%rsp)
    mov     X24(%rsp), %rcx
    cmp     $0x10, %rcx
    ja      6f                              /* unknown: skip */
    mov     $1, %eax
    shl     %cl, %rax
    test    %rax, X23(%rsp)
    jnz     8f
    or      %rax, X23(%rsp)
    test    %rcx, %rcx
    jz      10f
    cmp     $0x02, %rcx
    je      12f
    cmp     $0x0C, %rcx
    je      13f
    cmp     $0x0D, %rcx
    je      14f
    cmp     $0x0F, %rcx
    je      15f
    cmp     $0x10, %rcx
    je      16f
    /* An integer parameter: one varint that fills the value. */
    mov     %r12, %rdi
    mov     X26(%rsp), %rsi
    call    quic_vget
    cmp     X26(%rsp), %rax
    jne     8f
    mov     X24(%rsp), %rcx
    cmp     $0x01, %rcx
    jne     2f
    mov     %rdx, C_P_IDLE(%rbx)
    jmp     6f
2:  cmp     $0x03, %rcx
    jne     3f
    cmp     $1200, %rdx
    jb      8f
    mov     %rdx, C_P_UDP(%rbx)
    jmp     6f
3:  cmp     $0x04, %rcx
    jne     31f
    mov     %rdx, C_P_MAX_DATA(%rbx)
    jmp     6f
31: cmp     $0x05, %rcx
    jne     32f
    mov     %rdx, C_P_SD_LOCAL(%rbx)
    jmp     6f
32: cmp     $0x06, %rcx
    jne     33f
    mov     %rdx, C_P_SD_REMOTE(%rbx)
    jmp     6f
33: cmp     $0x08, %rcx
    jne     34f
    movabs  $(1 << 60), %rax
    cmp     %rax, %rdx
    ja      8f
    mov     %rdx, C_P_STREAMS(%rbx)
    jmp     6f
34: cmp     $0x09, %rcx
    jne     35f
    movabs  $(1 << 60), %rax
    cmp     %rax, %rdx
    ja      8f
    jmp     6f
35: cmp     $0x0A, %rcx
    jne     36f
    cmp     $20, %rdx
    ja      8f
    mov     %rdx, C_P_ACK_EXP(%rbx)
    jmp     6f
36: cmp     $0x0B, %rcx
    jne     37f
    cmp     $16384, %rdx
    jae     8f
    imul    $1000, %rdx, %rdx
    mov     %rdx, C_P_ACK_DELAY(%rbx)
    jmp     6f
37: cmp     $0x0E, %rcx
    jne     6f                              /* initial_max_stream_data_uni */
    cmp     $2, %rdx
    jb      8f
    mov     %rdx, C_P_CID_LIMIT(%rbx)
    jmp     6f
10: cmpq    $0, C_ROLE(%rbx)                /* original_destination_connection_id: from a server */
    jne     8f
    mov     %r12, %rdi
    mov     X25(%rsp), %rsi
    lea     C_ODCID(%rbx), %rdx
    call    quic_cid_is
    test    %rax, %rax
    jz      8f
    jmp     6f
12: cmpq    $0, C_ROLE(%rbx)                /* stateless_reset_token: from a server */
    jne     8f
    cmpq    $16, X25(%rsp)
    jne     8f
    lea     C_RCID_TOKEN(%rbx), %rdi
    mov     %r12, %rsi
    mov     $16, %edx
    call    quic_copy
    orq     $CF_RESET_TOKEN, C_FLAGS(%rbx)
    jmp     6f
13: cmpq    $0, X25(%rsp)                   /* disable_active_migration */
    jne     8f
    jmp     6f
14: cmpq    $0, C_ROLE(%rbx)                /* preferred_address: from a server, not used */
    jne     8f
    jmp     6f
15: mov     %r12, %rdi                      /* initial_source_connection_id */
    mov     X25(%rsp), %rsi
    lea     C_ISCID(%rbx), %rdx
    call    quic_cid_is
    test    %rax, %rax
    jz      8f
    jmp     6f
16: cmpq    $0, C_ROLE(%rbx)                /* retry_source_connection_id: from a server after a Retry */
    jne     8f
    testq   $CF_RETRIED, C_FLAGS(%rbx)
    jz      8f
    mov     %r12, %rdi
    mov     X25(%rsp), %rsi
    lea     C_RSCID(%rbx), %rdx
    call    quic_cid_is
    test    %rax, %rax
    jz      8f
6:  mov     X26(%rsp), %r12
    jmp     1b
7:  testq   $(1 << 0x0F), X23(%rsp)         /* initial_source_connection_id is required */
    jz      8f
    cmpq    $0, C_ROLE(%rbx)
    jne     71f
    testq   $1, X23(%rsp)                   /* and, from a server, original_destination_connection_id */
    jz      8f
    testq   $CF_RETRIED, C_FLAGS(%rbx)
    jz      71f
    testq   $(1 << 0x10), X23(%rsp)
    jz      8f
71: mov     C_P_MAX_DATA(%rbx), %rax        /* the connection send limit */
    cmp     C_TX_MAX(%rbx), %rax
    jbe     72f
    mov     %rax, C_TX_MAX(%rbx)
72: xor     %eax, %eax
    jmp     9f
8:  mov     $ERR_TP, %eax
9:  LEAVE   0
END_FUNCTION quic_tp_read

/* ---------------------------------------------------------------- Client */

/*
 * quic_client_hello() -> 0 or an error: our ClientHello on the Initial CRYPTO
 * stream: TLS_AES_128_GCM_SHA256, supported_versions TLS 1.3, supported_groups
 * x25519 and secp256r1, signature_algorithms ecdsa_secp256r1_sha256 and ed25519,
 * a key_share of T_GROUP, the ALPN "libp2p", the transport parameters, and the
 * cookie of a HelloRetryRequest. rbx the connection, rbp the TLS block.
 * r12 the message, r13 the extensions, X23 a part start, X24 a position, X25 the key length.
 */
LOCAL_FUNCTION quic_client_hello
    ENTER   0
    SCR     %r12, SC_TLS
    movb    $1, (%r12)
    movb    $3, 4(%r12)
    movb    $3, 5(%r12)
    cmpq    $0, T_HRR(%rbp)
    jne     1f
    lea     T_RANDOM(%rbp), %rdi
    mov     $32, %esi
    call    quic_random
1:  lea     6(%r12), %rdi
    lea     T_RANDOM(%rbp), %rsi
    mov     $32, %edx
    call    quic_copy
    mov     %rax, %rdi
    lea     614f(%rip), %rsi                /* session ID, cipher suites, compression */
    mov     $7, %edx
    call    quic_copy
    mov     %rax, %r13                      /* the extensions length, then the extensions */
    lea     2(%rax), %rdi
    lea     615f(%rip), %rsi                /* supported_versions, supported_groups, signature_algorithms, ALPN */
    mov     $(7 + 10 + 10 + 13), %edx
    call    quic_copy
    mov     %rax, X23(%rsp)                 /* key_share: type, length, shares length, group, key length, key */
    mov     %rax, %rdi
    mov     $0x0033, %esi
    call    quic_put16
    lea     8(%rax), %rsi                   /* the key */
    mov     %rsi, X24(%rsp)
    mov     T_GROUP(%rbp), %rdi
    call    quic_key_share
    mov     %rax, %rcx
    sub     X24(%rsp), %rcx
    mov     %rcx, X25(%rsp)                 /* the key length */
    mov     %rax, X24(%rsp)
    mov     X23(%rsp), %rdi
    add     $2, %rdi
    lea     6(%rcx), %rsi
    call    quic_put16
    mov     %rax, %rdi
    mov     X25(%rsp), %rsi
    add     $4, %rsi
    call    quic_put16
    mov     %rax, %rdi
    mov     T_GROUP(%rbp), %rsi
    call    quic_put16
    mov     %rax, %rdi
    mov     X25(%rsp), %rsi
    call    quic_put16
    mov     X24(%rsp), %rax
    cmpq    $0, T_COOKIE_LEN(%rbp)
    je      2f
    mov     %rax, %rdi
    mov     $0x002C, %esi                   /* cookie */
    call    quic_put16
    mov     %rax, %rdi
    mov     T_COOKIE_LEN(%rbp), %rsi
    add     $2, %rsi
    call    quic_put16
    mov     %rax, %rdi
    mov     T_COOKIE_LEN(%rbp), %rsi
    call    quic_put16
    mov     %rax, %rdi
    lea     T_COOKIE(%rbp), %rsi
    mov     T_COOKIE_LEN(%rbp), %rdx
    call    quic_copy
2:  mov     %rax, X23(%rsp)                 /* quic_transport_parameters */
    mov     %rax, %rdi
    mov     $0x0039, %esi
    call    quic_put16
    lea     2(%rax), %rdi
    call    quic_tp_write
    mov     %rax, X24(%rsp)
    mov     %rax, %rsi
    sub     X23(%rsp), %rsi
    sub     $4, %rsi
    mov     X23(%rsp), %rdi
    add     $2, %rdi
    call    quic_put16
    mov     X24(%rsp), %rsi
    sub     %r13, %rsi
    sub     $2, %rsi
    mov     %r13, %rdi
    call    quic_put16
    mov     X24(%rsp), %rsi
    sub     %r12, %rsi
    sub     $4, %rsi
    lea     1(%r12), %rdi
    call    quic_put24
    mov     $SPACE_INITIAL, %edi
    mov     %r12, %rsi
    mov     X24(%rsp), %rdx
    sub     %r12, %rdx
    call    quic_crypto_out
    LEAVE   0
END_FUNCTION quic_client_hello

/*
 * quic_tls_start() -> 0 or an error: the client starts with a ClientHello
 * with an x25519 key share. rbx the connection, rbp the TLS block.
 */
LOCAL_FUNCTION quic_tls_start
    ENTER   0
    movq    $GROUP_X25519, T_GROUP(%rbp)
    movq    $TS_WAIT_SH, T_STAGE(%rbp)
    call    quic_client_hello
    LEAVE   0
END_FUNCTION quic_tls_start

/*
 * quic_on_server_hello(p, end) -> 0 or an error: a ServerHello or a
 * HelloRetryRequest body. rbx the connection, rbp the TLS block.
 * r12 position, r13 end, X23 HRR, X24 the key share key, X25 its length,
 * X26 the selected group.
 */
LOCAL_FUNCTION quic_on_server_hello
    ENTER   0
    mov     %rdi, %r12
    mov     %rsi, %r13
    movq    $0, X24(%rsp)
    movq    $0, X26(%rsp)
    mov     %r13, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    cmp     $0x0303, %rdx
    jne     81f
    mov     %r13, %rcx
    sub     %rax, %rcx
    cmp     $32, %rcx
    jb      80f
    mov     %rax, %r12
    mov     %rax, %rdi
    mov     $32, %esi
    lea     602f(%rip), %rdx
    mov     $32, %ecx
    call    quic_bytes_is
    mov     %rax, X23(%rsp)
    lea     32(%r12), %rdi
    mov     %r13, %rsi
    call    quic_rd8                        /* legacy_session_id_echo: we send none */
    test    %rax, %rax
    jz      80f
    test    %rdx, %rdx
    jnz     81f
    mov     %rax, %rdi
    mov     %r13, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    cmp     $0x1301, %rdx
    jne     81f
    mov     %rax, %rdi
    mov     %r13, %rsi
    call    quic_rd8
    test    %rax, %rax
    jz      80f
    test    %rdx, %rdx
    jnz     81f
    mov     %rax, %rdi
    mov     %r13, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    lea     (%rax,%rdx), %rcx
    cmp     %r13, %rcx
    jne     80f
    mov     %rax, %r12
    movq    $0, X25(%rsp)
    movq    $0, T_HASH(%rbp)                /* supported_versions seen */
1:  cmp     %r13, %r12
    jae     5f
    mov     %r12, %rdi
    mov     %r13, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    mov     %rdx, (T_HASH + 8)(%rbp)        /* type */
    mov     %rax, %rdi
    mov     %r13, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    lea     (%rax,%rdx), %rcx
    cmp     %r13, %rcx
    ja      80f
    mov     %rcx, %r12                      /* the next extension */
    mov     (T_HASH + 8)(%rbp), %r8
    cmp     $0x002B, %r8
    jne     2f
    cmp     $2, %rdx
    jne     80f
    mov     %rax, %rdi
    mov     %r12, %rsi
    call    quic_rd16
    cmp     $0x0304, %rdx
    jne     82f
    movq    $1, T_HASH(%rbp)
    jmp     1b
2:  cmp     $0x0033, %r8
    jne     3f
    mov     %rax, %rdi
    mov     %r12, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    mov     %rdx, X26(%rsp)
    cmpq    $0, X23(%rsp)
    jne     1b                              /* HRR: the group only */
    mov     %rax, %rdi
    mov     %r12, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    lea     (%rax,%rdx), %rcx
    cmp     %r12, %rcx
    jne     80f
    mov     %rax, X24(%rsp)
    mov     %rdx, X25(%rsp)
    jmp     1b
3:  cmp     $0x002C, %r8                    /* cookie, in a HelloRetryRequest */
    jne     1b
    cmpq    $0, X23(%rsp)
    je      81f
    mov     %rax, %rdi
    mov     %r12, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    test    %rdx, %rdx
    jz      80f
    cmp     $128, %rdx
    ja      81f
    lea     (%rax,%rdx), %rcx
    cmp     %r12, %rcx
    jne     80f
    mov     %rdx, T_COOKIE_LEN(%rbp)
    lea     T_COOKIE(%rbp), %rdi
    mov     %rax, %rsi
    call    quic_copy
    jmp     1b
5:  cmpq    $0, T_HASH(%rbp)
    je      82f
    cmpq    $0, X26(%rsp)
    je      83f
    cmpq    $0, X23(%rsp)
    jne     6f
    mov     X26(%rsp), %rax                 /* ServerHello */
    cmp     T_GROUP(%rbp), %rax
    jne     81f
    cmpq    $0, X24(%rsp)
    je      83f
    mov     X24(%rsp), %rdi
    mov     X25(%rsp), %rsi
    call    quic_shared
    test    %rax, %rax
    jnz     9f
    xor     %eax, %eax
    jmp     9f
6:  cmpq    $0, T_HRR(%rbp)                 /* HelloRetryRequest: once, for the other group */
    jne     84f
    mov     X26(%rsp), %rax
    cmp     T_GROUP(%rbp), %rax
    je      81f
    cmp     $GROUP_P256, %rax
    jne     81f
    mov     %rax, T_GROUP(%rbp)
    movq    $1, T_HRR(%rbp)
    mov     $2, %eax                        /* 2: a HelloRetryRequest to answer */
    jmp     9f
80: mov     $(TLS_ERR + ALERT_DECODE), %eax
    jmp     9f
81: mov     $(TLS_ERR + ALERT_ILLEGAL), %eax
    jmp     9f
82: mov     $(TLS_ERR + ALERT_VERSION), %eax
    jmp     9f
83: mov     $(TLS_ERR + ALERT_MISSING_EXT), %eax
    jmp     9f
84: mov     $(TLS_ERR + ALERT_UNEXPECTED), %eax
9:  LEAVE   0
END_FUNCTION quic_on_server_hello

/*
 * quic_message_hash(): after a HelloRetryRequest: the transcript becomes
 * message_hash (254, 0, 0, 32, SHA-256 of ClientHello1) (RFC 8446 section
 * 4.4.1). rbp the TLS block.
 */
LOCAL_FUNCTION quic_message_hash
    ENTER   0
    call    quic_tls_hash
    movb    $254, T_TRANSCRIPT(%rbp)
    movb    $0, (T_TRANSCRIPT + 1)(%rbp)
    movb    $0, (T_TRANSCRIPT + 2)(%rbp)
    movb    $32, (T_TRANSCRIPT + 3)(%rbp)
    lea     (T_TRANSCRIPT + 4)(%rbp), %rdi
    lea     T_HASH(%rbp), %rsi
    mov     $32, %edx
    call    quic_copy
    movq    $36, T_LEN(%rbp)
    LEAVE   0
END_FUNCTION quic_message_hash

/*
 * quic_on_ee(p, end) -> 0 or an error: EncryptedExtensions must hold the ALPN
 * "libp2p" and the transport parameters. rbx the connection, rbp the TLS block.
 * r12 position, r13 end, X23 seen: 1 ALPN, 2 parameters; X24 the type.
 */
LOCAL_FUNCTION quic_on_ee
    ENTER   0
    mov     %rsi, %r13
    movq    $0, X23(%rsp)
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    lea     (%rax,%rdx), %rcx
    cmp     %r13, %rcx
    jne     80f
    mov     %rax, %r12
1:  cmp     %r13, %r12
    jae     5f
    mov     %r12, %rdi
    mov     %r13, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    mov     %rdx, X24(%rsp)
    mov     %rax, %rdi
    mov     %r13, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    lea     (%rax,%rdx), %rcx
    cmp     %r13, %rcx
    ja      80f
    mov     %rcx, %r12
    cmpq    $0x0010, X24(%rsp)
    jne     2f
    mov     %rax, %rdi                      /* ALPN: one protocol, "libp2p" */
    mov     %rcx, %rsi
    call    quic_alpn_libp2p
    test    %rax, %rax
    jz      81f
    orq     $1, X23(%rsp)
    jmp     1b
2:  cmpq    $0x0039, X24(%rsp)
    jne     1b
    mov     %rax, %rdi
    mov     %rcx, %rsi
    call    quic_tp_read
    test    %rax, %rax
    jnz     9f
    orq     $2, X23(%rsp)
    jmp     1b
5:  testq   $1, X23(%rsp)
    jz      82f
    testq   $2, X23(%rsp)
    jz      83f
    xor     %eax, %eax
    jmp     9f
80: mov     $(TLS_ERR + ALERT_DECODE), %eax
    jmp     9f
81: mov     $(TLS_ERR + ALERT_NO_ALPN), %eax
    jmp     9f
82: mov     $(TLS_ERR + ALERT_NO_ALPN), %eax
    jmp     9f
83: mov     $(TLS_ERR + ALERT_MISSING_EXT), %eax
9:  LEAVE   0
END_FUNCTION quic_on_ee

/*
 * quic_alpn_libp2p(p, end) -> 1 when the ALPN extension data at p lists
 * "libp2p"; else 0. r12 position, r13 end, X23 the protocol end.
 */
LOCAL_FUNCTION quic_alpn_libp2p
    ENTER   0
    mov     %rsi, %r13
    call    quic_rd16
    test    %rax, %rax
    jz      8f
    lea     (%rax,%rdx), %rcx
    cmp     %r13, %rcx
    jne     8f
    mov     %rax, %r12
1:  cmp     %r13, %r12
    jae     8f
    mov     %r12, %rdi
    mov     %r13, %rsi
    call    quic_rd8
    test    %rax, %rax
    jz      8f
    lea     (%rax,%rdx), %rcx
    cmp     %r13, %rcx
    ja      8f
    mov     %rcx, X23(%rsp)
    mov     %rax, %rdi
    mov     %rdx, %rsi
    lea     612f(%rip), %rdx
    mov     $6, %ecx
    call    quic_bytes_is
    test    %rax, %rax
    jnz     9f
    mov     X23(%rsp), %r12
    jmp     1b
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_alpn_libp2p

/*
 * quic_sigalgs_ok(p, end) -> 1 when the signature_algorithms extension data at
 * p lists ecdsa_secp256r1_sha256, the scheme we sign with; else 0.
 */
LOCAL_FUNCTION quic_sigalgs_ok
    ENTER   0
    mov     %rsi, %r13
    call    quic_rd16
    test    %rax, %rax
    jz      8f
    lea     (%rax,%rdx), %rcx
    cmp     %r13, %rcx
    jne     8f
    mov     %rax, %r12
1:  mov     %r12, %rdi
    mov     %r13, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      8f
    mov     %rax, %r12
    cmp     $0x0403, %rdx
    jne     1b
    mov     $1, %eax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_sigalgs_ok

/*
 * quic_on_cr(p, end) -> 0 or an error: a CertificateRequest with an empty
 * context, whose signature_algorithms list ecdsa_secp256r1_sha256.
 * rbp the TLS block. r12 position, r13 end, X23 found, X24 the type.
 */
LOCAL_FUNCTION quic_on_cr
    ENTER   0
    mov     %rsi, %r13
    movq    $0, X23(%rsp)
    call    quic_rd8
    test    %rax, %rax
    jz      80f
    test    %rdx, %rdx
    jnz     81f
    mov     %rax, %rdi
    mov     %r13, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    lea     (%rax,%rdx), %rcx
    cmp     %r13, %rcx
    jne     80f
    mov     %rax, %r12
1:  cmp     %r13, %r12
    jae     5f
    mov     %r12, %rdi
    mov     %r13, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    mov     %rdx, X24(%rsp)
    mov     %rax, %rdi
    mov     %r13, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    lea     (%rax,%rdx), %rcx
    cmp     %r13, %rcx
    ja      80f
    mov     %rcx, %r12
    cmpq    $0x000D, X24(%rsp)
    jne     1b
    mov     %rax, %rdi
    mov     %rcx, %rsi
    call    quic_sigalgs_ok
    or      %rax, X23(%rsp)
    jmp     1b
5:  cmpq    $0, X23(%rsp)
    je      82f
    movq    $1, T_CERT_REQ(%rbp)
    xor     %eax, %eax
    jmp     9f
80: mov     $(TLS_ERR + ALERT_DECODE), %eax
    jmp     9f
81: mov     $(TLS_ERR + ALERT_ILLEGAL), %eax
    jmp     9f
82: mov     $(TLS_ERR + ALERT_HANDSHAKE), %eax
9:  LEAVE   0
END_FUNCTION quic_on_cr

/*
 * quic_on_cert(p, end) -> 0 or an error: a Certificate with an empty context
 * and exactly one certificate, which quic_cert_check accepts; T_PEER gets its
 * CertInfo. A dialer then checks the peer ID. rbx the connection, rbp the TLS
 * block. r12 the certificate, r13 end, X23 its end, X24 its length.
 */
LOCAL_FUNCTION quic_on_cert
    ENTER   0
    mov     %rsi, %r13
    call    quic_rd8
    test    %rax, %rax
    jz      80f
    test    %rdx, %rdx
    jnz     81f
    mov     %rax, %rdi
    mov     %r13, %rsi
    call    quic_rd24
    test    %rax, %rax
    jz      80f
    lea     (%rax,%rdx), %rcx
    cmp     %r13, %rcx
    jne     80f
    test    %rdx, %rdx
    jz      82f                             /* no certificate */
    mov     %rax, %rdi
    mov     %r13, %rsi
    call    quic_rd24
    test    %rax, %rax
    jz      80f
    mov     %rax, %r12
    lea     (%rax,%rdx), %rcx               /* the end of the certificate */
    mov     %rcx, X23(%rsp)
    mov     %rdx, X24(%rsp)
    mov     %rcx, %rdi
    mov     %r13, %rsi
    call    quic_rd16                       /* its extensions */
    test    %rax, %rax
    jz      80f
    lea     (%rax,%rdx), %rcx
    cmp     %r13, %rcx                      /* one certificate only */
    jne     83f
    mov     %r12, %rdi
    mov     X24(%rsp), %rsi
    mov     ST_UNIX(%r15), %rdx
    lea     T_PEER(%rbp), %rcx
    movq    $QUIC_CI_FIXED, (%rcx)
    SCR     %r8, SC_CERT
    call    quic_cert_check
    test    %rax, %rax
    jnz     83f
    mov     (T_PEER + QUIC_CI_HOST_LEN)(%rbp), %rdx /* the host key, for CONNECTED */
    mov     %rdx, C_PEER_KEY_LEN(%rbx)
    lea     C_PEER_KEY(%rbx), %rdi
    lea     (T_PEER + QUIC_CI_HOST)(%rbp), %rsi
    call    quic_copy
    cmpq    $0, C_ROLE(%rbx)
    jne     7f
    cmpq    $0, T_PID_LEN(%rbp)
    je      7f
    call    quic_peer_id_ok
    test    %rax, %rax
    jz      84f
7:  xor     %eax, %eax
    jmp     9f
80: mov     $(TLS_ERR + ALERT_DECODE), %eax
    jmp     9f
81: mov     $(TLS_ERR + ALERT_ILLEGAL), %eax
    jmp     9f
82: mov     $(TLS_ERR + ALERT_CERT_REQUIRED), %eax
    jmp     9f
83: mov     $(TLS_ERR + ALERT_BAD_CERT), %eax
    jmp     9f
84: movq    $QUIC_ERR_PEER_ID, C_REASON(%rbx)
    mov     $(TLS_ERR + ALERT_BAD_CERT), %eax
9:  LEAVE   0
END_FUNCTION quic_on_cert

/*
 * quic_peer_id_ok() -> 1 when the peer ID the dialer named is the multihash of
 * the peer's host key: identity for a protobuf of at most 42 bytes, else
 * SHA-256 (libp2p peer IDs). rbp the TLS block. r12 the key length, r13 the ID length.
 */
.set PI_LIST, 0                         /* ByteList: 24 + 128 */
.set PI_ID, 152                         /* 48 bytes */
.set PI_FRAME, 208
LOCAL_FUNCTION quic_peer_id_ok
    ENTER   0, PI_FRAME
    mov     (T_PEER + QUIC_CI_HOST_LEN)(%rbp), %r12
    cmp     $42, %r12
    ja      1f
    movb    $0, (32 + PI_ID)(%rsp)
    movb    %r12b, (32 + PI_ID + 1)(%rsp)
    lea     (32 + PI_ID + 2)(%rsp), %rdi
    lea     (T_PEER + QUIC_CI_HOST)(%rbp), %rsi
    mov     %r12, %rdx
    call    quic_copy
    lea     2(%r12), %r13
    jmp     2f
1:  BYTELIST %rsp, (32 + PI_LIST), 152, %r12
    lea     (32 + PI_LIST + 24)(%rsp), %rdi
    lea     (T_PEER + QUIC_CI_HOST)(%rbp), %rsi
    mov     %r12, %rdx
    call    quic_copy
    movb    $0x12, (32 + PI_ID)(%rsp)
    movb    $0x20, (32 + PI_ID + 1)(%rsp)
    lea     (32 + PI_LIST)(%rsp), %rdi
    lea     (32 + PI_ID + 2)(%rsp), %rsi
    CALL_GLOBAL crypto_sha256
    mov     $34, %r13d
2:  lea     (32 + PI_ID)(%rsp), %rdi
    mov     %r13, %rsi
    lea     T_PID(%rbp), %rdx
    mov     T_PID_LEN(%rbp), %rcx
    call    quic_bytes_is
    LEAVE   0, PI_FRAME
END_FUNCTION quic_peer_id_ok

/*
 * quic_on_cv(p, end, server) -> 0 or an error: the peer's CertificateVerify
 * signs the transcript hash with the key of its certificate: ecdsa_secp256r1_sha256
 * (DER) for a P-256 key, ed25519 for an Ed25519 key. server 1 when the peer is
 * the server. rbp the TLS block. r12 position, r13 end, X23 server, X24 the
 * scheme, X25 the signature length.
 */
.set PV_MSG, 0                          /* ByteList: 24 + 130, room to 160 */
.set PV_HASH, 160
.set PV_SIG, 192
.set PV_KEY, 256                        /* 72 bytes */
.set PV_VALID, 328
.set PV_FRAME, 336
LOCAL_FUNCTION quic_on_cv
    ENTER   0, PV_FRAME
    mov     %rdi, %r12
    mov     %rsi, %r13
    mov     %rdx, X23(%rsp)
    call    quic_tls_hash
    lea     (32 + PV_MSG)(%rsp), %rdi
    mov     X23(%rsp), %rsi
    lea     T_HASH(%rbp), %rdx
    call    quic_cv_put
    mov     %r12, %rdi
    mov     %r13, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    mov     %rdx, X24(%rsp)                 /* the scheme */
    mov     %rax, %rdi
    mov     %r13, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    lea     (%rax,%rdx), %rcx
    cmp     %r13, %rcx
    jne     80f
    mov     %rax, %r12
    mov     %rdx, X25(%rsp)
    lea     (32 + PV_KEY)(%rsp), %rdi
    lea     (T_PEER + QUIC_CI_KEY)(%rbp), %rsi
    mov     $72, %edx
    call    quic_copy
    cmpq    $QUIC_CERT_ED25519, (T_PEER + QUIC_CI_KIND)(%rbp)
    jne     1f
    cmpq    $0x0807, X24(%rsp)
    jne     81f
    cmpq    $64, X25(%rsp)
    jne     81f
    lea     (32 + PV_SIG)(%rsp), %rdi
    mov     %r12, %rsi
    mov     $64, %edx
    call    quic_copy
    lea     (32 + PV_KEY)(%rsp), %rdi
    lea     (32 + PV_MSG)(%rsp), %rsi
    lea     (32 + PV_SIG)(%rsp), %rdx
    lea     (32 + PV_VALID)(%rsp), %rcx
    CALL_GLOBAL crypto_ed25519_verify
    jmp     2f
1:  cmpq    $0x0403, X24(%rsp)
    jne     81f
    lea     (32 + PV_SIG)(%rsp), %rdi
    mov     %r12, %rsi
    mov     X25(%rsp), %rdx
    call    quic_der_sig_get
    test    %rax, %rax
    jz      82f
    lea     (32 + PV_MSG)(%rsp), %rdi
    lea     (32 + PV_HASH)(%rsp), %rsi
    CALL_GLOBAL crypto_sha256
    lea     (32 + PV_KEY)(%rsp), %rdi
    lea     (32 + PV_HASH)(%rsp), %rsi
    lea     (32 + PV_SIG)(%rsp), %rdx
    lea     (32 + PV_VALID)(%rsp), %rcx
    CALL_GLOBAL crypto_p256_verify
2:  test    %rax, %rax
    jnz     82f
    cmpq    $0, (32 + PV_VALID)(%rsp)
    je      82f
    xor     %eax, %eax
    jmp     9f
80: mov     $(TLS_ERR + ALERT_DECODE), %eax
    jmp     9f
81: mov     $(TLS_ERR + ALERT_ILLEGAL), %eax
    jmp     9f
82: mov     $(TLS_ERR + ALERT_DECRYPT), %eax
9:  LEAVE   0, PV_FRAME
END_FUNCTION quic_on_cv

/*
 * quic_on_fin(p, end, secret) -> 0 or an error: the peer's Finished holds the
 * MAC of its handshake traffic secret over the transcript hash.
 * rbp the TLS block. r12 p.
 */
.set PF_MAC, 0
.set PF_FRAME, 32
LOCAL_FUNCTION quic_on_fin
    ENTER   0, PF_FRAME
    mov     %rdi, %r12
    mov     %rsi, %rax
    sub     %rdi, %rax
    cmp     $32, %rax
    jne     80f
    mov     %rdx, %rdi
    lea     (32 + PF_MAC)(%rsp), %rsi
    call    quic_finished_mac
    mov     %r12, %rdi
    lea     (32 + PF_MAC)(%rsp), %rsi
    mov     $32, %edx
    call    quic_equal
    test    %rax, %rax
    jz      82f
    xor     %eax, %eax
    jmp     9f
80: mov     $(TLS_ERR + ALERT_DECODE), %eax
    jmp     9f
82: mov     $(TLS_ERR + ALERT_DECRYPT), %eax
9:  LEAVE   0, PF_FRAME
END_FUNCTION quic_on_fin

/*
 * quic_client_finish() -> 0 or an error: after the server Finished: the
 * 1-RTT keys, then our Certificate and CertificateVerify when the server asked,
 * and our Finished, on the Handshake CRYPTO stream. The handshake is complete.
 * rbx the connection, rbp the TLS block. r12 the message.
 */
LOCAL_FUNCTION quic_client_finish
    ENTER   0
    call    quic_app_keys
    cmpq    $0, T_CERT_REQ(%rbp)
    je      1f
    SCR     %r12, SC_TLS
    mov     %r12, %rdi
    call    quic_cert_message
    mov     %rax, %rdx
    sub     %r12, %rdx
    mov     %r12, %rsi
    mov     $SPACE_HANDSHAKE, %edi
    call    quic_crypto_out
    test    %rax, %rax
    jnz     9f
    mov     %r12, %rdi
    xor     %esi, %esi
    call    quic_cv_message
    mov     %rax, %rdx
    sub     %r12, %rdx
    mov     %r12, %rsi
    mov     $SPACE_HANDSHAKE, %edi
    call    quic_crypto_out
    test    %rax, %rax
    jnz     9f
1:  SCR     %r12, SC_TLS
    mov     %r12, %rdi
    lea     T_C_HS(%rbp), %rsi
    call    quic_fin_message
    mov     %rax, %rdx
    sub     %r12, %rdx
    mov     %r12, %rsi
    mov     $SPACE_HANDSHAKE, %edi
    call    quic_crypto_out
    test    %rax, %rax
    jnz     9f
    call    quic_handshake_complete
    xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_client_finish

/* ---------------------------------------------------------------- Server */

/*
 * quic_on_client_hello(p, end) -> 0, 2 when a HelloRetryRequest is to be sent,
 * or an error. rbx the connection, rbp the TLS block.
 * r12 position, r13 end, X23 flags: 1 TLS 1.3, 2 cipher, 4 signature, 8 ALPN,
 * 16 parameters, 32 x25519 group, 64 secp256r1 group, 128 key share;
 * X24 the key share key, X25 the end of a list, X26 the key share group.
 */
LOCAL_FUNCTION quic_on_client_hello
    ENTER   0
    mov     %rsi, %r13
    movq    $0, X23(%rsp)
    movq    $0, X24(%rsp)
    movq    $0, X26(%rsp)
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    cmp     $0x0303, %rdx
    jne     81f
    mov     %r13, %rcx
    sub     %rax, %rcx
    cmp     $32, %rcx
    jb      80f
    lea     32(%rax), %rdi                  /* random */
    mov     %r13, %rsi
    call    quic_rd8                        /* legacy_session_id: must be empty in QUIC */
    test    %rax, %rax
    jz      80f
    test    %rdx, %rdx
    jnz     85f
    mov     %rax, %rdi
    mov     %r13, %rsi
    call    quic_rd16                       /* cipher_suites */
    test    %rax, %rax
    jz      80f
    lea     (%rax,%rdx), %r12
    cmp     %r13, %r12
    ja      80f
    mov     %r12, X25(%rsp)
1:  cmp     X25(%rsp), %rax
    jae     2f
    mov     %rax, %rdi
    mov     X25(%rsp), %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    cmp     $0x1301, %rdx
    jne     1b
    orq     $2, X23(%rsp)
    jmp     1b
2:  mov     %r12, %rdi
    mov     %r13, %rsi
    call    quic_rd8                        /* legacy_compression_methods: null only */
    test    %rax, %rax
    jz      80f
    cmp     $1, %rdx
    jne     81f
    mov     %rax, %rdi
    mov     %r13, %rsi
    call    quic_rd8
    test    %rax, %rax
    jz      80f
    test    %rdx, %rdx
    jnz     81f
    mov     %rax, %rdi
    mov     %r13, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    lea     (%rax,%rdx), %rcx
    cmp     %r13, %rcx
    jne     80f
    mov     %rax, %r12
3:  cmp     %r13, %r12
    jae     6f
    mov     %r12, %rdi
    mov     %r13, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    mov     %rdx, (T_HASH + 8)(%rbp)
    mov     %rax, %rdi
    mov     %r13, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    lea     (%rax,%rdx), %rcx
    cmp     %r13, %rcx
    ja      80f
    mov     %rcx, %r12                      /* the next extension */
    mov     %rcx, (T_HASH + 16)(%rbp)
    mov     (T_HASH + 8)(%rbp), %r8
    cmp     $0x002B, %r8
    je      31f
    cmp     $0x000A, %r8
    je      32f
    cmp     $0x0033, %r8
    je      33f
    cmp     $0x000D, %r8
    je      34f
    cmp     $0x0010, %r8
    je      35f
    cmp     $0x0039, %r8
    je      36f
    jmp     3b
31: mov     %rax, %rdi                      /* supported_versions */
    mov     %r12, %rsi
    call    quic_rd8
    test    %rax, %rax
    jz      80f
    lea     (%rax,%rdx), %rcx
    cmp     %r12, %rcx
    jne     80f
    mov     %rcx, X25(%rsp)
4:  cmp     X25(%rsp), %rax
    jae     3b
    mov     %rax, %rdi
    mov     X25(%rsp), %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    cmp     $0x0304, %rdx
    jne     4b
    orq     $1, X23(%rsp)
    jmp     4b
32: mov     %rax, %rdi                      /* supported_groups */
    mov     %r12, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    lea     (%rax,%rdx), %rcx
    cmp     %r12, %rcx
    jne     80f
    mov     %rcx, X25(%rsp)
5:  cmp     X25(%rsp), %rax
    jae     3b
    mov     %rax, %rdi
    mov     X25(%rsp), %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    cmp     $GROUP_X25519, %rdx
    jne     51f
    orq     $32, X23(%rsp)
51: cmp     $GROUP_P256, %rdx
    jne     5b
    orq     $64, X23(%rsp)
    jmp     5b
33: mov     %rax, %rdi                      /* key_share: x25519 first, then secp256r1 */
    mov     %r12, %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    lea     (%rax,%rdx), %rcx
    cmp     %r12, %rcx
    jne     80f
    mov     %rcx, X25(%rsp)
7:  cmp     X25(%rsp), %rax
    jae     3b
    mov     %rax, %rdi
    mov     X25(%rsp), %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    mov     %rdx, (T_HASH + 24)(%rbp)
    mov     %rax, %rdi
    mov     X25(%rsp), %rsi
    call    quic_rd16
    test    %rax, %rax
    jz      80f
    lea     (%rax,%rdx), %rcx
    cmp     X25(%rsp), %rcx
    ja      80f
    mov     (T_HASH + 24)(%rbp), %r8
    cmp     $GROUP_X25519, %r8
    jne     71f
    cmp     $32, %rdx
    jne     72f
    mov     %rax, X24(%rsp)                 /* x25519 wins */
    mov     %r8, X26(%rsp)
    orq     $128, X23(%rsp)
    jmp     72f
71: cmp     $GROUP_P256, %r8
    jne     72f
    cmpq    $GROUP_X25519, X26(%rsp)
    je      72f
    cmp     $65, %rdx
    jne     72f
    mov     %rax, X24(%rsp)
    mov     %r8, X26(%rsp)
    orq     $128, X23(%rsp)
72: mov     %rcx, %rax
    jmp     7b
34: mov     %rax, %rdi                      /* signature_algorithms */
    mov     %r12, %rsi
    call    quic_sigalgs_ok
    test    %rax, %rax
    jz      3b
    orq     $4, X23(%rsp)
    jmp     3b
35: mov     %rax, %rdi                      /* ALPN */
    mov     %r12, %rsi
    call    quic_alpn_libp2p
    test    %rax, %rax
    jz      3b
    orq     $8, X23(%rsp)
    jmp     3b
36: mov     %rax, %rdi                      /* quic_transport_parameters */
    mov     %r12, %rsi
    call    quic_tp_read
    test    %rax, %rax
    jnz     9f
    orq     $16, X23(%rsp)
    jmp     3b
6:  mov     X23(%rsp), %rax
    test    $1, %al
    jz      82f
    test    $2, %al
    jz      83f
    test    $4, %al
    jz      83f
    test    $8, %al
    jz      84f
    test    $16, %al
    jz      86f
    test    $128, %al
    jz      61f                             /* no usable key share */
    mov     X26(%rsp), %rcx
    mov     %rcx, T_GROUP(%rbp)
    mov     $65, %edx
    cmp     $GROUP_X25519, %rcx
    jne     64f
    mov     $32, %edx
64: mov     X24(%rsp), %rcx
    mov     %rcx, (T_HASH + 16)(%rbp)
    mov     %rdx, (T_HASH + 24)(%rbp)
    xor     %eax, %eax
    jmp     9f
61: cmpq    $0, T_HRR(%rbp)                 /* after a HelloRetryRequest the share must be there */
    jne     81f
    mov     $GROUP_X25519, %ecx
    test    $32, %al
    jnz     62f
    mov     $GROUP_P256, %ecx
    test    $64, %al
    jz      83f
62: mov     %rcx, T_GROUP(%rbp)
    mov     $2, %eax
    jmp     9f
80: mov     $(TLS_ERR + ALERT_DECODE), %eax
    jmp     9f
81: mov     $(TLS_ERR + ALERT_ILLEGAL), %eax
    jmp     9f
82: mov     $(TLS_ERR + ALERT_VERSION), %eax
    jmp     9f
83: mov     $(TLS_ERR + ALERT_HANDSHAKE), %eax
    jmp     9f
84: mov     $(TLS_ERR + ALERT_NO_ALPN), %eax
    jmp     9f
85: mov     $ERR_PROTOCOL, %eax
    jmp     9f
86: mov     $(TLS_ERR + ALERT_MISSING_EXT), %eax
9:  LEAVE   0
END_FUNCTION quic_on_client_hello

/*
 * quic_server_hello(hrr) -> 0 or an error: a ServerHello with our key share,
 * or a HelloRetryRequest for T_GROUP when hrr is 1, on the Initial CRYPTO
 * stream. rbx the connection, rbp the TLS block. r12 the message, r13 the
 * extensions, X23 hrr, X24 a position, X25 the key length, X26 after the key.
 */
LOCAL_FUNCTION quic_server_hello
    ENTER   0
    mov     %rdi, X23(%rsp)
    SCR     %r12, SC_TLS
    movb    $2, (%r12)
    movb    $3, 4(%r12)
    movb    $3, 5(%r12)
    lea     6(%r12), %rdi
    cmpq    $0, X23(%rsp)
    je      1f
    lea     602f(%rip), %rsi
    mov     $32, %edx
    call    quic_copy
    jmp     2f
1:  mov     $32, %esi
    call    quic_random
2:  movb    $0, 38(%r12)                    /* legacy_session_id_echo: empty */
    lea     39(%r12), %rdi
    mov     $0x1301, %esi
    call    quic_put16
    movb    $0, (%rax)
    lea     1(%rax), %r13
    lea     3(%rax), %rdi
    mov     $0x002B, %esi
    call    quic_put16
    mov     %rax, %rdi
    mov     $2, %esi
    call    quic_put16
    mov     %rax, %rdi
    mov     $0x0304, %esi
    call    quic_put16
    mov     %rax, %rdi
    mov     $0x0033, %esi
    call    quic_put16
    cmpq    $0, X23(%rsp)
    je      3f
    mov     %rax, %rdi
    mov     $2, %esi
    call    quic_put16
    mov     %rax, %rdi
    mov     T_GROUP(%rbp), %rsi
    call    quic_put16
    jmp     4f
3:  mov     %rax, X24(%rsp)
    lea     6(%rax), %rsi
    mov     T_GROUP(%rbp), %rdi
    call    quic_key_share
    mov     %rax, X26(%rsp)
    mov     X24(%rsp), %rcx
    add     $6, %rcx
    sub     %rcx, %rax                      /* the key length */
    mov     %rax, X25(%rsp)
    mov     X24(%rsp), %rdi
    lea     4(%rax), %rsi
    call    quic_put16
    mov     %rax, %rdi
    mov     T_GROUP(%rbp), %rsi
    call    quic_put16
    mov     %rax, %rdi
    mov     X25(%rsp), %rsi
    call    quic_put16
    mov     X26(%rsp), %rax
4:  mov     %rax, X24(%rsp)
    mov     %rax, %rsi
    sub     %r13, %rsi
    sub     $2, %rsi
    mov     %r13, %rdi
    call    quic_put16
    mov     X24(%rsp), %rsi
    sub     %r12, %rsi
    sub     $4, %rsi
    lea     1(%r12), %rdi
    call    quic_put24
    mov     $SPACE_INITIAL, %edi
    mov     %r12, %rsi
    mov     X24(%rsp), %rdx
    sub     %r12, %rdx
    call    quic_crypto_out
    LEAVE   0
END_FUNCTION quic_server_hello

/*
 * quic_server_flight() -> 0 or an error: after ClientHello: ServerHello, the
 * handshake keys, then EncryptedExtensions, CertificateRequest, Certificate,
 * CertificateVerify and Finished on the Handshake CRYPTO stream, and the
 * 1-RTT keys. rbx the connection, rbp the TLS block. r12 the message,
 * r13 the extensions, X23 the end.
 */
LOCAL_FUNCTION quic_server_flight
    ENTER   0
    xor     %edi, %edi                      /* ServerHello draws our key share first */
    call    quic_server_hello
    test    %rax, %rax
    jnz     9f
    mov     (T_HASH + 16)(%rbp), %rdi       /* the client key share */
    mov     (T_HASH + 24)(%rbp), %rsi
    call    quic_shared
    test    %rax, %rax
    jnz     9f
    call    quic_handshake_keys
    /* EncryptedExtensions: ALPN libp2p and the transport parameters. */
    SCR     %r12, SC_TLS
    movb    $8, (%r12)
    lea     6(%r12), %rdi
    lea     616f(%rip), %rsi
    mov     $13, %edx
    call    quic_copy
    mov     %rax, %r13
    mov     %rax, %rdi
    mov     $0x0039, %esi
    call    quic_put16
    lea     2(%rax), %rdi
    call    quic_tp_write
    mov     %rax, X23(%rsp)
    mov     %rax, %rsi
    sub     %r13, %rsi
    sub     $4, %rsi
    lea     2(%r13), %rdi
    call    quic_put16
    mov     X23(%rsp), %rsi
    sub     %r12, %rsi
    sub     $6, %rsi
    lea     4(%r12), %rdi
    call    quic_put16
    mov     X23(%rsp), %rsi
    sub     %r12, %rsi
    sub     $4, %rsi
    lea     1(%r12), %rdi
    call    quic_put24
    mov     $SPACE_HANDSHAKE, %edi
    mov     %r12, %rsi
    mov     X23(%rsp), %rdx
    sub     %r12, %rdx
    call    quic_crypto_out
    test    %rax, %rax
    jnz     9f
    /* CertificateRequest: empty context, signature_algorithms. */
    mov     $SPACE_HANDSHAKE, %edi
    lea     617f(%rip), %rsi
    mov     $17, %edx
    call    quic_crypto_out
    test    %rax, %rax
    jnz     9f
    mov     %r12, %rdi
    call    quic_cert_message
    mov     %rax, %rdx
    sub     %r12, %rdx
    mov     %r12, %rsi
    mov     $SPACE_HANDSHAKE, %edi
    call    quic_crypto_out
    test    %rax, %rax
    jnz     9f
    mov     %r12, %rdi
    mov     $1, %esi
    call    quic_cv_message
    mov     %rax, %rdx
    sub     %r12, %rdx
    mov     %r12, %rsi
    mov     $SPACE_HANDSHAKE, %edi
    call    quic_crypto_out
    test    %rax, %rax
    jnz     9f
    mov     %r12, %rdi
    lea     T_S_HS(%rbp), %rsi
    call    quic_fin_message
    mov     %rax, %rdx
    sub     %r12, %rdx
    mov     %r12, %rsi
    mov     $SPACE_HANDSHAKE, %edi
    call    quic_crypto_out
    test    %rax, %rax
    jnz     9f
    call    quic_app_keys
    movq    $TS_WAIT_CCERT, T_STAGE(%rbp)
    xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_server_flight

/* ---------------------------------------------------------------- Messages in */

/*
 * quic_tls_message(space, type, p, end) -> 0 or an error: one handshake
 * message from the peer (p the body, end its end; the whole message is at
 * p - 4) in the order of the stage. rbx the connection, rbp the TLS block.
 * r12 space, r13 type, X23 body, X24 end.
 */
LOCAL_FUNCTION quic_tls_message
    ENTER   0
    mov     %rdi, %r12
    mov     %rsi, %r13
    mov     %rdx, X23(%rsp)
    mov     %rcx, X24(%rsp)
    test    %rbp, %rbp
    jz      30f                             /* after the handshake */
    mov     T_STAGE(%rbp), %rax
    cmp     $TS_WAIT_SH, %rax
    je      1f
    cmp     $TS_WAIT_EE, %rax
    je      2f
    cmp     $TS_WAIT_CERT_CR, %rax
    je      3f
    cmp     $TS_WAIT_CERT, %rax
    je      4f
    cmp     $TS_WAIT_CV, %rax
    je      5f
    cmp     $TS_WAIT_FIN, %rax
    je      6f
    cmp     $TS_WAIT_CH, %rax
    je      7f
    cmp     $TS_WAIT_CCERT, %rax
    je      8f
    jmp     30f
1:  cmp     $SPACE_INITIAL, %r12            /* client: ServerHello */
    jne     90f
    cmp     $2, %r13
    jne     90f
    mov     X23(%rsp), %rdi
    mov     X24(%rsp), %rsi
    call    quic_on_server_hello
    cmp     $2, %rax
    je      11f
    test    %rax, %rax
    jnz     99f
    mov     X23(%rsp), %rdi
    mov     X24(%rsp), %rsi
    call    quic_append_in
    test    %rax, %rax
    jnz     99f
    call    quic_handshake_keys
    movq    $TS_WAIT_EE, T_STAGE(%rbp)
    jmp     98f
11: call    quic_message_hash               /* HelloRetryRequest */
    mov     X23(%rsp), %rdi
    mov     X24(%rsp), %rsi
    call    quic_append_in
    test    %rax, %rax
    jnz     99f
    call    quic_client_hello
    jmp     99f
2:  cmp     $SPACE_HANDSHAKE, %r12          /* client: EncryptedExtensions */
    jne     90f
    cmp     $8, %r13
    jne     90f
    mov     X23(%rsp), %rdi
    mov     X24(%rsp), %rsi
    call    quic_on_ee
    test    %rax, %rax
    jnz     99f
    mov     $TS_WAIT_CERT_CR, %eax
    jmp     97f
3:  cmp     $SPACE_HANDSHAKE, %r12          /* client: CertificateRequest or Certificate */
    jne     90f
    cmp     $13, %r13
    jne     4f
    mov     X23(%rsp), %rdi
    mov     X24(%rsp), %rsi
    call    quic_on_cr
    test    %rax, %rax
    jnz     99f
    mov     $TS_WAIT_CERT, %eax
    jmp     97f
4:  cmp     $SPACE_HANDSHAKE, %r12          /* client: Certificate */
    jne     90f
    cmp     $11, %r13
    jne     90f
    mov     X23(%rsp), %rdi
    mov     X24(%rsp), %rsi
    call    quic_on_cert
    test    %rax, %rax
    jnz     99f
    mov     $TS_WAIT_CV, %eax
    jmp     97f
5:  cmp     $SPACE_HANDSHAKE, %r12          /* both: CertificateVerify */
    jne     90f
    cmp     $15, %r13
    jne     90f
    xor     %edx, %edx
    cmpq    $0, C_ROLE(%rbx)
    sete    %dl                             /* the peer is the server when we are the client */
    mov     X23(%rsp), %rdi
    mov     X24(%rsp), %rsi
    call    quic_on_cv
    test    %rax, %rax
    jnz     99f
    mov     $TS_WAIT_FIN, %eax
    jmp     97f
6:  cmp     $SPACE_HANDSHAKE, %r12          /* both: Finished */
    jne     90f
    cmp     $20, %r13
    jne     90f
    lea     T_S_HS(%rbp), %rdx
    cmpq    $0, C_ROLE(%rbx)
    je      63f
    lea     T_C_HS(%rbp), %rdx
63: mov     X23(%rsp), %rdi
    mov     X24(%rsp), %rsi
    call    quic_on_fin
    test    %rax, %rax
    jnz     99f
    mov     X23(%rsp), %rdi
    mov     X24(%rsp), %rsi
    call    quic_append_in
    test    %rax, %rax
    jnz     99f
    cmpq    $0, C_ROLE(%rbx)
    jne     61f
    call    quic_client_finish
    jmp     99f
61: call    quic_handshake_complete         /* server: the client is verified */
    xor     %eax, %eax
    jmp     99f
7:  cmp     $SPACE_INITIAL, %r12            /* server: ClientHello */
    jne     90f
    cmp     $1, %r13
    jne     90f
    mov     X23(%rsp), %rdi
    mov     X24(%rsp), %rsi
    call    quic_on_client_hello
    cmp     $2, %rax
    je      71f
    test    %rax, %rax
    jnz     99f
    mov     X23(%rsp), %rdi
    mov     X24(%rsp), %rsi
    call    quic_append_in
    test    %rax, %rax
    jnz     99f
    call    quic_server_flight
    jmp     99f
71: mov     X23(%rsp), %rdi                 /* HelloRetryRequest */
    mov     X24(%rsp), %rsi
    call    quic_append_in
    test    %rax, %rax
    jnz     99f
    call    quic_message_hash
    movq    $1, T_HRR(%rbp)
    mov     $1, %edi
    call    quic_server_hello
    jmp     99f
8:  cmp     $SPACE_HANDSHAKE, %r12          /* server: the client Certificate */
    jne     90f
    cmp     $11, %r13
    jne     90f
    mov     X23(%rsp), %rdi
    mov     X24(%rsp), %rsi
    call    quic_on_cert
    test    %rax, %rax
    jnz     99f
    mov     $TS_WAIT_CV, %eax
    jmp     97f
30: cmp     $4, %r13                        /* after the handshake: NewSessionTicket only, ignored */
    jne     90f
    cmpq    $0, C_ROLE(%rbx)
    jne     90f
    cmp     $SPACE_APP, %r12
    jne     90f
    xor     %eax, %eax
    jmp     99f
97: mov     %rax, T_STAGE(%rbp)
    mov     X23(%rsp), %rdi
    mov     X24(%rsp), %rsi
    call    quic_append_in
    jmp     99f
98: xor     %eax, %eax
    jmp     99f
90: mov     $(TLS_ERR + ALERT_UNEXPECTED), %eax
99: LEAVE   0
END_FUNCTION quic_tls_message

/* quic_append_in(body, end) -> 0 or an error: the message at body - 4 to end goes into the transcript. */
LOCAL_FUNCTION quic_append_in
    ENTER   0
    sub     $4, %rdi
    sub     %rdi, %rsi
    call    quic_tls_append
    LEAVE   0
END_FUNCTION quic_append_in

/*
 * quic_handshake_complete(): the TLS handshake is complete (RFC 9001 section
 * 4.1.1). A server confirms it at once and sends HANDSHAKE_DONE; the
 * application hears CONNECTED. rbx the connection, rbp the TLS block.
 */
LOCAL_FUNCTION quic_handshake_complete
    ENTER   0
    movq    $TS_DONE, T_STAGE(%rbp)
    mov     C_FLAGS(%rbx), %rax
    or      $(CF_COMPLETE | CF_TELL), %rax
    cmpq    $0, C_ROLE(%rbx)
    je      1f
    or      $(CF_CONFIRMED | CF_DONE_FRAME), %rax
1:  mov     %rax, C_FLAGS(%rbx)
    movq    $CS_ACTIVE, C_STATE(%rbx)
    cmpq    $0, C_ROLE(%rbx)
    je      2f
    mov     $SPACE_HANDSHAKE, %edi
    call    quic_discard_space
2:  LEAVE   0
END_FUNCTION quic_handshake_complete

/*
 * quic_tls_feed(space) -> 0 or an error: the complete handshake messages at
 * the start of the CRYPTO receive data of the space go to quic_tls_message in
 * order; the rest stays. rbx the connection.
 * r12 the space, r13 the block, X23 the contiguous end, X24 the bytes taken,
 * X25 the space index, X26 the body length.
 */
LOCAL_FUNCTION quic_tls_feed
    ENTER   0
    imul    $SP_SIZE, %rdi, %r12
    lea     C_SPACES(%rbx,%r12), %r12
    mov     %rdi, X25(%rsp)
1:  mov     SP_CRX(%r12), %r13
    test    %r13, %r13
    jz      8f
    add     %r15, %r13
    cmpq    $0, SP_CRX_NR(%r12)
    je      8f
    cmpq    $0, SP_CRX_RANGES(%r12)         /* the first range must start at 0 */
    jne     8f
    mov     (SP_CRX_RANGES + 8)(%r12), %rax
    mov     %rax, X23(%rsp)
    mov     SP_CRX_DONE(%r12), %rcx
    mov     %rcx, X24(%rsp)
    sub     %rcx, %rax
    cmp     $4, %rax
    jb      8f
    lea     1(%r13,%rcx), %rdi
    call    quic_get24
    mov     %rax, X26(%rsp)                 /* the body length */
    mov     X24(%rsp), %rcx
    lea     4(%rcx,%rax), %rcx              /* the message end */
    cmp     $CRYPTO_ROOM, %rcx
    ja      7f
    cmp     X23(%rsp), %rcx
    ja      8f
    mov     %rcx, SP_CRX_DONE(%r12)
    mov     C_TLS(%rbx), %rax
    xor     %ebp, %ebp
    test    %rax, %rax
    jz      2f
    lea     (%r15,%rax), %rbp
2:  mov     X25(%rsp), %rdi
    mov     X24(%rsp), %rcx
    movzbl  (%r13,%rcx), %esi
    lea     4(%r13,%rcx), %rdx
    mov     X26(%rsp), %rcx
    add     %rdx, %rcx
    call    quic_tls_message
    test    %rax, %rax
    jnz     9f
    call    quic_crx_compact
    jmp     1b
7:  mov     $ERR_CRYPTO_BUFFER, %eax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_tls_feed

/*
 * quic_crx_compact(): moves the CRYPTO data not yet taken to the start of the
 * block. r12 the space. r13 the block, X23 the bytes taken, X24 the ranges.
 */
LOCAL_FUNCTION quic_crx_compact
    ENTER   0
    mov     SP_CRX(%r12), %r13
    add     %r15, %r13
    mov     SP_CRX_DONE(%r12), %rax
    test    %rax, %rax
    jz      9f
    mov     %rax, X23(%rsp)
    mov     SP_CRX_NR(%r12), %rcx
    mov     %rcx, X24(%rsp)
    dec     %rcx                            /* the end of the last range */
    shl     $4, %rcx
    mov     (SP_CRX_RANGES + 8)(%r12,%rcx), %rdx
    mov     %r13, %rdi
    lea     (%r13,%rax), %rsi
    sub     %rax, %rdx
    call    quic_copy
    lea     SP_CRX_RANGES(%r12), %r8        /* shift the ranges */
    xor     %r9d, %r9d
    mov     X23(%rsp), %r10
1:  cmp     X24(%rsp), %r9
    jae     2f
    mov     (%r8), %rax
    mov     8(%r8), %rcx
    sub     %r10, %rax
    jae     3f
    xor     %eax, %eax
3:  sub     %r10, %rcx
    mov     %rax, (%r8)
    mov     %rcx, 8(%r8)
    add     $16, %r8
    inc     %r9
    jmp     1b
2:  mov     X23(%rsp), %rax
    add     %rax, SP_CRX_BASE(%r12)
    movq    $0, SP_CRX_DONE(%r12)
    mov     SP_CRX_RANGES(%r12), %rax       /* an empty first range goes */
    cmp     (SP_CRX_RANGES + 8)(%r12), %rax
    jb      9f
    mov     X24(%rsp), %rcx
    dec     %rcx
    mov     %rcx, SP_CRX_NR(%r12)
    lea     SP_CRX_RANGES(%r12), %rdi
    lea     16(%rdi), %rsi
    mov     %rcx, %rdx
    shl     $4, %rdx
    call    quic_copy
9:  LEAVE   0
END_FUNCTION quic_crx_compact

/* ---------------------------------------------------------------- Constants */

    .p2align 3
/* Derive-Secret(early_secret, "derived", ""), with no PSK (RFC 8448 section 3). */
600:
    .byte   0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5, 0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba, 0xb6, 0x97
    .byte   0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48, 0x25, 0x0c, 0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36, 0x11, 0xba
/* SHA-256 of the empty string. */
601:
    .byte   0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24
    .byte   0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
/* The random of a HelloRetryRequest: SHA-256 of "HelloRetryRequest" (RFC 8446 section 4.1.3). */
602:
    .byte   0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91
    .byte   0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
/* The X25519 base point u = 9. */
613:
    .byte   9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    .byte   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
603:
    .ascii  "c hs traffic"
604:
    .ascii  "s hs traffic"
605:
    .ascii  "c ap traffic"
606:
    .ascii  "s ap traffic"
607:
    .ascii  "derived"
608:
    .ascii  "finished"
609:
    .ascii  "quic ku"
610:
    .ascii  "TLS 1.3, server CertificateVerify"
611:
    .ascii  "TLS 1.3, client CertificateVerify"
612:
    .ascii  "libp2p"
/* ClientHello after the random: an empty session ID, TLS_AES_128_GCM_SHA256, null compression. */
614:
    .byte   0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00
/* ClientHello extensions: supported_versions TLS 1.3, supported_groups x25519 and secp256r1,
   signature_algorithms ecdsa_secp256r1_sha256 and ed25519, ALPN "libp2p". */
615:
    .byte   0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04
    .byte   0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17
    .byte   0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x07
    .byte   0x00, 0x10, 0x00, 0x09, 0x00, 0x07, 0x06
    .ascii  "libp2p"
/* EncryptedExtensions: the ALPN "libp2p". */
616:
    .byte   0x00, 0x10, 0x00, 0x09, 0x00, 0x07, 0x06
    .ascii  "libp2p"
/* CertificateRequest: an empty context, signature_algorithms ecdsa_secp256r1_sha256 and ed25519. */
617:
    .byte   13, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x0a, 0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x07
    .p2align 2
