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
 * x19 the connection, x20 the TLS block, in the functions that take them.
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

/* quic_rd8(p, end) -> x0 p + 1, or 0 past end; x1 the byte. A leaf. */
LOCAL_FUNCTION quic_rd8
    UNWIND_END_PROLOGUE
    cmp     x0, x1
    b.hs    8f
    ldrb    w1, [x0], #1
    ret
8:  mov     x0, #0
    ret
END_FUNCTION quic_rd8

/* quic_rd16(p, end) -> x0 p + 2, or 0 past end; x1 the big-endian value. A leaf. */
LOCAL_FUNCTION quic_rd16
    UNWIND_END_PROLOGUE
    sub     x2, x1, x0
    cmp     x0, x1
    b.hs    8f
    cmp     x2, #2
    b.lo    8f
    ldrb    w3, [x0]
    ldrb    w4, [x0, #1]
    orr     w1, w4, w3, lsl #8
    add     x0, x0, #2
    ret
8:  mov     x0, #0
    ret
END_FUNCTION quic_rd16

/* quic_rd24(p, end) -> x0 p + 3, or 0 past end; x1 the big-endian value. A leaf. */
LOCAL_FUNCTION quic_rd24
    UNWIND_END_PROLOGUE
    sub     x2, x1, x0
    cmp     x0, x1
    b.hs    8f
    cmp     x2, #3
    b.lo    8f
    ldrb    w3, [x0]
    ldrb    w4, [x0, #1]
    ldrb    w5, [x0, #2]
    lsl     w3, w3, #16
    orr     w3, w3, w4, lsl #8
    orr     w1, w3, w5
    add     x0, x0, #3
    ret
8:  mov     x0, #0
    ret
END_FUNCTION quic_rd24

/* ---------------------------------------------------------------- Transcript and key schedule */

/* quic_tls_append(msg, n) -> 0, or an error when the transcript has no room. x20 the TLS block. */
LOCAL_FUNCTION quic_tls_append
    ENTER   0
    mov     x19, x0
    ldr     x9, [x20, #T_LEN]
    add     x10, x9, x1
    MOV64   x11, TRANSCRIPT_ROOM
    cmp     x10, x11
    b.hi    8f
    str     x10, [x20, #T_LEN]
    add     x0, x20, #T_TRANSCRIPT
    add     x0, x0, x9
    mov     x2, x1
    mov     x1, x19
    bl      quic_copy
    mov     x0, #0
    b       9f
8:  mov     x0, #(TLS_ERR + ALERT_INTERNAL)
9:  LEAVE   0
END_FUNCTION quic_tls_append

/* quic_tls_hash(): T_HASH = SHA-256 of the transcript. x20 the TLS block. */
LOCAL_FUNCTION quic_tls_hash
    ENTER   0
    add     x0, x20, #T_LIST
    add     x1, x20, #T_HASH
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
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x10, #32
    BYTELIST sp, HX_SALT, 56, x10
    BYTELIST sp, HX_IKM, 56, x10
    add     x0, sp, #(HX_SALT + 24)
    mov     x1, #32
    bl      quic_zero
    add     x0, sp, #(HX_IKM + 24)
    mov     x1, #32
    bl      quic_zero
    cbz     x19, 1f
    add     x0, sp, #(HX_SALT + 24)
    mov     x1, x19
    mov     x2, #32
    bl      quic_copy
1:  cbz     x20, 2f
    add     x0, sp, #(HX_IKM + 24)
    mov     x1, x20
    mov     x2, #32
    bl      quic_copy
2:  mov     x9, #160
    str     x9, [sp, #HX_SCRATCH]
    add     x0, sp, #HX_SALT
    add     x1, sp, #HX_IKM
    add     x2, sp, #HX_SCRATCH
    mov     x3, x21
    CALL_GLOBAL crypto_hkdf_extract
    LEAVE   0, HX_FRAME
END_FUNCTION quic_hkdf_extract

/*
 * quic_derive_secret(secret, label, label_len, out): Derive-Secret of RFC 8446
 * section 7.1 with the hash of the transcript as it is. x20 the TLS block.
 */
LOCAL_FUNCTION quic_derive_secret
    ENTER   0
    mov     x21, x0
    mov     x22, x1
    mov     x23, x2
    mov     x24, x3
    bl      quic_tls_hash
    mov     x0, x21
    mov     x1, x22
    mov     x2, x23
    add     x3, x20, #T_HASH
    mov     x4, #32
    mov     x5, #32
    mov     x6, x24
    bl      quic_expand_label
    LEAVE   0
END_FUNCTION quic_derive_secret

/*
 * quic_finished_mac(secret, out): out = HMAC(finished_key, the transcript
 * hash), with finished_key = HKDF-Expand-Label(secret, "finished", "", 32).
 * x20 the TLS block.
 */
.set FM_KEY, 0                          /* ByteList: 24 + 32 */
.set FM_MSG, 56                         /* ByteList: 24 + 32 */
.set FM_SCRATCH, 112                    /* HmacScratch: 160 bytes */
.set FM_FRAME, 272
LOCAL_FUNCTION quic_finished_mac
    ENTER   0, FM_FRAME
    mov     x21, x0
    mov     x22, x1
    mov     x10, #32
    BYTELIST sp, FM_KEY, 56, x10
    BYTELIST sp, FM_MSG, 56, x10
    mov     x0, x21
    adr     x1, 608f
    mov     x2, #8
    mov     x3, #0
    mov     x4, #0
    mov     x5, #32
    add     x6, sp, #(FM_KEY + 24)
    bl      quic_expand_label
    bl      quic_tls_hash
    add     x0, sp, #(FM_MSG + 24)
    add     x1, x20, #T_HASH
    mov     x2, #32
    bl      quic_copy
    mov     x9, #160
    str     x9, [sp, #FM_SCRATCH]
    add     x0, sp, #FM_KEY
    add     x1, sp, #FM_MSG
    add     x2, sp, #FM_SCRATCH
    mov     x3, x22
    CALL_GLOBAL crypto_hmac_sha256
    LEAVE   0, FM_FRAME
END_FUNCTION quic_finished_mac

/*
 * quic_handshake_keys(): after ServerHello: the handshake secret from the
 * shared secret, the two handshake traffic secrets, and the Handshake keys
 * of both directions. x19 the connection, x20 the TLS block.
 */
LOCAL_FUNCTION quic_handshake_keys
    ENTER   0
    adr     x0, 600f
    add     x1, x20, #T_SHARED
    add     x2, x20, #T_HS_SECRET
    bl      quic_hkdf_extract
    add     x0, x20, #T_HS_SECRET
    adr     x1, 603f
    mov     x2, #12
    add     x3, x20, #T_C_HS
    bl      quic_derive_secret
    add     x0, x20, #T_HS_SECRET
    adr     x1, 604f
    mov     x2, #12
    add     x3, x20, #T_S_HS
    bl      quic_derive_secret
    mov     x0, #SPACE_HANDSHAKE
    add     x1, x20, #T_C_HS
    add     x2, x20, #T_S_HS
    bl      quic_install_keys
    /* The master secret, for later. */
    add     x0, x20, #T_HS_SECRET
    adr     x1, 607f
    mov     x2, #7
    adr     x3, 601f
    mov     x4, #32
    mov     x5, #32
    add     x6, x20, #T_MASTER
    bl      quic_expand_label
    add     x0, x20, #T_MASTER
    mov     x1, #0
    add     x2, x20, #T_MASTER
    bl      quic_hkdf_extract
    LEAVE   0
END_FUNCTION quic_handshake_keys

/*
 * quic_app_keys(): after the server Finished is in the transcript: the
 * application traffic secrets, kept in C_APP_SECRETS, and the 1-RTT keys.
 * x19 the connection, x20 the TLS block.
 */
LOCAL_FUNCTION quic_app_keys
    ENTER   0
    add     x0, x20, #T_MASTER
    adr     x1, 605f
    mov     x2, #12
    add     x3, x19, #C_APP_SECRETS
    bl      quic_derive_secret
    add     x0, x20, #T_MASTER
    adr     x1, 606f
    mov     x2, #12
    add     x3, x19, #(C_APP_SECRETS + 32)
    bl      quic_derive_secret
    mov     x0, #SPACE_APP
    add     x1, x19, #C_APP_SECRETS
    add     x2, x19, #(C_APP_SECRETS + 32)
    bl      quic_install_keys
    bl      quic_next_rx_keys
    LEAVE   0
END_FUNCTION quic_app_keys

/*
 * quic_install_keys(space, client_secret, server_secret): the receive and send
 * keys of a space for our role. x19 the connection.
 */
LOCAL_FUNCTION quic_install_keys
    ENTER   0
    mov     x21, #SP_SIZE
    madd    x21, x0, x21, x19
    add     x21, x21, #C_SPACES             /* the space */
    ldr     x9, [x19, #C_ROLE]
    cmp     x9, #0
    csel    x22, x2, x1, eq                 /* receive: the peer's secret */
    csel    x23, x1, x2, eq                 /* send: ours */
    mov     x0, x22
    add     x1, x21, #SP_RX_KEYS
    bl      quic_derive_keys
    mov     x0, x23
    add     x1, x21, #SP_TX_KEYS
    bl      quic_derive_keys
    ldr     x9, [x21, #SP_FLAGS]
    orr     x9, x9, #(SPF_RX | SPF_TX)
    str     x9, [x21, #SP_FLAGS]
    LEAVE   0
END_FUNCTION quic_install_keys

/*
 * quic_next_rx_keys(): C_NEXT_RX = the receive keys of the next key phase:
 * the key and IV of HKDF-Expand-Label(the peer's secret, "quic ku", "", 32),
 * and the same header protection key (RFC 9001 section 6). x19 the connection.
 */
.set NK_SECRET, 0
.set NK_KEYS, 32
.set NK_FRAME, 80
LOCAL_FUNCTION quic_next_rx_keys
    ENTER   0, NK_FRAME
    ldr     x9, [x19, #C_ROLE]
    add     x0, x19, #C_APP_SECRETS
    add     x10, x0, #32
    cmp     x9, #0
    csel    x0, x10, x0, eq                 /* the peer's secret */
    adr     x1, 609f
    mov     x2, #7
    mov     x3, #0
    mov     x4, #0
    mov     x5, #32
    add     x6, sp, #NK_SECRET
    bl      quic_expand_label
    add     x0, sp, #NK_SECRET
    add     x1, x19, #C_NEXT_RX
    bl      quic_derive_keys
    add     x9, x19, #(C_SPACES + 2 * SP_SIZE + SP_RX_KEYS + QUIC_KEYS_HP)
    ldp     x10, x11, [x9]
    add     x9, x19, #(C_NEXT_RX + QUIC_KEYS_HP)
    stp     x10, x11, [x9]
    LEAVE   0, NK_FRAME
END_FUNCTION quic_next_rx_keys

/*
 * quic_key_update(): moves to the next key phase. The peer's secret steps
 * on: the current receive keys become the previous ones and C_NEXT_RX the
 * current ones. Our secret steps on with it, and the send keys follow. x19 the connection.
 */
.set KU_SECRET, 0
.set KU_FRAME, 32
LOCAL_FUNCTION quic_key_update
    ENTER   0, KU_FRAME
    add     x21, x19, #(C_SPACES + 2 * SP_SIZE)
    add     x0, x19, #C_PREV_RX
    add     x1, x21, #SP_RX_KEYS
    mov     x2, #QUIC_KEYS_SIZE
    bl      quic_copy
    add     x0, x21, #SP_RX_KEYS
    add     x1, x19, #C_NEXT_RX
    mov     x2, #QUIC_KEYS_SIZE
    bl      quic_copy
    mov     x22, #0                         /* each secret steps: client 0, server 1 */
1:  add     x23, x19, #C_APP_SECRETS
    add     x23, x23, x22, lsl #5
    mov     x0, x23
    adr     x1, 609f
    mov     x2, #7
    mov     x3, #0
    mov     x4, #0
    mov     x5, #32
    add     x6, sp, #KU_SECRET
    bl      quic_expand_label
    mov     x0, x23
    add     x1, sp, #KU_SECRET
    mov     x2, #32
    bl      quic_copy
    add     x22, x22, #1
    cmp     x22, #2
    b.lo    1b
    /* The send keys from our new secret; the header protection key stays. */
    ldr     x9, [x19, #C_ROLE]
    add     x0, x19, #C_APP_SECRETS
    add     x10, x0, #32
    cmp     x9, #0
    csel    x0, x0, x10, eq
    add     x1, sp, #KU_SECRET
    ldp     x9, x10, [x21, #(SP_TX_KEYS + QUIC_KEYS_HP)]
    stp     x9, x10, [sp, #KU_SECRET]
    mov     x1, x21
    add     x1, x1, #SP_TX_KEYS
    bl      quic_derive_keys
    ldp     x9, x10, [sp, #KU_SECRET]
    stp     x9, x10, [x21, #(SP_TX_KEYS + QUIC_KEYS_HP)]
    /* The next receive keys from the peer's new secret. */
    bl      quic_next_rx_keys
    ldr     x9, [x19, #C_KEY_PHASE]
    eor     x9, x9, #1
    str     x9, [x19, #C_KEY_PHASE]
    str     xzr, [x19, #C_PHASE_SENT]
    mov     x9, #NONE
    str     x9, [x19, #C_PHASE_PN]
    LEAVE   0, KU_FRAME
END_FUNCTION quic_key_update

/* ---------------------------------------------------------------- Output */

/*
 * quic_crypto_out(space, msg, n) -> 0, or an error: appends a handshake
 * message to the CRYPTO stream of the space and to the transcript.
 * x19 the connection, x20 the TLS block.
 */
LOCAL_FUNCTION quic_crypto_out
    ENTER   0
    mov     x21, #SP_SIZE
    madd    x21, x0, x21, x19
    add     x21, x21, #C_SPACES
    mov     x22, x1
    mov     x23, x2
    ldr     x24, [x21, #SP_CTX]
    cbnz    x24, 1f
    mov     x0, #CRYPTO_ROOM
    bl      quic_heap_alloc
    cbz     x0, 8f
    mov     x24, x0
    str     x24, [x21, #SP_CTX]
    str     xzr, [x21, #SP_CTX_LEN]
    str     xzr, [x21, #SP_CTX_SENT]
1:  ldr     x9, [x21, #SP_CTX_LEN]
    add     x10, x9, x23
    cmp     x10, #CRYPTO_ROOM
    b.hi    8f
    str     x10, [x21, #SP_CTX_LEN]
    add     x0, x27, x24
    add     x0, x0, x9
    mov     x1, x22
    mov     x2, x23
    bl      quic_copy
    mov     x0, x22
    mov     x1, x23
    bl      quic_tls_append
    b       9f
8:  mov     x0, #(TLS_ERR + ALERT_INTERNAL)
9:  LEAVE   0
END_FUNCTION quic_crypto_out

/*
 * quic_key_share(group, dst) -> dst after our public key for the group: a new
 * private key in T_X25519, and the X25519 key of 32 bytes or the P-256 point
 * of 65. x20 the TLS block.
 */
.set KS_BASE, 0
.set KS_PUB, 32                         /* 72 bytes */
.set KS_FRAME, 112
LOCAL_FUNCTION quic_key_share
    ENTER   0, KS_FRAME
    mov     x21, x0
    mov     x22, x1
1:  add     x0, x20, #T_X25519
    mov     x1, #32
    bl      quic_random
    cmp     x21, #GROUP_X25519
    b.ne    2f
    adr     x9, 613f
    ldp     x10, x11, [x9]
    stp     x10, x11, [sp, #KS_BASE]
    ldp     x10, x11, [x9, #16]
    stp     x10, x11, [sp, #(KS_BASE + 16)]
    add     x0, x20, #T_X25519
    add     x1, sp, #KS_BASE
    add     x2, sp, #KS_PUB
    CALL_GLOBAL crypto_x25519
    mov     x23, #32
    b       3f
2:  add     x0, x20, #T_X25519
    add     x1, sp, #KS_PUB
    CALL_GLOBAL crypto_p256_public_key
    cbnz    x0, 1b                          /* 0 or n or more: draw again */
    mov     x23, #65
3:  mov     x0, x22
    add     x1, sp, #KS_PUB
    mov     x2, x23
    bl      quic_copy
    LEAVE   0, KS_FRAME
END_FUNCTION quic_key_share

/*
 * quic_shared(key, n) -> 0 when T_SHARED holds the ECDHE secret of our key and
 * the peer's key of n bytes for T_GROUP; else the alert error.
 * x20 the TLS block.
 */
.set SH_KEY, 0                          /* 72 bytes */
.set SH_FRAME, 80
LOCAL_FUNCTION quic_shared
    ENTER   0, SH_FRAME
    mov     x21, x0
    mov     x22, x1
    ldr     x9, [x20, #T_GROUP]
    mov     x23, #65
    cmp     x9, #GROUP_X25519
    mov     x10, #32
    csel    x23, x10, x23, eq
    cmp     x22, x23
    b.ne    8f
    add     x0, sp, #SH_KEY
    mov     x1, x21
    mov     x2, x23
    bl      quic_copy
    ldr     x9, [x20, #T_GROUP]
    cmp     x9, #GROUP_X25519
    b.ne    1f
    add     x0, x20, #T_X25519
    add     x1, sp, #SH_KEY
    add     x2, x20, #T_SHARED
    CALL_GLOBAL crypto_x25519
    cbnz    x0, 8f
    b       9f
1:  add     x0, sp, #SH_KEY
    add     x1, x20, #T_X25519
    add     x2, x20, #T_SHARED
    CALL_GLOBAL crypto_p256_ecdh
    cbnz    x0, 8f
    b       9f
8:  mov     x0, #(TLS_ERR + ALERT_ILLEGAL)
9:  LEAVE   0, SH_FRAME
END_FUNCTION quic_shared

/*
 * quic_cert_message(dst) -> dst after a Certificate message with our
 * certificate and an empty context. x27 the state.
 */
LOCAL_FUNCTION quic_cert_message
    ENTER   0
    mov     x19, x0
    ldr     x20, [x27, #ST_CERT_LEN]
    mov     w9, #11
    strb    w9, [x19]
    add     x0, x19, #1
    add     x1, x20, #9                     /* context, list length, entry length, extensions */
    bl      quic_put24
    strb    wzr, [x0], #1
    add     x1, x20, #5
    bl      quic_put24
    mov     x1, x20
    bl      quic_put24
    add     x1, x27, #ST_CERT
    mov     x2, x20
    bl      quic_copy
    strb    wzr, [x0], #1
    strb    wzr, [x0], #1
    LEAVE   0
END_FUNCTION quic_cert_message

/*
 * quic_cv_message(dst, server) -> dst after our CertificateVerify: ECDSA P-256
 * of the SHA-256 of 64 spaces, the context string of the side, a zero byte
 * and the transcript hash, in DER. x20 the TLS block, x27 the state.
 */
.set CV_MSG, 0                          /* ByteList: 24 + 64 + 34 + 32 */
.set CV_HASH, 160
.set CV_SIG, 192
.set CV_FRAME, 256
LOCAL_FUNCTION quic_cv_message
    ENTER   0, CV_FRAME
    mov     x21, x0
    mov     x22, x1
    bl      quic_tls_hash
    add     x0, sp, #CV_MSG
    mov     x1, x22
    add     x2, x20, #T_HASH
    bl      quic_cv_put
    add     x0, sp, #CV_MSG
    add     x1, sp, #CV_HASH
    CALL_GLOBAL crypto_sha256
    add     x0, x27, #ST_CERT_PRIV
    add     x1, sp, #CV_HASH
    add     x2, sp, #CV_SIG
    CALL_GLOBAL crypto_p256_sign
    mov     w9, #15
    strb    w9, [x21]
    mov     w9, #0x04                       /* ecdsa_secp256r1_sha256 */
    strb    w9, [x21, #4]
    mov     w9, #0x03
    strb    w9, [x21, #5]
    add     x0, x21, #8
    add     x1, sp, #CV_SIG
    bl      quic_der_sig_put
    mov     x23, x0
    lsr     x9, x23, #8
    strb    w9, [x21, #6]
    strb    w23, [x21, #7]
    add     x1, x23, #4
    add     x0, x21, #1
    bl      quic_put24
    add     x0, x21, #8
    add     x0, x0, x23
    LEAVE   0, CV_FRAME
END_FUNCTION quic_cv_message

/*
 * quic_cv_put(list, server, hash): the ByteList of the content a
 * CertificateVerify signs (RFC 8446 section 4.4.3).
 */
LOCAL_FUNCTION quic_cv_put
    ENTER   0
    mov     x19, x0
    mov     x20, x1
    mov     x21, x2
    mov     x9, #130
    BYTELIST x19, 0, 160, x9
    add     x0, x19, #24
    mov     x9, #0x2020
    movk    x9, #0x2020, lsl #16
    movk    x9, #0x2020, lsl #32
    movk    x9, #0x2020, lsl #48
    mov     x10, #8
1:  str     x9, [x0], #8
    subs    x10, x10, #1
    b.ne    1b
    adr     x1, 610f
    adr     x2, 611f
    cmp     x20, #0
    csel    x1, x2, x1, eq
    mov     x2, #33
    bl      quic_copy
    strb    wzr, [x0], #1
    mov     x1, x21
    mov     x2, #32
    bl      quic_copy
    LEAVE   0
END_FUNCTION quic_cv_put

/* quic_fin_message(dst, secret) -> dst after a Finished message with the MAC of the secret. x20 the TLS block. */
LOCAL_FUNCTION quic_fin_message
    ENTER   0
    mov     x21, x0
    mov     w9, #20
    strb    w9, [x21]
    strb    wzr, [x21, #1]
    strb    wzr, [x21, #2]
    mov     w9, #32
    strb    w9, [x21, #3]
    mov     x0, x1
    add     x1, x21, #4
    bl      quic_finished_mac
    add     x0, x21, #36
    LEAVE   0
END_FUNCTION quic_fin_message

/* ---------------------------------------------------------------- Transport parameters */

/* quic_tp_int(dst, id, v) -> dst after one integer transport parameter. A leaf calling quic_vput through a frame. */
LOCAL_FUNCTION quic_tp_int
    ENTER   0
    mov     x19, x2
    bl      quic_vput
    mov     x20, x0
    mov     x0, x19
    bl      quic_vlen
    mov     x1, x0
    mov     x0, x20
    bl      quic_vput
    mov     x1, x19
    bl      quic_vput
    LEAVE   0
END_FUNCTION quic_tp_int

/*
 * quic_tp_write(dst) -> dst after our transport parameters (RFC 9000 section
 * 18): max_idle_timeout, max_udp_payload_size 1452, the flow control limits,
 * initial_max_streams_bidi, disable_active_migration and
 * initial_source_connection_id; a server adds original_destination_connection_id.
 * x19 the connection.
 */
LOCAL_FUNCTION quic_tp_write
    ENTER   0
    mov     x1, #0x01
    ldr     x2, [x27, #(ST_CONFIG + QUIC_CFG_IDLE)]
    bl      quic_tp_int
    mov     x1, #0x03
    mov     x2, #1452
    bl      quic_tp_int
    mov     x1, #0x04
    ldr     x2, [x27, #(ST_CONFIG + QUIC_CFG_MAX_DATA)]
    bl      quic_tp_int
    mov     x1, #0x05
    ldr     x2, [x27, #(ST_CONFIG + QUIC_CFG_STREAM_DATA)]
    bl      quic_tp_int
    mov     x1, #0x06
    ldr     x2, [x27, #(ST_CONFIG + QUIC_CFG_STREAM_DATA)]
    bl      quic_tp_int
    mov     x1, #0x08
    ldr     x2, [x27, #(ST_CONFIG + QUIC_CFG_MAX_STREAMS)]
    bl      quic_tp_int
    mov     w9, #0x0C                       /* disable_active_migration, empty */
    strb    w9, [x0], #1
    strb    wzr, [x0], #1
    mov     w9, #0x0F                       /* initial_source_connection_id */
    strb    w9, [x0], #1
    mov     w9, #8
    strb    w9, [x0], #1
    add     x1, x19, #C_LCID
    mov     x2, #8
    bl      quic_copy
    ldr     x9, [x19, #C_ROLE]
    cbz     x9, 9f
    strb    wzr, [x0], #1                   /* original_destination_connection_id */
    ldr     x2, [x19, #(C_ODCID + QUIC_CID_LENGTH)]
    strb    w2, [x0], #1
    add     x1, x19, #(C_ODCID + QUIC_CID_ID)
    bl      quic_copy
9:  LEAVE   0
END_FUNCTION quic_tp_write

/* quic_cid_is(p, n, cid) -> 1 when the n bytes at p are the ConnectionId cid. */
LOCAL_FUNCTION quic_cid_is
    ENTER   0
    ldr     x3, [x2, #QUIC_CID_LENGTH]
    add     x2, x2, #QUIC_CID_ID
    bl      quic_bytes_is
    LEAVE   0
END_FUNCTION quic_cid_is

/*
 * quic_tp_read(p, end) -> 0 when the transport parameters of the peer are
 * valid, with their values in the C_P_* fields; else TRANSPORT_PARAMETER_ERROR.
 * Unknown parameters are skipped; each known one may appear once.
 * x19 the connection; x21 position, x22 end, x23 seen bits, x24 id, x25 length, x26 the value end.
 */
LOCAL_FUNCTION quic_tp_read
    ENTER   0
    mov     x21, x0
    mov     x22, x1
    mov     x23, #0
    /* Defaults (RFC 9000 section 18.2). */
    str     xzr, [x19, #C_P_IDLE]
    mov     x9, #65527
    str     x9, [x19, #C_P_UDP]
    str     xzr, [x19, #C_P_MAX_DATA]
    str     xzr, [x19, #C_P_SD_LOCAL]
    str     xzr, [x19, #C_P_SD_REMOTE]
    str     xzr, [x19, #C_P_STREAMS]
    mov     x9, #3
    str     x9, [x19, #C_P_ACK_EXP]
    mov     x9, #25000
    str     x9, [x19, #C_P_ACK_DELAY]
    mov     x9, #2
    str     x9, [x19, #C_P_CID_LIMIT]
1:  cmp     x21, x22
    b.hs    7f
    mov     x0, x21
    mov     x1, x22
    bl      quic_vget
    cbz     x0, 8f
    mov     x24, x1
    mov     x1, x22
    bl      quic_vget
    cbz     x0, 8f
    mov     x25, x1
    sub     x9, x22, x0
    cmp     x25, x9
    b.hi    8f
    mov     x21, x0
    add     x26, x21, x25
    cmp     x24, #0x10
    b.hi    6f                              /* unknown: skip */
    mov     x9, #1
    lsl     x9, x9, x24
    tst     x23, x9
    b.ne    8f
    orr     x23, x23, x9
    cmp     x24, #0x00
    b.eq    10f
    cmp     x24, #0x02
    b.eq    12f
    cmp     x24, #0x0C
    b.eq    13f
    cmp     x24, #0x0D
    b.eq    14f
    cmp     x24, #0x0F
    b.eq    15f
    cmp     x24, #0x10
    b.eq    16f
    /* An integer parameter: one varint that fills the value. */
    mov     x0, x21
    mov     x1, x26
    bl      quic_vget
    cmp     x0, x26
    b.ne    8f
    cmp     x24, #0x01
    b.ne    2f
    str     x1, [x19, #C_P_IDLE]
    b       6f
2:  cmp     x24, #0x03
    b.ne    3f
    cmp     x1, #1200
    b.lo    8f
    str     x1, [x19, #C_P_UDP]
    b       6f
3:  cmp     x24, #0x04
    b.ne    31f
    str     x1, [x19, #C_P_MAX_DATA]
    b       6f
31: cmp     x24, #0x05
    b.ne    32f
    str     x1, [x19, #C_P_SD_LOCAL]
    b       6f
32: cmp     x24, #0x06
    b.ne    33f
    str     x1, [x19, #C_P_SD_REMOTE]
    b       6f
33: cmp     x24, #0x08
    b.ne    34f
    mov     x9, #1
    lsl     x9, x9, #60
    cmp     x1, x9
    b.hi    8f
    str     x1, [x19, #C_P_STREAMS]
    b       6f
34: cmp     x24, #0x09
    b.ne    35f
    mov     x9, #1
    lsl     x9, x9, #60
    cmp     x1, x9
    b.hi    8f
    b       6f
35: cmp     x24, #0x0A
    b.ne    36f
    cmp     x1, #20
    b.hi    8f
    str     x1, [x19, #C_P_ACK_EXP]
    b       6f
36: cmp     x24, #0x0B
    b.ne    37f
    mov     x9, #16384
    cmp     x1, x9
    b.hs    8f
    mov     x9, #1000
    mul     x1, x1, x9
    str     x1, [x19, #C_P_ACK_DELAY]
    b       6f
37: cmp     x24, #0x0E
    b.ne    6f                              /* initial_max_stream_data_uni */
    cmp     x1, #2
    b.lo    8f
    str     x1, [x19, #C_P_CID_LIMIT]
    b       6f
10: ldr     x9, [x19, #C_ROLE]              /* original_destination_connection_id: from a server */
    cbnz    x9, 8f
    mov     x0, x21
    mov     x1, x25
    add     x2, x19, #C_ODCID
    bl      quic_cid_is
    cbz     x0, 8f
    b       6f
12: ldr     x9, [x19, #C_ROLE]              /* stateless_reset_token: from a server */
    cbnz    x9, 8f
    cmp     x25, #16
    b.ne    8f
    ldr     x9, [x21]
    ldr     x10, [x21, #8]
    stp     x9, x10, [x19, #C_RCID_TOKEN]
    ldr     x9, [x19, #C_FLAGS]
    orr     x9, x9, #CF_RESET_TOKEN
    str     x9, [x19, #C_FLAGS]
    b       6f
13: cbnz    x25, 8f                         /* disable_active_migration */
    b       6f
14: ldr     x9, [x19, #C_ROLE]              /* preferred_address: from a server, not used */
    cbnz    x9, 8f
    b       6f
15: mov     x0, x21                         /* initial_source_connection_id */
    mov     x1, x25
    add     x2, x19, #C_ISCID
    bl      quic_cid_is
    cbz     x0, 8f
    b       6f
16: ldr     x9, [x19, #C_ROLE]              /* retry_source_connection_id: from a server after a Retry */
    cbnz    x9, 8f
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_RETRIED
    b.eq    8f
    mov     x0, x21
    mov     x1, x25
    add     x2, x19, #C_RSCID
    bl      quic_cid_is
    cbz     x0, 8f
6:  mov     x21, x26
    b       1b
7:  tst     x23, #(1 << 0x0F)               /* initial_source_connection_id is required */
    b.eq    8f
    ldr     x9, [x19, #C_ROLE]
    cbnz    x9, 71f
    tst     x23, #1                         /* and, from a server, original_destination_connection_id */
    b.eq    8f
    ldr     x9, [x19, #C_FLAGS]
    tst     x9, #CF_RETRIED
    b.eq    71f
    tst     x23, #(1 << 0x10)
    b.eq    8f
71: ldr     x9, [x19, #C_P_MAX_DATA]     /* the connection send limit */
    ldr     x10, [x19, #C_TX_MAX]
    cmp     x9, x10
    csel    x9, x9, x10, hi
    str     x9, [x19, #C_TX_MAX]
    mov     x0, #0
    b       9f
8:  mov     x0, #ERR_TP
9:  LEAVE   0
END_FUNCTION quic_tp_read

/* ---------------------------------------------------------------- Client */

/*
 * quic_client_hello() -> 0 or an error: our ClientHello on the Initial CRYPTO
 * stream: TLS_AES_128_GCM_SHA256, supported_versions TLS 1.3, supported_groups
 * x25519 and secp256r1, signature_algorithms ecdsa_secp256r1_sha256 and ed25519,
 * a key_share of T_GROUP, the ALPN "libp2p", the transport parameters, and the
 * cookie of a HelloRetryRequest. x19 the connection, x20 the TLS block.
 * x21 the message, x22 the extensions.
 */
LOCAL_FUNCTION quic_client_hello
    ENTER   0
    SCR     x21, SC_TLS
    mov     w9, #1
    strb    w9, [x21]
    mov     w9, #3
    strb    w9, [x21, #4]
    strb    w9, [x21, #5]
    ldr     x9, [x20, #T_HRR]
    cbnz    x9, 1f
    add     x0, x20, #T_RANDOM
    mov     x1, #32
    bl      quic_random
1:  add     x0, x21, #6
    add     x1, x20, #T_RANDOM
    mov     x2, #32
    bl      quic_copy
    adr     x1, 614f                        /* session ID, cipher suites, compression */
    mov     x2, #7
    bl      quic_copy
    mov     x22, x0                         /* the extensions length, then the extensions */
    add     x0, x0, #2
    adr     x1, 615f                        /* supported_versions, supported_groups, signature_algorithms, ALPN */
    mov     x2, #(7 + 10 + 10 + 13)
    bl      quic_copy
    mov     x23, x0                         /* key_share: type, length, shares length, group, key length, key */
    mov     x1, #0x0033
    bl      quic_put16
    add     x24, x0, #8                     /* the key */
    ldr     x0, [x20, #T_GROUP]
    mov     x1, x24
    bl      quic_key_share
    sub     x9, x0, x24                     /* the key length */
    mov     x24, x0
    add     x0, x23, #2
    add     x1, x9, #6
    bl      quic_put16
    add     x1, x9, #4
    bl      quic_put16
    ldr     x1, [x20, #T_GROUP]
    bl      quic_put16
    mov     x1, x9
    bl      quic_put16
    mov     x0, x24
    ldr     x9, [x20, #T_COOKIE_LEN]
    cbz     x9, 2f
    mov     x1, #0x002C                     /* cookie */
    bl      quic_put16
    ldr     x1, [x20, #T_COOKIE_LEN]
    add     x1, x1, #2
    bl      quic_put16
    ldr     x1, [x20, #T_COOKIE_LEN]
    bl      quic_put16
    add     x1, x20, #T_COOKIE
    ldr     x2, [x20, #T_COOKIE_LEN]
    bl      quic_copy
2:  mov     x23, x0                         /* quic_transport_parameters */
    mov     x1, #0x0039
    bl      quic_put16
    add     x0, x0, #2
    bl      quic_tp_write
    sub     x1, x0, x23
    sub     x1, x1, #4
    mov     x24, x0
    add     x0, x23, #2
    bl      quic_put16
    sub     x1, x24, x22
    sub     x1, x1, #2
    mov     x0, x22
    bl      quic_put16
    sub     x1, x24, x21
    sub     x1, x1, #4
    add     x0, x21, #1
    bl      quic_put24
    mov     x0, #SPACE_INITIAL
    mov     x1, x21
    sub     x2, x24, x21
    bl      quic_crypto_out
    LEAVE   0
END_FUNCTION quic_client_hello

/*
 * quic_tls_start() -> 0 or an error: the client starts with a ClientHello
 * with an x25519 key share. x19 the connection, x20 the TLS block.
 */
LOCAL_FUNCTION quic_tls_start
    ENTER   0
    mov     x9, #GROUP_X25519
    str     x9, [x20, #T_GROUP]
    mov     x9, #TS_WAIT_SH
    str     x9, [x20, #T_STAGE]
    bl      quic_client_hello
    LEAVE   0
END_FUNCTION quic_tls_start

/*
 * quic_on_server_hello(p, end) -> 0 or an error: a ServerHello or a
 * HelloRetryRequest body. x19 the connection, x20 the TLS block.
 * x21 position, x22 end, x23 HRR, x24 the key share key, x25 its length,
 * x26 the selected group.
 */
LOCAL_FUNCTION quic_on_server_hello
    ENTER   0
    mov     x21, x0
    mov     x22, x1
    mov     x24, #0
    mov     x26, #0
    mov     x1, x22
    bl      quic_rd16
    cbz     x0, 80f
    cmp     x1, #0x0303
    b.ne    81f
    sub     x9, x22, x0
    cmp     x9, #32
    b.lo    80f
    mov     x21, x0
    adr     x2, 602f
    mov     x1, #32
    mov     x3, #32
    bl      quic_bytes_is
    mov     x23, x0
    add     x0, x21, #32
    mov     x1, x22
    bl      quic_rd8                        /* legacy_session_id_echo: we send none */
    cbz     x0, 80f
    cbnz    x1, 81f
    mov     x1, x22
    bl      quic_rd16
    cbz     x0, 80f
    mov     x9, #0x1301
    cmp     x1, x9
    b.ne    81f
    mov     x1, x22
    bl      quic_rd8
    cbz     x0, 80f
    cbnz    x1, 81f
    mov     x1, x22
    bl      quic_rd16
    cbz     x0, 80f
    add     x9, x0, x1
    cmp     x9, x22
    b.ne    80f
    mov     x21, x0
    mov     x25, #0
    mov     x10, #0                         /* supported_versions seen */
    str     x10, [x20, #T_HASH]
1:  cmp     x21, x22
    b.hs    5f
    mov     x0, x21
    mov     x1, x22
    bl      quic_rd16
    cbz     x0, 80f
    mov     x9, x1                          /* type */
    mov     x1, x22
    str     x9, [x20, #(T_HASH + 8)]
    bl      quic_rd16
    cbz     x0, 80f
    add     x10, x0, x1
    cmp     x10, x22
    b.hi    80f
    mov     x21, x10                        /* the next extension */
    ldr     x9, [x20, #(T_HASH + 8)]
    cmp     x9, #0x002B
    b.ne    2f
    cmp     x1, #2
    b.ne    80f
    mov     x1, x21
    bl      quic_rd16
    cmp     x1, #0x0304
    b.ne    82f
    mov     x10, #1
    str     x10, [x20, #T_HASH]
    b       1b
2:  cmp     x9, #0x0033
    b.ne    3f
    mov     x1, x21
    bl      quic_rd16
    cbz     x0, 80f
    mov     x26, x1
    cbnz    x23, 1b                         /* HRR: the group only */
    mov     x1, x21
    bl      quic_rd16
    cbz     x0, 80f
    add     x9, x0, x1
    cmp     x9, x21
    b.ne    80f
    mov     x24, x0
    mov     x25, x1
    b       1b
3:  cmp     x9, #0x002C                     /* cookie, in a HelloRetryRequest */
    b.ne    1b
    cbz     x23, 81f
    mov     x1, x21
    bl      quic_rd16
    cbz     x0, 80f
    cbz     x1, 80f
    cmp     x1, #128
    b.hi    81f
    add     x9, x0, x1
    cmp     x9, x21
    b.ne    80f
    str     x1, [x20, #T_COOKIE_LEN]
    mov     x2, x1
    mov     x1, x0
    add     x0, x20, #T_COOKIE
    bl      quic_copy
    b       1b
5:  ldr     x9, [x20, #T_HASH]
    cbz     x9, 82f
    cbz     x26, 83f
    cbnz    x23, 6f
    ldr     x9, [x20, #T_GROUP]             /* ServerHello */
    cmp     x26, x9
    b.ne    81f
    cbz     x24, 83f
    mov     x0, x24
    mov     x1, x25
    bl      quic_shared
    cbnz    x0, 9f
    mov     x0, #0
    b       9f
6:  ldr     x9, [x20, #T_HRR]               /* HelloRetryRequest: once, for the other group */
    cbnz    x9, 84f
    ldr     x9, [x20, #T_GROUP]
    cmp     x26, x9
    b.eq    81f
    cmp     x26, #GROUP_P256
    b.ne    81f
    str     x26, [x20, #T_GROUP]
    mov     x9, #1
    str     x9, [x20, #T_HRR]
    mov     x0, #2                          /* 2: a HelloRetryRequest to answer */
    b       9f
80: mov     x0, #(TLS_ERR + ALERT_DECODE)
    b       9f
81: mov     x0, #(TLS_ERR + ALERT_ILLEGAL)
    b       9f
82: mov     x0, #(TLS_ERR + ALERT_VERSION)
    b       9f
83: mov     x0, #(TLS_ERR + ALERT_MISSING_EXT)
    b       9f
84: mov     x0, #(TLS_ERR + ALERT_UNEXPECTED)
9:  LEAVE   0
END_FUNCTION quic_on_server_hello

/*
 * quic_message_hash(): after a HelloRetryRequest: the transcript becomes
 * message_hash (254, 0, 0, 32, SHA-256 of ClientHello1) (RFC 8446 section
 * 4.4.1). x20 the TLS block.
 */
LOCAL_FUNCTION quic_message_hash
    ENTER   0
    bl      quic_tls_hash
    mov     w9, #254
    strb    w9, [x20, #T_TRANSCRIPT]
    add     x9, x20, #T_TRANSCRIPT
    strb    wzr, [x9, #1]
    strb    wzr, [x9, #2]
    mov     w9, #32
    strb    w9, [x20, #(T_TRANSCRIPT + 3)]
    add     x0, x20, #(T_TRANSCRIPT + 4)
    add     x1, x20, #T_HASH
    mov     x2, #32
    bl      quic_copy
    mov     x9, #36
    str     x9, [x20, #T_LEN]
    LEAVE   0
END_FUNCTION quic_message_hash

/*
 * quic_on_ee(p, end) -> 0 or an error: EncryptedExtensions must hold the ALPN
 * "libp2p" and the transport parameters. x19 the connection, x20 the TLS block.
 * x21 position, x22 end, x23 seen: 1 ALPN, 2 parameters.
 */
LOCAL_FUNCTION quic_on_ee
    ENTER   0
    mov     x22, x1
    mov     x23, #0
    bl      quic_rd16
    cbz     x0, 80f
    add     x9, x0, x1
    cmp     x9, x22
    b.ne    80f
    mov     x21, x0
1:  cmp     x21, x22
    b.hs    5f
    mov     x0, x21
    mov     x1, x22
    bl      quic_rd16
    cbz     x0, 80f
    mov     x24, x1
    mov     x1, x22
    bl      quic_rd16
    cbz     x0, 80f
    add     x25, x0, x1
    cmp     x25, x22
    b.hi    80f
    mov     x21, x25
    cmp     x24, #0x0010
    b.ne    2f
    mov     x1, x25                         /* ALPN: one protocol, "libp2p" */
    bl      quic_alpn_libp2p
    cbz     x0, 81f
    orr     x23, x23, #1
    b       1b
2:  cmp     x24, #0x0039
    b.ne    1b
    mov     x1, x25
    bl      quic_tp_read
    cbnz    x0, 9f
    orr     x23, x23, #2
    b       1b
5:  tst     x23, #1
    b.eq    82f
    tst     x23, #2
    b.eq    83f
    mov     x0, #0
    b       9f
80: mov     x0, #(TLS_ERR + ALERT_DECODE)
    b       9f
81: mov     x0, #(TLS_ERR + ALERT_NO_ALPN)
    b       9f
82: mov     x0, #(TLS_ERR + ALERT_NO_ALPN)
    b       9f
83: mov     x0, #(TLS_ERR + ALERT_MISSING_EXT)
9:  LEAVE   0
END_FUNCTION quic_on_ee

/*
 * quic_alpn_libp2p(p, end) -> 1 when the ALPN extension data at p lists
 * "libp2p"; else 0.
 */
LOCAL_FUNCTION quic_alpn_libp2p
    ENTER   0
    mov     x20, x1
    bl      quic_rd16
    cbz     x0, 8f
    add     x9, x0, x1
    cmp     x9, x20
    b.ne    8f
    mov     x19, x0
1:  cmp     x19, x20
    b.hs    8f
    mov     x0, x19
    mov     x1, x20
    bl      quic_rd8
    cbz     x0, 8f
    add     x21, x0, x1
    cmp     x21, x20
    b.hi    8f
    adr     x2, 612f
    mov     x3, #6
    bl      quic_bytes_is
    cbnz    x0, 9f
    mov     x19, x21
    b       1b
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_alpn_libp2p

/*
 * quic_sigalgs_ok(p, end) -> 1 when the signature_algorithms extension data at
 * p lists ecdsa_secp256r1_sha256, the scheme we sign with; else 0.
 */
LOCAL_FUNCTION quic_sigalgs_ok
    ENTER   0
    mov     x20, x1
    bl      quic_rd16
    cbz     x0, 8f
    add     x9, x0, x1
    cmp     x9, x20
    b.ne    8f
    mov     x19, x0
1:  mov     x0, x19
    mov     x1, x20
    bl      quic_rd16
    cbz     x0, 8f
    mov     x19, x0
    cmp     x1, #0x0403
    b.ne    1b
    mov     x0, #1
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_sigalgs_ok

/*
 * quic_on_cr(p, end) -> 0 or an error: a CertificateRequest with an empty
 * context, whose signature_algorithms list ecdsa_secp256r1_sha256.
 * x20 the TLS block. x21 position, x22 end, x23 found.
 */
LOCAL_FUNCTION quic_on_cr
    ENTER   0
    mov     x22, x1
    mov     x23, #0
    bl      quic_rd8
    cbz     x0, 80f
    cbnz    x1, 81f
    mov     x1, x22
    bl      quic_rd16
    cbz     x0, 80f
    add     x9, x0, x1
    cmp     x9, x22
    b.ne    80f
    mov     x21, x0
1:  cmp     x21, x22
    b.hs    5f
    mov     x0, x21
    mov     x1, x22
    bl      quic_rd16
    cbz     x0, 80f
    mov     x24, x1
    mov     x1, x22
    bl      quic_rd16
    cbz     x0, 80f
    add     x25, x0, x1
    cmp     x25, x22
    b.hi    80f
    mov     x21, x25
    cmp     x24, #0x000D
    b.ne    1b
    mov     x1, x25
    bl      quic_sigalgs_ok
    orr     x23, x23, x0
    b       1b
5:  cbz     x23, 82f
    mov     x9, #1
    str     x9, [x20, #T_CERT_REQ]
    mov     x0, #0
    b       9f
80: mov     x0, #(TLS_ERR + ALERT_DECODE)
    b       9f
81: mov     x0, #(TLS_ERR + ALERT_ILLEGAL)
    b       9f
82: mov     x0, #(TLS_ERR + ALERT_HANDSHAKE)
9:  LEAVE   0
END_FUNCTION quic_on_cr

/*
 * quic_on_cert(p, end) -> 0 or an error: a Certificate with an empty context
 * and exactly one certificate, which quic_cert_check accepts; T_PEER gets its
 * CertInfo. A dialer then checks the peer ID. x19 the connection, x20 the TLS
 * block. x21 position, x22 end.
 */
LOCAL_FUNCTION quic_on_cert
    ENTER   0
    mov     x22, x1
    bl      quic_rd8
    cbz     x0, 80f
    cbnz    x1, 81f
    mov     x1, x22
    bl      quic_rd24
    cbz     x0, 80f
    add     x9, x0, x1
    cmp     x9, x22
    b.ne    80f
    cbz     x1, 82f                         /* no certificate */
    mov     x1, x22
    bl      quic_rd24
    cbz     x0, 80f
    mov     x21, x0
    add     x23, x0, x1                     /* the end of the certificate */
    mov     x24, x1
    mov     x0, x23
    mov     x1, x22
    bl      quic_rd16                       /* its extensions */
    cbz     x0, 80f
    add     x9, x0, x1
    cmp     x9, x22                         /* one certificate only */
    b.ne    83f
    mov     x0, x21
    mov     x1, x24
    ldr     x2, [x27, #ST_UNIX]
    add     x3, x20, #T_PEER
    mov     x9, #QUIC_CI_FIXED
    str     x9, [x3]
    SCR     x4, SC_CERT
    bl      quic_cert_check
    cbnz    x0, 83f
    ldr     x2, [x20, #(T_PEER + QUIC_CI_HOST_LEN)]   /* the host key, for CONNECTED */
    str     x2, [x19, #C_PEER_KEY_LEN]
    add     x0, x19, #C_PEER_KEY
    add     x1, x20, #(T_PEER + QUIC_CI_HOST)
    bl      quic_copy
    ldr     x9, [x19, #C_ROLE]
    cbnz    x9, 7f
    ldr     x9, [x20, #T_PID_LEN]
    cbz     x9, 7f
    bl      quic_peer_id_ok
    cbz     x0, 84f
7:  mov     x0, #0
    b       9f
80: mov     x0, #(TLS_ERR + ALERT_DECODE)
    b       9f
81: mov     x0, #(TLS_ERR + ALERT_ILLEGAL)
    b       9f
82: mov     x0, #(TLS_ERR + ALERT_CERT_REQUIRED)
    b       9f
83: mov     x0, #(TLS_ERR + ALERT_BAD_CERT)
    b       9f
84: mov     x9, #QUIC_ERR_PEER_ID
    str     x9, [x19, #C_REASON]
    mov     x0, #(TLS_ERR + ALERT_BAD_CERT)
9:  LEAVE   0
END_FUNCTION quic_on_cert

/*
 * quic_peer_id_ok() -> 1 when the peer ID the dialer named is the multihash of
 * the peer's host key: identity for a protobuf of at most 42 bytes, else
 * SHA-256 (libp2p peer IDs). x20 the TLS block.
 */
.set PI_LIST, 0                         /* ByteList: 24 + 128 */
.set PI_ID, 152                         /* 48 bytes */
.set PI_FRAME, 208
LOCAL_FUNCTION quic_peer_id_ok
    ENTER   0, PI_FRAME
    ldr     x21, [x20, #(T_PEER + QUIC_CI_HOST_LEN)]
    cmp     x21, #42
    b.hi    1f
    strb    wzr, [sp, #PI_ID]
    strb    w21, [sp, #(PI_ID + 1)]
    add     x0, sp, #(PI_ID + 2)
    add     x1, x20, #(T_PEER + QUIC_CI_HOST)
    mov     x2, x21
    bl      quic_copy
    add     x22, x21, #2
    b       2f
1:  BYTELIST sp, PI_LIST, 152, x21
    add     x0, sp, #(PI_LIST + 24)
    add     x1, x20, #(T_PEER + QUIC_CI_HOST)
    mov     x2, x21
    bl      quic_copy
    mov     w9, #0x12
    strb    w9, [sp, #PI_ID]
    mov     w9, #0x20
    strb    w9, [sp, #(PI_ID + 1)]
    add     x0, sp, #PI_LIST
    add     x1, sp, #(PI_ID + 2)
    CALL_GLOBAL crypto_sha256
    mov     x22, #34
2:  add     x0, sp, #PI_ID
    mov     x1, x22
    add     x2, x20, #T_PID
    ldr     x3, [x20, #T_PID_LEN]
    bl      quic_bytes_is
    LEAVE   0, PI_FRAME
END_FUNCTION quic_peer_id_ok

/*
 * quic_on_cv(p, end, server) -> 0 or an error: the peer's CertificateVerify
 * signs the transcript hash with the key of its certificate: ecdsa_secp256r1_sha256
 * (DER) for a P-256 key, ed25519 for an Ed25519 key. server 1 when the peer is
 * the server. x20 the TLS block.
 */
.set PV_MSG, 0                          /* ByteList: 24 + 130, room to 160 */
.set PV_HASH, 160
.set PV_SIG, 192
.set PV_KEY, 256                        /* 72 bytes */
.set PV_VALID, 328
.set PV_FRAME, 336
LOCAL_FUNCTION quic_on_cv
    ENTER   0, PV_FRAME
    mov     x21, x0
    mov     x22, x1
    mov     x23, x2
    bl      quic_tls_hash
    add     x0, sp, #PV_MSG
    mov     x1, x23
    add     x2, x20, #T_HASH
    bl      quic_cv_put
    mov     x0, x21
    mov     x1, x22
    bl      quic_rd16
    cbz     x0, 80f
    mov     x24, x1                         /* the scheme */
    mov     x1, x22
    bl      quic_rd16
    cbz     x0, 80f
    add     x9, x0, x1
    cmp     x9, x22
    b.ne    80f
    mov     x21, x0
    mov     x25, x1
    add     x0, sp, #PV_KEY
    add     x1, x20, #(T_PEER + QUIC_CI_KEY)
    mov     x2, #72
    bl      quic_copy
    ldr     x9, [x20, #(T_PEER + QUIC_CI_KIND)]
    cmp     x9, #QUIC_CERT_ED25519
    b.ne    1f
    mov     x10, #0x0807
    cmp     x24, x10
    b.ne    81f
    cmp     x25, #64
    b.ne    81f
    add     x0, sp, #PV_SIG
    mov     x1, x21
    mov     x2, #64
    bl      quic_copy
    add     x0, sp, #PV_KEY
    add     x1, sp, #PV_MSG
    add     x2, sp, #PV_SIG
    add     x3, sp, #PV_VALID
    CALL_GLOBAL crypto_ed25519_verify
    b       2f
1:  cmp     x24, #0x0403
    b.ne    81f
    add     x0, sp, #PV_SIG
    mov     x1, x21
    mov     x2, x25
    bl      quic_der_sig_get
    cbz     x0, 82f
    add     x0, sp, #PV_MSG
    add     x1, sp, #PV_HASH
    CALL_GLOBAL crypto_sha256
    add     x0, sp, #PV_KEY
    add     x1, sp, #PV_HASH
    add     x2, sp, #PV_SIG
    add     x3, sp, #PV_VALID
    CALL_GLOBAL crypto_p256_verify
2:  cbnz    x0, 82f
    ldr     x9, [sp, #PV_VALID]
    cbz     x9, 82f
    mov     x0, #0
    b       9f
80: mov     x0, #(TLS_ERR + ALERT_DECODE)
    b       9f
81: mov     x0, #(TLS_ERR + ALERT_ILLEGAL)
    b       9f
82: mov     x0, #(TLS_ERR + ALERT_DECRYPT)
9:  LEAVE   0, PV_FRAME
END_FUNCTION quic_on_cv

/*
 * quic_on_fin(p, end, secret) -> 0 or an error: the peer's Finished holds the
 * MAC of its handshake traffic secret over the transcript hash.
 * x20 the TLS block.
 */
.set PF_MAC, 0
.set PF_FRAME, 32
LOCAL_FUNCTION quic_on_fin
    ENTER   0, PF_FRAME
    mov     x21, x0
    sub     x9, x1, x0
    cmp     x9, #32
    b.ne    80f
    mov     x0, x2
    add     x1, sp, #PF_MAC
    bl      quic_finished_mac
    mov     x0, x21
    add     x1, sp, #PF_MAC
    mov     x2, #32
    bl      quic_equal
    cbz     x0, 82f
    mov     x0, #0
    b       9f
80: mov     x0, #(TLS_ERR + ALERT_DECODE)
    b       9f
82: mov     x0, #(TLS_ERR + ALERT_DECRYPT)
9:  LEAVE   0, PF_FRAME
END_FUNCTION quic_on_fin

/*
 * quic_client_finish() -> 0 or an error: after the server Finished: the
 * 1-RTT keys, then our Certificate and CertificateVerify when the server asked,
 * and our Finished, on the Handshake CRYPTO stream. The handshake is complete.
 * x19 the connection, x20 the TLS block.
 */
LOCAL_FUNCTION quic_client_finish
    ENTER   0
    bl      quic_app_keys
    ldr     x9, [x20, #T_CERT_REQ]
    cbz     x9, 1f
    SCR     x21, SC_TLS
    mov     x0, x21
    bl      quic_cert_message
    mov     x2, x0
    sub     x2, x2, x21
    mov     x1, x21
    mov     x0, #SPACE_HANDSHAKE
    bl      quic_crypto_out
    cbnz    x0, 9f
    mov     x0, x21
    mov     x1, #0
    bl      quic_cv_message
    sub     x2, x0, x21
    mov     x1, x21
    mov     x0, #SPACE_HANDSHAKE
    bl      quic_crypto_out
    cbnz    x0, 9f
1:  SCR     x21, SC_TLS
    mov     x0, x21
    add     x1, x20, #T_C_HS
    bl      quic_fin_message
    sub     x2, x0, x21
    mov     x1, x21
    mov     x0, #SPACE_HANDSHAKE
    bl      quic_crypto_out
    cbnz    x0, 9f
    bl      quic_handshake_complete
    mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_client_finish

/* ---------------------------------------------------------------- Server */

/*
 * quic_on_client_hello(p, end) -> 0, 2 when a HelloRetryRequest is to be sent,
 * or an error. x19 the connection, x20 the TLS block.
 * x21 position, x22 end, x23 flags: 1 TLS 1.3, 2 cipher, 4 signature, 8 ALPN,
 * 16 parameters, 32 x25519 group, 64 secp256r1 group, 128 key share;
 * x24 the key share key, x25 its length, x26 its group.
 */
LOCAL_FUNCTION quic_on_client_hello
    ENTER   0
    mov     x22, x1
    mov     x23, #0
    mov     x24, #0
    mov     x26, #0
    bl      quic_rd16
    cbz     x0, 80f
    cmp     x1, #0x0303
    b.ne    81f
    sub     x9, x22, x0
    cmp     x9, #32
    b.lo    80f
    add     x0, x0, #32                     /* random */
    mov     x1, x22
    bl      quic_rd8                        /* legacy_session_id: must be empty in QUIC */
    cbz     x0, 80f
    cbnz    x1, 85f
    mov     x1, x22
    bl      quic_rd16                       /* cipher_suites */
    cbz     x0, 80f
    add     x21, x0, x1
    cmp     x21, x22
    b.hi    80f
    mov     x25, x21
1:  cmp     x0, x25
    b.hs    2f
    mov     x1, x25
    bl      quic_rd16
    cbz     x0, 80f
    mov     x9, #0x1301
    cmp     x1, x9
    b.ne    1b
    orr     x23, x23, #2
    b       1b
2:  mov     x0, x21
    mov     x1, x22
    bl      quic_rd8                        /* legacy_compression_methods: null only */
    cbz     x0, 80f
    cmp     x1, #1
    b.ne    81f
    mov     x1, x22
    bl      quic_rd8
    cbz     x0, 80f
    cbnz    x1, 81f
    mov     x1, x22
    bl      quic_rd16
    cbz     x0, 80f
    add     x9, x0, x1
    cmp     x9, x22
    b.ne    80f
    mov     x21, x0
3:  cmp     x21, x22
    b.hs    6f
    mov     x0, x21
    mov     x1, x22
    bl      quic_rd16
    cbz     x0, 80f
    str     x1, [x20, #(T_HASH + 8)]
    mov     x1, x22
    bl      quic_rd16
    cbz     x0, 80f
    add     x9, x0, x1
    cmp     x9, x22
    b.hi    80f
    mov     x21, x9                         /* the next extension */
    str     x9, [x20, #(T_HASH + 16)]
    ldr     x10, [x20, #(T_HASH + 8)]
    cmp     x10, #0x002B
    b.eq    31f
    cmp     x10, #0x000A
    b.eq    32f
    cmp     x10, #0x0033
    b.eq    33f
    cmp     x10, #0x000D
    b.eq    34f
    cmp     x10, #0x0010
    b.eq    35f
    cmp     x10, #0x0039
    b.eq    36f
    b       3b
31: mov     x1, x21                         /* supported_versions */
    bl      quic_rd8
    cbz     x0, 80f
    add     x25, x0, x1
    cmp     x25, x21
    b.ne    80f
4:  cmp     x0, x25
    b.hs    3b
    mov     x1, x25
    bl      quic_rd16
    cbz     x0, 80f
    cmp     x1, #0x0304
    b.ne    4b
    orr     x23, x23, #1
    b       4b
32: mov     x1, x21                         /* supported_groups */
    bl      quic_rd16
    cbz     x0, 80f
    add     x25, x0, x1
    cmp     x25, x21
    b.ne    80f
5:  cmp     x0, x25
    b.hs    3b
    mov     x1, x25
    bl      quic_rd16
    cbz     x0, 80f
    cmp     x1, #GROUP_X25519
    b.ne    51f
    orr     x23, x23, #32
51: cmp     x1, #GROUP_P256
    b.ne    5b
    orr     x23, x23, #64
    b       5b
33: mov     x1, x21                         /* key_share: x25519 first, then secp256r1 */
    bl      quic_rd16
    cbz     x0, 80f
    add     x25, x0, x1
    cmp     x25, x21
    b.ne    80f
7:  cmp     x0, x25
    b.hs    3b
    mov     x1, x25
    bl      quic_rd16
    cbz     x0, 80f
    mov     x9, x1
    mov     x1, x25
    str     x9, [x20, #(T_HASH + 24)]
    bl      quic_rd16
    cbz     x0, 80f
    add     x10, x0, x1
    cmp     x10, x25
    b.hi    80f
    ldr     x9, [x20, #(T_HASH + 24)]
    cmp     x9, #GROUP_X25519
    b.ne    71f
    cmp     x1, #32
    b.ne    72f
    mov     x24, x0                         /* x25519 wins */
    mov     x26, x9
    orr     x23, x23, #128
    b       72f
71: cmp     x9, #GROUP_P256
    b.ne    72f
    cmp     x26, #GROUP_X25519
    b.eq    72f
    cmp     x1, #65
    b.ne    72f
    mov     x24, x0
    mov     x26, x9
    orr     x23, x23, #128
72: mov     x0, x10
    b       7b
34: mov     x1, x21                         /* signature_algorithms */
    bl      quic_sigalgs_ok
    cbz     x0, 3b
    orr     x23, x23, #4
    b       3b
35: mov     x1, x21                         /* ALPN */
    bl      quic_alpn_libp2p
    cbz     x0, 3b
    orr     x23, x23, #8
    b       3b
36: mov     x1, x21                         /* quic_transport_parameters */
    bl      quic_tp_read
    cbnz    x0, 9f
    orr     x23, x23, #16
    b       3b
6:  tst     x23, #1
    b.eq    82f
    tst     x23, #2
    b.eq    83f
    tst     x23, #4
    b.eq    83f
    tst     x23, #8
    b.eq    84f
    tst     x23, #16
    b.eq    86f
    tbz     x23, #7, 61f                    /* no usable key share */
    str     x26, [x20, #T_GROUP]
    mov     x0, x26
    cmp     x0, #GROUP_X25519
    mov     x1, #32
    mov     x2, #65
    csel    x1, x1, x2, eq
    mov     x0, x24
    str     x0, [x20, #(T_HASH + 16)]
    str     x1, [x20, #(T_HASH + 24)]
    mov     x0, #0
    b       9f
61: ldr     x9, [x20, #T_HRR]               /* after a HelloRetryRequest the share must be there */
    cbnz    x9, 81f
    mov     x9, #GROUP_X25519
    tst     x23, #32
    b.ne    62f
    mov     x9, #GROUP_P256
    tst     x23, #64
    b.eq    83f
62: str     x9, [x20, #T_GROUP]
    mov     x0, #2
    b       9f
80: mov     x0, #(TLS_ERR + ALERT_DECODE)
    b       9f
81: mov     x0, #(TLS_ERR + ALERT_ILLEGAL)
    b       9f
82: mov     x0, #(TLS_ERR + ALERT_VERSION)
    b       9f
83: mov     x0, #(TLS_ERR + ALERT_HANDSHAKE)
    b       9f
84: mov     x0, #(TLS_ERR + ALERT_NO_ALPN)
    b       9f
85: mov     x0, #ERR_PROTOCOL
    b       9f
86: mov     x0, #(TLS_ERR + ALERT_MISSING_EXT)
9:  LEAVE   0
END_FUNCTION quic_on_client_hello

/*
 * quic_server_hello(hrr) -> 0 or an error: a ServerHello with our key share,
 * or a HelloRetryRequest for T_GROUP when hrr is 1, on the Initial CRYPTO
 * stream. x19 the connection, x20 the TLS block. x21 the message, x22 the extensions.
 */
LOCAL_FUNCTION quic_server_hello
    ENTER   0
    mov     x23, x0
    SCR     x21, SC_TLS
    mov     w9, #2
    strb    w9, [x21]
    mov     w9, #3
    strb    w9, [x21, #4]
    strb    w9, [x21, #5]
    add     x0, x21, #6
    cbz     x23, 1f
    adr     x1, 602f
    mov     x2, #32
    bl      quic_copy
    b       2f
1:  mov     x1, #32
    bl      quic_random
2:  add     x0, x21, #38
    strb    wzr, [x0], #1                   /* legacy_session_id_echo: empty */
    mov     x1, #0x1301
    bl      quic_put16
    strb    wzr, [x0], #1
    mov     x22, x0
    add     x0, x0, #2
    mov     x1, #0x002B
    bl      quic_put16
    mov     x1, #2
    bl      quic_put16
    mov     x1, #0x0304
    bl      quic_put16
    mov     x1, #0x0033
    bl      quic_put16
    cbz     x23, 3f
    mov     x1, #2
    bl      quic_put16
    ldr     x1, [x20, #T_GROUP]
    bl      quic_put16
    b       4f
3:  mov     x24, x0
    add     x0, x0, #6
    ldr     x9, [x20, #T_GROUP]
    mov     x1, x0
    mov     x0, x9
    bl      quic_key_share
    add     x9, x24, #6
    sub     x25, x0, x9                     /* the key length */
    mov     x26, x0
    mov     x0, x24
    add     x1, x25, #4
    bl      quic_put16
    ldr     x1, [x20, #T_GROUP]
    bl      quic_put16
    mov     x1, x25
    bl      quic_put16
    mov     x0, x26
4:  mov     x24, x0
    sub     x1, x24, x22
    sub     x1, x1, #2
    mov     x0, x22
    bl      quic_put16
    sub     x1, x24, x21
    sub     x1, x1, #4
    add     x0, x21, #1
    bl      quic_put24
    mov     x0, #SPACE_INITIAL
    mov     x1, x21
    sub     x2, x24, x21
    bl      quic_crypto_out
    LEAVE   0
END_FUNCTION quic_server_hello

/*
 * quic_server_flight() -> 0 or an error: after ClientHello: ServerHello, the
 * handshake keys, then EncryptedExtensions, CertificateRequest, Certificate,
 * CertificateVerify and Finished on the Handshake CRYPTO stream, and the
 * 1-RTT keys. x19 the connection, x20 the TLS block. x21 the message.
 */
LOCAL_FUNCTION quic_server_flight
    ENTER   0
    mov     x0, #0                          /* ServerHello draws our key share first */
    bl      quic_server_hello
    cbnz    x0, 9f
    ldr     x0, [x20, #(T_HASH + 16)]       /* the client key share */
    ldr     x1, [x20, #(T_HASH + 24)]
    bl      quic_shared
    cbnz    x0, 9f
    bl      quic_handshake_keys
    /* EncryptedExtensions: ALPN libp2p and the transport parameters. */
    SCR     x21, SC_TLS
    mov     w9, #8
    strb    w9, [x21]
    add     x0, x21, #6
    adr     x1, 616f
    mov     x2, #13
    bl      quic_copy
    mov     x22, x0
    mov     x1, #0x0039
    bl      quic_put16
    add     x0, x0, #2
    bl      quic_tp_write
    mov     x23, x0
    sub     x1, x23, x22
    sub     x1, x1, #4
    add     x0, x22, #2
    bl      quic_put16
    sub     x1, x23, x21
    sub     x1, x1, #6
    add     x0, x21, #4
    bl      quic_put16
    sub     x1, x23, x21
    sub     x1, x1, #4
    add     x0, x21, #1
    bl      quic_put24
    mov     x0, #SPACE_HANDSHAKE
    mov     x1, x21
    sub     x2, x23, x21
    bl      quic_crypto_out
    cbnz    x0, 9f
    /* CertificateRequest: empty context, signature_algorithms. */
    mov     x0, #SPACE_HANDSHAKE
    adr     x1, 617f
    mov     x2, #17
    bl      quic_crypto_out
    cbnz    x0, 9f
    mov     x0, x21
    bl      quic_cert_message
    sub     x2, x0, x21
    mov     x1, x21
    mov     x0, #SPACE_HANDSHAKE
    bl      quic_crypto_out
    cbnz    x0, 9f
    mov     x0, x21
    mov     x1, #1
    bl      quic_cv_message
    sub     x2, x0, x21
    mov     x1, x21
    mov     x0, #SPACE_HANDSHAKE
    bl      quic_crypto_out
    cbnz    x0, 9f
    mov     x0, x21
    add     x1, x20, #T_S_HS
    bl      quic_fin_message
    sub     x2, x0, x21
    mov     x1, x21
    mov     x0, #SPACE_HANDSHAKE
    bl      quic_crypto_out
    cbnz    x0, 9f
    bl      quic_app_keys
    mov     x9, #TS_WAIT_CCERT
    str     x9, [x20, #T_STAGE]
    mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_server_flight

/* ---------------------------------------------------------------- Messages in */

/*
 * quic_tls_message(space, type, p, end) -> 0 or an error: one handshake
 * message from the peer (p the body, end its end; the whole message is at
 * p - 4) in the order of the stage. x19 the connection, x20 the TLS block.
 * x21 space, x22 type, x23 body, x24 end.
 */
LOCAL_FUNCTION quic_tls_message
    ENTER   0
    mov     x21, x0
    mov     x22, x1
    mov     x23, x2
    mov     x24, x3
    cbz     x20, 30f                        /* after the handshake */
    ldr     x9, [x20, #T_STAGE]
    cmp     x9, #TS_WAIT_SH
    b.eq    1f
    cmp     x9, #TS_WAIT_EE
    b.eq    2f
    cmp     x9, #TS_WAIT_CERT_CR
    b.eq    3f
    cmp     x9, #TS_WAIT_CERT
    b.eq    4f
    cmp     x9, #TS_WAIT_CV
    b.eq    5f
    cmp     x9, #TS_WAIT_FIN
    b.eq    6f
    cmp     x9, #TS_WAIT_CH
    b.eq    7f
    cmp     x9, #TS_WAIT_CCERT
    b.eq    8f
    b       30f
1:  cmp     x21, #SPACE_INITIAL             /* client: ServerHello */
    b.ne    90f
    cmp     x22, #2
    b.ne    90f
    mov     x0, x23
    mov     x1, x24
    bl      quic_on_server_hello
    cmp     x0, #2
    b.eq    11f
    cbnz    x0, 99f
    bl      quic_append_in
    cbnz    x0, 99f
    bl      quic_handshake_keys
    mov     x9, #TS_WAIT_EE
    str     x9, [x20, #T_STAGE]
    b       98f
11: bl      quic_message_hash               /* HelloRetryRequest */
    bl      quic_append_in
    cbnz    x0, 99f
    bl      quic_client_hello
    b       99f
2:  cmp     x21, #SPACE_HANDSHAKE           /* client: EncryptedExtensions */
    b.ne    90f
    cmp     x22, #8
    b.ne    90f
    mov     x0, x23
    mov     x1, x24
    bl      quic_on_ee
    cbnz    x0, 99f
    mov     x9, #TS_WAIT_CERT_CR
    b       97f
3:  cmp     x21, #SPACE_HANDSHAKE           /* client: CertificateRequest or Certificate */
    b.ne    90f
    cmp     x22, #13
    b.ne    4f
    mov     x0, x23
    mov     x1, x24
    bl      quic_on_cr
    cbnz    x0, 99f
    mov     x9, #TS_WAIT_CERT
    b       97f
4:  cmp     x21, #SPACE_HANDSHAKE           /* client: Certificate */
    b.ne    90f
    cmp     x22, #11
    b.ne    90f
    mov     x0, x23
    mov     x1, x24
    bl      quic_on_cert
    cbnz    x0, 99f
    mov     x9, #TS_WAIT_CV
    b       97f
5:  cmp     x21, #SPACE_HANDSHAKE           /* both: CertificateVerify */
    b.ne    90f
    cmp     x22, #15
    b.ne    90f
    ldr     x9, [x19, #C_ROLE]
    mov     x2, #1
    cmp     x9, #0
    csel    x2, x2, xzr, eq                 /* the peer is the server when we are the client */
    mov     x0, x23
    mov     x1, x24
    bl      quic_on_cv
    cbnz    x0, 99f
    mov     x9, #TS_WAIT_FIN
    b       97f
6:  cmp     x21, #SPACE_HANDSHAKE           /* both: Finished */
    b.ne    90f
    cmp     x22, #20
    b.ne    90f
    ldr     x9, [x19, #C_ROLE]
    add     x2, x20, #T_S_HS
    add     x10, x20, #T_C_HS
    cmp     x9, #0
    csel    x2, x2, x10, eq
    mov     x0, x23
    mov     x1, x24
    bl      quic_on_fin
    cbnz    x0, 99f
    bl      quic_append_in
    cbnz    x0, 99f
    ldr     x9, [x19, #C_ROLE]
    cbnz    x9, 61f
    bl      quic_client_finish
    b       99f
61: bl      quic_handshake_complete         /* server: the client is verified */
    mov     x0, #0
    b       99f
7:  cmp     x21, #SPACE_INITIAL             /* server: ClientHello */
    b.ne    90f
    cmp     x22, #1
    b.ne    90f
    mov     x0, x23
    mov     x1, x24
    bl      quic_on_client_hello
    cmp     x0, #2
    b.eq    71f
    cbnz    x0, 99f
    bl      quic_append_in
    cbnz    x0, 99f
    bl      quic_server_flight
    b       99f
71: bl      quic_append_in                  /* HelloRetryRequest */
    cbnz    x0, 99f
    bl      quic_message_hash
    mov     x9, #1
    str     x9, [x20, #T_HRR]
    mov     x0, #1
    bl      quic_server_hello
    b       99f
8:  cmp     x21, #SPACE_HANDSHAKE           /* server: the client Certificate */
    b.ne    90f
    cmp     x22, #11
    b.ne    90f
    mov     x0, x23
    mov     x1, x24
    bl      quic_on_cert
    cbnz    x0, 99f
    mov     x9, #TS_WAIT_CV
    b       97f
30: cmp     x22, #4                         /* after the handshake: NewSessionTicket only, ignored */
    b.ne    90f
    ldr     x9, [x19, #C_ROLE]
    cbnz    x9, 90f
    cmp     x21, #SPACE_APP
    b.ne    90f
    mov     x0, #0
    b       99f
97: str     x9, [x20, #T_STAGE]
    bl      quic_append_in
    b       99f
98: mov     x0, #0
    b       99f
90: mov     x0, #(TLS_ERR + ALERT_UNEXPECTED)
99: LEAVE   0
END_FUNCTION quic_tls_message

/* quic_append_in() -> 0 or an error: the message at x23 - 4 to x24 goes into the transcript. */
LOCAL_FUNCTION quic_append_in
    ENTER   0
    sub     x0, x23, #4
    sub     x1, x24, x0
    bl      quic_tls_append
    LEAVE   0
END_FUNCTION quic_append_in

/*
 * quic_handshake_complete(): the TLS handshake is complete (RFC 9001 section
 * 4.1.1). A server confirms it at once and sends HANDSHAKE_DONE; the
 * application hears CONNECTED. x19 the connection, x20 the TLS block.
 */
LOCAL_FUNCTION quic_handshake_complete
    ENTER   0
    mov     x9, #TS_DONE
    str     x9, [x20, #T_STAGE]
    ldr     x9, [x19, #C_FLAGS]
    mov     x11, #(CF_COMPLETE | CF_TELL)
    orr     x9, x9, x11
    ldr     x10, [x19, #C_ROLE]
    cbz     x10, 1f
    mov     x11, #(CF_CONFIRMED | CF_DONE_FRAME)
    orr     x9, x9, x11
1:  str     x9, [x19, #C_FLAGS]
    mov     x9, #CS_ACTIVE
    str     x9, [x19, #C_STATE]
    ldr     x10, [x19, #C_ROLE]
    cbz     x10, 2f
    mov     x0, #SPACE_HANDSHAKE
    bl      quic_discard_space
2:  LEAVE   0
END_FUNCTION quic_handshake_complete

/*
 * quic_tls_feed(space) -> 0 or an error: the complete handshake messages at
 * the start of the CRYPTO receive data of the space go to quic_tls_message in
 * order; the rest stays. x19 the connection.
 * x21 the space, x22 the block, x23 the contiguous end.
 */
LOCAL_FUNCTION quic_tls_feed
    ENTER   0
    mov     x21, #SP_SIZE
    madd    x21, x0, x21, x19
    add     x21, x21, #C_SPACES
    mov     x25, x0
1:  ldr     x22, [x21, #SP_CRX]
    cbz     x22, 8f
    add     x22, x27, x22
    ldr     x9, [x21, #SP_CRX_NR]
    cbz     x9, 8f
    ldr     x10, [x21, #SP_CRX_RANGES]      /* the first range must start at 0 */
    cbnz    x10, 8f
    ldr     x23, [x21, #(SP_CRX_RANGES + 8)]
    ldr     x24, [x21, #SP_CRX_DONE]
    sub     x9, x23, x24
    cmp     x9, #4
    b.lo    8f
    add     x0, x22, x24
    add     x0, x0, #1
    bl      quic_get24
    mov     x26, x0                         /* the body length */
    add     x9, x24, #4
    add     x9, x9, x26                     /* the message end */
    cmp     x9, #CRYPTO_ROOM
    b.hi    7f
    cmp     x9, x23
    b.hi    8f
    str     x9, [x21, #SP_CRX_DONE]
    ldr     x10, [x19, #C_TLS]
    mov     x20, #0
    cbz     x10, 2f
    add     x20, x27, x10
2:  mov     x0, x25
    ldrb    w1, [x22, x24]
    add     x2, x22, x24
    add     x2, x2, #4
    add     x3, x2, x26
    bl      quic_tls_message
    cbnz    x0, 9f
    bl      quic_crx_compact
    b       1b
7:  mov     x0, #ERR_CRYPTO_BUFFER
    b       9f
8:  mov     x0, #0
9:  LEAVE   0
END_FUNCTION quic_tls_feed

/*
 * quic_crx_compact(): moves the CRYPTO data not yet taken to the start of the
 * block. x21 the space.
 */
LOCAL_FUNCTION quic_crx_compact
    ENTER   0
    ldr     x22, [x21, #SP_CRX]
    add     x22, x27, x22
    ldr     x23, [x21, #SP_CRX_DONE]
    cbz     x23, 9f
    ldr     x24, [x21, #SP_CRX_NR]
    sub     x9, x24, #1                     /* the end of the last range */
    add     x10, x21, #SP_CRX_RANGES
    add     x10, x10, x9, lsl #4
    ldr     x25, [x10, #8]
    mov     x0, x22
    add     x1, x22, x23
    sub     x2, x25, x23
    bl      quic_copy
    add     x10, x21, #SP_CRX_RANGES        /* shift the ranges */
    mov     x11, #0
1:  cmp     x11, x24
    b.hs    2f
    ldp     x12, x13, [x10]
    subs    x12, x12, x23
    csel    x12, xzr, x12, lo
    sub     x13, x13, x23
    stp     x12, x13, [x10], #16
    add     x11, x11, #1
    b       1b
2:  ldr     x9, [x21, #SP_CRX_BASE]
    add     x9, x9, x23
    str     x9, [x21, #SP_CRX_BASE]
    str     xzr, [x21, #SP_CRX_DONE]
    ldp     x12, x13, [x21, #SP_CRX_RANGES] /* an empty first range goes */
    cmp     x12, x13
    b.lo    9f
    sub     x24, x24, #1
    str     x24, [x21, #SP_CRX_NR]
    add     x0, x21, #SP_CRX_RANGES
    add     x1, x0, #16
    lsl     x2, x24, #4
    bl      quic_copy
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
