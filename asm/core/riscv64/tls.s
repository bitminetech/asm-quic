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
 * s1 the connection, s2 the TLS block, in the functions that take them.
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

/* quic_rd8(p, end) -> a0 p + 1, or 0 past end; a1 the byte. A leaf. */
LOCAL_FUNCTION quic_rd8
    UNWIND_END_PROLOGUE
    bgeu    a0, a1, 8f
    lbu     a1, 0(a0)
    addi    a0, a0, 1
    ret
8:  li      a0, 0
    ret
END_FUNCTION quic_rd8

/* quic_rd16(p, end) -> a0 p + 2, or 0 past end; a1 the big-endian value. A leaf. */
LOCAL_FUNCTION quic_rd16
    UNWIND_END_PROLOGUE
    sub     a2, a1, a0
    bgeu    a0, a1, 8f
    li      a5, 2
    bltu    a2, a5, 8f
    lbu     a3, 0(a0)
    lbu     a4, 1(a0)
    slli    a3, a3, 8
    or      a1, a4, a3
    addi    a0, a0, 2
    ret
8:  li      a0, 0
    ret
END_FUNCTION quic_rd16

/* quic_rd24(p, end) -> a0 p + 3, or 0 past end; a1 the big-endian value. A leaf. */
LOCAL_FUNCTION quic_rd24
    UNWIND_END_PROLOGUE
    sub     a2, a1, a0
    bgeu    a0, a1, 8f
    li      a6, 3
    bltu    a2, a6, 8f
    lbu     a3, 0(a0)
    lbu     a4, 1(a0)
    lbu     a5, 2(a0)
    slli    a3, a3, 16
    slli    a4, a4, 8
    or      a3, a3, a4
    or      a1, a3, a5
    addi    a0, a0, 3
    ret
8:  li      a0, 0
    ret
END_FUNCTION quic_rd24

/* ---------------------------------------------------------------- Transcript and key schedule */

/* quic_tls_append(msg, n) -> 0, or an error when the transcript has no room. s2 the TLS block. */
LOCAL_FUNCTION quic_tls_append
    ENTER   0
    mv      s1, a0
    ld      t0, T_LEN(s2)
    add     t1, t0, a1
    li      t2, TRANSCRIPT_ROOM
    bltu    t2, t1, 8f
    sd      t1, T_LEN(s2)
    addi    a0, s2, T_TRANSCRIPT
    add     a0, a0, t0
    mv      a2, a1
    mv      a1, s1
    call    quic_copy
    li      a0, 0
    j       9f
8:  li      a0, (TLS_ERR + ALERT_INTERNAL)
9:  LEAVE   0
END_FUNCTION quic_tls_append

/* quic_tls_hash(): T_HASH = SHA-256 of the transcript. s2 the TLS block. */
LOCAL_FUNCTION quic_tls_hash
    ENTER   0
    addi    a0, s2, T_LIST
    addi    a1, s2, T_HASH
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
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    li      t1, 32
    BYTELIST sp, (FL + HX_SALT), 56, t1
    BYTELIST sp, (FL + HX_IKM), 56, t1
    addi    a0, sp, (FL + HX_SALT + 24)
    li      a1, 32
    call    quic_zero
    addi    a0, sp, (FL + HX_IKM + 24)
    li      a1, 32
    call    quic_zero
    beqz    s1, 1f
    addi    a0, sp, (FL + HX_SALT + 24)
    mv      a1, s1
    li      a2, 32
    call    quic_copy
1:  beqz    s2, 2f
    addi    a0, sp, (FL + HX_IKM + 24)
    mv      a1, s2
    li      a2, 32
    call    quic_copy
2:  li      t0, 160
    sd      t0, (FL + HX_SCRATCH)(sp)
    addi    a0, sp, (FL + HX_SALT)
    addi    a1, sp, (FL + HX_IKM)
    addi    a2, sp, (FL + HX_SCRATCH)
    mv      a3, s3
    CALL_GLOBAL crypto_hkdf_extract
    LEAVE   0, HX_FRAME
END_FUNCTION quic_hkdf_extract

/*
 * quic_derive_secret(secret, label, label_len, out): Derive-Secret of RFC 8446
 * section 7.1 with the hash of the transcript as it is. s2 the TLS block.
 */
LOCAL_FUNCTION quic_derive_secret
    ENTER   0
    mv      s3, a0
    mv      s4, a1
    mv      s5, a2
    mv      s6, a3
    call    quic_tls_hash
    mv      a0, s3
    mv      a1, s4
    mv      a2, s5
    addi    a3, s2, T_HASH
    li      a4, 32
    li      a5, 32
    mv      a6, s6
    call    quic_expand_label
    LEAVE   0
END_FUNCTION quic_derive_secret

/*
 * quic_finished_mac(secret, out): out = HMAC(finished_key, the transcript
 * hash), with finished_key = HKDF-Expand-Label(secret, "finished", "", 32).
 * s2 the TLS block.
 */
.set FM_KEY, 0                          /* ByteList: 24 + 32 */
.set FM_MSG, 56                         /* ByteList: 24 + 32 */
.set FM_SCRATCH, 112                    /* HmacScratch: 160 bytes */
.set FM_FRAME, 272
LOCAL_FUNCTION quic_finished_mac
    ENTER   0, FM_FRAME
    mv      s3, a0
    mv      s4, a1
    li      t1, 32
    BYTELIST sp, (FL + FM_KEY), 56, t1
    BYTELIST sp, (FL + FM_MSG), 56, t1
    mv      a0, s3
    lla     a1, 608f
    li      a2, 8
    li      a3, 0
    li      a4, 0
    li      a5, 32
    addi    a6, sp, (FL + FM_KEY + 24)
    call    quic_expand_label
    call    quic_tls_hash
    addi    a0, sp, (FL + FM_MSG + 24)
    addi    a1, s2, T_HASH
    li      a2, 32
    call    quic_copy
    li      t0, 160
    sd      t0, (FL + FM_SCRATCH)(sp)
    addi    a0, sp, (FL + FM_KEY)
    addi    a1, sp, (FL + FM_MSG)
    addi    a2, sp, (FL + FM_SCRATCH)
    mv      a3, s4
    CALL_GLOBAL crypto_hmac_sha256
    LEAVE   0, FM_FRAME
END_FUNCTION quic_finished_mac

/*
 * quic_handshake_keys(): after ServerHello: the handshake secret from the
 * shared secret, the two handshake traffic secrets, and the Handshake keys
 * of both directions. s1 the connection, s2 the TLS block.
 */
LOCAL_FUNCTION quic_handshake_keys
    ENTER   0
    lla     a0, 600f
    addi    a1, s2, T_SHARED
    addi    a2, s2, T_HS_SECRET
    call    quic_hkdf_extract
    addi    a0, s2, T_HS_SECRET
    lla     a1, 603f
    li      a2, 12
    addi    a3, s2, T_C_HS
    call    quic_derive_secret
    addi    a0, s2, T_HS_SECRET
    lla     a1, 604f
    li      a2, 12
    addi    a3, s2, T_S_HS
    call    quic_derive_secret
    li      a0, SPACE_HANDSHAKE
    addi    a1, s2, T_C_HS
    addi    a2, s2, T_S_HS
    call    quic_install_keys
    /* The master secret, for later. */
    addi    a0, s2, T_HS_SECRET
    lla     a1, 607f
    li      a2, 7
    lla     a3, 601f
    li      a4, 32
    li      a5, 32
    addi    a6, s2, T_MASTER
    call    quic_expand_label
    addi    a0, s2, T_MASTER
    li      a1, 0
    addi    a2, s2, T_MASTER
    call    quic_hkdf_extract
    LEAVE   0
END_FUNCTION quic_handshake_keys

/*
 * quic_app_keys(): after the server Finished is in the transcript: the
 * application traffic secrets, kept in C_APP_SECRETS, and the 1-RTT keys.
 * s1 the connection, s2 the TLS block.
 */
LOCAL_FUNCTION quic_app_keys
    ENTER   0
    addi    a0, s2, T_MASTER
    lla     a1, 605f
    li      a2, 12
    ADDX    a3, s1, C_APP_SECRETS
    call    quic_derive_secret
    addi    a0, s2, T_MASTER
    lla     a1, 606f
    li      a2, 12
    ADDX    a3, s1, (C_APP_SECRETS + 32)
    call    quic_derive_secret
    li      a0, SPACE_APP
    ADDX    a1, s1, C_APP_SECRETS
    ADDX    a2, s1, (C_APP_SECRETS + 32)
    call    quic_install_keys
    call    quic_next_rx_keys
    LEAVE   0
END_FUNCTION quic_app_keys

/*
 * quic_install_keys(space, client_secret, server_secret): the receive and send
 * keys of a space for our role. s1 the connection.
 */
LOCAL_FUNCTION quic_install_keys
    ENTER   0
    li      t0, SP_SIZE
    mul     s3, a0, t0
    add     s3, s3, s1
    addi    s3, s3, C_SPACES                # the space
    ld      t0, C_ROLE(s1)
    mv      s4, a1                          # receive: the peer's secret
    mv      s5, a2                          # send: ours
    bnez    t0, 1f
    mv      s4, a2
    mv      s5, a1
1:  mv      a0, s4
    addi    a1, s3, SP_RX_KEYS
    call    quic_derive_keys
    mv      a0, s5
    addi    a1, s3, SP_TX_KEYS
    call    quic_derive_keys
    ld      t0, SP_FLAGS(s3)
    ori     t0, t0, (SPF_RX | SPF_TX)
    sd      t0, SP_FLAGS(s3)
    LEAVE   0
END_FUNCTION quic_install_keys

/*
 * quic_next_rx_keys(): C_NEXT_RX = the receive keys of the next key phase:
 * the key and IV of HKDF-Expand-Label(the peer's secret, "quic ku", "", 32),
 * and the same header protection key (RFC 9001 section 6). s1 the connection.
 */
.set NK_SECRET, 0
.set NK_KEYS, 32
.set NK_FRAME, 80
LOCAL_FUNCTION quic_next_rx_keys
    ENTER   0, NK_FRAME
    ld      t0, C_ROLE(s1)
    ADDX    a0, s1, C_APP_SECRETS
    bnez    t0, 1f
    addi    a0, a0, 32                      # the peer's secret
1:  lla     a1, 609f
    li      a2, 7
    li      a3, 0
    li      a4, 0
    li      a5, 32
    addi    a6, sp, (FL + NK_SECRET)
    call    quic_expand_label
    addi    a0, sp, (FL + NK_SECRET)
    ADDX    a1, s1, C_NEXT_RX
    call    quic_derive_keys
    ADDX    t0, s1, (C_SPACES + 2 * SP_SIZE + SP_RX_KEYS + QUIC_KEYS_HP)
    ld      t1, 0(t0)
    ld      t2, 8(t0)
    ADDX    t0, s1, (C_NEXT_RX + QUIC_KEYS_HP)
    sd      t1, 0(t0)
    sd      t2, 8(t0)
    LEAVE   0, NK_FRAME
END_FUNCTION quic_next_rx_keys

/*
 * quic_key_update(): moves to the next key phase. The peer's secret steps
 * on: the current receive keys become the previous ones and C_NEXT_RX the
 * current ones. Our secret steps on with it, and the send keys follow. s1 the connection.
 */
.set KU_SECRET, 0
.set KU_FRAME, 32
LOCAL_FUNCTION quic_key_update
    ENTER   0, KU_FRAME
    ADDX    s3, s1, (C_SPACES + 2 * SP_SIZE)
    ADDX    a0, s1, C_PREV_RX
    addi    a1, s3, SP_RX_KEYS
    li      a2, QUIC_KEYS_SIZE
    call    quic_copy
    addi    a0, s3, SP_RX_KEYS
    ADDX    a1, s1, C_NEXT_RX
    li      a2, QUIC_KEYS_SIZE
    call    quic_copy
    li      s4, 0                           # each secret steps: client 0, server 1
1:  ADDX    s5, s1, C_APP_SECRETS
    slli    t0, s4, 5
    add     s5, s5, t0
    mv      a0, s5
    lla     a1, 609f
    li      a2, 7
    li      a3, 0
    li      a4, 0
    li      a5, 32
    addi    a6, sp, (FL + KU_SECRET)
    call    quic_expand_label
    mv      a0, s5
    addi    a1, sp, (FL + KU_SECRET)
    li      a2, 32
    call    quic_copy
    addi    s4, s4, 1
    li      t0, 2
    bltu    s4, t0, 1b
    /* The send keys from our new secret; the header protection key stays. */
    ld      t0, C_ROLE(s1)
    ADDX    a0, s1, C_APP_SECRETS
    beqz    t0, 2f
    addi    a0, a0, 32
2:  ld      t0, (SP_TX_KEYS + QUIC_KEYS_HP)(s3)
    ld      t1, (SP_TX_KEYS + QUIC_KEYS_HP + 8)(s3)
    sd      t0, (FL + KU_SECRET)(sp)
    sd      t1, (FL + KU_SECRET + 8)(sp)
    addi    a1, s3, SP_TX_KEYS
    call    quic_derive_keys
    ld      t0, (FL + KU_SECRET)(sp)
    ld      t1, (FL + KU_SECRET + 8)(sp)
    sd      t0, (SP_TX_KEYS + QUIC_KEYS_HP)(s3)
    sd      t1, (SP_TX_KEYS + QUIC_KEYS_HP + 8)(s3)
    /* The next receive keys from the peer's new secret. */
    call    quic_next_rx_keys
    LDX     t0, s1, C_KEY_PHASE
    xori    t0, t0, 1
    SDX     t0, s1, C_KEY_PHASE
    SDX     zero, s1, C_PHASE_SENT
    li      t0, NONE
    SDX     t0, s1, C_PHASE_PN
    LEAVE   0, KU_FRAME
END_FUNCTION quic_key_update

/* ---------------------------------------------------------------- Output */

/*
 * quic_crypto_out(space, msg, n) -> 0, or an error: appends a handshake
 * message to the CRYPTO stream of the space and to the transcript.
 * s1 the connection, s2 the TLS block.
 */
LOCAL_FUNCTION quic_crypto_out
    ENTER   0
    li      t0, SP_SIZE
    mul     s3, a0, t0
    add     s3, s3, s1
    addi    s3, s3, C_SPACES
    mv      s4, a1
    mv      s5, a2
    ld      s6, SP_CTX(s3)
    bnez    s6, 1f
    li      a0, CRYPTO_ROOM
    call    quic_heap_alloc
    beqz    a0, 8f
    mv      s6, a0
    sd      s6, SP_CTX(s3)
    sd      zero, SP_CTX_LEN(s3)
    sd      zero, SP_CTX_SENT(s3)
1:  ld      t0, SP_CTX_LEN(s3)
    add     t1, t0, s5
    li      t2, CRYPTO_ROOM
    bltu    t2, t1, 8f
    sd      t1, SP_CTX_LEN(s3)
    add     a0, s9, s6
    add     a0, a0, t0
    mv      a1, s4
    mv      a2, s5
    call    quic_copy
    mv      a0, s4
    mv      a1, s5
    call    quic_tls_append
    j       9f
8:  li      a0, (TLS_ERR + ALERT_INTERNAL)
9:  LEAVE   0
END_FUNCTION quic_crypto_out

/*
 * quic_key_share(group, dst) -> dst after our public key for the group: a new
 * private key in T_X25519, and the X25519 key of 32 bytes or the P-256 point
 * of 65. s2 the TLS block.
 */
.set KS_BASE, 0
.set KS_PUB, 32                         /* 72 bytes */
.set KS_FRAME, 112
LOCAL_FUNCTION quic_key_share
    ENTER   0, KS_FRAME
    mv      s3, a0
    mv      s4, a1
1:  addi    a0, s2, T_X25519
    li      a1, 32
    call    quic_random
    li      t0, GROUP_X25519
    bne     s3, t0, 2f
    addi    a0, sp, (FL + KS_BASE)
    lla     a1, 613f
    li      a2, 32
    call    quic_copy
    addi    a0, s2, T_X25519
    addi    a1, sp, (FL + KS_BASE)
    addi    a2, sp, (FL + KS_PUB)
    CALL_GLOBAL crypto_x25519
    li      s5, 32
    j       3f
2:  addi    a0, s2, T_X25519
    addi    a1, sp, (FL + KS_PUB)
    CALL_GLOBAL crypto_p256_public_key
    bnez    a0, 1b                          # 0 or n or more: draw again
    li      s5, 65
3:  mv      a0, s4
    addi    a1, sp, (FL + KS_PUB)
    mv      a2, s5
    call    quic_copy
    LEAVE   0, KS_FRAME
END_FUNCTION quic_key_share

/*
 * quic_shared(key, n) -> 0 when T_SHARED holds the ECDHE secret of our key and
 * the peer's key of n bytes for T_GROUP; else the alert error.
 * s2 the TLS block.
 */
.set SH_KEY, 0                          /* 72 bytes */
.set SH_FRAME, 80
LOCAL_FUNCTION quic_shared
    ENTER   0, SH_FRAME
    mv      s3, a0
    mv      s4, a1
    ld      t0, T_GROUP(s2)
    li      s5, 65
    li      t1, GROUP_X25519
    bne     t0, t1, 1f
    li      s5, 32
1:  bne     s4, s5, 8f
    addi    a0, sp, (FL + SH_KEY)
    mv      a1, s3
    mv      a2, s5
    call    quic_copy
    ld      t0, T_GROUP(s2)
    li      t1, GROUP_X25519
    bne     t0, t1, 2f
    addi    a0, s2, T_X25519
    addi    a1, sp, (FL + SH_KEY)
    addi    a2, s2, T_SHARED
    CALL_GLOBAL crypto_x25519
    bnez    a0, 8f
    j       9f
2:  addi    a0, sp, (FL + SH_KEY)
    addi    a1, s2, T_X25519
    addi    a2, s2, T_SHARED
    CALL_GLOBAL crypto_p256_ecdh
    bnez    a0, 8f
    j       9f
8:  li      a0, (TLS_ERR + ALERT_ILLEGAL)
9:  LEAVE   0, SH_FRAME
END_FUNCTION quic_shared

/*
 * quic_cert_message(dst) -> dst after a Certificate message with our
 * certificate and an empty context. s9 the state.
 */
LOCAL_FUNCTION quic_cert_message
    ENTER   0
    mv      s1, a0
    ld      s2, ST_CERT_LEN(s9)
    li      t0, 11
    sb      t0, 0(s1)
    addi    a0, s1, 1
    addi    a1, s2, 9                       # context, list length, entry length, extensions
    call    quic_put24
    sb      zero, 0(a0)
    addi    a0, a0, 1
    addi    a1, s2, 5
    call    quic_put24
    mv      a1, s2
    call    quic_put24
    addi    a1, s9, ST_CERT
    mv      a2, s2
    call    quic_copy
    sb      zero, 0(a0)
    sb      zero, 1(a0)
    addi    a0, a0, 2
    LEAVE   0
END_FUNCTION quic_cert_message

/*
 * quic_cv_message(dst, server) -> dst after our CertificateVerify: ECDSA P-256
 * of the SHA-256 of 64 spaces, the context string of the side, a zero byte
 * and the transcript hash, in DER. s2 the TLS block, s9 the state.
 */
.set CV_MSG, 0                          /* ByteList: 24 + 64 + 34 + 32 */
.set CV_HASH, 160
.set CV_SIG, 192
.set CV_FRAME, 256
LOCAL_FUNCTION quic_cv_message
    ENTER   0, CV_FRAME
    mv      s3, a0
    mv      s4, a1
    call    quic_tls_hash
    addi    a0, sp, (FL + CV_MSG)
    mv      a1, s4
    addi    a2, s2, T_HASH
    call    quic_cv_put
    addi    a0, sp, (FL + CV_MSG)
    addi    a1, sp, (FL + CV_HASH)
    CALL_GLOBAL crypto_sha256
    addi    a0, s9, ST_CERT_PRIV
    addi    a1, sp, (FL + CV_HASH)
    addi    a2, sp, (FL + CV_SIG)
    CALL_GLOBAL crypto_p256_sign
    li      t0, 15
    sb      t0, 0(s3)
    li      t0, 0x04                        # ecdsa_secp256r1_sha256
    sb      t0, 4(s3)
    li      t0, 0x03
    sb      t0, 5(s3)
    addi    a0, s3, 8
    addi    a1, sp, (FL + CV_SIG)
    call    quic_der_sig_put
    mv      s5, a0
    srli    t0, s5, 8
    sb      t0, 6(s3)
    sb      s5, 7(s3)
    addi    a1, s5, 4
    addi    a0, s3, 1
    call    quic_put24
    addi    a0, s3, 8
    add     a0, a0, s5
    LEAVE   0, CV_FRAME
END_FUNCTION quic_cv_message

/*
 * quic_cv_put(list, server, hash): the ByteList of the content a
 * CertificateVerify signs (RFC 8446 section 4.4.3).
 */
LOCAL_FUNCTION quic_cv_put
    ENTER   0
    mv      s1, a0
    mv      s2, a1
    mv      s3, a2
    li      t0, 130
    BYTELIST s1, 0, 160, t0
    addi    a0, s1, 24
    li      t0, 0x2020202020202020
    li      t1, 8
1:  sd      t0, 0(a0)
    addi    a0, a0, 8
    addi    t1, t1, -1
    bnez    t1, 1b
    lla     a1, 610f
    bnez    s2, 2f
    lla     a1, 611f
2:  li      a2, 33
    call    quic_copy
    sb      zero, 0(a0)
    addi    a0, a0, 1
    mv      a1, s3
    li      a2, 32
    call    quic_copy
    LEAVE   0
END_FUNCTION quic_cv_put

/* quic_fin_message(dst, secret) -> dst after a Finished message with the MAC of the secret. s2 the TLS block. */
LOCAL_FUNCTION quic_fin_message
    ENTER   0
    mv      s3, a0
    li      t0, 20
    sb      t0, 0(s3)
    sb      zero, 1(s3)
    sb      zero, 2(s3)
    li      t0, 32
    sb      t0, 3(s3)
    mv      a0, a1
    addi    a1, s3, 4
    call    quic_finished_mac
    addi    a0, s3, 36
    LEAVE   0
END_FUNCTION quic_fin_message

/* ---------------------------------------------------------------- Transport parameters */

/* quic_tp_int(dst, id, v) -> dst after one integer transport parameter. */
LOCAL_FUNCTION quic_tp_int
    ENTER   0
    mv      s1, a2
    call    quic_vput
    mv      s2, a0
    mv      a0, s1
    call    quic_vlen
    mv      a1, a0
    mv      a0, s2
    call    quic_vput
    mv      a1, s1
    call    quic_vput
    LEAVE   0
END_FUNCTION quic_tp_int

/*
 * quic_tp_write(dst) -> dst after our transport parameters (RFC 9000 section
 * 18): max_idle_timeout, max_udp_payload_size 1452, the flow control limits,
 * initial_max_streams_bidi, disable_active_migration and
 * initial_source_connection_id; a server adds original_destination_connection_id.
 * s1 the connection.
 */
LOCAL_FUNCTION quic_tp_write
    ENTER   0
    li      a1, 0x01
    CFG     a2, QUIC_CFG_IDLE
    call    quic_tp_int
    li      a1, 0x03
    li      a2, 1452
    call    quic_tp_int
    li      a1, 0x04
    CFG     a2, QUIC_CFG_MAX_DATA
    call    quic_tp_int
    li      a1, 0x05
    CFG     a2, QUIC_CFG_STREAM_DATA
    call    quic_tp_int
    li      a1, 0x06
    CFG     a2, QUIC_CFG_STREAM_DATA
    call    quic_tp_int
    li      a1, 0x08
    CFG     a2, QUIC_CFG_MAX_STREAMS
    call    quic_tp_int
    li      t0, 0x0C                        # disable_active_migration, empty
    sb      t0, 0(a0)
    sb      zero, 1(a0)
    li      t0, 0x0F                        # initial_source_connection_id
    sb      t0, 2(a0)
    li      t0, 8
    sb      t0, 3(a0)
    addi    a0, a0, 4
    addi    a1, s1, C_LCID
    li      a2, 8
    call    quic_copy
    ld      t0, C_ROLE(s1)
    beqz    t0, 9f
    sb      zero, 0(a0)                     # original_destination_connection_id
    ld      a2, (C_ODCID + QUIC_CID_LENGTH)(s1)
    sb      a2, 1(a0)
    addi    a0, a0, 2
    addi    a1, s1, (C_ODCID + QUIC_CID_ID)
    call    quic_copy
9:  LEAVE   0
END_FUNCTION quic_tp_write

/* quic_cid_is(p, n, cid) -> 1 when the n bytes at p are the ConnectionId cid. */
LOCAL_FUNCTION quic_cid_is
    ENTER   0
    ld      a3, QUIC_CID_LENGTH(a2)
    addi    a2, a2, QUIC_CID_ID
    call    quic_bytes_is
    LEAVE   0
END_FUNCTION quic_cid_is

/*
 * quic_tp_read(p, end) -> 0 when the transport parameters of the peer are
 * valid, with their values in the C_P_* fields; else TRANSPORT_PARAMETER_ERROR.
 * Unknown parameters are skipped; each known one may appear once.
 * s1 the connection; s3 position, s4 end, s5 seen bits, s6 id, s7 length, s8 the value end.
 */
LOCAL_FUNCTION quic_tp_read
    ENTER   0
    mv      s3, a0
    mv      s4, a1
    li      s5, 0
    /* Defaults (RFC 9000 section 18.2). */
    SDX     zero, s1, C_P_IDLE
    li      t0, 65527
    SDX     t0, s1, C_P_UDP
    SDX     zero, s1, C_P_MAX_DATA
    SDX     zero, s1, C_P_SD_LOCAL
    SDX     zero, s1, C_P_SD_REMOTE
    SDX     zero, s1, C_P_STREAMS
    li      t0, 3
    SDX     t0, s1, C_P_ACK_EXP
    li      t0, 25000
    SDX     t0, s1, C_P_ACK_DELAY
    li      t0, 2
    SDX     t0, s1, C_P_CID_LIMIT
1:  bgeu    s3, s4, 7f
    mv      a0, s3
    mv      a1, s4
    call    quic_vget
    beqz    a0, 8f
    mv      s6, a1
    mv      a1, s4
    call    quic_vget
    beqz    a0, 8f
    mv      s7, a1
    sub     t0, s4, a0
    bltu    t0, s7, 8f
    mv      s3, a0
    add     s8, s3, s7
    li      t0, 0x10
    bltu    t0, s6, 6f                      # unknown: skip
    li      t0, 1
    sll     t0, t0, s6
    and     t1, s5, t0
    bnez    t1, 8f
    or      s5, s5, t0
    beqz    s6, 10f
    li      t0, 0x02
    beq     s6, t0, 12f
    li      t0, 0x0C
    beq     s6, t0, 13f
    li      t0, 0x0D
    beq     s6, t0, 14f
    li      t0, 0x0F
    beq     s6, t0, 15f
    li      t0, 0x10
    beq     s6, t0, 16f
    /* An integer parameter: one varint that fills the value. */
    mv      a0, s3
    mv      a1, s8
    call    quic_vget
    bne     a0, s8, 8f
    li      t0, 0x01
    bne     s6, t0, 2f
    SDX     a1, s1, C_P_IDLE
    j       6f
2:  li      t0, 0x03
    bne     s6, t0, 3f
    li      t0, 1200
    bltu    a1, t0, 8f
    SDX     a1, s1, C_P_UDP
    j       6f
3:  li      t0, 0x04
    bne     s6, t0, 31f
    SDX     a1, s1, C_P_MAX_DATA
    j       6f
31: li      t0, 0x05
    bne     s6, t0, 32f
    SDX     a1, s1, C_P_SD_LOCAL
    j       6f
32: li      t0, 0x06
    bne     s6, t0, 33f
    SDX     a1, s1, C_P_SD_REMOTE
    j       6f
33: li      t0, 0x08
    bne     s6, t0, 34f
    li      t0, 1
    slli    t0, t0, 60
    bltu    t0, a1, 8f
    SDX     a1, s1, C_P_STREAMS
    j       6f
34: li      t0, 0x09
    bne     s6, t0, 35f
    li      t0, 1
    slli    t0, t0, 60
    bltu    t0, a1, 8f
    j       6f
35: li      t0, 0x0A
    bne     s6, t0, 36f
    li      t0, 20
    bltu    t0, a1, 8f
    SDX     a1, s1, C_P_ACK_EXP
    j       6f
36: li      t0, 0x0B
    bne     s6, t0, 37f
    li      t0, 16384
    bgeu    a1, t0, 8f
    li      t0, 1000
    mul     a1, a1, t0
    SDX     a1, s1, C_P_ACK_DELAY
    j       6f
37: li      t0, 0x0E
    bne     s6, t0, 6f                      # initial_max_stream_data_uni
    li      t0, 2
    bltu    a1, t0, 8f
    SDX     a1, s1, C_P_CID_LIMIT
    j       6f
10: ld      t0, C_ROLE(s1)                  # original_destination_connection_id: from a server
    bnez    t0, 8f
    mv      a0, s3
    mv      a1, s7
    addi    a2, s1, C_ODCID
    call    quic_cid_is
    beqz    a0, 8f
    j       6f
12: ld      t0, C_ROLE(s1)                  # stateless_reset_token: from a server
    bnez    t0, 8f
    li      t0, 16
    bne     s7, t0, 8f
    addi    a0, s1, C_RCID_TOKEN
    mv      a1, s3
    li      a2, 16
    call    quic_copy
    ld      t0, C_FLAGS(s1)
    ORV     t0, CF_RESET_TOKEN
    sd      t0, C_FLAGS(s1)
    j       6f
13: bnez    s7, 8f                          # disable_active_migration
    j       6f
14: ld      t0, C_ROLE(s1)                  # preferred_address: from a server, not used
    bnez    t0, 8f
    j       6f
15: mv      a0, s3                          # initial_source_connection_id
    mv      a1, s7
    addi    a2, s1, C_ISCID
    call    quic_cid_is
    beqz    a0, 8f
    j       6f
16: ld      t0, C_ROLE(s1)                  # retry_source_connection_id: from a server after a Retry
    bnez    t0, 8f
    ld      t0, C_FLAGS(s1)
    ANDV    t0, CF_RETRIED
    beqz    t0, 8f
    mv      a0, s3
    mv      a1, s7
    addi    a2, s1, C_RSCID
    call    quic_cid_is
    beqz    a0, 8f
6:  mv      s3, s8
    j       1b
7:  li      t0, (1 << 0x0F)                 # initial_source_connection_id is required
    and     t0, s5, t0
    beqz    t0, 8f
    ld      t0, C_ROLE(s1)
    bnez    t0, 71f
    andi    t0, s5, 1                       # and, from a server, original_destination_connection_id
    beqz    t0, 8f
    ld      t0, C_FLAGS(s1)
    ANDV    t0, CF_RETRIED
    beqz    t0, 71f
    li      t0, (1 << 0x10)
    and     t0, s5, t0
    beqz    t0, 8f
71: LDX     t0, s1, C_P_MAX_DATA            # the connection send limit
    LDX     t1, s1, C_TX_MAX
    bgeu    t1, t0, 72f
    mv      t1, t0
72: SDX     t1, s1, C_TX_MAX
    li      a0, 0
    j       9f
8:  li      a0, ERR_TP
9:  LEAVE   0
END_FUNCTION quic_tp_read

/* ---------------------------------------------------------------- Client */

/*
 * quic_client_hello() -> 0 or an error: our ClientHello on the Initial CRYPTO
 * stream: TLS_AES_128_GCM_SHA256, supported_versions TLS 1.3, supported_groups
 * x25519 and secp256r1, signature_algorithms ecdsa_secp256r1_sha256 and ed25519,
 * a key_share of T_GROUP, the ALPN "libp2p", the transport parameters, and the
 * cookie of a HelloRetryRequest. s1 the connection, s2 the TLS block.
 * s3 the message, s4 the extensions.
 */
LOCAL_FUNCTION quic_client_hello
    ENTER   0
    SCR     s3, SC_TLS
    li      t0, 1
    sb      t0, 0(s3)
    li      t0, 3
    sb      t0, 4(s3)
    sb      t0, 5(s3)
    ld      t0, T_HRR(s2)
    bnez    t0, 1f
    addi    a0, s2, T_RANDOM
    li      a1, 32
    call    quic_random
1:  addi    a0, s3, 6
    addi    a1, s2, T_RANDOM
    li      a2, 32
    call    quic_copy
    lla     a1, 614f                        # session ID, cipher suites, compression
    li      a2, 7
    call    quic_copy
    mv      s4, a0                          # the extensions length, then the extensions
    addi    a0, a0, 2
    lla     a1, 615f                        # supported_versions, supported_groups, signature_algorithms, ALPN
    li      a2, (7 + 10 + 10 + 13)
    call    quic_copy
    mv      s5, a0                          # key_share: type, length, shares length, group, key length, key
    li      a1, 0x0033
    call    quic_put16
    addi    s6, a0, 8                       # the key
    ld      a0, T_GROUP(s2)
    mv      a1, s6
    call    quic_key_share
    sub     t0, a0, s6                      # the key length
    mv      s6, a0
    addi    a0, s5, 2
    addi    a1, t0, 6
    call    quic_put16
    addi    a1, t0, 4
    call    quic_put16
    ld      a1, T_GROUP(s2)
    call    quic_put16
    mv      a1, t0
    call    quic_put16
    mv      a0, s6
    ld      t0, T_COOKIE_LEN(s2)
    beqz    t0, 2f
    li      a1, 0x002C                      # cookie
    call    quic_put16
    ld      a1, T_COOKIE_LEN(s2)
    addi    a1, a1, 2
    call    quic_put16
    ld      a1, T_COOKIE_LEN(s2)
    call    quic_put16
    addi    a1, s2, T_COOKIE
    ld      a2, T_COOKIE_LEN(s2)
    call    quic_copy
2:  mv      s5, a0                          # quic_transport_parameters
    li      a1, 0x0039
    call    quic_put16
    addi    a0, a0, 2
    call    quic_tp_write
    sub     a1, a0, s5
    addi    a1, a1, -4
    mv      s6, a0
    addi    a0, s5, 2
    call    quic_put16
    sub     a1, s6, s4
    addi    a1, a1, -2
    mv      a0, s4
    call    quic_put16
    sub     a1, s6, s3
    addi    a1, a1, -4
    addi    a0, s3, 1
    call    quic_put24
    li      a0, SPACE_INITIAL
    mv      a1, s3
    sub     a2, s6, s3
    call    quic_crypto_out
    LEAVE   0
END_FUNCTION quic_client_hello

/*
 * quic_tls_start() -> 0 or an error: the client starts with a ClientHello
 * with an x25519 key share. s1 the connection, s2 the TLS block.
 */
LOCAL_FUNCTION quic_tls_start
    ENTER   0
    li      t0, GROUP_X25519
    sd      t0, T_GROUP(s2)
    li      t0, TS_WAIT_SH
    sd      t0, T_STAGE(s2)
    call    quic_client_hello
    LEAVE   0
END_FUNCTION quic_tls_start

/*
 * quic_on_server_hello(p, end) -> 0 or an error: a ServerHello or a
 * HelloRetryRequest body. s1 the connection, s2 the TLS block.
 * s3 position, s4 end, s5 HRR, s6 the key share key, s7 its length,
 * s8 the selected group.
 */
LOCAL_FUNCTION quic_on_server_hello
    ENTER   0
    mv      s3, a0
    mv      s4, a1
    li      s6, 0
    li      s8, 0
    mv      a1, s4
    call    quic_rd16
    beqz    a0, 80f
    li      t0, 0x0303
    bne     a1, t0, 81f
    sub     t0, s4, a0
    li      t1, 32
    bltu    t0, t1, 80f
    mv      s3, a0
    lla     a2, 602f
    li      a1, 32
    li      a3, 32
    call    quic_bytes_is
    mv      s5, a0
    addi    a0, s3, 32
    mv      a1, s4
    call    quic_rd8                        # legacy_session_id_echo: we send none
    beqz    a0, 80f
    bnez    a1, 81f
    mv      a1, s4
    call    quic_rd16
    beqz    a0, 80f
    li      t0, 0x1301
    bne     a1, t0, 81f
    mv      a1, s4
    call    quic_rd8
    beqz    a0, 80f
    bnez    a1, 81f
    mv      a1, s4
    call    quic_rd16
    beqz    a0, 80f
    add     t0, a0, a1
    bne     t0, s4, 80f
    mv      s3, a0
    li      s7, 0
    sd      zero, T_HASH(s2)                # supported_versions seen
1:  bgeu    s3, s4, 5f
    mv      a0, s3
    mv      a1, s4
    call    quic_rd16
    beqz    a0, 80f
    mv      t0, a1                          # type
    mv      a1, s4
    sd      t0, (T_HASH + 8)(s2)
    call    quic_rd16
    beqz    a0, 80f
    add     t1, a0, a1
    bltu    s4, t1, 80f
    mv      s3, t1                          # the next extension
    ld      t0, (T_HASH + 8)(s2)
    li      t2, 0x002B
    bne     t0, t2, 2f
    li      t2, 2
    bne     a1, t2, 80f
    mv      a1, s3
    call    quic_rd16
    li      t2, 0x0304
    bne     a1, t2, 82f
    li      t1, 1
    sd      t1, T_HASH(s2)
    j       1b
2:  li      t2, 0x0033
    bne     t0, t2, 3f
    mv      a1, s3
    call    quic_rd16
    beqz    a0, 80f
    mv      s8, a1
    bnez    s5, 1b                          # HRR: the group only
    mv      a1, s3
    call    quic_rd16
    beqz    a0, 80f
    add     t0, a0, a1
    bne     t0, s3, 80f
    mv      s6, a0
    mv      s7, a1
    j       1b
3:  li      t2, 0x002C                      # cookie, in a HelloRetryRequest
    bne     t0, t2, 1b
    beqz    s5, 81f
    mv      a1, s3
    call    quic_rd16
    beqz    a0, 80f
    beqz    a1, 80f
    li      t0, 128
    bltu    t0, a1, 81f
    add     t0, a0, a1
    bne     t0, s3, 80f
    sd      a1, T_COOKIE_LEN(s2)
    mv      a2, a1
    mv      a1, a0
    addi    a0, s2, T_COOKIE
    call    quic_copy
    j       1b
5:  ld      t0, T_HASH(s2)
    beqz    t0, 82f
    beqz    s8, 83f
    bnez    s5, 6f
    ld      t0, T_GROUP(s2)                 # ServerHello
    bne     s8, t0, 81f
    beqz    s6, 83f
    mv      a0, s6
    mv      a1, s7
    call    quic_shared
    bnez    a0, 9f
    li      a0, 0
    j       9f
6:  ld      t0, T_HRR(s2)                   # HelloRetryRequest: once, for the other group
    bnez    t0, 84f
    ld      t0, T_GROUP(s2)
    beq     s8, t0, 81f
    li      t0, GROUP_P256
    bne     s8, t0, 81f
    sd      s8, T_GROUP(s2)
    li      t0, 1
    sd      t0, T_HRR(s2)
    li      a0, 2                           # 2: a HelloRetryRequest to answer
    j       9f
80: li      a0, (TLS_ERR + ALERT_DECODE)
    j       9f
81: li      a0, (TLS_ERR + ALERT_ILLEGAL)
    j       9f
82: li      a0, (TLS_ERR + ALERT_VERSION)
    j       9f
83: li      a0, (TLS_ERR + ALERT_MISSING_EXT)
    j       9f
84: li      a0, (TLS_ERR + ALERT_UNEXPECTED)
9:  LEAVE   0
END_FUNCTION quic_on_server_hello

/*
 * quic_message_hash(): after a HelloRetryRequest: the transcript becomes
 * message_hash (254, 0, 0, 32, SHA-256 of ClientHello1) (RFC 8446 section
 * 4.4.1). s2 the TLS block.
 */
LOCAL_FUNCTION quic_message_hash
    ENTER   0
    call    quic_tls_hash
    li      t0, 254
    sb      t0, T_TRANSCRIPT(s2)
    sb      zero, (T_TRANSCRIPT + 1)(s2)
    sb      zero, (T_TRANSCRIPT + 2)(s2)
    li      t0, 32
    sb      t0, (T_TRANSCRIPT + 3)(s2)
    addi    a0, s2, (T_TRANSCRIPT + 4)
    addi    a1, s2, T_HASH
    li      a2, 32
    call    quic_copy
    li      t0, 36
    sd      t0, T_LEN(s2)
    LEAVE   0
END_FUNCTION quic_message_hash

/*
 * quic_on_ee(p, end) -> 0 or an error: EncryptedExtensions must hold the ALPN
 * "libp2p" and the transport parameters. s1 the connection, s2 the TLS block.
 * s3 position, s4 end, s5 seen: 1 ALPN, 2 parameters.
 */
LOCAL_FUNCTION quic_on_ee
    ENTER   0
    mv      s4, a1
    li      s5, 0
    call    quic_rd16
    beqz    a0, 80f
    add     t0, a0, a1
    bne     t0, s4, 80f
    mv      s3, a0
1:  bgeu    s3, s4, 5f
    mv      a0, s3
    mv      a1, s4
    call    quic_rd16
    beqz    a0, 80f
    mv      s6, a1
    mv      a1, s4
    call    quic_rd16
    beqz    a0, 80f
    add     s7, a0, a1
    bltu    s4, s7, 80f
    mv      s3, s7
    li      t0, 0x0010
    bne     s6, t0, 2f
    mv      a1, s7                          # ALPN: one protocol, "libp2p"
    call    quic_alpn_libp2p
    beqz    a0, 81f
    ori     s5, s5, 1
    j       1b
2:  li      t0, 0x0039
    bne     s6, t0, 1b
    mv      a1, s7
    call    quic_tp_read
    bnez    a0, 9f
    ori     s5, s5, 2
    j       1b
5:  andi    t0, s5, 1
    beqz    t0, 82f
    andi    t0, s5, 2
    beqz    t0, 83f
    li      a0, 0
    j       9f
80: li      a0, (TLS_ERR + ALERT_DECODE)
    j       9f
81: li      a0, (TLS_ERR + ALERT_NO_ALPN)
    j       9f
82: li      a0, (TLS_ERR + ALERT_NO_ALPN)
    j       9f
83: li      a0, (TLS_ERR + ALERT_MISSING_EXT)
9:  LEAVE   0
END_FUNCTION quic_on_ee

/*
 * quic_alpn_libp2p(p, end) -> 1 when the ALPN extension data at p lists
 * "libp2p"; else 0.
 */
LOCAL_FUNCTION quic_alpn_libp2p
    ENTER   0
    mv      s2, a1
    call    quic_rd16
    beqz    a0, 8f
    add     t0, a0, a1
    bne     t0, s2, 8f
    mv      s1, a0
1:  bgeu    s1, s2, 8f
    mv      a0, s1
    mv      a1, s2
    call    quic_rd8
    beqz    a0, 8f
    add     s3, a0, a1
    bltu    s2, s3, 8f
    lla     a2, 612f
    li      a3, 6
    call    quic_bytes_is
    bnez    a0, 9f
    mv      s1, s3
    j       1b
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_alpn_libp2p

/*
 * quic_sigalgs_ok(p, end) -> 1 when the signature_algorithms extension data at
 * p lists ecdsa_secp256r1_sha256, the scheme we sign with; else 0.
 */
LOCAL_FUNCTION quic_sigalgs_ok
    ENTER   0
    mv      s2, a1
    call    quic_rd16
    beqz    a0, 8f
    add     t0, a0, a1
    bne     t0, s2, 8f
    mv      s1, a0
1:  mv      a0, s1
    mv      a1, s2
    call    quic_rd16
    beqz    a0, 8f
    mv      s1, a0
    li      t0, 0x0403
    bne     a1, t0, 1b
    li      a0, 1
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_sigalgs_ok

/*
 * quic_on_cr(p, end) -> 0 or an error: a CertificateRequest with an empty
 * context, whose signature_algorithms list ecdsa_secp256r1_sha256.
 * s2 the TLS block. s3 position, s4 end, s5 found.
 */
LOCAL_FUNCTION quic_on_cr
    ENTER   0
    mv      s4, a1
    li      s5, 0
    call    quic_rd8
    beqz    a0, 80f
    bnez    a1, 81f
    mv      a1, s4
    call    quic_rd16
    beqz    a0, 80f
    add     t0, a0, a1
    bne     t0, s4, 80f
    mv      s3, a0
1:  bgeu    s3, s4, 5f
    mv      a0, s3
    mv      a1, s4
    call    quic_rd16
    beqz    a0, 80f
    mv      s6, a1
    mv      a1, s4
    call    quic_rd16
    beqz    a0, 80f
    add     s7, a0, a1
    bltu    s4, s7, 80f
    mv      s3, s7
    li      t0, 0x000D
    bne     s6, t0, 1b
    mv      a1, s7
    call    quic_sigalgs_ok
    or      s5, s5, a0
    j       1b
5:  beqz    s5, 82f
    li      t0, 1
    sd      t0, T_CERT_REQ(s2)
    li      a0, 0
    j       9f
80: li      a0, (TLS_ERR + ALERT_DECODE)
    j       9f
81: li      a0, (TLS_ERR + ALERT_ILLEGAL)
    j       9f
82: li      a0, (TLS_ERR + ALERT_HANDSHAKE)
9:  LEAVE   0
END_FUNCTION quic_on_cr

/*
 * quic_on_cert(p, end) -> 0 or an error: a Certificate with an empty context
 * and exactly one certificate, which quic_cert_check accepts; T_PEER gets its
 * CertInfo. A dialer then checks the peer ID. s1 the connection, s2 the TLS
 * block. s3 position, s4 end.
 */
LOCAL_FUNCTION quic_on_cert
    ENTER   0
    mv      s4, a1
    call    quic_rd8
    beqz    a0, 80f
    bnez    a1, 81f
    mv      a1, s4
    call    quic_rd24
    beqz    a0, 80f
    add     t0, a0, a1
    bne     t0, s4, 80f
    beqz    a1, 82f                         # no certificate
    mv      a1, s4
    call    quic_rd24
    beqz    a0, 80f
    mv      s3, a0
    add     s5, a0, a1                      # the end of the certificate
    mv      s6, a1
    mv      a0, s5
    mv      a1, s4
    call    quic_rd16                       # its extensions
    beqz    a0, 80f
    add     t0, a0, a1
    bne     t0, s4, 83f                     # one certificate only
    mv      a0, s3
    mv      a1, s6
    ld      a2, ST_UNIX(s9)
    addi    a3, s2, T_PEER
    li      t0, QUIC_CI_FIXED
    sd      t0, 0(a3)
    SCR     a4, SC_CERT
    call    quic_cert_check
    bnez    a0, 83f
    ld      a2, (T_PEER + QUIC_CI_HOST_LEN)(s2)     # the host key, for CONNECTED
    SDX     a2, s1, C_PEER_KEY_LEN
    ADDX    a0, s1, C_PEER_KEY
    addi    a1, s2, (T_PEER + QUIC_CI_HOST)
    call    quic_copy
    ld      t0, C_ROLE(s1)
    bnez    t0, 7f
    ld      t0, T_PID_LEN(s2)
    beqz    t0, 7f
    call    quic_peer_id_ok
    beqz    a0, 84f
7:  li      a0, 0
    j       9f
80: li      a0, (TLS_ERR + ALERT_DECODE)
    j       9f
81: li      a0, (TLS_ERR + ALERT_ILLEGAL)
    j       9f
82: li      a0, (TLS_ERR + ALERT_CERT_REQUIRED)
    j       9f
83: li      a0, (TLS_ERR + ALERT_BAD_CERT)
    j       9f
84: li      t0, QUIC_ERR_PEER_ID
    sd      t0, C_REASON(s1)
    li      a0, (TLS_ERR + ALERT_BAD_CERT)
9:  LEAVE   0
END_FUNCTION quic_on_cert

/*
 * quic_peer_id_ok() -> 1 when the peer ID the dialer named is the multihash of
 * the peer's host key: identity for a protobuf of at most 42 bytes, else
 * SHA-256 (libp2p peer IDs). s2 the TLS block.
 */
.set PI_LIST, 0                         /* ByteList: 24 + 128 */
.set PI_ID, 152                         /* 48 bytes */
.set PI_FRAME, 208
LOCAL_FUNCTION quic_peer_id_ok
    ENTER   0, PI_FRAME
    ld      s3, (T_PEER + QUIC_CI_HOST_LEN)(s2)
    li      t0, 42
    bltu    t0, s3, 1f
    sb      zero, (FL + PI_ID)(sp)
    sb      s3, (FL + PI_ID + 1)(sp)
    addi    a0, sp, (FL + PI_ID + 2)
    addi    a1, s2, (T_PEER + QUIC_CI_HOST)
    mv      a2, s3
    call    quic_copy
    addi    s4, s3, 2
    j       2f
1:  BYTELIST sp, (FL + PI_LIST), 152, s3
    addi    a0, sp, (FL + PI_LIST + 24)
    addi    a1, s2, (T_PEER + QUIC_CI_HOST)
    mv      a2, s3
    call    quic_copy
    li      t0, 0x12
    sb      t0, (FL + PI_ID)(sp)
    li      t0, 0x20
    sb      t0, (FL + PI_ID + 1)(sp)
    addi    a0, sp, (FL + PI_LIST)
    addi    a1, sp, (FL + PI_ID + 2)
    CALL_GLOBAL crypto_sha256
    li      s4, 34
2:  addi    a0, sp, (FL + PI_ID)
    mv      a1, s4
    addi    a2, s2, T_PID
    ld      a3, T_PID_LEN(s2)
    call    quic_bytes_is
    LEAVE   0, PI_FRAME
END_FUNCTION quic_peer_id_ok

/*
 * quic_on_cv(p, end, server) -> 0 or an error: the peer's CertificateVerify
 * signs the transcript hash with the key of its certificate: ecdsa_secp256r1_sha256
 * (DER) for a P-256 key, ed25519 for an Ed25519 key. server 1 when the peer is
 * the server. s2 the TLS block.
 */
.set PV_MSG, 0                          /* ByteList: 24 + 130, room to 160 */
.set PV_HASH, 160
.set PV_SIG, 192
.set PV_KEY, 256                        /* 72 bytes */
.set PV_VALID, 328
.set PV_FRAME, 336
LOCAL_FUNCTION quic_on_cv
    ENTER   0, PV_FRAME
    mv      s3, a0
    mv      s4, a1
    mv      s5, a2
    call    quic_tls_hash
    addi    a0, sp, (FL + PV_MSG)
    mv      a1, s5
    addi    a2, s2, T_HASH
    call    quic_cv_put
    mv      a0, s3
    mv      a1, s4
    call    quic_rd16
    beqz    a0, 80f
    mv      s6, a1                          # the scheme
    mv      a1, s4
    call    quic_rd16
    beqz    a0, 80f
    add     t0, a0, a1
    bne     t0, s4, 80f
    mv      s3, a0
    mv      s7, a1
    addi    a0, sp, (FL + PV_KEY)
    addi    a1, s2, (T_PEER + QUIC_CI_KEY)
    li      a2, 72
    call    quic_copy
    ld      t0, (T_PEER + QUIC_CI_KIND)(s2)
    li      t1, QUIC_CERT_ED25519
    bne     t0, t1, 1f
    li      t1, 0x0807
    bne     s6, t1, 81f
    li      t1, 64
    bne     s7, t1, 81f
    addi    a0, sp, (FL + PV_SIG)
    mv      a1, s3
    li      a2, 64
    call    quic_copy
    addi    a0, sp, (FL + PV_KEY)
    addi    a1, sp, (FL + PV_MSG)
    addi    a2, sp, (FL + PV_SIG)
    addi    a3, sp, (FL + PV_VALID)
    CALL_GLOBAL crypto_ed25519_verify
    j       2f
1:  li      t1, 0x0403
    bne     s6, t1, 81f
    addi    a0, sp, (FL + PV_SIG)
    mv      a1, s3
    mv      a2, s7
    call    quic_der_sig_get
    beqz    a0, 82f
    addi    a0, sp, (FL + PV_MSG)
    addi    a1, sp, (FL + PV_HASH)
    CALL_GLOBAL crypto_sha256
    addi    a0, sp, (FL + PV_KEY)
    addi    a1, sp, (FL + PV_HASH)
    addi    a2, sp, (FL + PV_SIG)
    addi    a3, sp, (FL + PV_VALID)
    CALL_GLOBAL crypto_p256_verify
2:  bnez    a0, 82f
    ld      t0, (FL + PV_VALID)(sp)
    beqz    t0, 82f
    li      a0, 0
    j       9f
80: li      a0, (TLS_ERR + ALERT_DECODE)
    j       9f
81: li      a0, (TLS_ERR + ALERT_ILLEGAL)
    j       9f
82: li      a0, (TLS_ERR + ALERT_DECRYPT)
9:  LEAVE   0, PV_FRAME
END_FUNCTION quic_on_cv

/*
 * quic_on_fin(p, end, secret) -> 0 or an error: the peer's Finished holds the
 * MAC of its handshake traffic secret over the transcript hash.
 * s2 the TLS block.
 */
.set PF_MAC, 0
.set PF_FRAME, 32
LOCAL_FUNCTION quic_on_fin
    ENTER   0, PF_FRAME
    mv      s3, a0
    sub     t0, a1, a0
    li      t1, 32
    bne     t0, t1, 80f
    mv      a0, a2
    addi    a1, sp, (FL + PF_MAC)
    call    quic_finished_mac
    mv      a0, s3
    addi    a1, sp, (FL + PF_MAC)
    li      a2, 32
    call    quic_equal
    beqz    a0, 82f
    li      a0, 0
    j       9f
80: li      a0, (TLS_ERR + ALERT_DECODE)
    j       9f
82: li      a0, (TLS_ERR + ALERT_DECRYPT)
9:  LEAVE   0, PF_FRAME
END_FUNCTION quic_on_fin

/*
 * quic_client_finish() -> 0 or an error: after the server Finished: the
 * 1-RTT keys, then our Certificate and CertificateVerify when the server asked,
 * and our Finished, on the Handshake CRYPTO stream. The handshake is complete.
 * s1 the connection, s2 the TLS block.
 */
LOCAL_FUNCTION quic_client_finish
    ENTER   0
    call    quic_app_keys
    ld      t0, T_CERT_REQ(s2)
    beqz    t0, 1f
    SCR     s3, SC_TLS
    mv      a0, s3
    call    quic_cert_message
    sub     a2, a0, s3
    mv      a1, s3
    li      a0, SPACE_HANDSHAKE
    call    quic_crypto_out
    bnez    a0, 9f
    mv      a0, s3
    li      a1, 0
    call    quic_cv_message
    sub     a2, a0, s3
    mv      a1, s3
    li      a0, SPACE_HANDSHAKE
    call    quic_crypto_out
    bnez    a0, 9f
1:  SCR     s3, SC_TLS
    mv      a0, s3
    addi    a1, s2, T_C_HS
    call    quic_fin_message
    sub     a2, a0, s3
    mv      a1, s3
    li      a0, SPACE_HANDSHAKE
    call    quic_crypto_out
    bnez    a0, 9f
    call    quic_handshake_complete
    li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_client_finish

/* ---------------------------------------------------------------- Server */

/*
 * quic_on_client_hello(p, end) -> 0, 2 when a HelloRetryRequest is to be sent,
 * or an error. s1 the connection, s2 the TLS block.
 * s3 position, s4 end, s5 flags: 1 TLS 1.3, 2 cipher, 4 signature, 8 ALPN,
 * 16 parameters, 32 x25519 group, 64 secp256r1 group, 128 key share;
 * s6 the key share key, s7 its length, s8 its group.
 */
LOCAL_FUNCTION quic_on_client_hello
    ENTER   0
    mv      s4, a1
    li      s5, 0
    li      s6, 0
    li      s8, 0
    call    quic_rd16
    beqz    a0, 80f
    li      t0, 0x0303
    bne     a1, t0, 81f
    sub     t0, s4, a0
    li      t1, 32
    bltu    t0, t1, 80f
    addi    a0, a0, 32                      # random
    mv      a1, s4
    call    quic_rd8                        # legacy_session_id: must be empty in QUIC
    beqz    a0, 80f
    bnez    a1, 85f
    mv      a1, s4
    call    quic_rd16                       # cipher_suites
    beqz    a0, 80f
    add     s3, a0, a1
    bltu    s4, s3, 80f
    mv      s7, s3
1:  bgeu    a0, s7, 2f
    mv      a1, s7
    call    quic_rd16
    beqz    a0, 80f
    li      t0, 0x1301
    bne     a1, t0, 1b
    ori     s5, s5, 2
    j       1b
2:  mv      a0, s3
    mv      a1, s4
    call    quic_rd8                        # legacy_compression_methods: null only
    beqz    a0, 80f
    li      t0, 1
    bne     a1, t0, 81f
    mv      a1, s4
    call    quic_rd8
    beqz    a0, 80f
    bnez    a1, 81f
    mv      a1, s4
    call    quic_rd16
    beqz    a0, 80f
    add     t0, a0, a1
    bne     t0, s4, 80f
    mv      s3, a0
3:  bgeu    s3, s4, 6f
    mv      a0, s3
    mv      a1, s4
    call    quic_rd16
    beqz    a0, 80f
    sd      a1, (T_HASH + 8)(s2)
    mv      a1, s4
    call    quic_rd16
    beqz    a0, 80f
    add     t0, a0, a1
    bltu    s4, t0, 80f
    mv      s3, t0                          # the next extension
    sd      t0, (T_HASH + 16)(s2)
    ld      t1, (T_HASH + 8)(s2)
    li      t2, 0x002B
    beq     t1, t2, 31f
    li      t2, 0x000A
    beq     t1, t2, 32f
    li      t2, 0x0033
    beq     t1, t2, 33f
    li      t2, 0x000D
    beq     t1, t2, 34f
    li      t2, 0x0010
    beq     t1, t2, 35f
    li      t2, 0x0039
    beq     t1, t2, 36f
    j       3b
31: mv      a1, s3                          # supported_versions
    call    quic_rd8
    beqz    a0, 80f
    add     s7, a0, a1
    bne     s7, s3, 80f
4:  bgeu    a0, s7, 3b
    mv      a1, s7
    call    quic_rd16
    beqz    a0, 80f
    li      t0, 0x0304
    bne     a1, t0, 4b
    ori     s5, s5, 1
    j       4b
32: mv      a1, s3                          # supported_groups
    call    quic_rd16
    beqz    a0, 80f
    add     s7, a0, a1
    bne     s7, s3, 80f
5:  bgeu    a0, s7, 3b
    mv      a1, s7
    call    quic_rd16
    beqz    a0, 80f
    li      t0, GROUP_X25519
    bne     a1, t0, 51f
    ori     s5, s5, 32
51: li      t0, GROUP_P256
    bne     a1, t0, 5b
    ori     s5, s5, 64
    j       5b
33: mv      a1, s3                          # key_share: x25519 first, then secp256r1
    call    quic_rd16
    beqz    a0, 80f
    add     s7, a0, a1
    bne     s7, s3, 80f
7:  bgeu    a0, s7, 3b
    mv      a1, s7
    call    quic_rd16
    beqz    a0, 80f
    mv      t0, a1
    mv      a1, s7
    sd      t0, (T_HASH + 24)(s2)
    call    quic_rd16
    beqz    a0, 80f
    add     t1, a0, a1
    bltu    s7, t1, 80f
    ld      t0, (T_HASH + 24)(s2)
    li      t2, GROUP_X25519
    bne     t0, t2, 71f
    li      t2, 32
    bne     a1, t2, 72f
    mv      s6, a0                          # x25519 wins
    mv      s8, t0
    ori     s5, s5, 128
    j       72f
71: li      t2, GROUP_P256
    bne     t0, t2, 72f
    li      t2, GROUP_X25519
    beq     s8, t2, 72f
    li      t2, 65
    bne     a1, t2, 72f
    mv      s6, a0
    mv      s8, t0
    ori     s5, s5, 128
72: mv      a0, t1
    j       7b
34: mv      a1, s3                          # signature_algorithms
    call    quic_sigalgs_ok
    beqz    a0, 3b
    ori     s5, s5, 4
    j       3b
35: mv      a1, s3                          # ALPN
    call    quic_alpn_libp2p
    beqz    a0, 3b
    ori     s5, s5, 8
    j       3b
36: mv      a1, s3                          # quic_transport_parameters
    call    quic_tp_read
    bnez    a0, 9f
    ori     s5, s5, 16
    j       3b
6:  andi    t0, s5, 1
    beqz    t0, 82f
    andi    t0, s5, 2
    beqz    t0, 83f
    andi    t0, s5, 4
    beqz    t0, 83f
    andi    t0, s5, 8
    beqz    t0, 84f
    andi    t0, s5, 16
    beqz    t0, 86f
    andi    t0, s5, 128
    beqz    t0, 61f                         # no usable key share
    sd      s8, T_GROUP(s2)
    li      a1, 65
    li      t0, GROUP_X25519
    bne     s8, t0, 64f
    li      a1, 32
64: sd      s6, (T_HASH + 16)(s2)
    sd      a1, (T_HASH + 24)(s2)
    li      a0, 0
    j       9f
61: ld      t0, T_HRR(s2)                   # after a HelloRetryRequest the share must be there
    bnez    t0, 81f
    li      t1, GROUP_X25519
    andi    t0, s5, 32
    bnez    t0, 62f
    li      t1, GROUP_P256
    andi    t0, s5, 64
    beqz    t0, 83f
62: sd      t1, T_GROUP(s2)
    li      a0, 2
    j       9f
80: li      a0, (TLS_ERR + ALERT_DECODE)
    j       9f
81: li      a0, (TLS_ERR + ALERT_ILLEGAL)
    j       9f
82: li      a0, (TLS_ERR + ALERT_VERSION)
    j       9f
83: li      a0, (TLS_ERR + ALERT_HANDSHAKE)
    j       9f
84: li      a0, (TLS_ERR + ALERT_NO_ALPN)
    j       9f
85: li      a0, ERR_PROTOCOL
    j       9f
86: li      a0, (TLS_ERR + ALERT_MISSING_EXT)
9:  LEAVE   0
END_FUNCTION quic_on_client_hello

/*
 * quic_server_hello(hrr) -> 0 or an error: a ServerHello with our key share,
 * or a HelloRetryRequest for T_GROUP when hrr is 1, on the Initial CRYPTO
 * stream. s1 the connection, s2 the TLS block. s3 the message, s4 the extensions.
 */
LOCAL_FUNCTION quic_server_hello
    ENTER   0
    mv      s5, a0
    SCR     s3, SC_TLS
    li      t0, 2
    sb      t0, 0(s3)
    li      t0, 3
    sb      t0, 4(s3)
    sb      t0, 5(s3)
    addi    a0, s3, 6
    beqz    s5, 1f
    lla     a1, 602f
    li      a2, 32
    call    quic_copy
    j       2f
1:  li      a1, 32
    call    quic_random
2:  addi    a0, s3, 38
    sb      zero, 0(a0)                     # legacy_session_id_echo: empty
    addi    a0, a0, 1
    li      a1, 0x1301
    call    quic_put16
    sb      zero, 0(a0)
    addi    a0, a0, 1
    mv      s4, a0
    addi    a0, a0, 2
    li      a1, 0x002B
    call    quic_put16
    li      a1, 2
    call    quic_put16
    li      a1, 0x0304
    call    quic_put16
    li      a1, 0x0033
    call    quic_put16
    beqz    s5, 3f
    li      a1, 2
    call    quic_put16
    ld      a1, T_GROUP(s2)
    call    quic_put16
    j       4f
3:  mv      s6, a0
    addi    a0, a0, 6
    ld      t0, T_GROUP(s2)
    mv      a1, a0
    mv      a0, t0
    call    quic_key_share
    addi    t0, s6, 6
    sub     s7, a0, t0                      # the key length
    mv      s8, a0
    mv      a0, s6
    addi    a1, s7, 4
    call    quic_put16
    ld      a1, T_GROUP(s2)
    call    quic_put16
    mv      a1, s7
    call    quic_put16
    mv      a0, s8
4:  mv      s6, a0
    sub     a1, s6, s4
    addi    a1, a1, -2
    mv      a0, s4
    call    quic_put16
    sub     a1, s6, s3
    addi    a1, a1, -4
    addi    a0, s3, 1
    call    quic_put24
    li      a0, SPACE_INITIAL
    mv      a1, s3
    sub     a2, s6, s3
    call    quic_crypto_out
    LEAVE   0
END_FUNCTION quic_server_hello

/*
 * quic_server_flight() -> 0 or an error: after ClientHello: ServerHello, the
 * handshake keys, then EncryptedExtensions, CertificateRequest, Certificate,
 * CertificateVerify and Finished on the Handshake CRYPTO stream, and the
 * 1-RTT keys. s1 the connection, s2 the TLS block. s3 the message.
 */
LOCAL_FUNCTION quic_server_flight
    ENTER   0
    li      a0, 0                           # ServerHello draws our key share first
    call    quic_server_hello
    bnez    a0, 9f
    ld      a0, (T_HASH + 16)(s2)           # the client key share
    ld      a1, (T_HASH + 24)(s2)
    call    quic_shared
    bnez    a0, 9f
    call    quic_handshake_keys
    /* EncryptedExtensions: ALPN libp2p and the transport parameters. */
    SCR     s3, SC_TLS
    li      t0, 8
    sb      t0, 0(s3)
    addi    a0, s3, 6
    lla     a1, 616f
    li      a2, 13
    call    quic_copy
    mv      s4, a0
    li      a1, 0x0039
    call    quic_put16
    addi    a0, a0, 2
    call    quic_tp_write
    mv      s5, a0
    sub     a1, s5, s4
    addi    a1, a1, -4
    addi    a0, s4, 2
    call    quic_put16
    sub     a1, s5, s3
    addi    a1, a1, -6
    addi    a0, s3, 4
    call    quic_put16
    sub     a1, s5, s3
    addi    a1, a1, -4
    addi    a0, s3, 1
    call    quic_put24
    li      a0, SPACE_HANDSHAKE
    mv      a1, s3
    sub     a2, s5, s3
    call    quic_crypto_out
    bnez    a0, 9f
    /* CertificateRequest: empty context, signature_algorithms. */
    li      a0, SPACE_HANDSHAKE
    lla     a1, 617f
    li      a2, 17
    call    quic_crypto_out
    bnez    a0, 9f
    mv      a0, s3
    call    quic_cert_message
    sub     a2, a0, s3
    mv      a1, s3
    li      a0, SPACE_HANDSHAKE
    call    quic_crypto_out
    bnez    a0, 9f
    mv      a0, s3
    li      a1, 1
    call    quic_cv_message
    sub     a2, a0, s3
    mv      a1, s3
    li      a0, SPACE_HANDSHAKE
    call    quic_crypto_out
    bnez    a0, 9f
    mv      a0, s3
    addi    a1, s2, T_S_HS
    call    quic_fin_message
    sub     a2, a0, s3
    mv      a1, s3
    li      a0, SPACE_HANDSHAKE
    call    quic_crypto_out
    bnez    a0, 9f
    call    quic_app_keys
    li      t0, TS_WAIT_CCERT
    sd      t0, T_STAGE(s2)
    li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_server_flight

/* ---------------------------------------------------------------- Messages in */

/*
 * quic_tls_message(space, type, p, end) -> 0 or an error: one handshake
 * message from the peer (p the body, end its end; the whole message is at
 * p - 4) in the order of the stage. s1 the connection, s2 the TLS block.
 * s3 space, s4 type, s5 body, s6 end.
 */
LOCAL_FUNCTION quic_tls_message
    ENTER   0
    mv      s3, a0
    mv      s4, a1
    mv      s5, a2
    mv      s6, a3
    beqz    s2, 30f                         # after the handshake
    ld      t0, T_STAGE(s2)
    li      t1, TS_WAIT_SH
    beq     t0, t1, 1f
    li      t1, TS_WAIT_EE
    beq     t0, t1, 2f
    li      t1, TS_WAIT_CERT_CR
    beq     t0, t1, 3f
    li      t1, TS_WAIT_CERT
    beq     t0, t1, 4f
    li      t1, TS_WAIT_CV
    beq     t0, t1, 5f
    li      t1, TS_WAIT_FIN
    beq     t0, t1, 6f
    li      t1, TS_WAIT_CH
    beq     t0, t1, 7f
    li      t1, TS_WAIT_CCERT
    beq     t0, t1, 8f
    j       30f
1:  li      t0, SPACE_INITIAL               # client: ServerHello
    bne     s3, t0, 90f
    li      t0, 2
    bne     s4, t0, 90f
    mv      a0, s5
    mv      a1, s6
    call    quic_on_server_hello
    li      t0, 2
    beq     a0, t0, 11f
    bnez    a0, 99f
    call    quic_append_in
    bnez    a0, 99f
    call    quic_handshake_keys
    li      t0, TS_WAIT_EE
    sd      t0, T_STAGE(s2)
    j       98f
11: call    quic_message_hash               # HelloRetryRequest
    call    quic_append_in
    bnez    a0, 99f
    call    quic_client_hello
    j       99f
2:  li      t0, SPACE_HANDSHAKE             # client: EncryptedExtensions
    bne     s3, t0, 90f
    li      t0, 8
    bne     s4, t0, 90f
    mv      a0, s5
    mv      a1, s6
    call    quic_on_ee
    bnez    a0, 99f
    li      t0, TS_WAIT_CERT_CR
    j       97f
3:  li      t0, SPACE_HANDSHAKE             # client: CertificateRequest or Certificate
    bne     s3, t0, 90f
    li      t0, 13
    bne     s4, t0, 4f
    mv      a0, s5
    mv      a1, s6
    call    quic_on_cr
    bnez    a0, 99f
    li      t0, TS_WAIT_CERT
    j       97f
4:  li      t0, SPACE_HANDSHAKE             # client: Certificate
    bne     s3, t0, 90f
    li      t0, 11
    bne     s4, t0, 90f
    mv      a0, s5
    mv      a1, s6
    call    quic_on_cert
    bnez    a0, 99f
    li      t0, TS_WAIT_CV
    j       97f
5:  li      t0, SPACE_HANDSHAKE             # both: CertificateVerify
    bne     s3, t0, 90f
    li      t0, 15
    bne     s4, t0, 90f
    ld      t0, C_ROLE(s1)
    seqz    a2, t0                          # the peer is the server when we are the client
    mv      a0, s5
    mv      a1, s6
    call    quic_on_cv
    bnez    a0, 99f
    li      t0, TS_WAIT_FIN
    j       97f
6:  li      t0, SPACE_HANDSHAKE             # both: Finished
    bne     s3, t0, 90f
    li      t0, 20
    bne     s4, t0, 90f
    ld      t0, C_ROLE(s1)
    addi    a2, s2, T_S_HS
    beqz    t0, 63f
    addi    a2, s2, T_C_HS
63: mv      a0, s5
    mv      a1, s6
    call    quic_on_fin
    bnez    a0, 99f
    call    quic_append_in
    bnez    a0, 99f
    ld      t0, C_ROLE(s1)
    bnez    t0, 61f
    call    quic_client_finish
    j       99f
61: call    quic_handshake_complete         # server: the client is verified
    li      a0, 0
    j       99f
7:  li      t0, SPACE_INITIAL               # server: ClientHello
    bne     s3, t0, 90f
    li      t0, 1
    bne     s4, t0, 90f
    mv      a0, s5
    mv      a1, s6
    call    quic_on_client_hello
    li      t0, 2
    beq     a0, t0, 71f
    bnez    a0, 99f
    call    quic_append_in
    bnez    a0, 99f
    call    quic_server_flight
    j       99f
71: call    quic_append_in                  # HelloRetryRequest
    bnez    a0, 99f
    call    quic_message_hash
    li      t0, 1
    sd      t0, T_HRR(s2)
    li      a0, 1
    call    quic_server_hello
    j       99f
8:  li      t0, SPACE_HANDSHAKE             # server: the client Certificate
    bne     s3, t0, 90f
    li      t0, 11
    bne     s4, t0, 90f
    mv      a0, s5
    mv      a1, s6
    call    quic_on_cert
    bnez    a0, 99f
    li      t0, TS_WAIT_CV
    j       97f
30: li      t0, 4                           # after the handshake: NewSessionTicket only, ignored
    bne     s4, t0, 90f
    ld      t0, C_ROLE(s1)
    bnez    t0, 90f
    li      t0, SPACE_APP
    bne     s3, t0, 90f
    li      a0, 0
    j       99f
97: sd      t0, T_STAGE(s2)
    call    quic_append_in
    j       99f
98: li      a0, 0
    j       99f
90: li      a0, (TLS_ERR + ALERT_UNEXPECTED)
99: LEAVE   0
END_FUNCTION quic_tls_message

/* quic_append_in() -> 0 or an error: the message at s5 - 4 to s6 goes into the transcript. */
LOCAL_FUNCTION quic_append_in
    ENTER   0
    addi    a0, s5, -4
    sub     a1, s6, a0
    call    quic_tls_append
    LEAVE   0
END_FUNCTION quic_append_in

/*
 * quic_handshake_complete(): the TLS handshake is complete (RFC 9001 section
 * 4.1.1). A server confirms it at once and sends HANDSHAKE_DONE; the
 * application hears CONNECTED. s1 the connection, s2 the TLS block.
 */
LOCAL_FUNCTION quic_handshake_complete
    ENTER   0
    li      t0, TS_DONE
    sd      t0, T_STAGE(s2)
    ld      t0, C_FLAGS(s1)
    ORV     t0, (CF_COMPLETE | CF_TELL)
    ld      t1, C_ROLE(s1)
    beqz    t1, 1f
    ORV     t0, (CF_CONFIRMED | CF_DONE_FRAME)
1:  sd      t0, C_FLAGS(s1)
    li      t0, CS_ACTIVE
    sd      t0, C_STATE(s1)
    ld      t1, C_ROLE(s1)
    beqz    t1, 2f
    li      a0, SPACE_HANDSHAKE
    call    quic_discard_space
2:  LEAVE   0
END_FUNCTION quic_handshake_complete

/*
 * quic_tls_feed(space) -> 0 or an error: the complete handshake messages at
 * the start of the CRYPTO receive data of the space go to quic_tls_message in
 * order; the rest stays. s1 the connection.
 * s3 the space, s4 the block, s5 the contiguous end.
 */
LOCAL_FUNCTION quic_tls_feed
    ENTER   0
    li      t0, SP_SIZE
    mul     s3, a0, t0
    add     s3, s3, s1
    addi    s3, s3, C_SPACES
    mv      s7, a0
1:  ld      s4, SP_CRX(s3)
    beqz    s4, 8f
    add     s4, s9, s4
    ld      t0, SP_CRX_NR(s3)
    beqz    t0, 8f
    ld      t1, SP_CRX_RANGES(s3)           # the first range must start at 0
    bnez    t1, 8f
    ld      s5, (SP_CRX_RANGES + 8)(s3)
    ld      s6, SP_CRX_DONE(s3)
    sub     t0, s5, s6
    li      t1, 4
    bltu    t0, t1, 8f
    add     a0, s4, s6
    addi    a0, a0, 1
    call    quic_get24
    mv      s8, a0                          # the body length
    addi    t0, s6, 4
    add     t0, t0, s8                      # the message end
    li      t1, CRYPTO_ROOM
    bltu    t1, t0, 7f
    bltu    s5, t0, 8f
    sd      t0, SP_CRX_DONE(s3)
    LDX     t1, s1, C_TLS
    li      s2, 0
    beqz    t1, 2f
    add     s2, s9, t1
2:  mv      a0, s7
    add     t0, s4, s6
    lbu     a1, 0(t0)
    add     a2, s4, s6
    addi    a2, a2, 4
    add     a3, a2, s8
    call    quic_tls_message
    bnez    a0, 9f
    call    quic_crx_compact
    j       1b
7:  li      a0, ERR_CRYPTO_BUFFER
    j       9f
8:  li      a0, 0
9:  LEAVE   0
END_FUNCTION quic_tls_feed

/*
 * quic_crx_compact(): moves the CRYPTO data not yet taken to the start of the
 * block. s3 the space.
 */
LOCAL_FUNCTION quic_crx_compact
    ENTER   0
    ld      s4, SP_CRX(s3)
    add     s4, s9, s4
    ld      s5, SP_CRX_DONE(s3)
    beqz    s5, 9f
    ld      s6, SP_CRX_NR(s3)
    addi    t0, s6, -1                      # the end of the last range
    slli    t0, t0, 4
    addi    t1, s3, SP_CRX_RANGES
    add     t1, t1, t0
    ld      s7, 8(t1)
    mv      a0, s4
    add     a1, s4, s5
    sub     a2, s7, s5
    call    quic_copy
    addi    t1, s3, SP_CRX_RANGES           # shift the ranges
    li      t2, 0
1:  bgeu    t2, s6, 2f
    ld      t3, 0(t1)
    ld      t4, 8(t1)
    sub     t5, t3, s5
    bgeu    t3, s5, 3f
    li      t5, 0
3:  sub     t4, t4, s5
    sd      t5, 0(t1)
    sd      t4, 8(t1)
    addi    t1, t1, 16
    addi    t2, t2, 1
    j       1b
2:  ld      t0, SP_CRX_BASE(s3)
    add     t0, t0, s5
    sd      t0, SP_CRX_BASE(s3)
    sd      zero, SP_CRX_DONE(s3)
    ld      t3, SP_CRX_RANGES(s3)           # an empty first range goes
    ld      t4, (SP_CRX_RANGES + 8)(s3)
    bltu    t3, t4, 9f
    addi    s6, s6, -1
    sd      s6, SP_CRX_NR(s3)
    addi    a0, s3, SP_CRX_RANGES
    addi    a1, a0, 16
    slli    a2, s6, 4
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
