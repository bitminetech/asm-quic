/*
 * Receiving (RFC 9000 sections 5, 12, 17 and 19): datagrams, packet headers,
 * finding or making the connection, opening packets with the key phases,
 * Version Negotiation and Retry for a client, and the frames.
 */

.set ERR_FRAME_ENCODING, 0x07
.set ERR_CID_LIMIT, 0x09
.set ERR_NONE, 0x00

/* ---------------------------------------------------------------- Keys */

/*
 * quic_initial_install(dcid): the Initial keys of the connection from a
 * ConnectionId, for its role. rbx the connection. rbp the Initial space,
 * r12 the client keys, r13 the server keys.
 */
.set II_KEYS, 0                         /* InitialKeys, 96 bytes */
.set II_FRAME, 96
LOCAL_FUNCTION quic_initial_install
    ENTER   0, II_FRAME
    mov     %rdi, %rsi
    lea     (32 + II_KEYS)(%rsp), %rdi
    call    quic_initial_derive
    lea     C_SPACES(%rbx), %rbp
    lea     (32 + II_KEYS + QUIC_INITIAL_CLIENT)(%rsp), %r12
    lea     (32 + II_KEYS + QUIC_INITIAL_SERVER)(%rsp), %r13
    mov     %r12, %rsi                      /* receive: the peer's keys */
    cmpq    $0, C_ROLE(%rbx)
    jne     1f
    mov     %r13, %rsi
1:  lea     SP_RX_KEYS(%rbp), %rdi
    mov     $QUIC_KEYS_SIZE, %edx
    call    quic_copy
    mov     %r13, %rsi
    cmpq    $0, C_ROLE(%rbx)
    jne     2f
    mov     %r12, %rsi
2:  lea     SP_TX_KEYS(%rbp), %rdi
    mov     $QUIC_KEYS_SIZE, %edx
    call    quic_copy
    orq     $(SPF_RX | SPF_TX), SP_FLAGS(%rbp)
    LEAVE   0, II_FRAME
END_FUNCTION quic_initial_install

/* quic_cid_put(cid, p, n): the ConnectionId cid = the n bytes at p (n at most 20). */
LOCAL_FUNCTION quic_cid_put
    ENTER   0
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    lea     QUIC_CID_ID(%rbx), %rdi
    mov     $24, %esi
    call    quic_zero
    mov     %r12, QUIC_CID_LENGTH(%rbx)
    lea     QUIC_CID_ID(%rbx), %rdi
    mov     %rbp, %rsi
    mov     %r12, %rdx
    call    quic_copy
    LEAVE   0
END_FUNCTION quic_cid_put

/* ---------------------------------------------------------------- Datagrams */

/*
 * quic_on_datagram(event): each packet of the datagram in turn (RFC 9000
 * section 12.2): long headers until a short one, which takes the rest.
 * rbp position, r12 end, r13 the datagram size, X23 the event, X24 the
 * connection of the first packet (for the amplification count),
 * X25 the packet start, X26 the connection.
 */
.set DG_DCID, 0                         /* pointer */
.set DG_DCID_LEN, 8
.set DG_SCID, 16
.set DG_SCID_LEN, 24
.set DG_TYPE, 32
.set DG_VERSION, 40
.set DG_PN_OFF, 48
.set DG_END, 56
.set DG_TOKEN, 64
.set DG_TOKEN_LEN, 72
.set DG_FRAME, 80
LOCAL_FUNCTION quic_on_datagram
    ENTER   0, DG_FRAME
    mov     %rdi, X23(%rsp)
    lea     QUIC_EV_DATA(%rdi), %rbp
    mov     QUIC_EV_COUNT(%rdi), %r13
    lea     (%rbp,%r13), %r12
    movq    $0, X24(%rsp)
1:  cmp     %r12, %rbp
    jae     9f
    mov     %rbp, X25(%rsp)
    movzbl  (%rbp), %eax
    test    $0x80, %al
    jz      50f
    /* A long header: the version, the connection IDs. */
    mov     %r12, %rcx
    sub     %rbp, %rcx
    cmp     $7, %rcx
    jb      9f
    mov     1(%rbp), %ecx
    bswap   %ecx
    mov     %rcx, (32 + DG_VERSION)(%rsp)
    movzbl  5(%rbp), %edx
    cmp     $QUIC_CID_MAX, %rdx
    ja      9f
    lea     6(%rbp), %r8
    mov     %r8, (32 + DG_DCID)(%rsp)
    mov     %rdx, (32 + DG_DCID_LEN)(%rsp)
    add     %rdx, %r8
    cmp     %r12, %r8
    jae     9f
    movzbl  (%r8), %r9d
    inc     %r8
    cmp     $QUIC_CID_MAX, %r9
    ja      9f
    mov     %r8, (32 + DG_SCID)(%rsp)
    mov     %r9, (32 + DG_SCID_LEN)(%rsp)
    add     %r9, %r8
    cmp     %r12, %r8
    ja      9f
    mov     %r8, (32 + DG_END)(%rsp)        /* after the SCID: the versions of Version Negotiation */
    cmpq    $0, (32 + DG_VERSION)(%rsp)
    je      40f                             /* Version Negotiation */
    cmpq    $1, (32 + DG_VERSION)(%rsp)
    jne     45f
    shr     $4, %eax
    and     $3, %eax
    mov     %rax, (32 + DG_TYPE)(%rsp)
    cmp     $3, %eax
    je      42f                             /* Retry */
    movq    $0, (32 + DG_TOKEN_LEN)(%rsp)
    test    %eax, %eax
    jnz     2f
    mov     %r8, %rdi                       /* Initial: the token */
    mov     %r12, %rsi
    call    quic_vget
    test    %rax, %rax
    jz      9f
    mov     %r12, %rcx
    sub     %rax, %rcx
    cmp     %rcx, %rdx
    ja      9f
    mov     %rax, (32 + DG_TOKEN)(%rsp)
    mov     %rdx, (32 + DG_TOKEN_LEN)(%rsp)
    lea     (%rax,%rdx), %r8
2:  mov     %r8, %rdi                       /* Length */
    mov     %r12, %rsi
    call    quic_vget
    test    %rax, %rax
    jz      9f
    mov     %r12, %rcx
    sub     %rax, %rcx
    cmp     %rcx, %rdx
    ja      9f
    mov     %rax, (32 + DG_PN_OFF)(%rsp)
    add     %rax, %rdx
    mov     %rdx, (32 + DG_END)(%rsp)
    cmpq    $1, (32 + DG_TYPE)(%rsp)
    je      48f                             /* 0-RTT: dropped */
    /* The connection. */
    mov     (32 + DG_DCID)(%rsp), %rdi
    mov     (32 + DG_DCID_LEN)(%rsp), %rsi
    call    quic_conn_find
    test    %rax, %rax
    jnz     3f
    cmpq    $0, (32 + DG_TYPE)(%rsp)
    jne     48f
    mov     (32 + DG_DCID)(%rsp), %rdi
    mov     (32 + DG_DCID_LEN)(%rsp), %rsi
    mov     X23(%rsp), %rcx
    mov     QUIC_EV_SOCKET(%rcx), %rdx
    add     $QUIC_EV_ADDR, %rcx
    call    quic_conn_find_odcid
    test    %rax, %rax
    jnz     3f
    lea     (32 + DG_DCID)(%rsp), %rdi
    mov     X23(%rsp), %rsi
    call    quic_accept
    test    %rax, %rax
    jz      9f
3:  mov     %rax, X26(%rsp)
    cmpq    $0, X24(%rsp)
    jne     31f
    mov     %rax, X24(%rsp)
31: mov     %rax, %rbx
    cmpq    $0, C_ROLE(%rbx)                /* a client takes the server's connection ID from its first packet */
    jne     32f
    testq   $CF_GOT_PACKET, C_FLAGS(%rbx)
    jnz     32f
    cmpq    $2, (32 + DG_TYPE)(%rsp)
    ja      32f
    lea     C_RCID(%rbx), %rdi
    mov     (32 + DG_SCID)(%rsp), %rsi
    mov     (32 + DG_SCID_LEN)(%rsp), %rdx
    call    quic_cid_put
    lea     C_ISCID(%rbx), %rdi
    mov     (32 + DG_SCID)(%rsp), %rsi
    mov     (32 + DG_SCID_LEN)(%rsp), %rdx
    call    quic_cid_put
32: mov     $SPACE_INITIAL, %esi
    cmpq    $2, (32 + DG_TYPE)(%rsp)
    jne     33f
    mov     $SPACE_HANDSHAKE, %esi
33: mov     %rbx, %rdi
    mov     X25(%rsp), %rdx
    mov     (32 + DG_PN_OFF)(%rsp), %rcx
    sub     %rdx, %rcx
    mov     (32 + DG_END)(%rsp), %r8
    sub     %rdx, %r8
    call    quic_packet_in
    mov     (32 + DG_END)(%rsp), %rbp
    jmp     1b
    /* A short header: our connection ID of 8 bytes, then the rest of the datagram. */
50: mov     %r12, %rcx
    sub     %rbp, %rcx
    cmp     $(1 + 8 + 20), %rcx
    jb      9f
    lea     1(%rbp), %rdi
    mov     $8, %esi
    call    quic_conn_find
    test    %rax, %rax
    jz      9f
    mov     %rax, X26(%rsp)
    cmpq    $0, X24(%rsp)
    jne     51f
    mov     %rax, X24(%rsp)
51: mov     %rax, %rbx
    mov     %rbx, %rdi
    mov     $SPACE_APP, %esi
    mov     %rbp, %rdx
    mov     $9, %ecx
    mov     %r12, %r8
    sub     %rbp, %r8
    call    quic_packet_in
    jmp     9f
40: mov     (32 + DG_DCID)(%rsp), %rdi      /* Version Negotiation, for a client */
    mov     (32 + DG_DCID_LEN)(%rsp), %rsi
    call    quic_conn_find
    test    %rax, %rax
    jz      9f
    mov     %rax, %rbx
    mov     (32 + DG_END)(%rsp), %rdi
    mov     %r12, %rsi
    call    quic_on_vn
    jmp     9f
42: mov     (32 + DG_DCID)(%rsp), %rdi      /* Retry, for a client */
    mov     (32 + DG_DCID_LEN)(%rsp), %rsi
    call    quic_conn_find
    test    %rax, %rax
    jz      9f
    mov     %rax, %rbx
    mov     X25(%rsp), %rdi
    mov     %r12, %rsi
    sub     %rdi, %rsi
    mov     (32 + DG_SCID)(%rsp), %rdx
    mov     (32 + DG_SCID_LEN)(%rsp), %rcx
    call    quic_on_retry
    jmp     9f
45: CFG     %rax, QUIC_CFG_FLAGS            /* another version: Version Negotiation from a server */
    test    $QUIC_CFG_ACCEPT, %al
    jz      9f
    cmp     $1200, %r13
    jb      9f
    mov     (32 + DG_DCID)(%rsp), %rdi
    mov     (32 + DG_DCID_LEN)(%rsp), %rsi
    call    quic_conn_find
    test    %rax, %rax
    jnz     9f
    lea     (32 + DG_DCID)(%rsp), %rdi
    mov     X23(%rsp), %rsi
    call    quic_send_vn
    jmp     9f
48: mov     (32 + DG_END)(%rsp), %rbp       /* skip the packet */
    jmp     1b
9:  mov     X24(%rsp), %rax
    test    %rax, %rax
    jz      99f
    add     %r13, C_RX_BYTES(%rax)
99: LEAVE   0, DG_FRAME
END_FUNCTION quic_on_datagram

/*
 * quic_accept(header, event) -> a new server connection for the first Initial
 * of a client, or 0: the server accepts, the datagram is at least 1200 bytes,
 * the Destination Connection ID is at least 8 bytes, and a slot is free.
 * header: the DG_* fields. rbp header, r12 event.
 */
LOCAL_FUNCTION quic_accept
    ENTER   0
    mov     %rdi, %rbp
    mov     %rsi, %r12
    CFG     %rax, QUIC_CFG_FLAGS
    test    $QUIC_CFG_ACCEPT, %al
    jz      8f
    cmpq    $1200, QUIC_EV_COUNT(%r12)
    jb      8f
    cmpq    $8, DG_DCID_LEN(%rbp)
    jb      8f
    mov     $1, %edi
    call    quic_conn_new
    test    %rax, %rax
    jz      8f
    mov     %rax, %rbx
    mov     QUIC_EV_SOCKET(%r12), %rax
    mov     %rax, C_SOCKET(%rbx)
    lea     C_ADDR(%rbx), %rdi
    lea     QUIC_EV_ADDR(%r12), %rsi
    mov     $QUIC_ADDR_SIZE, %edx
    call    quic_copy
    lea     C_ODCID(%rbx), %rdi
    mov     DG_DCID(%rbp), %rsi
    mov     DG_DCID_LEN(%rbp), %rdx
    call    quic_cid_put
    lea     C_RCID(%rbx), %rdi
    mov     DG_SCID(%rbp), %rsi
    mov     DG_SCID_LEN(%rbp), %rdx
    call    quic_cid_put
    lea     C_ISCID(%rbx), %rdi
    mov     DG_SCID(%rbp), %rsi
    mov     DG_SCID_LEN(%rbp), %rdx
    call    quic_cid_put
    lea     C_ODCID(%rbx), %rdi
    call    quic_initial_install
    mov     C_TLS(%rbx), %rax
    movq    $TS_WAIT_CH, T_STAGE(%r15,%rax)
    call    quic_idle_reset
    mov     %rbx, %rax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_accept

/*
 * quic_send_vn(header, event): a Version Negotiation packet back to a client
 * that offered another version (RFC 9000 section 6.1): the connection IDs
 * swapped, version 1 the only one listed. header: the DG_* fields.
 * rbp header, r12 event, r13 the length, X23 the action, X24 its data.
 */
LOCAL_FUNCTION quic_send_vn
    ENTER   0
    mov     %rdi, %rbp
    mov     %rsi, %r12
    mov     DG_DCID_LEN(%rbp), %r13
    add     DG_SCID_LEN(%rbp), %r13
    add     $11, %r13                       /* first byte, version, two lengths, one version */
    lea     (QUIC_ACT_DATA + 7)(%r13), %rsi
    and     $-8, %rsi
    mov     $QUIC_ACTION_SEND, %edi
    call    quic_action
    test    %rax, %rax
    jz      9f
    mov     %rax, X23(%rsp)
    mov     QUIC_EV_SOCKET(%r12), %rcx
    mov     %rcx, QUIC_ACT_SOCKET(%rax)
    lea     QUIC_ACT_ADDR(%rax), %rdi
    lea     QUIC_EV_ADDR(%r12), %rsi
    mov     $QUIC_ADDR_SIZE, %edx
    call    quic_copy
    mov     X23(%rsp), %rax
    mov     %r13, QUIC_ACT_COUNT(%rax)
    lea     QUIC_ACT_DATA(%rax), %rdi
    mov     %rdi, X24(%rsp)
    mov     $1, %esi
    call    quic_random
    mov     X24(%rsp), %rax
    orb     $0x80, (%rax)
    movl    $0, 1(%rax)
    mov     DG_SCID_LEN(%rbp), %rdx
    movb    %dl, 5(%rax)
    lea     6(%rax), %rdi
    mov     DG_SCID(%rbp), %rsi
    call    quic_copy
    mov     DG_DCID_LEN(%rbp), %rdx
    movb    %dl, (%rax)
    lea     1(%rax), %rdi
    mov     DG_DCID(%rbp), %rsi
    call    quic_copy
    movl    $0x01000000, (%rax)             /* version 1, big endian */
9:  LEAVE   0
END_FUNCTION quic_send_vn

/*
 * quic_on_vn(p, end): Version Negotiation for a client before any packet of
 * the server: when it does not list version 1, the dial fails with
 * QUIC_ERR_VERSION (RFC 9000 section 6.2). rbx the connection. rbp p, r12 end.
 */
LOCAL_FUNCTION quic_on_vn
    ENTER   0
    mov     %rdi, %rbp
    mov     %rsi, %r12
    cmpq    $0, C_ROLE(%rbx)
    jne     9f
    testq   $CF_GOT_PACKET, C_FLAGS(%rbx)
    jnz     9f
    cmpq    $CS_HANDSHAKE, C_STATE(%rbx)
    jne     9f
1:  mov     %r12, %rax
    sub     %rbp, %rax
    cmp     $4, %rax
    jb      2f
    mov     (%rbp), %eax
    add     $4, %rbp
    cmp     $0x01000000, %eax
    je      9f                              /* lists ours: ignored */
    jmp     1b
2:  movq    $QUIC_ERR_VERSION, C_REASON(%rbx)
    mov     %rbx, %rdi
    xor     %esi, %esi
    call    quic_conn_drain
    movq    $0, C_CLOSE_AT(%rbx)            /* nothing to wait for */
9:  LEAVE   0
END_FUNCTION quic_on_vn

/*
 * quic_on_retry(packet, n, scid, scid_len): a Retry for a client before any
 * other packet of the server, once (RFC 9000 section 17.2.5): with a valid
 * integrity tag, the server's connection ID and the token are taken, the
 * Initial keys change, and the ClientHello goes again in new Initial packets.
 * rbx the connection.
 * rbp packet, r12 n, r13 scid, X23 scid length, X24 the pseudo-packet then
 * the token, X25 the Retry without its tag, then the token length.
 */
.set RY_TAG, 0
.set RY_PLAIN, 16                       /* ByteList: empty */
.set RY_SEALED, 40                      /* ByteList: 24 + 16 */
.set RY_NONCE, 80
.set RY_FRAME, 96
LOCAL_FUNCTION quic_on_retry
    ENTER   0, RY_FRAME
    mov     %rdi, %rbp
    mov     %rsi, %r12
    mov     %rdx, %r13
    mov     %rcx, X23(%rsp)
    cmpq    $0, C_ROLE(%rbx)
    jne     9f
    testq   $(CF_GOT_PACKET | CF_RETRIED), C_FLAGS(%rbx)
    jnz     9f
    lea     (%r13,%rcx), %rax               /* the token: after the SCID, up to the tag */
    lea     -16(%rbp,%r12), %rdx
    cmp     %rdx, %rax
    jae     9f                              /* no token */
    lea     -16(%r12), %rax
    cmp     $W_SEALED_MAX, %rax
    ja      9f
    /* The pseudo-packet in the packet buffer of the scratch: ODCID, then the Retry without its tag. */
    lea     SC_PKT_BUF(%r14), %rax
    mov     %rax, X24(%rsp)
    lea     -16(%r12), %rcx
    mov     %rcx, X25(%rsp)
    mov     (C_ODCID + QUIC_CID_LENGTH)(%rbx), %rdx
    lea     1(%rcx,%rdx), %r8
    BYTELIST %rax, 0, 1776, %r8
    movb    %dl, QUIC_BL_FIXED(%rax)
    lea     (QUIC_BL_FIXED + 1)(%rax), %rdi
    lea     (C_ODCID + QUIC_CID_ID)(%rbx), %rsi
    call    quic_copy
    mov     %rax, %rdi
    mov     %rbp, %rsi
    mov     X25(%rsp), %rdx
    call    quic_copy
    xor     %eax, %eax
    BYTELIST %rsp, (32 + RY_PLAIN), 24, %rax
    movq    $40, (32 + RY_SEALED)(%rsp)
    lea     508b(%rip), %rax                /* the Retry nonce and key, in keys.s */
    mov     (%rax), %rcx
    movl    8(%rax), %edx
    mov     %rcx, (32 + RY_NONCE)(%rsp)
    mov     %rdx, (32 + RY_NONCE + 8)(%rsp)
    lea     507b(%rip), %rdi
    lea     (32 + RY_NONCE)(%rsp), %rsi
    lea     (32 + RY_PLAIN)(%rsp), %rdx
    mov     X24(%rsp), %rcx
    lea     (32 + RY_SEALED)(%rsp), %r8
    CALL_GLOBAL crypto_aes128_gcm_ae
    lea     (32 + RY_SEALED + 24)(%rsp), %rdi
    mov     X25(%rsp), %rsi
    add     %rbp, %rsi
    mov     $16, %edx
    call    quic_equal
    test    %rax, %rax
    jz      9f
    /* Valid: the new connection ID, the token, new Initial keys. */
    orq     $CF_RETRIED, C_FLAGS(%rbx)
    lea     C_RSCID(%rbx), %rdi
    mov     %r13, %rsi
    mov     X23(%rsp), %rdx
    call    quic_cid_put
    lea     C_RCID(%rbx), %rdi
    mov     %r13, %rsi
    mov     X23(%rsp), %rdx
    call    quic_cid_put
    mov     %r13, %rax                      /* the token */
    add     X23(%rsp), %rax
    mov     %rax, X24(%rsp)
    lea     -16(%rbp,%r12), %rcx
    sub     %rax, %rcx
    mov     %rcx, X25(%rsp)
    mov     %rcx, %rdi
    call    quic_heap_alloc
    test    %rax, %rax
    jz      9f
    mov     %rax, C_TOKEN(%rbx)
    mov     X25(%rsp), %rcx
    mov     %rcx, C_TOKEN_LEN(%rbx)
    lea     (%r15,%rax), %rdi
    mov     X24(%rsp), %rsi
    mov     X25(%rsp), %rdx
    call    quic_copy
    lea     C_RCID(%rbx), %rdi
    call    quic_initial_install
    mov     $SPACE_INITIAL, %edi            /* the Initial packets sent are gone; the ClientHello goes again */
    call    quic_drop_space_records
    mov     %rbx, %rdi
    mov     $SPACE_INITIAL, %esi
    call    quic_space
    movq    $0, SP_CTX_SENT(%rax)
    movq    $0, C_PTO_COUNT(%rbx)
    call    quic_set_loss_timer
9:  LEAVE   0, RY_FRAME
END_FUNCTION quic_on_retry

/* ---------------------------------------------------------------- Packets */

/*
 * quic_packet_in(conn, space, packet, pn_offset, n): one packet of a
 * datagram: opened with the keys of its space (the next or the previous key
 * phase for a 1-RTT packet), checked, its packet number recorded, and its
 * frames handled. A packet that does not open is dropped; a 1-RTT one may be
 * a stateless reset.
 * rbx conn, rbp space, r12 packet, r13 pn offset then pn, X23 n, X24 the space record.
 */
LOCAL_FUNCTION quic_packet_in
    ENTER   0
    mov     %rdi, %rbx
    mov     %rsi, %rbp
    mov     %rdx, %r12
    mov     %rcx, %r13
    mov     %r8, X23(%rsp)
    mov     %rbx, %rdi
    mov     %rbp, %rsi
    call    quic_space
    mov     %rax, X24(%rsp)
    cmpq    $CS_DRAINING, C_STATE(%rbx)
    jae     9f
    mov     SP_FLAGS(%rax), %rcx
    test    $SPF_RX, %cl
    jz      9f
    test    $SPF_DISCARDED, %cl
    jnz     9f
    cmpq    $(W_HEADER_MAX + W_SEALED_MAX), X23(%rsp)
    ja      9f
    lea     SP_RX_KEYS(%rax), %rdi
    mov     X23(%rsp), %rsi
    mov     X24(%rsp), %rdx
    call    quic_try_open
    test    %rax, %rax
    jz      5f
    cmp     $SPACE_APP, %rbp                /* 1-RTT: another key phase? */
    jne     4f
    movzbl  SC_PKT_BUF(%r14), %eax
    shr     $2, %eax
    and     $1, %eax
    cmp     C_KEY_PHASE(%rbx), %rax
    je      4f
    lea     C_NEXT_RX(%rbx), %rdi
    mov     X23(%rsp), %rsi
    mov     X24(%rsp), %rdx
    call    quic_try_open
    test    %rax, %rax
    jnz     2f
    mov     SC_PKT_RESULT(%r14), %rax       /* the next phase must be newer than the current one */
    mov     C_PHASE_PN(%rbx), %rcx
    cmp     $-1, %rcx
    je      1f
    cmp     %rcx, %rax
    jbe     2f
1:  call    quic_key_update                 /* the peer moved to the next key phase */
    call    quic_phase_start
    mov     SC_PKT_RESULT(%r14), %rax
    mov     %rax, C_PHASE_PN(%rbx)
    jmp     5f
2:  mov     C_PREV_UNTIL(%rbx), %rax        /* a late packet of the previous phase */
    cmp     $-1, %rax
    je      4f
    cmp     %rax, ST_NOW(%r15)
    jae     4f
    lea     C_PREV_RX(%rbx), %rdi
    mov     X23(%rsp), %rsi
    mov     X24(%rsp), %rdx
    call    quic_try_open
    test    %rax, %rax
    jz      5f
4:  cmp     $SPACE_APP, %rbp                /* a stateless reset? (RFC 9000 section 10.3.1) */
    jne     9f
    testq   $CF_RESET_TOKEN, C_FLAGS(%rbx)
    jz      9f
    mov     X23(%rsp), %rdi
    lea     -16(%r12,%rdi), %rdi
    lea     C_RCID_TOKEN(%rbx), %rsi
    mov     $16, %edx
    call    quic_equal
    test    %rax, %rax
    jz      9f
    movq    $QUIC_ERR_RESET, C_REASON(%rbx)
    mov     %rbx, %rdi
    xor     %esi, %esi
    call    quic_conn_drain
    jmp     9f
5:  /* Opened: the reserved bits, duplicates, then the frames. */
    movzbl  SC_PKT_BUF(%r14), %eax
    mov     $0x18, %ecx
    test    $0x80, %al
    jz      51f
    mov     $0x0C, %ecx
51: test    %ecx, %eax
    jz      6f
    mov     %rbx, %rdi
    mov     $ERR_PROTOCOL, %esi
    mov     $QUIC_ERR_PROTOCOL, %edx
    call    quic_conn_close
    jmp     9f
6:  cmpq    $CS_CLOSING, C_STATE(%rbx)
    jne     61f
    orq     $CF_CLOSE_FRAME, C_FLAGS(%rbx)  /* closing: answer with CONNECTION_CLOSE again */
    jmp     9f
61: mov     SC_PKT_RESULT(%r14), %r13       /* the packet number */
    mov     X24(%rsp), %rdi
    mov     %r13, %rsi
    call    quic_recv_pn
    test    %rax, %rax
    jnz     9f
    mov     X24(%rsp), %rax
    mov     SP_LARGEST_RECV(%rax), %rcx
    cmp     $-1, %rcx
    je      7f
    cmp     %r13, %rcx
    jae     71f
7:  mov     %r13, SP_LARGEST_RECV(%rax)
    mov     ST_NOW(%r15), %rcx
    mov     %rcx, SP_RECV_TIME(%rax)
71: mov     C_FLAGS(%rbx), %rax
    or      $CF_GOT_PACKET, %rax
    and     $~CF_ELICIT_SENT, %rax
    mov     %rax, C_FLAGS(%rbx)
    mov     (SC_PKT_RESULT + 8)(%r14), %rdi
    lea     SC_PKT_BUF(%r14,%rdi), %rdi
    mov     (SC_PKT_RESULT + 16)(%r14), %rsi
    mov     %rbp, %rdx
    call    quic_frames
    test    %rax, %rax
    jz      72f
    cmp     $-1, %rax
    je      9f                              /* CONNECTION_CLOSE: draining */
    mov     %rax, %rsi
    mov     %rbx, %rdi
    mov     $QUIC_ERR_PROTOCOL, %edx
    call    quic_conn_close
    jmp     9f
72: test    $1, %dl                         /* ack-eliciting: an ACK is due */
    jz      74f
    mov     X24(%rsp), %rax
    mov     SP_ACK_COUNT(%rax), %rcx
    inc     %rcx
    mov     %rcx, SP_ACK_COUNT(%rax)
    cmp     $SPACE_APP, %rbp
    jne     73f
    cmp     $2, %rcx
    jae     73f
    mov     ST_NOW(%r15), %rcx
    add     $25000, %rcx                    /* our max_ack_delay */
    cmp     SP_ACK_AT(%rax), %rcx
    jae     74f
    mov     %rcx, SP_ACK_AT(%rax)
    jmp     74f
73: orq     $SPF_ACK_NOW, SP_FLAGS(%rax)
74: call    quic_idle_reset
    cmpq    $0, C_ROLE(%rbx)                /* a server: a Handshake packet validates the address and ends Initial */
    je      9f
    cmp     $SPACE_HANDSHAKE, %rbp
    jne     9f
    orq     $CF_VALIDATED, C_FLAGS(%rbx)
    mov     $SPACE_INITIAL, %edi
    call    quic_discard_space
9:  LEAVE   0
END_FUNCTION quic_packet_in

/*
 * quic_try_open(keys, n, space) -> 0 when the packet at r12 (n bytes, the
 * packet number at r13) opens with the keys: it is copied to the packet buffer
 * of the scratch and opened there (quic_unprotect, then quic_open), the result
 * in SC_PKT_RESULT. Else the error; when quic_unprotect gave QUIC_OK, the
 * buffer then holds the packet without header protection.
 * space: the space record. rbp keys, X23 n, X24 the space record.
 */
LOCAL_FUNCTION quic_try_open
    ENTER   0
    mov     %rdi, %rbp
    mov     %rsi, X23(%rsp)
    mov     %rdx, X24(%rsp)
    lea     SC_PKT_BUF(%r14), %rdi
    mov     %r12, %rsi
    mov     X23(%rsp), %rdx
    call    quic_copy
    mov     %rbp, %rdi
    lea     SC_PKT_BUF(%r14), %rsi
    mov     %r13, %rdx
    mov     X23(%rsp), %rcx
    lea     SC_PKT_WORK(%r14), %r8
    call    quic_unprotect
    test    %rax, %rax
    jnz     9f
    mov     %rbp, %rdi
    lea     SC_PKT_BUF(%r14), %rsi
    mov     %r13, %rdx
    mov     X23(%rsp), %rcx
    mov     X24(%rsp), %rax
    mov     SP_LARGEST_RECV(%rax), %r8
    lea     SC_PKT_WORK(%r14), %r9
    lea     SC_PKT_RESULT(%r14), %r10
    call    quic_open
9:  LEAVE   0
END_FUNCTION quic_try_open

/* ---------------------------------------------------------------- Frames */

/*
 * quic_frames(p, n, space) -> rax 0, -1 after a CONNECTION_CLOSE, or the error
 * code; rdx bit 0 when the packet is ack-eliciting. The frames of a packet in
 * order (RFC 9000 section 19); Initial and Handshake packets carry PADDING,
 * PING, ACK, CRYPTO and CONNECTION_CLOSE only (section 12.4).
 * rbx the connection, rbp position, r12 end, r13 space, X23 ack-eliciting, X24 type.
 */
LOCAL_FUNCTION quic_frames
    ENTER   0
    mov     %rdi, %rbp
    lea     (%rdi,%rsi), %r12
    mov     %rdx, %r13
    movq    $0, X23(%rsp)
    test    %rsi, %rsi
    jz      80f                             /* a packet with no frames */
1:  cmp     %r12, %rbp
    jae     90f
    mov     %rbp, %rdi
    mov     %r12, %rsi
    call    quic_vget
    test    %rax, %rax
    jz      81f
    mov     %rax, %rbp
    mov     %rdx, X24(%rsp)
    test    %rdx, %rdx
    jz      1b                              /* PADDING */
    cmp     $SPACE_APP, %r13
    je      2f
    cmp     $0x01, %rdx
    je      2f
    cmp     $0x02, %rdx
    je      2f
    cmp     $0x03, %rdx
    je      2f
    cmp     $0x06, %rdx
    je      2f
    cmp     $0x1C, %rdx
    je      2f
    jmp     80f
2:  cmp     $0x02, %rdx
    je      20f
    cmp     $0x03, %rdx
    je      20f
    cmp     $0x1C, %rdx
    je      28f
    cmp     $0x1D, %rdx
    je      28f
    orq     $1, X23(%rsp)                   /* every other frame is ack-eliciting */
    cmp     $0x01, %rdx
    je      1b
    cmp     $0x04, %rdx
    je      21f
    cmp     $0x05, %rdx
    je      22f
    cmp     $0x06, %rdx
    je      23f
    cmp     $0x07, %rdx
    je      24f
    cmp     $0x08, %rdx
    jb      81f
    cmp     $0x0F, %rdx
    jbe     25f
    cmp     $0x10, %rdx
    je      30f
    cmp     $0x11, %rdx
    je      31f
    cmp     $0x12, %rdx
    je      32f
    cmp     $0x13, %rdx
    je      33f
    cmp     $0x14, %rdx
    je      33f
    cmp     $0x15, %rdx
    je      34f
    cmp     $0x16, %rdx
    je      33f
    cmp     $0x17, %rdx
    je      33f
    cmp     $0x18, %rdx
    je      35f
    cmp     $0x19, %rdx
    je      36f
    cmp     $0x1A, %rdx
    je      37f
    cmp     $0x1B, %rdx
    je      38f
    cmp     $0x1E, %rdx
    je      39f
    jmp     81f
20: mov     %rbp, %rdi                      /* ACK */
    mov     %r12, %rsi
    mov     %r13, %rdx
    mov     X24(%rsp), %rcx
    call    quic_frame_ack
    jmp     60f
21: mov     %rbp, %rdi                      /* RESET_STREAM */
    mov     %r12, %rsi
    call    quic_v3
    test    %rax, %rax
    jz      81f
    mov     %rax, %rbp
    mov     SC_FRAME(%r14), %rdi
    mov     (SC_FRAME + 8)(%r14), %rsi
    mov     (SC_FRAME + 16)(%r14), %rdx
    call    quic_on_reset_stream
    jmp     61f
22: mov     %rbp, %rdi                      /* STOP_SENDING */
    mov     %r12, %rsi
    call    quic_v2
    test    %rax, %rax
    jz      81f
    mov     %rax, %rbp
    mov     SC_FRAME(%r14), %rdi
    mov     (SC_FRAME + 8)(%r14), %rsi
    call    quic_on_stop_sending
    jmp     61f
23: mov     %rbp, %rdi                      /* CRYPTO */
    mov     %r12, %rsi
    call    quic_v2
    test    %rax, %rax
    jz      81f
    mov     (SC_FRAME + 8)(%r14), %rcx
    mov     %r12, %rdx
    sub     %rax, %rdx
    cmp     %rdx, %rcx
    ja      81f
    lea     (%rax,%rcx), %rbp
    mov     %rax, %rdx
    mov     %r13, %rdi
    mov     SC_FRAME(%r14), %rsi
    call    quic_on_crypto
    jmp     61f
24: cmpq    $0, C_ROLE(%rbx)                /* NEW_TOKEN: for a client, not used */
    jne     80f
    mov     %rbp, %rdi
    mov     %r12, %rsi
    call    quic_vget
    test    %rax, %rax
    jz      81f
    mov     %r12, %rcx
    sub     %rax, %rcx
    cmp     %rcx, %rdx
    ja      81f
    test    %rdx, %rdx
    jz      81f
    lea     (%rax,%rdx), %rbp
    jmp     1b
25: mov     %rbp, %rdi                      /* STREAM */
    mov     %r12, %rsi
    mov     X24(%rsp), %rdx
    call    quic_frame_stream
    jmp     60f
30: mov     %rbp, %rdi                      /* MAX_DATA */
    mov     %r12, %rsi
    call    quic_vget
    test    %rax, %rax
    jz      81f
    mov     %rax, %rbp
    cmp     C_TX_MAX(%rbx), %rdx
    jbe     1b
    mov     %rdx, C_TX_MAX(%rbx)
    jmp     1b
31: mov     %rbp, %rdi                      /* MAX_STREAM_DATA */
    mov     %r12, %rsi
    call    quic_v2
    test    %rax, %rax
    jz      81f
    mov     %rax, %rbp
    mov     SC_FRAME(%r14), %rdi
    mov     (SC_FRAME + 8)(%r14), %rsi
    call    quic_on_max_stream_data
    jmp     61f
32: mov     %rbp, %rdi                      /* MAX_STREAMS (bidirectional) */
    mov     %r12, %rsi
    call    quic_vget
    test    %rax, %rax
    jz      81f
    mov     %rax, %rbp
    movabs  $(1 << 60), %rcx
    cmp     %rcx, %rdx
    ja      81f
    cmp     C_P_STREAMS(%rbx), %rdx
    jbe     1b
    mov     %rdx, C_P_STREAMS(%rbx)
    call    quic_assign_ids
    jmp     1b
33: mov     %rbp, %rdi                      /* MAX_STREAMS (uni), DATA_BLOCKED, STREAMS_BLOCKED: one varint */
    mov     %r12, %rsi
    call    quic_vget
    test    %rax, %rax
    jz      81f
    mov     %rax, %rbp
    jmp     1b
34: mov     %rbp, %rdi                      /* STREAM_DATA_BLOCKED: two varints */
    mov     %r12, %rsi
    call    quic_v2
    test    %rax, %rax
    jz      81f
    mov     %rax, %rbp
    jmp     1b
35: mov     %rbp, %rdi                      /* NEW_CONNECTION_ID */
    mov     %r12, %rsi
    call    quic_frame_new_cid
    jmp     60f
36: mov     %rbp, %rdi                      /* RETIRE_CONNECTION_ID: we gave only sequence 0 */
    mov     %r12, %rsi
    call    quic_vget
    test    %rax, %rax
    jz      81f
    mov     %rax, %rbp
    test    %rdx, %rdx
    jnz     80f
    jmp     1b
37: mov     %r12, %rax                      /* PATH_CHALLENGE */
    sub     %rbp, %rax
    cmp     $8, %rax
    jb      81f
    mov     (%rbp), %rax
    mov     %rax, C_CHALLENGE(%rbx)
    add     $8, %rbp
    orq     $CF_CHALLENGE, C_FLAGS(%rbx)
    jmp     1b
38: mov     %r12, %rax                      /* PATH_RESPONSE: we send no challenge */
    sub     %rbp, %rax
    cmp     $8, %rax
    jb      81f
    add     $8, %rbp
    jmp     1b
39: cmpq    $0, C_ROLE(%rbx)                /* HANDSHAKE_DONE: for a client */
    jne     80f
    testq   $CF_CONFIRMED, C_FLAGS(%rbx)
    jnz     1b
    call    quic_confirm
    jmp     1b
28: mov     %rbp, %rdi                      /* CONNECTION_CLOSE */
    mov     %r12, %rsi
    mov     X24(%rsp), %rdx
    call    quic_frame_close
    test    %rax, %rax
    jz      81f
    mov     $-1, %rax
    jmp     99f
60: test    %rax, %rax                      /* rax the position, rdx the error */
    jz      81f
    test    %rdx, %rdx
    jnz     98f
    mov     %rax, %rbp
    jmp     1b
61: test    %rax, %rax                      /* rax the error */
    jnz     99f
    jmp     1b
80: mov     $ERR_PROTOCOL, %eax
    jmp     99f
81: mov     $ERR_FRAME_ENCODING, %eax
    jmp     99f
90: xor     %eax, %eax
    jmp     99f
98: mov     %rdx, %rax
99: mov     X23(%rsp), %rdx
    LEAVE   0
END_FUNCTION quic_frames

/* quic_v2(p, end) -> the position after two varints, their values at SC_FRAME, or 0. rbx end. */
LOCAL_FUNCTION quic_v2
    ENTER   0
    mov     %rsi, %rbx
    call    quic_vget
    test    %rax, %rax
    jz      9f
    mov     %rdx, SC_FRAME(%r14)
    mov     %rax, %rdi
    mov     %rbx, %rsi
    call    quic_vget
    test    %rax, %rax
    jz      9f
    mov     %rdx, (SC_FRAME + 8)(%r14)
9:  LEAVE   0
END_FUNCTION quic_v2

/* quic_v3(p, end) -> the position after three varints, their values at SC_FRAME, or 0. rbx end. */
LOCAL_FUNCTION quic_v3
    ENTER   0
    mov     %rsi, %rbx
    call    quic_v2
    test    %rax, %rax
    jz      9f
    mov     %rax, %rdi
    mov     %rbx, %rsi
    call    quic_vget
    test    %rax, %rax
    jz      9f
    mov     %rdx, (SC_FRAME + 16)(%r14)
9:  LEAVE   0
END_FUNCTION quic_v3

/*
 * quic_frame_ack(p, end, space, type) -> rax the position after the ACK frame
 * or 0; rdx 0 or the error. Its ranges go to the area SC_OUT (at most 64; the
 * rest are not read for loss) and to quic_on_ack. An ACK of a packet number
 * never sent is a PROTOCOL_VIOLATION.
 * rbx the connection, rbp position, r12 end, r13 space, X23 ranges, X24 count,
 * X25 smallest so far, X26 n kept.
 */
LOCAL_FUNCTION quic_frame_ack
    ENTER   0
    mov     %rdi, %rbp
    mov     %rsi, %r12
    mov     %rdx, %r13
    mov     %rcx, (SC_FRAME + 32)(%r14)
    movq    $0, (SC_FRAME + 40)(%r14)
    lea     SC_OUT(%r14), %rax
    mov     %rax, X23(%rsp)
    mov     %rbp, %rdi
    mov     %r12, %rsi
    call    quic_v3                         /* largest, delay, range count */
    test    %rax, %rax
    jz      8f
    mov     %rax, %rbp
    mov     %rbx, %rdi                      /* the largest: below the next packet number */
    mov     %r13, %rsi
    call    quic_space
    mov     SC_FRAME(%r14), %rcx
    cmp     SP_NEXT_PN(%rax), %rcx
    jae     7f
    mov     (SC_FRAME + 16)(%r14), %rax
    mov     %rax, X24(%rsp)
    mov     (SC_FRAME + 8)(%r14), %rax      /* the delay, in microseconds */
    mov     C_P_ACK_EXP(%rbx), %rcx
    shl     %cl, %rax
    mov     %rax, (SC_FRAME + 24)(%r14)
    mov     %rbp, %rdi                      /* the first range */
    mov     %r12, %rsi
    call    quic_vget
    test    %rax, %rax
    jz      8f
    mov     %rax, %rbp
    mov     SC_FRAME(%r14), %rcx
    cmp     %rdx, %rcx
    jb      6f
    mov     %rcx, %r8
    sub     %rdx, %r8
    mov     %r8, X25(%rsp)
    mov     X23(%rsp), %rax
    mov     %r8, (%rax)
    mov     %rcx, 8(%rax)
    movq    $1, X26(%rsp)
1:  cmpq    $0, X24(%rsp)
    je      3f
    mov     %rbp, %rdi
    mov     %r12, %rsi
    call    quic_v2                         /* gap, length */
    test    %rax, %rax
    jz      8f
    mov     %rax, %rbp
    mov     SC_FRAME(%r14), %rcx
    mov     (SC_FRAME + 8)(%r14), %rdx
    add     $2, %rcx
    mov     X25(%rsp), %r8
    cmp     %rcx, %r8
    jb      6f
    sub     %rcx, %r8                       /* the largest of this range */
    cmp     %rdx, %r8
    jb      6f
    mov     %r8, %r9
    sub     %rdx, %r9
    mov     %r9, X25(%rsp)
    mov     X26(%rsp), %rax
    cmp     $64, %rax
    jae     2f
    shl     $4, %rax
    add     X23(%rsp), %rax
    mov     %r9, (%rax)
    mov     %r8, 8(%rax)
    incq    X26(%rsp)
2:  decq    X24(%rsp)
    jmp     1b
3:  cmpq    $0x03, (SC_FRAME + 32)(%r14)
    jne     4f
    mov     %rbp, %rdi                      /* ECN counts */
    mov     %r12, %rsi
    call    quic_v3
    test    %rax, %rax
    jz      8f
    mov     %rax, %rbp
4:  mov     %r13, %rdi
    mov     X23(%rsp), %rsi
    mov     X26(%rsp), %rdx
    mov     (SC_FRAME + 24)(%r14), %rcx
    call    quic_on_ack
    mov     %rbp, %rax
    xor     %edx, %edx
    jmp     9f
6:  mov     %rbp, %rax
    mov     $ERR_FRAME_ENCODING, %edx
    jmp     9f
7:  mov     %rbp, %rax
    mov     $ERR_PROTOCOL, %edx
    jmp     9f
8:  xor     %eax, %eax
    xor     %edx, %edx
9:  LEAVE   0
END_FUNCTION quic_frame_ack

/*
 * quic_frame_stream(p, end, type) -> rax the position after the STREAM frame
 * or 0; rdx 0 or the error.
 * rbp position, r12 end, r13 type, X23 id, X24 offset, X25 length, X26 the frame end.
 */
LOCAL_FUNCTION quic_frame_stream
    ENTER   0
    mov     %rdi, %rbp
    mov     %rsi, %r12
    mov     %rdx, %r13
    call    quic_vget
    test    %rax, %rax
    jz      8f
    mov     %rax, %rbp
    mov     %rdx, X23(%rsp)
    movq    $0, X24(%rsp)
    test    $4, %r13b
    jz      1f
    mov     %rbp, %rdi
    mov     %r12, %rsi
    call    quic_vget
    test    %rax, %rax
    jz      8f
    mov     %rax, %rbp
    mov     %rdx, X24(%rsp)
1:  mov     %r12, %rax                      /* no LEN: to the end of the packet */
    sub     %rbp, %rax
    mov     %rax, X25(%rsp)
    test    $2, %r13b
    jz      2f
    mov     %rbp, %rdi
    mov     %r12, %rsi
    call    quic_vget
    test    %rax, %rax
    jz      8f
    mov     %rax, %rbp
    mov     %r12, %rcx
    sub     %rbp, %rcx
    cmp     %rcx, %rdx
    ja      8f
    mov     %rdx, X25(%rsp)
2:  mov     X25(%rsp), %rcx
    lea     (%rbp,%rcx), %rax
    mov     %rax, X26(%rsp)
    mov     X23(%rsp), %rdi
    mov     X24(%rsp), %rsi
    mov     %rbp, %rdx
    mov     %r13, %r8
    and     $1, %r8d
    call    quic_on_stream_frame
    mov     %rax, %rdx
    mov     X26(%rsp), %rax
    jmp     9f
8:  xor     %eax, %eax
    xor     %edx, %edx
9:  LEAVE   0
END_FUNCTION quic_frame_stream

/*
 * quic_frame_close(p, end, type) -> the position after the CONNECTION_CLOSE
 * frame, or 0: the connection drains; the application hears the code.
 * rbp end, r12 type, r13 the code, X23 the position after.
 */
LOCAL_FUNCTION quic_frame_close
    ENTER   0
    mov     %rsi, %rbp
    mov     %rdx, %r12
    call    quic_vget                       /* the error code */
    test    %rax, %rax
    jz      8f
    mov     %rdx, %r13
    cmp     $0x1C, %r12
    jne     1f
    mov     %rax, %rdi                      /* the frame type */
    mov     %rbp, %rsi
    call    quic_vget
    test    %rax, %rax
    jz      8f
1:  mov     %rax, %rdi                      /* the reason */
    mov     %rbp, %rsi
    call    quic_vget
    test    %rax, %rax
    jz      8f
    mov     %rbp, %rcx
    sub     %rax, %rcx
    cmp     %rcx, %rdx
    ja      8f
    add     %rdx, %rax
    mov     %rax, X23(%rsp)
    movq    $QUIC_ERR_PEER, C_REASON(%rbx)
    mov     %rbx, %rdi
    mov     %r13, %rsi
    call    quic_conn_drain
    mov     X23(%rsp), %rax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_frame_close

/*
 * quic_frame_new_cid(p, end) -> rax the position after the NEW_CONNECTION_ID
 * frame, or 0; rdx 0 or the error. We hold the peer's connection ID in use and
 * one spare (active_connection_id_limit 2); retire_prior_to moves us to the
 * spare and retires the old one.
 * rbp end, r12 seq, r13 retire_prior_to, X23 the ID, X24 its length,
 * X25 the token, X26 the frame end.
 */
LOCAL_FUNCTION quic_frame_new_cid
    ENTER   0
    mov     %rsi, %rbp
    call    quic_v2
    test    %rax, %rax
    jz      8f
    mov     SC_FRAME(%r14), %r12
    mov     (SC_FRAME + 8)(%r14), %r13
    cmp     %r13, %r12
    jb      7f
    cmp     %rbp, %rax
    jae     8f
    movzbl  (%rax), %ecx
    inc     %rax
    mov     %rcx, X24(%rsp)
    test    %rcx, %rcx
    jz      7f
    cmp     $QUIC_CID_MAX, %rcx
    ja      7f
    mov     %rax, X23(%rsp)
    add     %rcx, %rax
    mov     %rax, X25(%rsp)
    add     $16, %rax
    mov     %rax, X26(%rsp)
    cmp     %rbp, %rax
    ja      8f
    cmpq    $0, (C_RCID + QUIC_CID_LENGTH)(%rbx)
    je      6f                              /* the peer uses an empty ID */
    cmp     C_RCID_SEQ(%rbx), %r12
    je      5f                              /* known */
    cmp     C_NCID_SEQ(%rbx), %r12
    je      5f
    mov     C_RETIRE_PRIOR(%rbx), %rax
    cmp     %r13, %rax
    jae     11f
    mov     %r13, %rax
11: mov     %rax, C_RETIRE_PRIOR(%rbx)
    cmp     %rax, %r12
    jae     1f
    mov     %r12, C_RETIRE_SEQ(%rbx)        /* retired already */
    jmp     4f
1:  mov     C_NCID_SEQ(%rbx), %rcx          /* the spare */
    cmp     $-1, %rcx
    je      2f
    cmp     %rax, %rcx
    jae     3f
    mov     %rcx, C_RETIRE_SEQ(%rbx)        /* the spare is retired: replace it */
2:  lea     C_NCID(%rbx), %rdi
    mov     X23(%rsp), %rsi
    mov     X24(%rsp), %rdx
    call    quic_cid_put
    mov     %r12, C_NCID_SEQ(%rbx)
    lea     C_NCID_TOKEN(%rbx), %rdi
    mov     X25(%rsp), %rsi
    mov     $16, %edx
    call    quic_copy
    jmp     4f
3:  mov     C_RCID_SEQ(%rbx), %rax          /* one more than the limit */
    cmp     C_RETIRE_PRIOR(%rbx), %rax
    jae     71f
4:  mov     C_RCID_SEQ(%rbx), %rax          /* move off a retired ID in use */
    mov     C_RETIRE_PRIOR(%rbx), %rcx
    cmp     %rcx, %rax
    jae     5f
    mov     C_NCID_SEQ(%rbx), %rdx
    cmp     $-1, %rdx
    je      5f
    cmp     %rcx, %rdx
    jb      5f
    mov     %rax, C_RETIRE_SEQ(%rbx)
    lea     C_RCID(%rbx), %rdi
    lea     C_NCID(%rbx), %rsi
    mov     $(QUIC_CID_SIZE + 8 + 16), %edx
    call    quic_copy
    movq    $NONE, C_NCID_SEQ(%rbx)
    orq     $CF_RESET_TOKEN, C_FLAGS(%rbx)
5:  mov     X26(%rsp), %rax
    xor     %edx, %edx
    jmp     9f
6:  mov     X26(%rsp), %rax
    mov     $ERR_PROTOCOL, %edx
    jmp     9f
7:  mov     X26(%rsp), %rax
    mov     $ERR_FRAME_ENCODING, %edx
    jmp     9f
71: mov     X26(%rsp), %rax
    mov     $ERR_CID_LIMIT, %edx
    jmp     9f
8:  xor     %eax, %eax
    xor     %edx, %edx
9:  LEAVE   0
END_FUNCTION quic_frame_new_cid

/*
 * quic_on_crypto(space, offset, data, len) -> 0 or the error code: CRYPTO
 * data joins the receive block of the space (at most 4 separate ranges, the
 * block CRYPTO_ROOM bytes), then TLS takes the messages that are complete.
 * rbx the connection, rbp the space record, r12 offset, r13 data, X23 len,
 * X24 the block, X25 space, X26 end.
 */
LOCAL_FUNCTION quic_on_crypto
    ENTER   0
    mov     %rdi, X25(%rsp)
    mov     %rsi, %r12
    mov     %rdx, %r13
    mov     %rcx, X23(%rsp)
    mov     %rbx, %rdi
    mov     X25(%rsp), %rsi
    call    quic_space
    mov     %rax, %rbp
    mov     SP_CRX(%rbp), %rax
    test    %rax, %rax
    jnz     1f
    mov     $CRYPTO_ROOM, %edi
    call    quic_heap_alloc
    test    %rax, %rax
    jz      7f
    mov     %rax, SP_CRX(%rbp)
    movq    $0, SP_CRX_BASE(%rbp)
    movq    $0, SP_CRX_DONE(%rbp)
    movq    $0, SP_CRX_NR(%rbp)
1:  mov     %rax, X24(%rsp)
    mov     SP_CRX_BASE(%rbp), %rax
    mov     %r12, %rcx
    add     X23(%rsp), %rcx
    cmp     %rcx, %rax
    jae     8f                              /* taken already */
    cmp     %rax, %r12
    jae     2f
    mov     %rax, %rcx
    sub     %r12, %rcx
    add     %rcx, %r13
    sub     %rcx, X23(%rsp)
    mov     %rax, %r12
2:  sub     %rax, %r12                      /* block offsets */
    mov     X23(%rsp), %rcx
    lea     (%r12,%rcx), %rdx
    mov     %rdx, X26(%rsp)
    cmp     $CRYPTO_ROOM, %rdx
    ja      6f
    test    %rcx, %rcx
    jz      8f
    movzbl  SP_CRX_NR(%rbp), %eax           /* a fifth separate range does not fit */
    cmp     $4, %eax
    jb      3f
    mov     %rbp, %rdi
    mov     %r12, %rsi
    mov     X26(%rsp), %rdx
    call    quic_crx_touches
    test    %rax, %rax
    jz      6f
3:  mov     X24(%rsp), %rdi
    add     %r15, %rdi
    add     %r12, %rdi
    mov     %r13, %rsi
    mov     X23(%rsp), %rdx
    call    quic_copy
    mov     %rbp, %rdi
    mov     %r12, %rsi
    mov     X26(%rsp), %rdx
    lea     SP_CRX_NR(%rbp), %rcx
    mov     $4, %r8d
    call    quic_ranges_add
    mov     X25(%rsp), %rdi
    call    quic_tls_feed
    jmp     9f
6:  mov     $ERR_CRYPTO_BUFFER, %eax
    jmp     9f
7:  mov     $ERR_INTERNAL, %eax
    jmp     9f
8:  xor     %eax, %eax
9:  LEAVE   0
END_FUNCTION quic_on_crypto

/* quic_crx_touches(space, start, end) -> 1 when [start, end) touches a received CRYPTO range. A leaf. */
LOCAL_FUNCTION quic_crx_touches
    UNWIND_END_PROLOGUE
    movzbl  SP_CRX_NR(%rdi), %ecx
    lea     SP_CRX_RANGES(%rdi), %r8
1:  test    %ecx, %ecx
    jz      8f
    mov     (%r8), %r9
    mov     8(%r8), %r10
    add     $16, %r8
    dec     %ecx
    cmp     %r9, %rdx
    jb      1b
    cmp     %r10, %rsi
    ja      1b
    mov     $1, %eax
    ret
8:  xor     %eax, %eax
    ret
END_FUNCTION quic_crx_touches
