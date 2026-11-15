/*
 * asm-quic definitions, in assembler syntax.
 * The requirement entry for each function is in docs/reference/.
 */

/* ---------------------------------------------------------------- Status codes */

.set QUIC_OK, 0
.set QUIC_BUFFER_TOO_SMALL, 1           /* ARCHITECTURE.md section 6 */
.set QUIC_INVALID_ARGUMENT, 2           /* a value breaks a rule of its type */
.set QUIC_INVALID_PACKET, 3             /* a packet is too short or its header is malformed */
.set QUIC_DECRYPT_FAILED, 4             /* the AEAD tag of a packet does not match */
.set QUIC_INVALID_CERT, 5               /* a certificate breaks a rule of the libp2p TLS spec */
.set QUIC_INVALID_CONFIG, 6             /* a config breaks a rule of its type */
.set QUIC_INVALID_EVENT, 7              /* an event breaks a rule of its kind */
.set QUIC_INVALID_KEY, 8                /* a host private key is out of range */
.set QUIC_OS_ERROR, 9                   /* an OS call of the shell failed */

/* ---------------------------------------------------------------- Config */

/* Config: the input of quic_init. */
.set QUIC_CFG_SIZE_FIELD, 0
.set QUIC_CFG_VERSION, 8                /* QUIC_VERSION */
.set QUIC_CFG_KEY_TYPE, 16              /* QUIC_KEY_ED25519 or QUIC_KEY_SECP256K1 */
.set QUIC_CFG_KEY, 24                   /* the host private key, 32 bytes */
.set QUIC_CFG_CONNS, 56                 /* connection slots */
.set QUIC_CFG_STREAMS, 64               /* stream slots */
.set QUIC_CFG_HEAP, 72                  /* heap bytes: a power of two */
.set QUIC_CFG_IDLE, 80                  /* max_idle_timeout, ms */
.set QUIC_CFG_HANDSHAKE, 88             /* the handshake must end within this, ms */
.set QUIC_CFG_KEEP_ALIVE, 96            /* a PING after this quiet time, ms; 0: none */
.set QUIC_CFG_MAX_DATA, 104             /* initial_max_data */
.set QUIC_CFG_STREAM_DATA, 112          /* initial_max_stream_data_bidi_local and _remote */
.set QUIC_CFG_MAX_STREAMS, 120          /* initial_max_streams_bidi */
.set QUIC_CFG_STREAM_QUEUE, 128         /* bytes a stream may hold unacknowledged */
.set QUIC_CFG_FLAGS, 136                /* QUIC_CFG_ACCEPT */
.set QUIC_CFG_SENT, 144                 /* sent packet records of a connection */
.set QUIC_CFG_SEED, 152                 /* 32 random bytes for the first keys */
.set QUIC_CFG_KEY_UPDATE, 184           /* packets we send in one key phase; 0: 1000000 */
.set QUIC_CFG_SIZE, 192

.set QUIC_VERSION, 1                    /* the version of the Config and State layouts */
.set QUIC_CFG_ACCEPT, 1                 /* accept connections from peers */

/* ---------------------------------------------------------------- Step values */

/* Tick: the time and entropy of a step. */
.set QUIC_TICK_NOW, 0                   /* monotonic microseconds */
.set QUIC_TICK_UNIX, 8                  /* Unix time in seconds */
.set QUIC_TICK_ENTROPY, 16              /* 32 random bytes */
.set QUIC_TICK_SIZE, 48

/* Address: an IPv4 or IPv6 address and UDP port. */
.set QUIC_ADDR_FAMILY, 0                /* 4 or 6 */
.set QUIC_ADDR_PORT, 8
.set QUIC_ADDR_IP, 16                   /* 16 bytes, network order; IPv4 in the first 4 */
.set QUIC_ADDR_SIZE, 32

/* StepResult: the output of quic_step. */
.set QUIC_RESULT_HANDLED, 0             /* events handled */
.set QUIC_RESULT_SIZE, 8

/* Events: size, kind, then the fields of the kind. */
.set QUIC_EV_SIZE, 0
.set QUIC_EV_KIND, 8
.set QUIC_EVENT_DATAGRAM, 1             /* shell: a UDP datagram arrived */
.set QUIC_EVENT_DIAL, 2                 /* application: connect to a peer */
.set QUIC_EVENT_OPEN_STREAM, 3          /* application: open a bidirectional stream */
.set QUIC_EVENT_STREAM_WRITE, 4         /* application: bytes for a stream */
.set QUIC_EVENT_STREAM_CLOSE, 5         /* application: no more bytes on a stream (FIN) */
.set QUIC_EVENT_STREAM_RESET, 6         /* application: reset a stream both ways */
.set QUIC_EVENT_CLOSE, 7                /* application: close a connection */
.set QUIC_EVENT_KINDS, 7

.set QUIC_EV_SOCKET, 16                 /* DATAGRAM */
.set QUIC_EV_ADDR, 24
.set QUIC_EV_COUNT, 56
.set QUIC_EV_DATA, 64
.set QUIC_EV_TAG, 16                    /* DIAL */
.set QUIC_EV_DIAL_SOCKET, 24
.set QUIC_EV_DIAL_ADDR, 32
.set QUIC_EV_PEER_LEN, 64
.set QUIC_EV_PEER, 72                   /* the peer ID to expect, a multihash of at most 48 bytes */
.set QUIC_EV_DIAL_SIZE, 120
.set QUIC_EV_CONN, 16                   /* OPEN_STREAM, CLOSE */
.set QUIC_EV_OPEN_TAG, 24               /* OPEN_STREAM */
.set QUIC_EV_OPEN_SIZE, 32
.set QUIC_EV_CODE, 24                   /* CLOSE, STREAM_RESET: an application error code */
.set QUIC_EV_CLOSE_SIZE, 32
.set QUIC_EV_STREAM, 16                 /* STREAM_WRITE, STREAM_CLOSE, STREAM_RESET */
.set QUIC_EV_WRITE_COUNT, 24            /* STREAM_WRITE */
.set QUIC_EV_WRITE_DATA, 32
.set QUIC_EV_STREAM_SIZE, 24            /* STREAM_CLOSE */
.set QUIC_EV_RESET_SIZE, 32             /* STREAM_RESET */
.set QUIC_PEER_MAX, 48

/* Actions: size, kind, then the fields of the kind. */
.set QUIC_ACT_SIZE, 0
.set QUIC_ACT_KIND, 8
.set QUIC_ACTION_SEND, 1                /* shell: send a UDP datagram */
.set QUIC_ACTION_WAKEUP, 2              /* shell: the next step is due */
.set QUIC_ACTION_CONNECTED, 3           /* application: a connection is up */
.set QUIC_ACTION_DIAL_FAILED, 4         /* application: a DIAL ended without a connection */
.set QUIC_ACTION_CLOSED, 5              /* application: a connection is over */
.set QUIC_ACTION_STREAM_OPENED, 6       /* application: a stream is open */
.set QUIC_ACTION_STREAM_DATA, 7         /* application: bytes of a stream */
.set QUIC_ACTION_STREAM_FIN, 8          /* application: the peer sends no more on a stream */
.set QUIC_ACTION_STREAM_RESET, 9        /* application: the peer reset a stream */
.set QUIC_ACTION_STREAM_ACKED, 10       /* application: the peer acknowledged bytes of a stream */

.set QUIC_ACT_SOCKET, 16                /* SEND */
.set QUIC_ACT_ADDR, 24
.set QUIC_ACT_COUNT, 56
.set QUIC_ACT_DATA, 64
.set QUIC_ACT_TIME, 16                  /* WAKEUP: monotonic microseconds */
.set QUIC_ACT_WAKEUP_SIZE, 24
.set QUIC_ACT_CONN, 16                  /* CONNECTED, CLOSED */
.set QUIC_ACT_TAG, 24                   /* CONNECTED, DIAL_FAILED: the tag of the DIAL, 0 inbound */
.set QUIC_ACT_DIRECTION, 32             /* CONNECTED: 0 inbound, 1 outbound */
.set QUIC_ACT_C_SOCKET, 40
.set QUIC_ACT_C_ADDR, 48
.set QUIC_ACT_KEY_LEN, 80               /* the PublicKey protobuf of the peer host key */
.set QUIC_ACT_KEY, 88                   /* QUIC_HOST_MAX bytes */
.set QUIC_ACT_CONNECTED_SIZE, 216
.set QUIC_ACT_REASON, 32                /* DIAL_FAILED, CLOSED: QUIC_ERR_* */
.set QUIC_ACT_ERROR, 40                 /* DIAL_FAILED, CLOSED: the QUIC error code */
.set QUIC_ACT_CLOSED_SIZE, 48
.set QUIC_ACT_STREAM, 16                /* the STREAM_ actions */
.set QUIC_ACT_S_CONN, 24                /* STREAM_OPENED */
.set QUIC_ACT_S_TAG, 32                 /* STREAM_OPENED: the tag of OPEN_STREAM, 0 inbound */
.set QUIC_ACT_OPENED_SIZE, 40
.set QUIC_ACT_S_COUNT, 24               /* STREAM_DATA */
.set QUIC_ACT_S_DATA, 32
.set QUIC_ACT_FIN_SIZE, 24              /* STREAM_FIN */
.set QUIC_ACT_S_CODE, 24                /* STREAM_RESET */
.set QUIC_ACT_RESET_SIZE, 32
.set QUIC_ACT_ACKED_SIZE, 32             /* STREAM_ACKED: the count in QUIC_ACT_S_COUNT */

/* Why a connection ended (QUIC_ACT_REASON). */
.set QUIC_ERR_LOCAL, 1                  /* the application closed it */
.set QUIC_ERR_PEER, 2                   /* the peer closed it: QUIC_ACT_ERROR has its code */
.set QUIC_ERR_IDLE, 3                   /* no packet within the idle timeout */
.set QUIC_ERR_HANDSHAKE_TIMEOUT, 4      /* the handshake did not end in time */
.set QUIC_ERR_PROTOCOL, 5               /* the peer broke a rule: QUIC_ACT_ERROR has the code we sent */
.set QUIC_ERR_PEER_ID, 6                /* the peer is not the one the DIAL named */
.set QUIC_ERR_VERSION, 7                /* the peer speaks no version we do */
.set QUIC_ERR_LIMIT, 8                  /* no room for the connection */
.set QUIC_ERR_RESET, 9                  /* a stateless reset */

/* ShellContext: the UDP sockets of the shell, QUIC_SHELL_SIZE bytes. */
.set QUIC_SH_SIZE, 0
.set QUIC_SH_COUNT, 8                   /* sockets open */
.set QUIC_SH_SOCKETS, 16                /* QUIC_SH_MAX entries of QUIC_SH_STRIDE bytes */
.set QUIC_SH_FD, 0                      /* the native socket */
.set QUIC_SH_LOCAL, 8                   /* its local Address */
.set QUIC_SH_STRIDE, 40
.set QUIC_SH_MAX, 4
.set QUIC_SHELL_SIZE, QUIC_SH_SOCKETS + QUIC_SH_MAX * QUIC_SH_STRIDE

/* BindResult: the output of quic_shell_bind. */
.set QUIC_BR_SOCKET, 0                  /* the socket ID for events and actions */
.set QUIC_BR_LOCAL, 8                   /* the local Address */
.set QUIC_BR_SIZE, 40

.set QUIC_RECEIVE_MAX, 2048             /* the largest datagram the shell reads */

/* Sizes a step needs. */
.set QUIC_SCRATCH_SIZE, 14336           /* the scratch of quic_step */
.set QUIC_ACTIONS_MIN, 2048             /* the action room quic_step needs after the 24-byte header */

/* ---------------------------------------------------------------- Values */

/* ByteList (ARCHITECTURE.md section 6): size, offset 24, count, then the bytes. */
.set QUIC_BL_SIZE, 0
.set QUIC_BL_OFFSET, 8
.set QUIC_BL_COUNT, 16
.set QUIC_BL_FIXED, 24

/* ConnectionId: a QUIC connection ID of 0 to 20 bytes. */
.set QUIC_CID_LENGTH, 0                 /* u64 */
.set QUIC_CID_ID, 8                     /* 20 bytes, then 4 zero bytes */
.set QUIC_CID_SIZE, 32
.set QUIC_CID_MAX, 20

/* PacketKeys: the AEAD key, IV and header protection key of one direction (RFC 9001 section 5.1). */
.set QUIC_KEYS_KEY, 0                   /* 16 bytes */
.set QUIC_KEYS_IV, 16                   /* 12 bytes, then 4 zero bytes */
.set QUIC_KEYS_HP, 32                   /* 16 bytes */
.set QUIC_KEYS_SIZE, 48

/* InitialKeys: the client keys, then the server keys. */
.set QUIC_INITIAL_CLIENT, 0
.set QUIC_INITIAL_SERVER, 48
.set QUIC_INITIAL_SIZE, 96

/* PlainPacket: the input of quic_packet_seal. */
.set QUIC_PP_SIZE, 0
.set QUIC_PP_NUMBER, 8                  /* u64: the full packet number */
.set QUIC_PP_HEADER_OFF, 16             /* the header, the packet number last */
.set QUIC_PP_HEADER_COUNT, 24
.set QUIC_PP_PAYLOAD_OFF, 32            /* the frames */
.set QUIC_PP_PAYLOAD_COUNT, 40
.set QUIC_PP_FIXED, 48

/* OpenRequest: the input of quic_packet_open. */
.set QUIC_OR_SIZE, 0
.set QUIC_OR_PN_OFFSET, 8               /* u64: where the packet number starts */
.set QUIC_OR_LARGEST, 16                /* u64: the largest packet number received in the space, or NONE */
.set QUIC_OR_PACKET_OFF, 24             /* the protected packet */
.set QUIC_OR_PACKET_COUNT, 32
.set QUIC_OR_FIXED, 40

/* OpenedPacket: the output of quic_packet_open. */
.set QUIC_OP_SIZE, 0
.set QUIC_OP_NUMBER, 8                  /* u64: the full packet number */
.set QUIC_OP_HEADER_OFF, 16             /* the header without protection */
.set QUIC_OP_HEADER_COUNT, 24
.set QUIC_OP_PAYLOAD_OFF, 32            /* the frames */
.set QUIC_OP_PAYLOAD_COUNT, 40
.set QUIC_OP_FIXED, 48

/* PacketScratch: the work area of quic_packet_seal and quic_packet_open. */
.set QUIC_PACKET_SCRATCH, 5208

/* libp2p KeyType of a host key (libp2p/specs peer-ids). */
.set QUIC_KEY_RSA, 0
.set QUIC_KEY_ED25519, 1
.set QUIC_KEY_SECP256K1, 2
.set QUIC_KEY_ECDSA, 3

/* The key of a certificate: what signs CertificateVerify. */
.set QUIC_CERT_P256, 1                  /* ecdsa_secp256r1_sha256 */
.set QUIC_CERT_ED25519, 2               /* ed25519 */

/* CertInfo: the output of quic_cert_verify. */
.set QUIC_CI_SIZE, 0
.set QUIC_CI_KIND, 8                    /* u64: QUIC_CERT_P256 or QUIC_CERT_ED25519 */
.set QUIC_CI_KEY, 16                    /* 65 bytes 0x04, x, y; or 32 bytes; then zeros to 72 */
.set QUIC_CI_HOST_LEN, 88               /* u64: bytes of the host key */
.set QUIC_CI_HOST, 96                   /* the PublicKey protobuf of the host key, at most 128 bytes */
.set QUIC_CI_FIXED, 224
.set QUIC_HOST_MAX, 128

.set QUIC_CERT_MAX, 2048                /* the longest certificate a peer may send */
.set QUIC_CERT_SCRATCH, 2632            /* the scratch of quic_cert_verify */

.set QUIC_NONE, -1
.set QUIC_MAX_PACKET, 1500              /* the largest packet seal and open take */

/*
 * Functions, roles and allowed calls (ARCHITECTURE.md sections 4 and 5).
 * The L0 helpers each of them reaches, and their calls, are in docs/reference/.
 *
 * | Function           | Role | Arguments                                     | Requirements                        | Allowed calls |
 * |--------------------|------|-----------------------------------------------|-------------------------------------|---------------|
 * | quic_initial_keys  | L2   | dcid, keys                                    | docs/reference/packet-protection.md | quic_initial_derive |
 * | quic_packet_seal   | L2   | keys, packet, scratch, sealed                 | docs/reference/packet-protection.md | quic_copy, quic_seal |
 * | quic_packet_open   | L2   | keys, request, scratch, opened                | docs/reference/packet-protection.md | quic_copy, quic_open |
 * | quic_retry_tag     | L2   | odcid, retry, scratch, tag                    | docs/reference/packet-protection.md | quic_copy, crypto_aes128_gcm_ae |
 * | quic_cert_verify   | L2   | cert, now, scratch, info                      | docs/reference/certificates.md      | quic_cert_check |
 * | quic_state_size    | L2   | config, size                                  | docs/reference/node.md              | quic_layout |
 * | quic_init          | L2   | config, state                                 | docs/reference/node.md              | quic_layout, quic_zero, quic_copy, quic_random, quic_cert_build, crypto_secp256k1_public_key, crypto_ed25519_public_key, crypto_p256_public_key |
 * | quic_step          | L2   | state, tick, events, scratch, actions, result | docs/reference/node.md              | quic_check_event, quic_reseed, quic_room, quic_event, quic_connections, quic_wake_at, quic_action |
 * | quic_shell_init    | L2   | ctx                                           | docs/reference/shell.md             |  |
 * | quic_shell_bind    | L2   | ctx, addr, result                             | docs/reference/shell.md             | quic_shell_sockaddr, quic_shell_address, quic_shell_fcntl (macOS), quic_shell_wsa_start and quic_shell_no_connreset (Windows), OS calls |
 * | quic_shell_send    | L2   | ctx, actions                                  | docs/reference/shell.md             | quic_shell_sockaddr, OS calls |
 * | quic_shell_receive | L2   | ctx, events                                   | docs/reference/shell.md             | quic_shell_address, OS calls |
 * | quic_shell_wait    | L2   | ctx, until                                    | docs/reference/shell.md             | quic_shell_now (Windows), OS calls |
 * | quic_shell_clock   | L2   | tick                                          | docs/reference/shell.md             | quic_shell_now (Windows), OS calls |
 * | quic_shell_close   | L2   | ctx                                           | docs/reference/shell.md             | OS calls |
 */
