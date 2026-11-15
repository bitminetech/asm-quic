/*
 * Layouts inside the state of asm-quic, in assembler syntax. Offsets are
 * from the start of each record. The requirement entries are in
 * docs/reference/.
 *
 * The state: the fixed fields (ST_*), the connection table (C_SIZE each),
 * the stream table (S_SIZE each), then the heap. Records refer to each other
 * by slot index and to heap blocks by their offset from the state start.
 * Times are monotonic microseconds; NONE (all ones) means unset.
 */

.set NONE, -1

/* ---------------------------------------------------------------- Fixed fields */

.set ST_SIZE, 0
.set ST_VERSION, 8
.set ST_CONFIG, 16                      /* a copy of the Config, QUIC_CFG_SIZE bytes */
.set ST_NOW, ST_CONFIG + QUIC_CFG_SIZE
.set ST_UNIX, ST_NOW + 8                /* seconds, for certificates */
.set ST_DRBG_KEY, ST_UNIX + 8           /* 32 bytes */
.set ST_DRBG_COUNT, ST_DRBG_KEY + 32
.set ST_HOST_PROTO_LEN, ST_DRBG_COUNT + 8
.set ST_HOST_PROTO, ST_HOST_PROTO_LEN + 8    /* the PublicKey protobuf of the host key, 48 bytes */
.set ST_HOST_PUB, ST_HOST_PROTO + 48    /* the host public key, 40 bytes */
.set ST_CERT_PRIV, ST_HOST_PUB + 40     /* the P-256 key of the certificate */
.set ST_CERT_LEN, ST_CERT_PRIV + 32
.set ST_CERT, ST_CERT_LEN + 8           /* our certificate, CERT_ROOM bytes */
.set CERT_ROOM, 512
.set ST_CONN_OFF, ST_CERT + CERT_ROOM
.set ST_CONN_COUNT, ST_CONN_OFF + 8
.set ST_STREAM_OFF, ST_CONN_COUNT + 8
.set ST_STREAM_COUNT, ST_STREAM_OFF + 8
.set ST_HEAP_OFF, ST_STREAM_COUNT + 8
.set ST_HEAP_SIZE, ST_HEAP_OFF + 8
.set ST_HEAP_USED, ST_HEAP_SIZE + 8
.set ST_HEAP_FREE, ST_HEAP_USED + 8     /* 64 free lists, one per order */
.set ST_FIXED, ST_HEAP_FREE + 512

/* Heap blocks: a 16-byte header, then the bytes. Orders from HEAP_MIN_ORDER (64 bytes). */
.set HB_ORDER, 0                        /* u32 */
.set HB_FREE, 4                         /* u32: 1 when free */
.set HB_NEXT, 8                         /* free list: next free block, or NONE */
.set HB_PREV, 16                        /* free list: previous free block, or NONE */
.set HB_HEADER, 16
.set HEAP_MIN_ORDER, 6

/* ---------------------------------------------------------------- Packet number spaces */

/*
 * A space: Initial (0), Handshake (1) or Application (2). Its keys, the
 * packet numbers received and sent, and its CRYPTO stream.
 */
.set SPACE_INITIAL, 0
.set SPACE_HANDSHAKE, 1
.set SPACE_APP, 2

.set SP_FLAGS, 0                        /* SPF_* */
.set SP_NEXT_PN, 8                      /* the next packet number to send */
.set SP_LARGEST_ACKED, 16               /* the largest of our packets the peer acknowledged, or NONE */
.set SP_LARGEST_RECV, 24                /* the largest packet number received, or NONE */
.set SP_RECV_TIME, 32                   /* when it arrived */
.set SP_ACK_COUNT, 40                   /* ack-eliciting packets received since the last ACK sent */
.set SP_ACK_AT, 48                      /* when an ACK is due, or NONE */
.set SP_LOSS_TIME, 56                   /* the time threshold loss timer, or NONE */
.set SP_LAST_ELICIT, 64                 /* when the last ack-eliciting packet was sent, or NONE */
.set SP_NRANGES, 72                     /* received packet number ranges, largest first */
.set SP_RANGES, 80                      /* SP_MAX_RANGES pairs: smallest, largest */
.set SP_MAX_RANGES, 12
.set SP_RX_KEYS, SP_RANGES + 16 * SP_MAX_RANGES
.set SP_TX_KEYS, SP_RX_KEYS + QUIC_KEYS_SIZE
.set SP_CTX, SP_TX_KEYS + QUIC_KEYS_SIZE     /* CRYPTO send: heap block, or 0 */
.set SP_CTX_LEN, SP_CTX + 8             /* bytes written by TLS */
.set SP_CTX_SENT, SP_CTX_LEN + 8        /* the next offset to send */
.set SP_CRX, SP_CTX_SENT + 8            /* CRYPTO receive: heap block, or 0 */
.set SP_CRX_BASE, SP_CRX + 8            /* the stream offset of the first byte of the block */
.set SP_CRX_DONE, SP_CRX_BASE + 8       /* bytes of the block TLS has taken */
.set SP_CRX_NR, SP_CRX_DONE + 8         /* received ranges in the block, at most 4 */
.set SP_CRX_RANGES, SP_CRX_NR + 8       /* 4 pairs: start, end (block offsets) */
.set SP_ELICIT, SP_CRX_RANGES + 64      /* ack-eliciting packets of the space in flight */
.set SP_SIZE, SP_ELICIT + 8

.set SPF_RX, 1                          /* receive keys installed */
.set SPF_TX, 2                          /* send keys installed */
.set SPF_DISCARDED, 4                   /* keys dropped (RFC 9001 section 4.9) */
.set SPF_PROBE, 8                       /* a PTO probe is due in this space */
.set SPF_ACK_NOW, 16                    /* send an ACK at the next chance */

.set CRYPTO_ROOM, 4080                  /* bytes of a CRYPTO block, each way: 4096 with HB_HEADER */

/* ---------------------------------------------------------------- Connections */

.set C_GEN, 0                           /* u32: the generation of the slot */
.set C_USED, 4                          /* u32: 1 when in use */
.set C_STATE, 8                         /* CS_* */
.set C_ROLE, 16                         /* 0 client, 1 server */
.set C_TAG, 24                          /* the tag of the DIAL */
.set C_SOCKET, 32
.set C_ADDR, 40                         /* QUIC_ADDR_SIZE bytes */
.set C_FLAGS, C_ADDR + QUIC_ADDR_SIZE   /* CF_* */
.set C_ERROR, C_FLAGS + 8               /* the error code of the close */
.set C_REASON, C_ERROR + 8              /* QUIC_ERR_* for the application */
.set C_LCID, C_REASON + 8               /* our connection ID: 8 bytes */
.set C_RCID, C_LCID + 8                 /* the peer's connection ID: ConnectionId */
.set C_RCID_SEQ, C_RCID + QUIC_CID_SIZE
.set C_RCID_TOKEN, C_RCID_SEQ + 8       /* its stateless reset token, 16 bytes */
.set C_NCID, C_RCID_TOKEN + 16          /* a spare connection ID of the peer: ConnectionId */
.set C_NCID_SEQ, C_NCID + QUIC_CID_SIZE /* NONE when there is none */
.set C_NCID_TOKEN, C_NCID_SEQ + 8
.set C_RETIRE_PRIOR, C_NCID_TOKEN + 16  /* the largest retire_prior_to received */
.set C_RETIRE_SEQ, C_RETIRE_PRIOR + 8   /* a sequence number to retire, or NONE */
.set C_ODCID, C_RETIRE_SEQ + 8          /* the first DCID of the client: ConnectionId */
.set C_ISCID, C_ODCID + QUIC_CID_SIZE   /* the SCID of the first packet of the peer */
.set C_RSCID, C_ISCID + QUIC_CID_SIZE   /* the SCID of a Retry, or length NONE */
.set C_TOKEN, C_RSCID + QUIC_CID_SIZE   /* the Retry token: heap block, or 0 */
.set C_TOKEN_LEN, C_TOKEN + 8
.set C_SPACES, C_TOKEN_LEN + 8          /* three SP_SIZE spaces */
.set C_APP_SECRETS, C_SPACES + 3 * SP_SIZE   /* client then server application secrets, 64 bytes */
.set C_NEXT_RX, C_APP_SECRETS + 64      /* the receive keys of the next key phase */
.set C_PREV_RX, C_NEXT_RX + QUIC_KEYS_SIZE   /* the receive keys of the previous key phase */
.set C_KEY_PHASE, C_PREV_RX + QUIC_KEYS_SIZE /* 0 or 1 */
.set C_PHASE_PN, C_KEY_PHASE + 8        /* the first packet number of the current phase, or NONE */
.set C_PREV_UNTIL, C_PHASE_PN + 8       /* when the previous receive keys go, or NONE */
.set C_PHASE_SENT, C_PREV_UNTIL + 8     /* packets sent in the current key phase */
.set C_PHASE_FIRST, C_PHASE_SENT + 8    /* our first packet number of the current key phase */
.set C_TLS, C_PHASE_FIRST + 8           /* the TLS block: heap, or 0 after the handshake */
/* Transport parameters of the peer. */
.set C_P_IDLE, C_TLS + 8                /* max_idle_timeout, ms */
.set C_P_UDP, C_P_IDLE + 8              /* max_udp_payload_size */
.set C_P_MAX_DATA, C_P_UDP + 8
.set C_P_SD_LOCAL, C_P_MAX_DATA + 8     /* initial_max_stream_data_bidi_local */
.set C_P_SD_REMOTE, C_P_SD_LOCAL + 8    /* initial_max_stream_data_bidi_remote */
.set C_P_STREAMS, C_P_SD_REMOTE + 8     /* initial_max_streams_bidi, then MAX_STREAMS */
.set C_P_ACK_EXP, C_P_STREAMS + 8       /* ack_delay_exponent */
.set C_P_ACK_DELAY, C_P_ACK_EXP + 8     /* max_ack_delay, microseconds */
.set C_P_CID_LIMIT, C_P_ACK_DELAY + 8   /* active_connection_id_limit */
/* Flow control and stream counts. */
.set C_TX_MAX, C_P_CID_LIMIT + 8        /* MAX_DATA from the peer */
.set C_TX_SENT, C_TX_MAX + 8            /* stream bytes sent, first copies only */
.set C_RX_MAX, C_TX_SENT + 8            /* the MAX_DATA we gave */
.set C_RX_SEEN, C_RX_MAX + 8            /* the sum of the largest offset received on each stream */
.set C_RX_DONE, C_RX_SEEN + 8           /* stream bytes delivered to the application */
.set C_LOCAL_OPEN, C_RX_DONE + 8        /* bidirectional streams we opened (with an ID) */
.set C_PEER_OPEN, C_LOCAL_OPEN + 8      /* bidirectional streams the peer opened */
.set C_PEER_MAX, C_PEER_OPEN + 8        /* the MAX_STREAMS we gave */
.set C_PEER_DONE, C_PEER_MAX + 8        /* peer streams that are over */
.set C_STREAM_HEAD, C_PEER_DONE + 8     /* the first stream of the connection, a slot index, or NONE */
/* Recovery (RFC 9002). */
.set C_SENT, C_STREAM_HEAD + 8          /* the ring of sent packets: heap block, or 0 */
.set C_SENT_CAP, C_SENT + 8             /* records */
.set C_SENT_HEAD, C_SENT_CAP + 8        /* the oldest record */
.set C_SENT_COUNT, C_SENT_HEAD + 8      /* records from the oldest to the newest, live or gone */
.set C_IN_FLIGHT, C_SENT_COUNT + 8      /* bytes in flight */
.set C_CWND, C_IN_FLIGHT + 8
.set C_SSTHRESH, C_CWND + 8
.set C_RECOVERY, C_SSTHRESH + 8         /* when the last recovery started, or 0 */
.set C_RTT_LATEST, C_RECOVERY + 8
.set C_RTT_MIN, C_RTT_LATEST + 8
.set C_RTT_SMOOTH, C_RTT_MIN + 8
.set C_RTT_VAR, C_RTT_SMOOTH + 8
.set C_RTT_FIRST, C_RTT_VAR + 8         /* when the first RTT sample came, or NONE */
.set C_PTO_COUNT, C_RTT_FIRST + 8
.set C_LOSS_AT, C_PTO_COUNT + 8         /* the loss detection timer, or NONE */
/* Timers and limits. */
.set C_IDLE_AT, C_LOSS_AT + 8           /* the idle timeout, or NONE */
.set C_IDLE_US, C_IDLE_AT + 8           /* the idle timeout period */
.set C_START, C_IDLE_US + 8             /* when the connection began */
.set C_CLOSE_AT, C_START + 8            /* the end of closing or draining, or NONE */
.set C_PING_AT, C_CLOSE_AT + 8          /* the keep-alive PING, or NONE */
.set C_RX_BYTES, C_PING_AT + 8          /* datagram bytes received, for the amplification limit */
.set C_TX_BYTES, C_RX_BYTES + 8         /* datagram bytes sent */
.set C_CLOSE_RX, C_TX_BYTES + 8         /* packets received while closing */
.set C_CHALLENGE, C_CLOSE_RX + 8        /* PATH_CHALLENGE data to answer, 8 bytes */
.set C_PEER_KEY_LEN, C_CHALLENGE + 8    /* the PublicKey protobuf of the peer's host key */
.set C_PEER_KEY, C_PEER_KEY_LEN + 8     /* QUIC_HOST_MAX bytes */
.set C_SIZE, C_PEER_KEY + QUIC_HOST_MAX

/* Connection states. */
.set CS_HANDSHAKE, 1
.set CS_ACTIVE, 2
.set CS_CLOSING, 3                      /* we sent CONNECTION_CLOSE */
.set CS_DRAINING, 4                     /* the peer sent CONNECTION_CLOSE, or a stateless reset */
.set CS_DONE, 5                         /* over: the slot goes after the announcements */

/* Connection flags. */
.set CF_KNOWN, 1                        /* the application has CONNECTED */
.set CF_TELL, 2                         /* CONNECTED is due */
.set CF_GONE, 4                         /* CLOSED or DIAL_FAILED is due */
.set CF_CONFIRMED, 8                    /* the handshake is confirmed */
.set CF_COMPLETE, 16                    /* the TLS handshake is complete */
.set CF_VALIDATED, 32                   /* the peer address is validated */
.set CF_DONE_FRAME, 64                  /* HANDSHAKE_DONE is to be sent */
.set CF_MAX_DATA, 128                   /* MAX_DATA is to be sent */
.set CF_MAX_STREAMS, 256                /* MAX_STREAMS is to be sent */
.set CF_CLOSE_FRAME, 512                /* CONNECTION_CLOSE is to be sent */
.set CF_APP_CLOSE, 1024                 /* the close is the application's: frame type 0x1d */
.set CF_RETRIED, 2048                   /* a Retry was taken */
.set CF_GOT_PACKET, 4096                /* a packet of the peer was processed */
.set CF_PING, 8192                      /* a PING is to be sent */
.set CF_CHALLENGE, 16384                /* a PATH_RESPONSE is to be sent */
.set CF_ELICIT_SENT, 32768              /* an ack-eliciting packet went out since the last packet arrived */
.set CF_RESET_TOKEN, 65536              /* C_RCID_TOKEN holds a token */
.set CF_KEY_UPDATE, 131072              /* our key update waits for the acknowledgement of the current phase */

/* ---------------------------------------------------------------- The TLS block */

/* A heap block while the handshake runs. */
.set T_STAGE, 0                         /* TS_* */
.set T_GROUP, 8                         /* the key share group: 0x001d or 0x0017 */
.set T_HRR, 16                          /* 1 after a HelloRetryRequest */
.set T_X25519, 24                       /* our X25519 private key, or our P-256 private key */
.set T_SHARED, 56                       /* the ECDHE shared secret */
.set T_HS_SECRET, 88                    /* the handshake secret */
.set T_C_HS, 120                        /* client_handshake_traffic_secret */
.set T_S_HS, 152                        /* server_handshake_traffic_secret */
.set T_MASTER, 184
.set T_CERT_REQ, 216                    /* the server asked for a certificate */
.set T_PEER, 224                        /* the CertInfo of the peer certificate, QUIC_CI_FIXED bytes */
.set T_RANDOM, T_PEER + QUIC_CI_FIXED   /* our random, 32 bytes */
.set T_COOKIE_LEN, T_RANDOM + 32        /* a HelloRetryRequest cookie */
.set T_COOKIE, T_COOKIE_LEN + 8         /* 128 bytes */
.set T_HASH, T_COOKIE + 128             /* a transcript hash */
.set T_PID_LEN, T_HASH + 32             /* the peer ID the dialer expects */
.set T_PID, T_PID_LEN + 8               /* 48 bytes */
.set T_LIST, T_PID + 48                 /* the transcript: a ByteList of the handshake messages */
.set T_LEN, T_LIST + QUIC_BL_COUNT      /* its count: bytes of the transcript */
.set T_TRANSCRIPT, T_LIST + QUIC_BL_FIXED
.set TRANSCRIPT_ROOM, 7440              /* T_SIZE + HB_HEADER is 8192, one heap order */
.set T_SIZE, T_TRANSCRIPT + TRANSCRIPT_ROOM

/* TLS stages. */
.set TS_WAIT_SH, 1                      /* client: ServerHello */
.set TS_WAIT_EE, 2                      /* client: EncryptedExtensions */
.set TS_WAIT_CERT_CR, 3                 /* client: CertificateRequest or Certificate */
.set TS_WAIT_CERT, 4                    /* client: Certificate */
.set TS_WAIT_CV, 5                      /* both: CertificateVerify */
.set TS_WAIT_FIN, 6                     /* both: Finished */
.set TS_WAIT_CH, 7                      /* server: ClientHello */
.set TS_WAIT_CCERT, 8                   /* server: the client Certificate */
.set TS_DONE, 9

/* ---------------------------------------------------------------- Sent packets */

/* A record of the sent packet ring, SR_SIZE bytes. */
.set SR_PN, 0                           /* the packet number */
.set SR_TIME, 8                         /* when it was sent */
.set SR_INFO, 16                        /* bits 0-15 size, 16-23 space, 24-31 flags, 32-39 frames */
.set SR_FRAMES, 24                      /* SR_MAX_FRAMES refs of 16 bytes */
.set SR_MAX_FRAMES, 6
.set SR_SIZE, 128

.set SRF_LIVE, 1                        /* not yet acknowledged or lost */
.set SRF_ELICIT, 2                      /* ack-eliciting */
.set SRF_FLIGHT, 4                      /* counts in bytes in flight */

/* A frame ref: u8 kind, u8 flags, u16 the generation of the stream, u32 a slot or value, then a u64 offset (low 48 bits) and length (high 16 bits). */
.set FR_CRYPTO, 1
.set FR_STREAM, 2                       /* flags bit 0: FIN */
.set FR_MAX_DATA, 3
.set FR_MAX_STREAM_DATA, 4
.set FR_MAX_STREAMS, 5
.set FR_DONE, 6                         /* HANDSHAKE_DONE */
.set FR_RESET, 7                        /* RESET_STREAM */
.set FR_STOP, 8                         /* STOP_SENDING */
.set FR_RETIRE, 9                       /* RETIRE_CONNECTION_ID: the value is the sequence number */

/* ---------------------------------------------------------------- Streams */

.set S_GEN, 0                           /* u32 */
.set S_USED, 4                          /* u32 */
.set S_CONN, 8                          /* the connection slot */
.set S_CONN_GEN, 16                     /* its generation */
.set S_NEXT, 24                         /* the next stream of the connection, or NONE */
.set S_ID, 32                           /* the stream ID, or NONE while it waits for MAX_STREAMS */
.set S_TAG, 40
.set S_FLAGS, 48                        /* SF_* */
.set S_RESET_CODE, 56                   /* the code of a reset the peer sent */
.set S_APP_CODE, 64                     /* the code of a reset the application asked for */
/* Sending. */
.set S_Q_HEAD, 72                       /* the first chunk of unacknowledged data, or 0 */
.set S_Q_TAIL, 80                       /* the last chunk, or 0 */
.set S_Q_BASE, 88                       /* the stream offset of the first byte of the first chunk */
.set S_WRITTEN, 96                      /* bytes the application wrote */
.set S_SENT, 104                        /* the next new offset to send */
.set S_ACKED, 112                       /* bytes acknowledged from the start, with no gap */
.set S_TX_MAX, 120                      /* MAX_STREAM_DATA from the peer */
.set S_NLOST, 128                       /* lost ranges to send again */
.set S_LOST, 136                        /* 4 pairs: start, end */
.set S_NACKS, 200                       /* acknowledged ranges past S_ACKED */
.set S_ACKS, 208                        /* 6 pairs: start, end */
/* Receiving. */
.set S_RX_HEAD, 304                     /* the first buffered segment, or 0 */
.set S_RX_DONE, 312                     /* bytes delivered to the application */
.set S_RX_SEEN, 320                     /* the largest offset received */
.set S_RX_FINAL, 328                    /* the final size, or NONE */
.set S_RX_MAX, 336                      /* the MAX_STREAM_DATA we gave */
.set S_ACK_TOLD, 344                    /* bytes of S_ACKED the application has in STREAM_ACKED */
.set S_SIZE, 352

/* Stream flags. */
.set SF_LOCAL, 1                        /* we opened it */
.set SF_TELL_OPEN, 2                    /* STREAM_OPENED is due */
.set SF_TELL_FIN, 4                     /* STREAM_FIN is due */
.set SF_TELL_RESET, 8                   /* STREAM_RESET is due */
.set SF_FIN_WANT, 16                    /* the application closed its side */
.set SF_FIN_SENT, 32                    /* our FIN went out */
.set SF_FIN_ACKED, 64                   /* our FIN and all our data are acknowledged */
.set SF_FIN_LOST, 128                   /* our FIN must go out again */
.set SF_RX_DONE, 256                    /* the peer's side is over: FIN delivered, or reset */
.set SF_RESET_SEND, 512                 /* RESET_STREAM is to be sent */
.set SF_STOP_SEND, 1024                 /* STOP_SENDING is to be sent */
.set SF_RESET, 2048                     /* our side is reset */
.set SF_MSD, 4096                       /* MAX_STREAM_DATA is to be sent */
.set SF_TOLD_FIN, 8192                  /* the application has STREAM_FIN */
.set SF_TOLD_RESET, 16384               /* the application has STREAM_RESET */

/* A send chunk: heap block. */
.set Q_NEXT, 0                          /* the next chunk, or 0 */
.set Q_LEN, 8
.set Q_DATA, 16

/* A receive segment: heap block. */
.set R_NEXT, 0                          /* the next segment by offset, or 0 */
.set R_OFFSET, 8                        /* its stream offset */
.set R_LEN, 16
.set R_DATA, 24

/* ---------------------------------------------------------------- Scratch of a step */

.set SC_SIZE, 0
.set SC_ACTIONS, 8                      /* the action list */
.set SC_RESERVE, 16                     /* action bytes kept back */
.set SC_WAKE, 24                        /* the earliest deadline */
.set SC_FRAME, 64                       /* frame fields and saved values: 128 bytes */
.set SC_PKT_RESULT, 192                 /* the result of quic_open: 32 bytes */
.set SC_PKT_BUF, 224                    /* the packet being read: W_HEADER_MAX + W_SEALED_MAX bytes */
.set SC_PKT_WORK, SC_PKT_BUF + 1776     /* the work area of quic_seal and quic_open: 3400 bytes */
.set SC_CERT, SC_PKT_WORK + 3400        /* the work area of quic_cert_check */
.set SC_TLS, SC_CERT + 2624             /* TLS messages being built: 4096 bytes */
.set SC_OUT, SC_TLS + 4096              /* the datagram being built: 1776 bytes */
.set SC_NEED, SC_OUT + 1776

.if T_SIZE + HB_HEADER > 8192
.error "the TLS block is above 8192 bytes"
.endif
.if SC_NEED > QUIC_SCRATCH_SIZE
.error "QUIC_SCRATCH_SIZE is below the scratch layout"
.endif
