/*
 * The C view of the asm-quic interface in include/quic.inc and
 * docs/reference/, for the tests.
 */
#ifndef QUIC_H
#define QUIC_H

#include <stdint.h>

#if defined(_WIN32) && defined(__x86_64__)
#define QUIC_ABI __attribute__((sysv_abi))
#else
#define QUIC_ABI
#endif

enum {
    QUIC_OK = 0,
    QUIC_BUFFER_TOO_SMALL = 1,
    QUIC_INVALID_ARGUMENT = 2,
    QUIC_INVALID_PACKET = 3,
    QUIC_DECRYPT_FAILED = 4,
    QUIC_INVALID_CERT = 5,
};

#define QUIC_NONE UINT64_MAX
#define QUIC_PACKET_SCRATCH 5208
#define QUIC_CERT_SCRATCH 2632
#define QUIC_CI_FIXED 224

/* ConnectionId */
typedef struct {
    uint64_t length;
    uint8_t id[24];
} quic_cid;

/* PacketKeys */
typedef struct {
    uint8_t key[16];
    uint8_t iv[16];
    uint8_t hp[16];
} quic_keys;

QUIC_ABI uint64_t quic_initial_keys(const void *dcid, void *keys);
QUIC_ABI uint64_t quic_packet_seal(const void *keys, const void *packet, void *scratch, void *sealed);
QUIC_ABI uint64_t quic_packet_open(const void *keys, const void *request, void *scratch, void *opened);
QUIC_ABI uint64_t quic_retry_tag(const void *odcid, const void *retry, void *scratch, void *tag);
QUIC_ABI uint64_t quic_cert_verify(const void *cert, const void *now, void *scratch, void *info);
QUIC_ABI uint64_t quic_state_size(const void *config, void *size);
QUIC_ABI uint64_t quic_init(const void *config, void *state);
QUIC_ABI uint64_t quic_step(void *state, const void *tick, const void *events, void *scratch, void *actions,
                            void *result);

enum {
    QUIC_INVALID_CONFIG = 6,
    QUIC_INVALID_EVENT = 7,
    QUIC_INVALID_KEY = 8,
};

#define QUIC_CFG_SIZE 192
#define QUIC_SCRATCH_SIZE 14336
#define QUIC_ACTIONS_MIN 2048
#define QUIC_KEY_ED25519 1
#define QUIC_KEY_SECP256K1 2
#define QUIC_CFG_ACCEPT 1

/* Config */
typedef struct {
    uint64_t size, version, key_type;
    uint8_t key[32];
    uint64_t conns, streams, heap, idle, handshake, keep_alive, max_data, stream_data, max_streams, stream_queue,
        flags, sent;
    uint8_t seed[32];
    uint64_t key_update;
} quic_config;

/* Tick */
typedef struct {
    uint64_t now, unix_time;
    uint8_t entropy[32];
} quic_tick;

/* Address */
typedef struct {
    uint64_t family, port;
    uint8_t ip[16];
} quic_addr;

enum {
    QUIC_EVENT_DATAGRAM = 1,
    QUIC_EVENT_DIAL,
    QUIC_EVENT_OPEN_STREAM,
    QUIC_EVENT_STREAM_WRITE,
    QUIC_EVENT_STREAM_CLOSE,
    QUIC_EVENT_STREAM_RESET,
    QUIC_EVENT_CLOSE,
};
enum {
    QUIC_ACTION_SEND = 1,
    QUIC_ACTION_WAKEUP,
    QUIC_ACTION_CONNECTED,
    QUIC_ACTION_DIAL_FAILED,
    QUIC_ACTION_CLOSED,
    QUIC_ACTION_STREAM_OPENED,
    QUIC_ACTION_STREAM_DATA,
    QUIC_ACTION_STREAM_FIN,
    QUIC_ACTION_STREAM_RESET,
};

enum {
    QUIC_ERR_LOCAL = 1,
    QUIC_ERR_PEER,
    QUIC_ERR_IDLE,
    QUIC_ERR_HANDSHAKE_TIMEOUT,
    QUIC_ERR_PROTOCOL,
    QUIC_ERR_PEER_ID,
    QUIC_ERR_VERSION,
    QUIC_ERR_LIMIT,
    QUIC_ERR_RESET,
};

/* The shell */
enum { QUIC_OS_ERROR = 9 };
#define QUIC_SHELL_SIZE 176
/* BindResult */
typedef struct {
    uint64_t socket;
    quic_addr local;
} quic_bind_result;
QUIC_ABI uint64_t quic_shell_init(void *ctx);
QUIC_ABI uint64_t quic_shell_bind(void *ctx, const void *addr, void *result);
QUIC_ABI uint64_t quic_shell_send(void *ctx, const void *actions);
QUIC_ABI uint64_t quic_shell_receive(void *ctx, void *events);
QUIC_ABI uint64_t quic_shell_wait(void *ctx, const void *until);
QUIC_ABI uint64_t quic_shell_clock(void *tick);
QUIC_ABI uint64_t quic_shell_close(void *ctx);

#endif
