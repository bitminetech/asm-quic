/*
 * Shell loop test: two asm-quic nodes in one process, connected over
 * 127.0.0.1 through the shell of this OS. Standard C only, so the same file
 * runs on Linux, macOS and Windows.
 *
 * Each round: node A listens; node B dials it with the peer ID of A. B opens
 * a stream, writes 256 KiB and closes its side; A echoes the bytes, then
 * closes its side; B checks every byte and the end of the stream, then
 * closes the connection; A hears that the peer closed it. Round 1: A
 * Ed25519, B secp256k1; round 2: A secp256k1, B Ed25519. Exit 0 when both
 * rounds pass, after a "FUNCTION <name> PASS" line for each shell function,
 * for the tick tables. A failure prints FAIL and exits 1 at once.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../runner/quic.h"

#define EV_ROOM (4 << 20)
#define ACT_ROOM (4 << 20)
#define ECHO_LEN (256 * 1024)
#define CHUNK 16384
#define LIMIT_US 30000000ull
#define TAG_DIAL 1
#define TAG_STREAM 7

QUIC_ABI uint64_t crypto_ed25519_public_key(const void *private_key, void *public_key);
QUIC_ABI uint64_t crypto_secp256k1_public_key(const void *private_key, void *public_key);

typedef struct {
    const char *name;
    uint8_t *state, *scratch, *ev, *act;
    uint64_t shell[QUIC_SHELL_SIZE / 8];
    quic_bind_result bound;
    uint8_t id[48];                         /* its peer ID: the identity multihash of its host key */
    uint64_t id_len;
    uint64_t wake, conn, stream, reason;
    int connected, closed;
} node;

static node na, nb;
static uint8_t *echo_out, *echo_in;
static uint64_t echo_got;
static int echo_fin, close_sent, trace;

static void fail(const char *what) {
    printf("FAIL %s\n", what);
    exit(1);
}

static uint64_t now_us(void) {
    quic_tick t;
    if (quic_shell_clock(&t)) fail("quic_shell_clock");
    return t.now;
}

static void random_bytes(uint8_t *p, size_t n) {
    while (n) {
        quic_tick t;
        if (quic_shell_clock(&t)) fail("quic_shell_clock");
        size_t k = n < 32 ? n : 32;
        memcpy(p, t.entropy, k);
        p += k;
        n -= k;
    }
}

static void *ev_add(node *n, uint64_t kind, uint64_t size) {
    uint64_t *h = (uint64_t *)n->ev;
    size = (size + 7) & ~7ULL;
    if (24 + h[2] + size > EV_ROOM) fail("event room");
    uint8_t *p = n->ev + 24 + h[2];
    memset(p, 0, size);
    ((uint64_t *)p)[0] = size;
    ((uint64_t *)p)[1] = kind;
    h[2] += size;
    return p;
}

static void write_stream(node *n, uint64_t stream, const uint8_t *data, uint64_t len) {
    uint64_t *w = ev_add(n, QUIC_EVENT_STREAM_WRITE, 32 + len);
    w[2] = stream;
    w[3] = len;
    memcpy(w + 4, data, len);
}

static void make_node(node *n, const char *name, uint64_t key_type, int accept) {
    quic_config c;
    uint8_t pub[33];
    memset(n, 0, sizeof *n);
    n->name = name;
    for (;;) {
        memset(&c, 0, sizeof c);
        random_bytes(c.key, 32);
        if (key_type == QUIC_KEY_ED25519) {
            crypto_ed25519_public_key(c.key, pub);
            break;
        }
        if (crypto_secp256k1_public_key(c.key, pub) == 0) break;
    }
    c.size = QUIC_CFG_SIZE;
    c.version = 1;
    c.key_type = key_type;
    random_bytes(c.seed, 32);
    c.conns = 4;
    c.streams = 16;
    c.heap = 1 << 24;
    c.idle = 30000;
    c.handshake = 10000;
    c.max_data = 1 << 22;
    c.stream_data = 1 << 20;
    c.max_streams = 16;
    c.stream_queue = 1 << 22;
    c.flags = accept ? QUIC_CFG_ACCEPT : 0;
    c.sent = 512;
    uint64_t size = 0;
    if (quic_state_size(&c, &size)) fail("quic_state_size");
    n->state = calloc(1, size);
    n->scratch = malloc(QUIC_SCRATCH_SIZE);
    n->ev = malloc(EV_ROOM);
    n->act = malloc(ACT_ROOM);
    if (!n->state || !n->scratch || !n->ev || !n->act) fail("memory");
    ((uint64_t *)n->state)[0] = size;
    if (quic_init(&c, n->state)) fail("quic_init");
    ((uint64_t *)n->scratch)[0] = QUIC_SCRATCH_SIZE;
    ((uint64_t *)n->ev)[0] = EV_ROOM;
    ((uint64_t *)n->ev)[1] = 24;
    ((uint64_t *)n->ev)[2] = 0;
    /* The PublicKey protobuf (0x08 type 0x12 length key) in an identity multihash. */
    uint64_t kl = key_type == QUIC_KEY_ED25519 ? 32 : 33;
    n->id[0] = 0x00;
    n->id[1] = (uint8_t)(4 + kl);
    n->id[2] = 0x08;
    n->id[3] = (uint8_t)key_type;
    n->id[4] = 0x12;
    n->id[5] = (uint8_t)kl;
    memcpy(n->id + 6, pub, kl);
    n->id_len = 6 + kl;
    n->wake = QUIC_NONE;
    n->shell[0] = QUIC_SHELL_SIZE;
    if (quic_shell_init(n->shell)) fail("quic_shell_init");
    quic_addr a = {4, 0, {127, 0, 0, 1}};
    if (quic_shell_bind(n->shell, &a, &n->bound)) fail("quic_shell_bind");
    if (n->bound.local.family != 4 || n->bound.local.port == 0 || memcmp(n->bound.local.ip, a.ip, 16))
        fail("quic_shell_bind: the local address");
}

static void free_node(node *n) {
    if (quic_shell_close(n->shell)) fail("quic_shell_close");
    free(n->state);
    free(n->scratch);
    free(n->ev);
    free(n->act);
}

/* The key in a CONNECTED action is the PublicKey protobuf of the other node. */
static void check_key(const uint8_t *action, const node *other) {
    const uint64_t *w = (const uint64_t *)action;
    if (w[10] != other->id_len - 2 || memcmp(action + 88, other->id + 2, other->id_len - 2))
        fail("CONNECTED: the key of the peer");
}

static void handle_actions(node *n) {
    uint64_t *h = (uint64_t *)n->act;
    uint8_t *p = n->act + h[1], *end = p + h[2];
    while (p < end) {
        uint64_t *w = (uint64_t *)p, size = w[0], kind = w[1];
        if (trace) printf("%s action %llu\n", n->name, (unsigned long long)kind);
        switch (kind) {
        case QUIC_ACTION_WAKEUP: n->wake = w[2]; break;
        case QUIC_ACTION_CONNECTED:
            if (n->connected) fail("CONNECTED twice");
            n->connected = 1;
            n->conn = w[2];
            if (n == &nb) {
                if (w[3] != TAG_DIAL || w[4] != 1) fail("CONNECTED of B: tag and direction");
                check_key(p, &na);
                uint64_t *o = ev_add(n, QUIC_EVENT_OPEN_STREAM, 32);
                o[2] = n->conn;
                o[3] = TAG_STREAM;
            } else {
                if (w[3] != 0 || w[4] != 0) fail("CONNECTED of A: tag and direction");
                check_key(p, &nb);
            }
            break;
        case QUIC_ACTION_DIAL_FAILED: fail("DIAL_FAILED");
        case QUIC_ACTION_CLOSED:
            n->closed = 1;
            n->reason = w[4];
            break;
        case QUIC_ACTION_STREAM_OPENED:
            if (!w[2]) fail("STREAM_OPENED without a stream");
            n->stream = w[2];
            if (n == &nb) {
                if (w[4] != TAG_STREAM) fail("STREAM_OPENED of B: tag");
                for (uint64_t k = 0; k < ECHO_LEN; k += CHUNK) write_stream(n, n->stream, echo_out + k, CHUNK);
                uint64_t *c = ev_add(n, QUIC_EVENT_STREAM_CLOSE, 24);
                c[2] = n->stream;
            } else if (w[4] != 0) {
                fail("STREAM_OPENED of A: tag");
            }
            break;
        case QUIC_ACTION_STREAM_DATA:
            if (w[2] != n->stream) fail("STREAM_DATA: the stream");
            if (n == &na) {
                write_stream(n, w[2], p + 32, w[3]);   /* the echo */
            } else {
                if (echo_got + w[3] > ECHO_LEN) fail("echo: too many bytes");
                memcpy(echo_in + echo_got, p + 32, w[3]);
                echo_got += w[3];
            }
            break;
        case QUIC_ACTION_STREAM_FIN:
            if (w[2] != n->stream) fail("STREAM_FIN: the stream");
            if (n == &na) {
                uint64_t *c = ev_add(n, QUIC_EVENT_STREAM_CLOSE, 24);
                c[2] = w[2];
            } else {
                echo_fin = 1;
            }
            break;
        case QUIC_ACTION_STREAM_RESET: fail("STREAM_RESET");
        default: break;
        }
        p += size;
    }
}

static void step(node *n) {
    quic_tick t;
    if (quic_shell_clock(&t)) fail("quic_shell_clock");
    ((uint64_t *)n->act)[0] = ACT_ROOM;
    uint64_t handled = 0;
    if (quic_step(n->state, &t, n->ev, n->scratch, n->act, &handled)) fail("quic_step");
    uint64_t *eh = (uint64_t *)n->ev;
    uint8_t *e = n->ev + 24;
    uint64_t off = 0;
    for (uint64_t i = 0; i < handled; i++) off += ((uint64_t *)(e + off))[0];
    memmove(e, e + off, eh[2] - off);
    eh[2] -= off;
    if (quic_shell_send(n->shell, n->act)) fail("quic_shell_send");
    handle_actions(n);
}

static void run_round(int number, uint64_t key_a, uint64_t key_b) {
    make_node(&na, "A", key_a, 1);
    make_node(&nb, "B", key_b, 0);
    random_bytes(echo_out, ECHO_LEN);
    echo_got = 0;
    echo_fin = close_sent = 0;
    uint64_t *d = ev_add(&nb, QUIC_EVENT_DIAL, 120);
    d[2] = TAG_DIAL;
    d[3] = nb.bound.socket;
    memcpy(d + 4, &na.bound.local, sizeof na.bound.local);
    d[8] = na.id_len;
    memcpy(d + 9, na.id, na.id_len);

    uint64_t deadline = now_us() + LIMIT_US;
    while (!(na.closed && nb.closed)) {
        uint64_t now = now_us();
        if (now > deadline) {
            printf("FAIL round %d timed out: connected %d %d, echo %llu fin %d, closed %d %d\n", number,
                   na.connected, nb.connected, (unsigned long long)echo_got, echo_fin, na.closed, nb.closed);
            exit(1);
        }
        if (echo_fin && !close_sent) {
            if (echo_got != ECHO_LEN || memcmp(echo_in, echo_out, ECHO_LEN)) fail("echo bytes");
            uint64_t *c = ev_add(&nb, QUIC_EVENT_CLOSE, 32);
            c[2] = nb.conn;
            close_sent = 1;
        }
        step(&na);
        step(&nb);
        /* Wait on A for at most 1 ms or the earlier wakeup, then poll B without waiting. */
        now = now_us();
        uint64_t until = now + 1000, at_once = 0;
        if (na.wake < until) until = na.wake;
        if (nb.wake < until) until = nb.wake;
        if (((uint64_t *)na.ev)[2] == 0 && ((uint64_t *)nb.ev)[2] == 0) {
            if (quic_shell_wait(na.shell, &until)) fail("quic_shell_wait");
            if (quic_shell_wait(nb.shell, &at_once)) fail("quic_shell_wait");
        }
        if (quic_shell_receive(na.shell, na.ev)) fail("quic_shell_receive");
        if (quic_shell_receive(nb.shell, nb.ev)) fail("quic_shell_receive");
    }
    if (nb.reason != QUIC_ERR_LOCAL) fail("CLOSED of B: the reason");
    if (na.reason != QUIC_ERR_PEER) fail("CLOSED of A: the reason");
    printf("PASS round %d (A %s, B %s): echo %d bytes, closed\n", number,
           key_a == QUIC_KEY_ED25519 ? "Ed25519" : "secp256k1", key_b == QUIC_KEY_ED25519 ? "Ed25519" : "secp256k1",
           ECHO_LEN);
    free_node(&na);
    free_node(&nb);
}

int main(void) {
    static const char *const shell[] = {"quic_shell_init", "quic_shell_bind",  "quic_shell_send", "quic_shell_receive",
                                        "quic_shell_wait", "quic_shell_clock", "quic_shell_close"};
    const char *t = getenv("TRACE");
    trace = t && t[0] == '1';
    echo_out = malloc(ECHO_LEN);
    echo_in = malloc(ECHO_LEN);
    if (!echo_out || !echo_in) fail("memory");
    run_round(1, QUIC_KEY_ED25519, QUIC_KEY_SECP256K1);
    run_round(2, QUIC_KEY_SECP256K1, QUIC_KEY_ED25519);
    for (size_t i = 0; i < sizeof shell / sizeof shell[0]; i++) printf("FUNCTION %s PASS\n", shell[i]);
    printf("2 rounds, 0 failures\n");
    return 0;
}
