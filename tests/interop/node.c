/*
 * The asm-quic node of libp2p/test-plans transport-interop, quic-v1.
 *
 * Environment: transport (quic-v1), is_dialer, ip, redis_addr (default
 * redis:6379), test_timeout_seconds. The listener publishes
 * /ip4/<ip>/udp/<port>/quic-v1/p2p/<id> with RPUSH listenerAddr; the dialer
 * takes it with BLPOP, connects, opens a stream, agrees /ipfs/ping/1.0.0 with
 * multistream-select, pings (32 random bytes, echoed) and prints the JSON
 * result. Logs go to stderr; only the result goes to stdout.
 *
 * The library does QUIC and TLS, its shell the UDP socket; this file does
 * Redis, multistream-select and the ping protocol, which belong to libp2p.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../runner/quic.h"

QUIC_ABI uint64_t crypto_ed25519_public_key(const void *private_key, void *public_key);

#define EV_ROOM (8 << 20)
#define ACT_ROOM (8 << 20)
static const char MS[] = "/multistream/1.0.0\n";
static const char PING[] = "/ipfs/ping/1.0.0\n";

static void logf_(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static void die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static double now_f(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void random_bytes(uint8_t *p, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(p, 1, n, f) != n) die("urandom");
    fclose(f);
}

/* ---------------------------------------------------------------- base58btc */

static const char B58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static void b58_encode(const uint8_t *in, size_t n, char *out) {
    uint8_t buf[128] = {0};
    size_t len = 0, zeros = 0;
    while (zeros < n && in[zeros] == 0) zeros++;
    for (size_t i = zeros; i < n; i++) {
        int carry = in[i];
        for (size_t j = 0; j < len; j++) {
            carry += 256 * buf[j];
            buf[j] = carry % 58;
            carry /= 58;
        }
        while (carry) {
            buf[len++] = carry % 58;
            carry /= 58;
        }
    }
    size_t k = 0;
    for (size_t i = 0; i < zeros; i++) out[k++] = '1';
    for (size_t i = 0; i < len; i++) out[k++] = B58[buf[len - 1 - i]];
    out[k] = 0;
}

static int b58_decode(const char *s, uint8_t *out, size_t *n) {
    uint8_t buf[128] = {0};
    size_t len = 0, zeros = 0;
    while (s[zeros] == '1') zeros++;
    for (size_t i = zeros; s[i]; i++) {
        const char *p = strchr(B58, s[i]);
        if (!p || !*p) return -1;
        int carry = (int)(p - B58);
        for (size_t j = 0; j < len; j++) {
            carry += 58 * buf[j];
            buf[j] = carry & 0xFF;
            carry >>= 8;
        }
        while (carry) {
            buf[len++] = carry & 0xFF;
            carry >>= 8;
        }
    }
    if (zeros + len > *n) return -1;
    for (size_t i = 0; i < zeros; i++) out[i] = 0;
    for (size_t i = 0; i < len; i++) out[zeros + i] = buf[len - 1 - i];
    *n = zeros + len;
    return 0;
}

/* ---------------------------------------------------------------- Redis (RESP) */

static int tcp_connect_host(const char *hostport) {
    char host[256];
    const char *colon = strrchr(hostport, ':');
    if (!colon) die("bad redis_addr %s", hostport);
    snprintf(host, sizeof host, "%.*s", (int)(colon - hostport), hostport);
    struct addrinfo hints = {0}, *res;
    hints.ai_socktype = SOCK_STREAM;
    for (int attempt = 0; attempt < 50; attempt++) {
        if (getaddrinfo(host, colon + 1, &hints, &res) == 0) {
            int fd = socket(res->ai_family, SOCK_STREAM, 0);
            if (fd >= 0 && connect(fd, res->ai_addr, res->ai_addrlen) == 0) {
                freeaddrinfo(res);
                return fd;
            }
            if (fd >= 0) close(fd);
            freeaddrinfo(res);
        }
        usleep(200000);
    }
    die("cannot reach redis at %s", hostport);
    return -1;
}

static void redis_cmd(int fd, int argc, const char **argv) {
    char buf[1024];
    int k = snprintf(buf, sizeof buf, "*%d\r\n", argc);
    for (int i = 0; i < argc; i++) k += snprintf(buf + k, sizeof buf - k, "$%zu\r\n%s\r\n", strlen(argv[i]), argv[i]);
    if (write(fd, buf, k) != k) die("redis write");
}

static int redis_read(int fd, char *buf, int cap) {
    int n = 0;
    while (n < cap - 1) {
        int r = (int)read(fd, buf + n, cap - 1 - n);
        if (r <= 0) die("redis read");
        n += r;
        buf[n] = 0;
        if (buf[0] == '*') {
            int lines = 0;
            for (int i = 0; i < n; i++) lines += buf[i] == '\n';
            if (buf[1] == '-' ? lines >= 1 : lines >= 5) break;
        } else if (n >= 2 && buf[n - 2] == '\r' && buf[n - 1] == '\n') {
            break;
        }
    }
    return n;
}

/* ---------------------------------------------------------------- Node */

static uint8_t *state, *scratch, *events, *actions;
static uint64_t shell[QUIC_SHELL_SIZE / 8];
static int is_dialer, done;
static uint64_t wake_at, sock;
static double t_start, t_ping;
static uint8_t ping_bytes[32];

/* One stream of multistream-select, then ping. */
typedef struct {
    uint64_t handle;
    int ours;               /* we opened it: the dialer side of the ping */
    int stage;              /* 0 header, 1 protocol, 2 ping */
    uint8_t buf[256];
    size_t len;
    uint8_t got[32];
    size_t got_len;
} mstream;
static mstream streams[16];

static mstream *stream_of(uint64_t h) {
    for (int i = 0; i < 16; i++)
        if (streams[i].handle == h) return &streams[i];
    for (int i = 0; i < 16; i++)
        if (!streams[i].handle) {
            memset(&streams[i], 0, sizeof streams[i]);
            streams[i].handle = h;
            return &streams[i];
        }
    die("too many streams");
    return NULL;
}

static void *ev_add(uint64_t kind, uint64_t size) {
    uint64_t *h = (uint64_t *)events;
    size = (size + 7) & ~7ULL;
    if (h[2] + size > EV_ROOM - 24) die("event room");
    uint8_t *p = events + 24 + h[2];
    memset(p, 0, size);
    ((uint64_t *)p)[0] = size;
    ((uint64_t *)p)[1] = kind;
    h[2] += size;
    return p;
}

static void write_stream(uint64_t stream, const void *data, uint64_t n) {
    uint8_t *e = ev_add(QUIC_EVENT_STREAM_WRITE, 32 + n);
    ((uint64_t *)e)[2] = stream;
    ((uint64_t *)e)[3] = n;
    memcpy(e + 32, data, n);
}

/* A multistream-select message: a varint length, then the line. */
static void write_line(uint64_t stream, const char *line) {
    uint8_t b[128];
    size_t n = strlen(line);
    b[0] = (uint8_t)n;
    memcpy(b + 1, line, n);
    write_stream(stream, b, n + 1);
}

/* The next whole message in the buffer of the stream: its length, or 0. */
static size_t take_line(mstream *s, char *out) {
    if (s->len < 1) return 0;
    size_t n = s->buf[0];
    if (n >= 128 || s->len < 1 + n) return 0;
    memcpy(out, s->buf + 1, n);
    out[n] = 0;
    memmove(s->buf, s->buf + 1 + n, s->len - 1 - n);
    s->len -= 1 + n;
    return n;
}

static void on_data(uint64_t h, const uint8_t *d, uint64_t n) {
    mstream *s = stream_of(h);
    for (uint64_t i = 0; i < n;) {
        if (s->stage == 2) {
            if (s->ours) {
                while (i < n && s->got_len < 32) s->got[s->got_len++] = d[i++];
                if (s->got_len == 32 && !done) {
                    if (memcmp(s->got, ping_bytes, 32)) die("ping reply differs");
                    double t = now_f();
                    printf("{\"handshakePlusOneRTTMillis\": %.3f, \"pingRTTMilllis\": %.3f}\n", t - t_start,
                           t - t_ping);
                    fflush(stdout);
                    done = 1;
                }
                i = n;
            } else {
                write_stream(h, d + i, n - i);  /* echo */
                i = n;
            }
            continue;
        }
        while (i < n && s->len < sizeof s->buf) s->buf[s->len++] = d[i++];
        char line[128];
        while (s->stage < 2 && take_line(s, line)) {
            if (s->stage == 0) {
                if (strcmp(line, MS)) die("multistream header %s", line);
                if (!s->ours) write_line(h, MS);
                s->stage = 1;
            } else if (s->ours) {
                if (strcmp(line, PING)) die("listener answered %s", line);
                s->stage = 2;
                random_bytes(ping_bytes, 32);
                t_ping = now_f();
                write_stream(h, ping_bytes, 32);
            } else if (!strcmp(line, PING)) {
                write_line(h, PING);
                s->stage = 2;
            } else {
                write_line(h, "na\n");
            }
        }
        if (s->stage == 2 && s->len) {      /* bytes after the agreement */
            uint8_t rest[256];
            size_t rn = s->len;
            memcpy(rest, s->buf, rn);
            s->len = 0;
            on_data(h, rest, rn);
        }
    }
}

static void handle_actions(void) {
    uint64_t *h = (uint64_t *)actions;
    uint8_t *p = actions + h[1], *end = p + h[2];
    while (p < end) {
        uint64_t *w = (uint64_t *)p, size = w[0], kind = w[1];
        switch (kind) {
        case QUIC_ACTION_WAKEUP: wake_at = w[2]; break;
        case QUIC_ACTION_CONNECTED:
            logf_("connected, direction %llu", (unsigned long long)w[4]);
            if (is_dialer) {
                uint64_t *o = ev_add(QUIC_EVENT_OPEN_STREAM, 32);
                o[2] = w[2];
                o[3] = 1;
            }
            break;
        case QUIC_ACTION_DIAL_FAILED:
            die("dial failed, reason %llu, error 0x%llx", (unsigned long long)w[4], (unsigned long long)w[5]);
        case QUIC_ACTION_CLOSED:
            logf_("closed, reason %llu, error 0x%llx", (unsigned long long)w[4], (unsigned long long)w[5]);
            if (is_dialer && !done) die("closed before the ping");
            break;
        case QUIC_ACTION_STREAM_OPENED: {
            if (!w[2]) die("no stream");
            mstream *s = stream_of(w[2]);
            s->ours = w[4] != 0;            /* the tag of our OPEN_STREAM; 0 for a stream of the peer */
            if (s->ours) {
                write_line(w[2], MS);
                write_line(w[2], PING);
            }
            break;
        }
        case QUIC_ACTION_STREAM_DATA: on_data(w[2], p + 32, w[3]); break;
        case QUIC_ACTION_STREAM_FIN: {
            uint64_t *c = ev_add(QUIC_EVENT_STREAM_CLOSE, 24);
            c[2] = w[2];
            break;
        }
        case QUIC_ACTION_STREAM_RESET: logf_("stream reset, code %llu", (unsigned long long)w[3]); break;
        default: break;
        }
        p += size;
    }
}

static void step(void) {
    quic_tick t;
    if (quic_shell_clock(&t)) die("quic_shell_clock");
    uint64_t *ah = (uint64_t *)actions;
    ah[0] = ACT_ROOM;
    uint64_t result = 0;
    uint64_t st = quic_step(state, &t, events, scratch, actions, &result);
    if (st) die("quic_step: status %llu", (unsigned long long)st);
    uint64_t *eh = (uint64_t *)events;
    uint8_t *e = events + 24;
    uint64_t off = 0;
    for (uint64_t i = 0; i < result; i++) off += ((uint64_t *)(e + off))[0];
    memmove(e, e + off, eh[2] - off);
    eh[2] -= off;
    if (quic_shell_send(shell, actions)) die("quic_shell_send");
    handle_actions();
}

static void wait_and_receive(void) {
    uint64_t until = wake_at;
    quic_tick t;
    quic_shell_clock(&t);
    if (until > t.now + 100000) until = t.now + 100000;
    if (((uint64_t *)events)[2] == 0) quic_shell_wait(shell, &until);
    if (quic_shell_receive(shell, events)) die("quic_shell_receive");
}

int main(void) {
    const char *transport = getenv("transport"), *dialer = getenv("is_dialer"), *ip = getenv("ip");
    const char *redis = getenv("redis_addr"), *timeout_s = getenv("test_timeout_seconds");
    if (!transport || strcmp(transport, "quic-v1")) die("transport %s is not supported", transport ? transport : "(none)");
    is_dialer = dialer && !strcmp(dialer, "true");
    if (!ip) ip = "0.0.0.0";
    if (!redis) redis = "redis:6379";
    int timeout = timeout_s ? atoi(timeout_s) : 180;
    quic_tick t0;
    if (quic_shell_clock(&t0)) die("quic_shell_clock");
    quic_config c;
    memset(&c, 0, sizeof c);
    c.size = QUIC_CFG_SIZE;
    c.version = 1;
    c.key_type = QUIC_KEY_ED25519;
    random_bytes(c.key, 32);
    memcpy(c.seed, t0.entropy, 32);
    c.conns = 8;
    c.streams = 64;
    c.heap = 1 << 24;
    c.idle = 30000;
    c.handshake = 30000;
    c.keep_alive = 15000;
    c.max_data = 1 << 22;
    c.stream_data = 1 << 20;
    c.max_streams = 64;
    c.stream_queue = 1 << 22;
    c.flags = is_dialer ? 0 : QUIC_CFG_ACCEPT;
    c.sent = 512;
    uint64_t size = 0;
    if (quic_state_size(&c, &size)) die("quic_state_size");
    state = calloc(1, size);
    ((uint64_t *)state)[0] = size;
    uint64_t st = quic_init(&c, state);
    if (st) die("quic_init: status %llu", (unsigned long long)st);
    scratch = malloc(QUIC_SCRATCH_SIZE);
    ((uint64_t *)scratch)[0] = QUIC_SCRATCH_SIZE;
    events = malloc(EV_ROOM);
    actions = malloc(ACT_ROOM);
    ((uint64_t *)events)[0] = EV_ROOM;
    ((uint64_t *)events)[1] = 24;
    ((uint64_t *)events)[2] = 0;
    shell[0] = QUIC_SHELL_SIZE;
    if (quic_shell_init(shell)) die("quic_shell_init");
    /* Our peer ID: the identity multihash of the Ed25519 PublicKey protobuf. */
    uint8_t pub[32], pid[38];
    crypto_ed25519_public_key(c.key, pub);
    pid[0] = 0x00;
    pid[1] = 36;
    pid[2] = 0x08;
    pid[3] = 0x01;
    pid[4] = 0x12;
    pid[5] = 0x20;
    memcpy(pid + 6, pub, 32);
    char id58[128];
    b58_encode(pid, sizeof pid, id58);
    logf_("peer id %s, %s", id58, is_dialer ? "dialer" : "listener");
    int rfd = tcp_connect_host(redis);
    char reply[2048];
    uint64_t deadline = now_ms() + (uint64_t)timeout * 1000;
    quic_addr la = {4, 0, {0}};
    if (inet_pton(AF_INET, is_dialer ? "0.0.0.0" : ip, la.ip) != 1) die("bad ip %s", ip);
    uint64_t br[5];
    if (quic_shell_bind(shell, &la, br)) die("quic_shell_bind");
    sock = br[0];
    if (!is_dialer) {
        int port = (int)br[2];
        struct sockaddr_in me;
        socklen_t ml = sizeof me;
        getsockname(rfd, (struct sockaddr *)&me, &ml);   /* the address the dialer can reach */
        char ipbuf[64], maddr[256];
        inet_ntop(AF_INET, &me.sin_addr, ipbuf, sizeof ipbuf);
        snprintf(maddr, sizeof maddr, "/ip4/%s/udp/%d/quic-v1/p2p/%s", ipbuf, port, id58);
        logf_("listening on %s", maddr);
        const char *argv[] = {"RPUSH", "listenerAddr", maddr};
        redis_cmd(rfd, 3, argv);
        redis_read(rfd, reply, sizeof reply);
        while (now_ms() < deadline) {
            step();
            wait_and_receive();
        }
        die("listener timed out");
    }
    char tmo[16];
    snprintf(tmo, sizeof tmo, "%d", timeout);
    const char *argv[] = {"BLPOP", "listenerAddr", tmo};
    redis_cmd(rfd, 3, argv);
    int n = redis_read(rfd, reply, sizeof reply);
    char *v = reply;
    for (int lines = 0; lines < 4 && v < reply + n; v++)
        if (*v == '\n') lines++;
    char *cr = strstr(v, "\r\n");
    if (cr) *cr = 0;
    logf_("dialling %s", v);
    char host[64], idtxt[128];
    int port;
    if (sscanf(v, "/ip4/%63[^/]/udp/%d/quic-v1/p2p/%127s", host, &port, idtxt) != 3) die("cannot parse %s", v);
    uint64_t *d = ev_add(QUIC_EVENT_DIAL, 120);
    d[2] = 1;
    d[3] = sock;
    quic_addr *a = (quic_addr *)(d + 4);
    a->family = 4;
    a->port = (uint64_t)port;
    if (inet_pton(AF_INET, host, a->ip) != 1) die("bad ip %s", host);
    size_t idn = 48;
    if (b58_decode(idtxt, (uint8_t *)(d + 9), &idn)) die("bad peer id %s", idtxt);
    d[8] = idn;
    t_start = now_f();
    while (!done && now_ms() < deadline) {
        step();
        if (done) break;
        wait_and_receive();
    }
    if (!done) die("dialer timed out");
    return 0;
}
