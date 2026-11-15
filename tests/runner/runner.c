/*
 * Test runner for asm-quic.
 *
 * Usage: runner VECTOR_DIR [NAME ...]
 *
 * Runs the vector files that tests/generator/ writes (formats in
 * tests/generator/README.md). With no NAME it runs every file; a NAME
 * ending in .bin runs that file. It exits with status 0 only when every
 * case passes.
 *
 * Inputs sit at an offset with unused room after them, and must stay
 * unchanged. Outputs have guard bytes after them. Outputs and scratch get
 * exactly the size the function needs; one byte less must give
 * QUIC_BUFFER_TOO_SMALL.
 *
 * Every call goes through abi_call (tests/runner/abi_<ISA>.s). The runner
 * prints the most stack each function used, and fails when a call uses more
 * than STACK_CAP or changes state that the ABI says it must keep.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "quic.h"

#define STACK_CAP 16384 /* README: stack per call */
#define PAINT_BYTES (STACK_CAP + 4096)

typedef struct {
    uint64_t fn, arg[5], paint, status, fault, stack, scratch[4], arg5;
} abi_ctx;
QUIC_ABI void abi_call(abi_ctx *ctx);

enum { F_INITIAL_KEYS, F_PACKET_SEAL, F_PACKET_OPEN, F_RETRY_TAG, F_CERT_VERIFY, F_STATE_SIZE, F_INIT, F_STEP, F_COUNT };
static const char *FN_NAME[F_COUNT] = {"quic_initial_keys", "quic_packet_seal", "quic_packet_open", "quic_retry_tag",
                                       "quic_cert_verify",  "quic_state_size",  "quic_init",        "quic_step"};
static void *const FN_ADDR[F_COUNT] = {(void *)quic_initial_keys, (void *)quic_packet_seal, (void *)quic_packet_open,
                                       (void *)quic_retry_tag,    (void *)quic_cert_verify, (void *)quic_state_size,
                                       (void *)quic_init,         (void *)quic_step};
QUIC_ABI uint64_t crypto_ed25519_public_key(const void *private_key, void *public_key);
QUIC_ABI uint64_t crypto_secp256k1_public_key(const void *private_key, void *public_key);
static uint64_t stack_peak[F_COUNT], abi_fault[F_COUNT], fn_cases[F_COUNT], fn_bad[F_COUNT];

static uint64_t call(int fn, const void *a0, const void *a1, const void *a2, const void *a3, const void *a4,
                     const void *a5) {
    abi_ctx c;
    memset(&c, 0, sizeof c);
    c.fn = (uint64_t)(uintptr_t)FN_ADDR[fn];
    c.arg[0] = (uint64_t)(uintptr_t)a0;
    c.arg[1] = (uint64_t)(uintptr_t)a1;
    c.arg[2] = (uint64_t)(uintptr_t)a2;
    c.arg[3] = (uint64_t)(uintptr_t)a3;
    c.arg[4] = (uint64_t)(uintptr_t)a4;
    c.arg5 = (uint64_t)(uintptr_t)a5;
    c.paint = PAINT_BYTES;
    abi_call(&c);
    if (c.stack > stack_peak[fn]) stack_peak[fn] = c.stack;
    abi_fault[fn] |= c.fault;
    return c.status;
}

static void *xmalloc(size_t n) {
    void *p = calloc(1, n ? n : 1);
    if (!p) {
        fprintf(stderr, "out of memory\n");
        exit(2);
    }
    return p;
}

static uint64_t rd64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

static void wr64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

static int note(int fn, int ok, const char *file, const char *name) {
    fn_cases[fn]++;
    if (!ok) {
        if (fn_bad[fn] < 5) fprintf(stderr, "%s: %s: %s fails\n", file, name, FN_NAME[fn]);
        fn_bad[fn]++;
    }
    return ok;
}

/* ---------------------------------------------------------------- Buffers */

#define GUARD 16
#define FILL 0x5A

/* An input buffer, with a copy to check that the call left it unchanged. */
typedef struct {
    uint8_t *p, *copy;
    size_t n;
} input;

static input in_bytes(const uint8_t *b, size_t n) {
    size_t room = n + 7;
    input r = {xmalloc(room), xmalloc(room), room};
    memset(r.p, 0xA5, room);
    memcpy(r.p, b, n);
    memcpy(r.copy, r.p, room);
    return r;
}

/* A ByteList input: the bytes at offset 24, then 7 bytes of room. */
static input in_list(const uint8_t *b, uint64_t len) {
    size_t size = (size_t)(24 + len + 7);
    input r = {xmalloc(size), xmalloc(size), size};
    memset(r.p, 0xA5, size);
    wr64(r.p, size);
    wr64(r.p + 8, 24);
    wr64(r.p + 16, len);
    if (len) memcpy(r.p + 24, b, (size_t)len);
    memcpy(r.copy, r.p, size);
    return r;
}

static int in_done(input *r) {
    int ok = memcmp(r->p, r->copy, r->n) == 0;
    free(r->p);
    free(r->copy);
    return ok;
}

/* An output or scratch buffer of n bytes with its size field set, and GUARD bytes after it. */
typedef struct {
    uint8_t *p;
    size_t n;
} output;

static output out_new(size_t n, int sized) {
    output r = {xmalloc(n + GUARD), n};
    memset(r.p, FILL, n + GUARD);
    if (sized) wr64(r.p, n);
    return r;
}

static int out_guards(output *r) {
    for (int i = 0; i < GUARD; i++)
        if (r->p[r->n + i] != FILL) return 0;
    return 1;
}

static void out_free(output *r) { free(r->p); }

/* ---------------------------------------------------------------- Vector files */

typedef struct {
    const uint8_t *p, *end;
    const char *name;
} cursor;

typedef struct {
    const uint8_t *p;
    uint64_t n;
} blob;

static const uint8_t *take(cursor *c, uint64_t n) {
    if ((uint64_t)(c->end - c->p) < n) {
        fprintf(stderr, "%s: file ends early\n", c->name);
        exit(2);
    }
    const uint8_t *r = c->p;
    c->p += n;
    return r;
}

static uint64_t take64(cursor *c) { return rd64(take(c, 8)); }

static blob take_blob(cursor *c) {
    blob b;
    b.n = take64(c);
    b.p = take(c, b.n);
    return b;
}

enum { K_INITIAL_KEYS = 1, K_SEAL, K_OPEN, K_RETRY_TAG, K_CERT };

/* A ConnectionId input. */
static input in_cid(blob id) {
    uint8_t v[32];
    memset(v, 0, sizeof v);
    wr64(v, id.n);
    memcpy(v + 8, id.p, id.n > 20 ? 20 : (size_t)id.n);
    return in_bytes(v, 32);
}

static int case_initial_keys(cursor *c, const char *name) {
    blob dcid = take_blob(c);
    uint64_t want_status = take64(c);
    const uint8_t *want = take(c, 96);
    input d = in_cid(dcid);
    output k = out_new(96, 0);
    uint64_t status = call(F_INITIAL_KEYS, d.p, k.p, 0, 0, 0, 0);
    int ok = status == want_status && out_guards(&k) && (status != QUIC_OK || memcmp(k.p, want, 96) == 0);
    ok &= in_done(&d);
    out_free(&k);
    return note(F_INITIAL_KEYS, ok, c->name, name);
}

static int case_seal(cursor *c, const char *name) {
    const uint8_t *keys = take(c, 48);
    uint64_t pn = take64(c);
    blob header = take_blob(c), payload = take_blob(c);
    uint64_t want_status = take64(c);
    blob want = take_blob(c);
    /* PlainPacket: size, number, header (offset, count), payload (offset, count), then the parts. */
    uint64_t hoff = 48, poff = 48 + ((header.n + 7) & ~(uint64_t)7);
    size_t size = (size_t)(poff + payload.n + 5);
    uint8_t *pp = xmalloc(size);
    memset(pp, 0xA5, size);
    wr64(pp, size);
    wr64(pp + 8, pn);
    wr64(pp + 16, hoff);
    wr64(pp + 24, header.n);
    wr64(pp + 32, poff);
    wr64(pp + 40, payload.n);
    memcpy(pp + hoff, header.p, header.n);
    memcpy(pp + poff, payload.p, payload.n);
    input k = in_bytes(keys, 48), p = in_bytes(pp, size);
    free(pp);
    size_t need = (size_t)(24 + header.n + payload.n + 16);
    output s = out_new(need, 1), w = out_new(QUIC_PACKET_SCRATCH, 1);
    uint64_t status = call(F_PACKET_SEAL, k.p, p.p, w.p, s.p, 0, 0);
    int ok = status == want_status && out_guards(&s) && out_guards(&w);
    if (ok && status == QUIC_OK)
        ok = rd64(s.p) == need && rd64(s.p + 8) == 24 && rd64(s.p + 16) == want.n && memcmp(s.p + 24, want.p, want.n) == 0;
    if (ok && status == QUIC_OK) {
        output s1 = out_new(need - 1, 1), w1 = out_new(QUIC_PACKET_SCRATCH - 1, 1);
        ok = call(F_PACKET_SEAL, k.p, p.p, w.p, s1.p, 0, 0) == QUIC_BUFFER_TOO_SMALL &&
             call(F_PACKET_SEAL, k.p, p.p, w1.p, s.p, 0, 0) == QUIC_BUFFER_TOO_SMALL && out_guards(&s1) &&
             out_guards(&w1);
        out_free(&s1);
        out_free(&w1);
    }
    ok &= in_done(&k) & in_done(&p);
    out_free(&s);
    out_free(&w);
    return note(F_PACKET_SEAL, ok, c->name, name);
}

static int case_open(cursor *c, const char *name) {
    const uint8_t *keys = take(c, 48);
    uint64_t pn_offset = take64(c), largest = take64(c);
    blob packet = take_blob(c);
    uint64_t want_status = take64(c), want_pn = take64(c);
    blob header = take_blob(c), payload = take_blob(c);
    /* OpenRequest: size, pn_offset, largest, packet (offset, count), then the packet. */
    size_t size = (size_t)(40 + packet.n + 3);
    uint8_t *rq = xmalloc(size);
    memset(rq, 0xA5, size);
    wr64(rq, size);
    wr64(rq + 8, pn_offset);
    wr64(rq + 16, largest);
    wr64(rq + 24, 40);
    wr64(rq + 32, packet.n);
    memcpy(rq + 40, packet.p, packet.n);
    input k = in_bytes(keys, 48), r = in_bytes(rq, size);
    free(rq);
    size_t need = (size_t)(48 + packet.n + 8);
    output o = out_new(need, 1), w = out_new(QUIC_PACKET_SCRATCH, 1);
    uint64_t status = call(F_PACKET_OPEN, k.p, r.p, w.p, o.p, 0, 0);
    int ok = status == want_status && out_guards(&o) && out_guards(&w);
    if (ok && status == QUIC_OK) {
        uint64_t hoff = rd64(o.p + 16), hn = rd64(o.p + 24), poff = rd64(o.p + 32), pn = rd64(o.p + 40);
        ok = rd64(o.p) == need && rd64(o.p + 8) == want_pn && hn == header.n && pn == payload.n && hoff == 48 &&
             poff >= hoff + hn && poff % 8 == 0 && poff + pn <= need && memcmp(o.p + hoff, header.p, hn) == 0 &&
             memcmp(o.p + poff, payload.p, pn) == 0;
    }
    if (ok && status == QUIC_OK) {
        output o1 = out_new(need - 1, 1);
        ok = call(F_PACKET_OPEN, k.p, r.p, w.p, o1.p, 0, 0) == QUIC_BUFFER_TOO_SMALL && out_guards(&o1);
        out_free(&o1);
    }
    ok &= in_done(&k) & in_done(&r);
    out_free(&o);
    out_free(&w);
    return note(F_PACKET_OPEN, ok, c->name, name);
}

static int case_retry_tag(cursor *c, const char *name) {
    blob odcid = take_blob(c), retry = take_blob(c);
    uint64_t want_status = take64(c);
    const uint8_t *want = take(c, 16);
    input d = in_cid(odcid), r = in_list(retry.p, retry.n);
    size_t need = (size_t)(8 + 24 + 1 + odcid.n + retry.n);
    output t = out_new(16, 0), w = out_new(need, 1);
    uint64_t status = call(F_RETRY_TAG, d.p, r.p, w.p, t.p, 0, 0);
    int ok = status == want_status && out_guards(&t) && out_guards(&w) &&
             (status != QUIC_OK || memcmp(t.p, want, 16) == 0);
    if (ok && status == QUIC_OK) {
        output w1 = out_new(need - 1, 1);
        ok = call(F_RETRY_TAG, d.p, r.p, w1.p, t.p, 0, 0) == QUIC_BUFFER_TOO_SMALL && out_guards(&w1);
        out_free(&w1);
    }
    ok &= in_done(&d) & in_done(&r);
    out_free(&t);
    out_free(&w);
    return note(F_RETRY_TAG, ok, c->name, name);
}

static int case_cert(cursor *c, const char *name) {
    blob cert = take_blob(c);
    uint64_t now = take64(c), want_status = take64(c), want_kind = take64(c);
    blob key = take_blob(c), host = take_blob(c);
    uint8_t nowb[8];
    wr64(nowb, now);
    input d = in_list(cert.p, cert.n), t = in_bytes(nowb, 8);
    output info = out_new(QUIC_CI_FIXED, 1), w = out_new(QUIC_CERT_SCRATCH, 1);
    uint64_t status = call(F_CERT_VERIFY, d.p, t.p, w.p, info.p, 0, 0);
    int ok = status == want_status && out_guards(&info) && out_guards(&w);
    if (ok && status == QUIC_OK) {
        uint8_t k[72];
        memset(k, 0, sizeof k);
        memcpy(k, key.p, key.n > 72 ? 72 : (size_t)key.n);
        uint8_t h[128];
        memset(h, 0, sizeof h);
        memcpy(h, host.p, host.n > 128 ? 128 : (size_t)host.n);
        ok = rd64(info.p) == QUIC_CI_FIXED && rd64(info.p + 8) == want_kind && memcmp(info.p + 16, k, 72) == 0 &&
             rd64(info.p + 88) == host.n && memcmp(info.p + 96, h, 128) == 0;
    }
    if (ok && status == QUIC_OK) {
        output i1 = out_new(QUIC_CI_FIXED - 1, 1), w1 = out_new(QUIC_CERT_SCRATCH - 1, 1);
        ok = call(F_CERT_VERIFY, d.p, t.p, w.p, i1.p, 0, 0) == QUIC_BUFFER_TOO_SMALL &&
             call(F_CERT_VERIFY, d.p, t.p, w1.p, info.p, 0, 0) == QUIC_BUFFER_TOO_SMALL && out_guards(&i1) &&
             out_guards(&w1);
        out_free(&i1);
        out_free(&w1);
    }
    ok &= in_done(&d) & in_done(&t);
    out_free(&info);
    out_free(&w);
    return note(F_CERT_VERIFY, ok, c->name, name);
}


/* ---------------------------------------------------------------- Scenarios */

/*
 * Nodes in memory with the runner as their shell: a network that delivers
 * each datagram after a latency, and may drop some. Keys, entropy and time
 * are fixed, so every scenario is deterministic; its digest covers every
 * action of every node.
 */

#define MAX_NODES 4
#define ACTIONS_SIZE (1 << 18)
#define EVENTS_SIZE (1 << 22)

typedef struct {
    uint8_t *state, *scratch, *actions, *events;
    size_t nevents;
    uint64_t wake;
    quic_addr addr;
    uint8_t pid[48];
    uint64_t pid_len;
    uint64_t conn;          /* the last connection handle */
    uint64_t stream;        /* the last stream handle */
    uint64_t connected, dial_failed, closed, reason, error, opened, fins, resets;
    uint8_t *rx;            /* bytes received on streams */
    size_t rx_len;
    uint8_t peer_key[128];
    uint64_t peer_key_len;
} node;

typedef struct {
    uint64_t at;
    int to;
    quic_addr from;
    size_t n;
    uint8_t data[2048];
} packet;

static node nodes[MAX_NODES];
static int nnodes;
static packet *net;
static size_t nnet, net_cap;
static uint64_t now_us, entropy_counter, latency_us = 10000, drop_every, dropped, datagrams;
static uint64_t digest;
static int failures;
static const char *scenario;

static void fnv(const void *p, size_t n) {
    const uint8_t *b = p;
    for (size_t i = 0; i < n; i++) {
        digest ^= b[i];
        digest *= 0x100000001b3ULL;
    }
}

static void check(int ok, const char *what) {
    if (!ok) {
        fprintf(stderr, "%s: %s fails\n", scenario, what);
        failures++;
    }
}

static uint64_t key_update_packets, idle_ms = 30000, keep_alive_ms, conns_per_node = 8;
static void node_new(int i, uint64_t key_type, uint8_t seed) {
    node *n = &nodes[i];
    memset(n, 0, sizeof *n);
    quic_config c;
    memset(&c, 0, sizeof c);
    c.size = QUIC_CFG_SIZE;
    c.version = 1;
    c.key_type = key_type;
    for (int k = 0; k < 32; k++) c.key[k] = (uint8_t)(seed * 31 + k + 1);
    c.conns = conns_per_node;
    c.streams = 64;
    c.heap = 1 << 23;
    c.idle = idle_ms;
    c.handshake = 10000;
    c.keep_alive = keep_alive_ms;
    c.max_data = 1 << 22;
    c.stream_data = 1 << 20;
    c.max_streams = 16;
    c.stream_queue = 1 << 24;
    c.flags = QUIC_CFG_ACCEPT;
    c.sent = 256;
    for (int k = 0; k < 32; k++) c.seed[k] = (uint8_t)(seed + k * 7);
    c.key_update = key_update_packets;
    uint64_t size = 0;
    check(call(F_STATE_SIZE, &c, &size, 0, 0, 0, 0) == QUIC_OK, "quic_state_size");
    n->state = xmalloc((size_t)size);
    wr64(n->state, size);
    check(call(F_INIT, &c, n->state, 0, 0, 0, 0) == QUIC_OK, "quic_init");
    n->scratch = xmalloc(QUIC_SCRATCH_SIZE);
    n->actions = xmalloc(ACTIONS_SIZE);
    n->events = xmalloc(EVENTS_SIZE);
    n->rx = xmalloc(1 << 24);
    n->addr.family = 4;
    n->addr.port = 4000 + (uint64_t)i;
    n->addr.ip[0] = 10;
    n->addr.ip[3] = (uint8_t)(i + 1);
    n->wake = UINT64_MAX;
    /* The peer ID: the identity multihash of the PublicKey protobuf. */
    uint8_t pub[64];
    if (key_type == QUIC_KEY_ED25519) {
        crypto_ed25519_public_key(c.key, pub);
        n->pid[0] = 0;
        n->pid[1] = 36;
        n->pid[2] = 0x08;
        n->pid[3] = 1;
        n->pid[4] = 0x12;
        n->pid[5] = 32;
        memcpy(n->pid + 6, pub, 32);
        n->pid_len = 38;
    } else {
        crypto_secp256k1_public_key(c.key, pub);
        n->pid[0] = 0;
        n->pid[1] = 37;
        n->pid[2] = 0x08;
        n->pid[3] = 2;
        n->pid[4] = 0x12;
        n->pid[5] = 33;
        memcpy(n->pid + 6, pub, 33);
        n->pid_len = 39;
    }
}

static uint8_t *ev_add(node *n, uint64_t kind, size_t size) {
    size = (size + 7) & ~(size_t)7;
    if (n->nevents + size > EVENTS_SIZE - 24) {
        fprintf(stderr, "%s: events full\n", scenario);
        exit(2);
    }
    uint8_t *e = n->events + 24 + n->nevents;
    memset(e, 0, size);
    wr64(e, size);
    wr64(e + 8, kind);
    n->nevents += size;
    return e;
}

static void ev_dial(node *n, int to, uint64_t tag, const uint8_t *pid, uint64_t pid_len) {
    uint8_t *e = ev_add(n, QUIC_EVENT_DIAL, 120);
    wr64(e + 16, tag);
    wr64(e + 24, 1);
    memcpy(e + 32, &nodes[to].addr, 32);
    wr64(e + 64, pid_len);
    memcpy(e + 72, pid, pid_len);
}

static void ev_open(node *n, uint64_t conn, uint64_t tag) {
    uint8_t *e = ev_add(n, QUIC_EVENT_OPEN_STREAM, 32);
    wr64(e + 16, conn);
    wr64(e + 24, tag);
}

static void ev_write(node *n, uint64_t stream, const uint8_t *data, size_t len) {
    uint8_t *e = ev_add(n, QUIC_EVENT_STREAM_WRITE, 32 + len);
    wr64(e + 16, stream);
    wr64(e + 24, len);
    memcpy(e + 32, data, len);
}

static void ev_simple(node *n, uint64_t kind, uint64_t handle, uint64_t code, size_t size) {
    uint8_t *e = ev_add(n, kind, size);
    wr64(e + 16, handle);
    if (size > 24) wr64(e + 24, code);
}

static void net_send(int from, const uint8_t *a) {
    uint64_t count = rd64(a + 56);
    const uint8_t *to_addr = a + 24;
    int to = -1;
    for (int i = 0; i < nnodes; i++)
        if (memcmp(&nodes[i].addr, to_addr, 32) == 0) to = i;
    datagrams++;
    if (to < 0 || count > 2048) return;
    if (drop_every && datagrams % drop_every == 0) {
        dropped++;
        return;
    }
    if (nnet == net_cap) {
        net_cap = net_cap ? 2 * net_cap : 64;
        net = realloc(net, net_cap * sizeof *net);
        if (!net) exit(2);
    }
    packet *p = &net[nnet++];
    p->at = now_us + latency_us;
    p->to = to;
    p->from = nodes[from].addr;
    p->n = (size_t)count;
    memcpy(p->data, a + 64, (size_t)count);
}


/* QUIC_DEBUG=1: each action, and the first connection of each node after each step (offsets of include/state.inc). */
static int debug;
static void debug_conn(int i) {
    const uint8_t *st = nodes[i].state;
    const uint8_t *c = st + 1480;   /* ST_FIXED: connection 0 */
    if (!rd64(c + 0)) return;
    fprintf(stderr, "  node %d conn0: state %llu role %llu flags 0x%llx error 0x%llx reason %llu tls %llu phase %llu first %llu",
            i, (unsigned long long)rd64(c + 8), (unsigned long long)rd64(c + 16), (unsigned long long)rd64(c + 72),
            (unsigned long long)rd64(c + 80), (unsigned long long)rd64(c + 88), (unsigned long long)rd64(c + 2032),
            (unsigned long long)rd64(c + 1992), (unsigned long long)rd64(c + 2024));
    uint64_t tls = rd64(c + 2032);
    if (tls) fprintf(stderr, " stage %llu", (unsigned long long)rd64(st + tls));
    fprintf(stderr, " sent %llu inflight %llu rx %llu tx %llu\n", (unsigned long long)rd64(c + 2216),
            (unsigned long long)rd64(c + 2224), (unsigned long long)rd64(c + 2352),
            (unsigned long long)rd64(c + 2360));
    fprintf(stderr, "    streams head %lld local_open %llu p_streams %llu tx_max %llu\n",
            (long long)rd64(c + 2184), (unsigned long long)rd64(c + 2152),
            (unsigned long long)rd64(c + 2080), (unsigned long long)rd64(c + 2112));
    for (int sp = 0; sp < 3; sp++) {
        const uint8_t *p = c + 344 + 496 * sp;
        fprintf(stderr, "    space %d: flags 0x%llx next %llu largest %lld\n", sp, (unsigned long long)rd64(p),
                (unsigned long long)rd64(p + 8), (long long)rd64(p + 24));
    }
}

/* One step of node i with its queued events; then its actions. */
static void node_step(int i) {
    node *n = &nodes[i];
    quic_tick t;
    t.now = now_us;
    t.unix_time = 1794700800;   /* 2026-11-15 */
    for (int k = 0; k < 32; k++) t.entropy[k] = (uint8_t)(entropy_counter * 13 + (uint64_t)k);
    entropy_counter++;
    wr64(n->events, EVENTS_SIZE);
    wr64(n->events + 8, 24);
    wr64(n->events + 16, n->nevents);
    wr64(n->scratch, QUIC_SCRATCH_SIZE);
    wr64(n->actions, ACTIONS_SIZE);
    uint64_t result = 0;
    uint64_t st = call(F_STEP, n->state, &t, n->events, n->scratch, n->actions, &result);
    check(st == QUIC_OK, "quic_step status");
    if (st != QUIC_OK) {
        n->nevents = 0;
        return;
    }
    /* Keep the events not handled. */
    size_t off = 0;
    for (uint64_t k = 0; k < result && off < n->nevents; k++) off += (size_t)rd64(n->events + 24 + off);
    memmove(n->events + 24, n->events + 24 + off, n->nevents - off);
    n->nevents -= off;
    uint64_t count = rd64(n->actions + 16);
    uint8_t *a = n->actions + rd64(n->actions + 8);
    uint8_t *end = a + count;
    n->wake = UINT64_MAX;
    if (debug) fprintf(stderr, "t=%llu node %d: %llu events handled\n", (unsigned long long)now_us, i,
                       (unsigned long long)result);
    while (a < end) {
        uint64_t size = rd64(a), kind = rd64(a + 8);
        if (debug) fprintf(stderr, "  action %llu size %llu%s %016llx %016llx %016llx\n", (unsigned long long)kind,
                           (unsigned long long)size,
                           kind == QUIC_ACTION_SEND ? (rd64(a + 64) & 0x80 ? " long" : " short") : "",
                           (unsigned long long)rd64(a + 16), (unsigned long long)rd64(a + 24),
                           (unsigned long long)rd64(a + 32));
        fnv(&i, sizeof i);
        if (kind == QUIC_ACTION_SEND) {
            fnv(a, 64);     /* the datagram bytes are encrypted with fresh keys; their sizes are in the header */
            net_send(i, a);
        } else if (kind == QUIC_ACTION_WAKEUP) {
            n->wake = rd64(a + 16);
            fnv(a, (size_t)size);
        } else {
            fnv(a, (size_t)size);
            if (kind == QUIC_ACTION_CONNECTED) {
                n->connected++;
                n->conn = rd64(a + 16);
                n->peer_key_len = rd64(a + 80);
                memcpy(n->peer_key, a + 88, 128);
            } else if (kind == QUIC_ACTION_DIAL_FAILED) {
                n->dial_failed++;
                n->reason = rd64(a + 32);
                n->error = rd64(a + 40);
            } else if (kind == QUIC_ACTION_CLOSED) {
                n->closed++;
                n->reason = rd64(a + 32);
                n->error = rd64(a + 40);
            } else if (kind == QUIC_ACTION_STREAM_OPENED) {
                n->opened++;
                n->stream = rd64(a + 16);
            } else if (kind == QUIC_ACTION_STREAM_DATA) {
                uint64_t c = rd64(a + 24);
                if (n->rx_len + c <= (1 << 24)) {
                    memcpy(n->rx + n->rx_len, a + 32, (size_t)c);
                    n->rx_len += (size_t)c;
                }
            } else if (kind == QUIC_ACTION_STREAM_FIN) {
                n->fins++;
            } else if (kind == QUIC_ACTION_STREAM_RESET) {
                n->resets++;
            }
        }
        a += size;
    }
    if (debug) debug_conn(i);
}

/* Deliver the datagrams due, step the nodes that have work, then move time on. */
static void run_until(uint64_t limit_us, int (*done)(void)) {
    for (int guard = 0; guard < 200000; guard++) {
        for (size_t k = 0; k < nnet;) {
            if (net[k].at <= now_us) {
                node *n = &nodes[net[k].to];
                uint8_t *e = ev_add(n, QUIC_EVENT_DATAGRAM, 64 + net[k].n);
                wr64(e + 16, 1);
                memcpy(e + 24, &net[k].from, 32);
                wr64(e + 56, net[k].n);
                memcpy(e + 64, net[k].data, net[k].n);
                net[k] = net[--nnet];
            } else {
                k++;
            }
        }
        for (int i = 0; i < nnodes; i++)
            if (nodes[i].nevents || nodes[i].wake <= now_us) node_step(i);
        if (done && done()) return;
        uint64_t next = UINT64_MAX;
        for (size_t k = 0; k < nnet; k++)
            if (net[k].at < next) next = net[k].at;
        for (int i = 0; i < nnodes; i++) {
            if (nodes[i].nevents) next = now_us;
            if (nodes[i].wake < next) next = nodes[i].wake;
        }
        if (next == UINT64_MAX || next > limit_us) {
            now_us = limit_us;
            return;
        }
        if (next > now_us) now_us = next;
    }
    fprintf(stderr, "%s: no end\n", scenario);
    failures++;
}

static void reset_world(void) {
    for (int i = 0; i < nnodes; i++) {
        free(nodes[i].state);
        free(nodes[i].scratch);
        free(nodes[i].actions);
        free(nodes[i].events);
        free(nodes[i].rx);
    }
    nnodes = 0;
    nnet = 0;
    now_us = 1000000;
    entropy_counter = 0;
    latency_us = 10000;
    key_update_packets = 0;
    idle_ms = 30000;
    keep_alive_ms = 0;
    conns_per_node = 8;
    drop_every = 0;
    dropped = 0;
    datagrams = 0;
    digest = 0xcbf29ce484222325ULL;
}

static int both_connected(void) { return nodes[0].connected && nodes[1].connected; }
static int b_has_fin(void) { return nodes[1].fins > 0; }
static int a_has_fin(void) { return nodes[0].fins > 0; }
static int both_closed(void) { return nodes[0].closed && nodes[1].closed; }

static size_t big_len;
static int b_has_all(void) { return nodes[1].rx_len >= big_len && nodes[1].fins > 0; }

/* A dials B, a stream carries "hello" one way and "world" back, each with a FIN; A closes. */
static void scenario_handshake(uint64_t drop, uint64_t key_update) {
    reset_world();
    key_update_packets = key_update;
    nnodes = 2;
    node_new(0, QUIC_KEY_ED25519, 1);
    node_new(1, QUIC_KEY_ED25519, 2);
    drop_every = drop;
    ev_dial(&nodes[0], 1, 77, nodes[1].pid, nodes[1].pid_len);
    run_until(now_us + 5000000, both_connected);
    check(nodes[0].connected == 1 && nodes[1].connected == 1, "both CONNECTED");
    check(nodes[0].peer_key_len == 36 && memcmp(nodes[0].peer_key, nodes[1].pid + 2, 36) == 0, "A has B's host key");
    check(nodes[1].peer_key_len == 36 && memcmp(nodes[1].peer_key, nodes[0].pid + 2, 36) == 0, "B has A's host key");
    if (!both_connected()) return;
    ev_open(&nodes[0], nodes[0].conn, 5);
    run_until(now_us + 1000000, NULL);
    check(nodes[0].opened == 1, "A STREAM_OPENED");
    ev_write(&nodes[0], nodes[0].stream, (const uint8_t *)"hello", 5);
    ev_simple(&nodes[0], QUIC_EVENT_STREAM_CLOSE, nodes[0].stream, 0, 24);
    run_until(now_us + 5000000, b_has_fin);
    check(nodes[1].opened == 1 && nodes[1].rx_len == 5 && memcmp(nodes[1].rx, "hello", 5) == 0 && nodes[1].fins == 1,
          "B gets hello and FIN");
    ev_write(&nodes[1], nodes[1].stream, (const uint8_t *)"world", 5);
    ev_simple(&nodes[1], QUIC_EVENT_STREAM_CLOSE, nodes[1].stream, 0, 24);
    run_until(now_us + 5000000, a_has_fin);
    check(nodes[0].rx_len == 5 && memcmp(nodes[0].rx, "world", 5) == 0 && nodes[0].fins == 1, "A gets world and FIN");
    /* 1 MiB from A to B on a new stream. */
    big_len = 1 << 20;
    uint8_t *big = xmalloc(big_len);
    for (size_t k = 0; k < big_len; k++) big[k] = (uint8_t)(k * 7 + (k >> 9));
    nodes[1].rx_len = 0;
    nodes[1].fins = 0;
    ev_open(&nodes[0], nodes[0].conn, 6);
    run_until(now_us + 1000000, NULL);
    ev_write(&nodes[0], nodes[0].stream, big, big_len);
    ev_simple(&nodes[0], QUIC_EVENT_STREAM_CLOSE, nodes[0].stream, 0, 24);
    run_until(now_us + 60000000, b_has_all);
    check(nodes[1].rx_len == big_len && memcmp(nodes[1].rx, big, big_len) == 0 && nodes[1].fins == 1, "B gets 1 MiB");
    free(big);
    ev_simple(&nodes[0], QUIC_EVENT_CLOSE, nodes[0].conn, 9, 32);
    run_until(now_us + 5000000, both_closed);
    check(nodes[0].closed == 1 && nodes[0].reason == 1, "A CLOSED, LOCAL");
    check(nodes[1].closed == 1 && nodes[1].reason == 2 && nodes[1].error == 9, "B CLOSED, PEER with code 9");
}

static void run_handshake(void) { scenario_handshake(0, 0); }
static void run_loss(void) { scenario_handshake(5, 0); }
/* The same with a key update every 40 packets each way, and with loss. */
static void run_key_update(void) { scenario_handshake(0, 40); }
static void run_key_update_loss(void) { scenario_handshake(7, 40); }

static int wrong_failed(void) { return nodes[0].dial_failed > 0; }

/* A dials B but names another peer ID: the dial fails with PEER_ID. */
static void run_peer_id(void) {
    reset_world();
    nnodes = 2;
    node_new(0, QUIC_KEY_ED25519, 1);
    node_new(1, QUIC_KEY_ED25519, 2);
    uint8_t wrong[48];
    memcpy(wrong, nodes[1].pid, 48);
    wrong[10] ^= 1;
    ev_dial(&nodes[0], 1, 1, wrong, nodes[1].pid_len);
    run_until(now_us + 5000000, wrong_failed);
    check(nodes[0].dial_failed == 1 && nodes[0].reason == 6, "DIAL_FAILED with PEER_ID");
    check(nodes[0].connected == 0, "A not CONNECTED");
}

/* A dials an address with no node: the handshake times out. */
static void run_timeout(void) {
    reset_world();
    nnodes = 2;
    node_new(0, QUIC_KEY_ED25519, 1);
    node_new(1, QUIC_KEY_ED25519, 2);
    nodes[1].addr.port = 9;  /* nothing answers */
    quic_addr real = nodes[1].addr;
    real.port = 4001;
    uint8_t *e = ev_add(&nodes[0], QUIC_EVENT_DIAL, 120);
    wr64(e + 16, 3);
    wr64(e + 24, 1);
    memcpy(e + 32, &real, 32);
    run_until(now_us + 20000000, wrong_failed);
    check(nodes[0].dial_failed == 1 && nodes[0].reason == 4, "DIAL_FAILED with HANDSHAKE_TIMEOUT");
}


static void connect_pair(uint64_t key_type) {
    nnodes = 2;
    node_new(0, key_type, 1);
    node_new(1, key_type, 2);
    ev_dial(&nodes[0], 1, 1, nodes[1].pid, nodes[1].pid_len);
    run_until(now_us + 5000000, both_connected);
    check(both_connected(), "both CONNECTED");
}

/* secp256k1 host keys, as consensus clients use: the handshake and a stream. */
static void run_secp256k1(void) {
    reset_world();
    connect_pair(QUIC_KEY_SECP256K1);
    check(nodes[0].peer_key_len == 37 && memcmp(nodes[0].peer_key, nodes[1].pid + 2, 37) == 0, "A has B's key");
    check(nodes[1].peer_key_len == 37 && memcmp(nodes[1].peer_key, nodes[0].pid + 2, 37) == 0, "B has A's key");
    ev_open(&nodes[0], nodes[0].conn, 1);
    run_until(now_us + 1000000, NULL);
    ev_write(&nodes[0], nodes[0].stream, (const uint8_t *)"secp", 4);
    ev_simple(&nodes[0], QUIC_EVENT_STREAM_CLOSE, nodes[0].stream, 0, 24);
    run_until(now_us + 5000000, b_has_fin);
    check(nodes[1].rx_len == 4 && memcmp(nodes[1].rx, "secp", 4) == 0, "B gets the bytes");
}

static uint64_t want_resets;
static int b_resets(void) { return nodes[1].resets >= want_resets; }
static int a_resets(void) { return nodes[0].resets >= want_resets; }

/* Resets: A resets a stream it wrote to; B resets one A opened; data on a third still flows. */
static void run_reset(void) {
    reset_world();
    connect_pair(QUIC_KEY_ED25519);
    ev_open(&nodes[0], nodes[0].conn, 1);
    run_until(now_us + 1000000, NULL);
    uint64_t s1 = nodes[0].stream;
    ev_write(&nodes[0], s1, (const uint8_t *)"first", 5);
    run_until(now_us + 1000000, NULL);
    uint64_t b1 = nodes[1].stream;
    ev_simple(&nodes[0], QUIC_EVENT_STREAM_RESET, s1, 42, 32);
    want_resets = 1;
    run_until(now_us + 5000000, b_resets);
    check(nodes[1].resets == 1, "B hears the reset of A");
    ev_open(&nodes[0], nodes[0].conn, 2);
    run_until(now_us + 1000000, NULL);
    uint64_t s2 = nodes[0].stream;
    ev_write(&nodes[0], s2, (const uint8_t *)"second", 6);
    run_until(now_us + 1000000, NULL);
    uint64_t b2 = nodes[1].stream;
    check(b2 != b1, "B has a new stream");
    ev_simple(&nodes[1], QUIC_EVENT_STREAM_RESET, b2, 7, 32);
    run_until(now_us + 5000000, a_resets);
    check(nodes[0].resets == 1, "A hears the reset of B");
    ev_open(&nodes[0], nodes[0].conn, 3);
    run_until(now_us + 1000000, NULL);
    nodes[1].rx_len = 0;
    nodes[1].fins = 0;
    ev_write(&nodes[0], nodes[0].stream, (const uint8_t *)"third", 5);
    ev_simple(&nodes[0], QUIC_EVENT_STREAM_CLOSE, nodes[0].stream, 0, 24);
    run_until(now_us + 5000000, b_has_fin);
    check(nodes[1].fins == 1 && nodes[1].rx_len == 5 && memcmp(nodes[1].rx, "third", 5) == 0, "the third stream works");
}

static int both_gone(void) { return nodes[0].closed && nodes[1].closed; }

/* Idle: no traffic for 3 s closes both with IDLE; with a 1 s keep-alive, 10 s pass with no close. */
static void run_idle(void) {
    reset_world();
    idle_ms = 3000;
    connect_pair(QUIC_KEY_ED25519);
    run_until(now_us + 10000000, both_gone);
    check(nodes[0].closed == 1 && nodes[0].reason == 3 && nodes[1].closed == 1 && nodes[1].reason == 3,
          "both CLOSED with IDLE");
    reset_world();
    idle_ms = 3000;
    keep_alive_ms = 1000;
    connect_pair(QUIC_KEY_ED25519);
    run_until(now_us + 10000000, both_gone);
    check(nodes[0].closed == 0 && nodes[1].closed == 0, "no close with keep-alive");
}

/* Garbage datagrams to a node, then a dial still works; an unknown version of 1200 bytes gets Version Negotiation. */
static void run_garbage(void) {
    reset_world();
    nnodes = 2;
    node_new(0, QUIC_KEY_ED25519, 1);
    node_new(1, QUIC_KEY_ED25519, 2);
    uint8_t g[1400];
    for (int round = 0; round < 200; round++) {
        size_t n = (size_t)(1 + (round * 37) % 1400);
        for (size_t k = 0; k < n; k++) g[k] = (uint8_t)(round * 131 + k * 17);
        if (round % 4 == 1) g[0] |= 0x80;           /* long headers */
        if (round % 4 == 2 && n > 7) {              /* version 1 */
            g[0] = 0xC0;
            g[1] = g[2] = g[3] = 0;
            g[4] = 1;
        }
        uint8_t *e = ev_add(&nodes[1], QUIC_EVENT_DATAGRAM, 64 + n);
        wr64(e + 16, 1);
        memcpy(e + 24, &nodes[0].addr, 32);
        wr64(e + 56, n);
        memcpy(e + 64, g, n);
    }
    uint64_t before = datagrams;
    run_until(now_us + 2000000, NULL);
    (void)before;
    /* An unknown version: a Version Negotiation packet back. */
    memset(g, 0, sizeof g);
    g[0] = 0xC0;
    g[1] = 0x1a;
    g[2] = 0x2a;
    g[3] = 0x3a;
    g[4] = 0x4a;
    g[5] = 8;
    g[14] = 8;
    uint8_t *e = ev_add(&nodes[1], QUIC_EVENT_DATAGRAM, 64 + 1200);
    wr64(e + 16, 1);
    memcpy(e + 24, &nodes[0].addr, 32);
    wr64(e + 56, 1200);
    memcpy(e + 64, g, 1200);
    uint64_t sent_before = datagrams;
    run_until(now_us + 1000000, NULL);
    check(datagrams == sent_before + 1, "one Version Negotiation packet");
    ev_dial(&nodes[0], 1, 1, nodes[1].pid, nodes[1].pid_len);
    run_until(now_us + 5000000, both_connected);
    check(both_connected(), "a dial after the garbage works");
}

/* Malformed inputs give their status and change nothing. */
static void run_errors(void) {
    reset_world();
    nnodes = 1;
    node_new(0, QUIC_KEY_ED25519, 1);
    node *n = &nodes[0];
    uint64_t size = rd64(n->state);
    uint8_t *copy = xmalloc((size_t)size);
    memcpy(copy, n->state, (size_t)size);
    quic_tick t;
    memset(&t, 0, sizeof t);
    uint64_t result = 0;
    /* A short scratch, a short action list. */
    wr64(n->events, EVENTS_SIZE);
    wr64(n->events + 8, 24);
    wr64(n->events + 16, 0);
    wr64(n->scratch, QUIC_SCRATCH_SIZE - 1);
    wr64(n->actions, ACTIONS_SIZE);
    check(call(F_STEP, n->state, &t, n->events, n->scratch, n->actions, &result) == QUIC_BUFFER_TOO_SMALL, "short scratch");
    wr64(n->scratch, QUIC_SCRATCH_SIZE);
    wr64(n->actions, 24 + QUIC_ACTIONS_MIN - 1);
    check(call(F_STEP, n->state, &t, n->events, n->scratch, n->actions, &result) == QUIC_BUFFER_TOO_SMALL, "short actions");
    wr64(n->actions, ACTIONS_SIZE);
    /* Bad events. */
    static const struct { uint64_t kind, size; int field; uint64_t value; } bad[] = {
        {QUIC_EVENT_DATAGRAM, 64, 56, 9},               /* count past the event */
        {QUIC_EVENT_DATAGRAM, 72, 24, 5},               /* family 5 */
        {QUIC_EVENT_DATAGRAM, 72, 32, 70000},           /* port */
        {QUIC_EVENT_DIAL, 112, -1, 0},                  /* wrong size */
        {QUIC_EVENT_DIAL, 120, 64, 49},                 /* peer ID too long */
        {QUIC_EVENT_OPEN_STREAM, 40, -1, 0},
        {QUIC_EVENT_STREAM_WRITE, 40, 24, 9},           /* count past the event */
        {QUIC_EVENT_STREAM_CLOSE, 32, -1, 0},
        {QUIC_EVENT_STREAM_RESET, 32, 24, 1ULL << 62},  /* code too big */
        {QUIC_EVENT_CLOSE, 32, 24, 1ULL << 62},
        {99, 24, -1, 0},                                /* unknown kind */
    };
    for (size_t k = 0; k < sizeof bad / sizeof bad[0]; k++) {
        n->nevents = 0;
        uint8_t *e = ev_add(n, bad[k].kind, bad[k].size);
        if (bad[k].kind == QUIC_EVENT_DATAGRAM || bad[k].kind == QUIC_EVENT_DIAL) {
            uint8_t *a = e + (bad[k].kind == QUIC_EVENT_DIAL ? 32 : 24);
            wr64(a, 4);
            wr64(a + 8, 1);
        }
        if (bad[k].field >= 0) wr64(e + bad[k].field, bad[k].value);
        wr64(n->events + 16, n->nevents);
        check(call(F_STEP, n->state, &t, n->events, n->scratch, n->actions, &result) == QUIC_INVALID_EVENT, "a bad event");
    }
    n->nevents = 0;
    wr64(n->events + 8, 20);            /* a bad list offset */
    check(call(F_STEP, n->state, &t, n->events, n->scratch, n->actions, &result) == QUIC_INVALID_EVENT, "a bad list");
    check(memcmp(copy, n->state, (size_t)size) == 0, "the state is unchanged");
    free(copy);
    /* Configs. */
    quic_config c;
    memset(&c, 0, sizeof c);
    c.size = QUIC_CFG_SIZE; c.version = 1; c.key_type = QUIC_KEY_ED25519; c.conns = 1; c.streams = 1;
    c.heap = 1 << 16; c.handshake = 1; c.stream_queue = 1; c.sent = 16;
    uint64_t sz = 0;
    check(call(F_STATE_SIZE, &c, &sz, 0, 0, 0, 0) == QUIC_OK, "a small config");
    quic_config b = c; b.version = 2;
    check(call(F_STATE_SIZE, &b, &sz, 0, 0, 0, 0) == QUIC_INVALID_CONFIG, "version");
    b = c; b.heap = 3 << 16;
    check(call(F_STATE_SIZE, &b, &sz, 0, 0, 0, 0) == QUIC_INVALID_CONFIG, "heap not a power of two");
    b = c; b.conns = 0;
    check(call(F_STATE_SIZE, &b, &sz, 0, 0, 0, 0) == QUIC_INVALID_CONFIG, "no connections");
    b = c; b.key_type = 3;
    check(call(F_STATE_SIZE, &b, &sz, 0, 0, 0, 0) == QUIC_INVALID_CONFIG, "key type");
    b = c; b.flags = 2;
    check(call(F_STATE_SIZE, &b, &sz, 0, 0, 0, 0) == QUIC_INVALID_CONFIG, "flags");
    b = c; b.key_update = 1 << 23;
    check(call(F_STATE_SIZE, &b, &sz, 0, 0, 0, 0) == QUIC_INVALID_CONFIG, "key update");
    call(F_STATE_SIZE, &c, &sz, 0, 0, 0, 0);
    uint8_t *st = xmalloc((size_t)sz);
    wr64(st, sz - 8);
    check(call(F_INIT, &c, st, 0, 0, 0, 0) == QUIC_BUFFER_TOO_SMALL, "a short state");
    wr64(st, sz);
    b = c; b.key_type = QUIC_KEY_SECP256K1;
    memset(b.key, 0, 32);
    check(call(F_INIT, &b, st, 0, 0, 0, 0) == QUIC_INVALID_KEY, "a secp256k1 key of 0");
    memset(b.key, 0xFF, 32);
    check(call(F_INIT, &b, st, 0, 0, 0, 0) == QUIC_INVALID_KEY, "a secp256k1 key above n");
    free(st);
}

/* A node with one connection slot: a second dialer gets no answer. */
static int c_failed(void) { return nodes[2].dial_failed > 0; }
static void run_limits(void) {
    reset_world();
    conns_per_node = 1;
    nnodes = 3;
    node_new(0, QUIC_KEY_ED25519, 1);
    node_new(1, QUIC_KEY_ED25519, 2);
    node_new(2, QUIC_KEY_ED25519, 3);
    ev_dial(&nodes[0], 1, 1, nodes[1].pid, nodes[1].pid_len);
    run_until(now_us + 5000000, both_connected);
    check(both_connected(), "the first connection");
    ev_dial(&nodes[2], 1, 1, nodes[1].pid, nodes[1].pid_len);
    run_until(now_us + 20000000, c_failed);
    check(nodes[2].dial_failed == 1 && nodes[2].reason == 4, "the second dial times out");
    check(nodes[1].connected == 1, "B keeps one connection");
}

typedef struct {
    const char *name;
    void (*run)(void);
    uint64_t want;
} scenario_entry;

static const scenario_entry SCENARIOS[] = {
    {"handshake", run_handshake, 0xc7b1cd72edb19129ULL},
    {"loss", run_loss, 0x8db79dc2f6bbc9e7ULL},
    {"key_update", run_key_update, 0xef1d3320d7daf296ULL},
    {"key_update_loss", run_key_update_loss, 0xd31820bd697c2eddULL},
    {"peer_id", run_peer_id, 0x61813c189bb2401fULL},
    {"timeout", run_timeout, 0x9e0b9e9770332633ULL},
    {"secp256k1", run_secp256k1, 0xe90be1cac9ba1e82ULL},
    {"reset", run_reset, 0x569075c84ac02beaULL},
    {"idle", run_idle, 0x6ea0ce32cdc1aef1ULL},
    {"garbage", run_garbage, 0xc1b107ae09169c51ULL},
    {"errors", run_errors, 0xcbf29ce484222325ULL},
    {"limits", run_limits, 0x4c8e189cb0961f1eULL},
};

static int run_scenario(const scenario_entry *e) {
    scenario = e->name;
    int before = failures;
    e->run();
    if (e->want && digest != e->want) {
        fprintf(stderr, "%s: digest %016llx, want %016llx\n", e->name, (unsigned long long)digest,
                (unsigned long long)e->want);
        failures++;
    }
    int bad = failures != before;
    printf("%s scenario %s: digest %016llx, %llu datagrams, %llu dropped\n", bad ? "FAIL" : "PASS", e->name,
           (unsigned long long)digest, (unsigned long long)datagrams, (unsigned long long)dropped);
    reset_world();
    return bad;
}

static uint8_t *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *data = malloc(n > 0 ? (size_t)n : 1);
    if (!data || fread(data, 1, (size_t)n, f) != (size_t)n) {
        fclose(f);
        free(data);
        return NULL;
    }
    fclose(f);
    *len = (size_t)n;
    return data;
}

static const char *ALL_FILES[] = {"rfc9001.bin", "packet-generated.bin", "libp2p-tls.bin", "cert-generated.bin"};

static int run_file(const char *dir, const char *name) {
    char path[4096];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    size_t len = 0;
    uint8_t *data = read_file(path, &len);
    if (!data) {
        fprintf(stderr, "%s: cannot read\n", path);
        return 1;
    }
    cursor c = {data, data + len, name};
    if (memcmp(take(&c, 8), "QUICVEC1", 8) != 0) {
        fprintf(stderr, "%s: wrong magic\n", name);
        exit(2);
    }
    uint64_t n = take64(&c);
    int bad = 0;
    for (uint64_t i = 0; i < n; i++) {
        uint64_t kind = take64(&c);
        blob nm = take_blob(&c);
        char cname[256];
        snprintf(cname, sizeof cname, "%.*s", (int)(nm.n < 255 ? nm.n : 255), (const char *)nm.p);
        int ok;
        if (kind == K_INITIAL_KEYS) ok = case_initial_keys(&c, cname);
        else if (kind == K_SEAL) ok = case_seal(&c, cname);
        else if (kind == K_OPEN) ok = case_open(&c, cname);
        else if (kind == K_RETRY_TAG) ok = case_retry_tag(&c, cname);
        else if (kind == K_CERT) ok = case_cert(&c, cname);
        else {
            fprintf(stderr, "%s: unknown kind %llu\n", name, (unsigned long long)kind);
            exit(2);
        }
        bad += !ok;
    }
    if (c.p != c.end) {
        fprintf(stderr, "%s: bytes left after the last case\n", name);
        exit(2);
    }
    printf("%s %s: %llu cases\n", bad ? "FAIL" : "PASS", name, (unsigned long long)n);
    free(data);
    return bad != 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: runner VECTOR_DIR [NAME ...]\n");
        return 2;
    }
    int failed = 0;
    debug = getenv("QUIC_DEBUG") != NULL;
    if (argc == 2) {
        for (size_t i = 0; i < sizeof ALL_FILES / sizeof ALL_FILES[0]; i++) failed |= run_file(argv[1], ALL_FILES[i]);
        for (size_t i = 0; i < sizeof SCENARIOS / sizeof SCENARIOS[0]; i++) failed |= run_scenario(&SCENARIOS[i]);
    } else {
        for (int i = 2; i < argc; i++) {
            size_t len = strlen(argv[i]);
            if (len > 4 && strcmp(argv[i] + len - 4, ".bin") == 0) {
                failed |= run_file(argv[1], argv[i]);
                continue;
            }
            int found = 0;
            for (size_t k = 0; k < sizeof SCENARIOS / sizeof SCENARIOS[0]; k++)
                if (strcmp(SCENARIOS[k].name, argv[i]) == 0) {
                    failed |= run_scenario(&SCENARIOS[k]);
                    found = 1;
                }
            if (!found) {
                fprintf(stderr, "unknown name %s\n", argv[i]);
                failed = 1;
            }
        }
    }
    for (int f = 0; f < F_COUNT; f++) {
        if (!fn_cases[f] && !stack_peak[f]) continue;
        int over = stack_peak[f] > STACK_CAP;
        printf("%s stack %s: %llu bytes, cap %d\n", over ? "FAIL" : "PASS", FN_NAME[f],
               (unsigned long long)stack_peak[f], STACK_CAP);
        if (abi_fault[f])
            printf("FAIL abi %s: kept state changed, mask 0x%016llx\n", FN_NAME[f], (unsigned long long)abi_fault[f]);
        else
            printf("PASS abi %s: kept registers, stack pointer and flags\n", FN_NAME[f]);
        int bad = over || abi_fault[f] || fn_bad[f];
        failed |= bad;
        if (argc == 2) printf("FUNCTION %s %s\n", FN_NAME[f], bad ? "FAIL" : "PASS");
    }
    return failed;
}
