/* Copyright StrongLoop, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "defs.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "tunnel.h"
#include "dump_info.h"

/* A connection is modeled as an abstraction on top of two simple state
 * machines, one for reading and one for writing.  Either state machine
 * is, when active, in one of three states: busy, done or stop; the fourth
 * and final state, dead, is an end state and only relevant when shutting
 * down the connection.  A short overview:
 *
 *                          busy                  done           stop
 *  ----------|---------------------------|--------------------|------|
 *  readable  | waiting for incoming data | have incoming data | idle |
 *  writable  | busy writing out data     | completed write    | idle |
 *
 * We could remove the done state from the writable state machine. For our
 * purposes, it's functionally equivalent to the stop state.
 *
 * When the connection with upstream has been established, the struct tunnel_ctx
 * moves into a state where incoming data from the client is sent upstream
 * and vice versa, incoming data from upstream is sent to the client.  In
 * other words, we're just piping data back and forth.  See tunnel_traditional_streaming()
 * for details.
 *
 * An interesting deviation from libuv's I/O model is that reads are discrete
 * rather than continuous events.  In layman's terms, when a read operation
 * completes, the connection stops reading until further notice.
 *
 * The rationale for this approach is that we have to wait until the data
 * has been sent out again before we can reuse the read buffer.
 *
 * It also pleasingly unifies with the request model that libuv uses for
 * writes and everything else; libuv may switch to a request model for
 * reads in the future.
 */

/* Session states. */
enum session_state {
    session_handshake,        /* Wait for client handshake. */
    session_handshake_auth,   /* Wait for client authentication data. */
    session_req_start,        /* Start waiting for request data. */
    session_req_parse,        /* Wait for request data. */
    session_req_lookup,       /* Wait for upstream hostname DNS lookup to complete. */
    session_req_connect,      /* Wait for uv_tcp_connect() to complete. */
    session_proxy_start,      /* Connected. Start piping data. */
    session_streaming,            /* Connected. Pipe data back and forth. */
    session_kill,             /* Tear down session. */
    session_dead,             /* Dead. Safe to free now. */
};

struct s5_proxy_ctx {
    struct s5_ctx *parser;  /* The SOCKS protocol parser. */
    enum session_state state;
};


static uint8_t* tunnel_extract_data(struct socket_ctx *socket, void*(*allocator)(size_t size), size_t *size);
static void tunnel_dying(struct tunnel_ctx *tunnel);
static void tunnel_timeout_expire_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_outgoing_connected_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_read_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_getaddrinfo_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void tunnel_write_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static size_t tunnel_get_alloc_size(struct tunnel_ctx *tunnel, size_t suggested_size);
static bool tunnel_is_in_streaming(struct tunnel_ctx *tunnel);

static void do_next(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void do_handshake(struct tunnel_ctx *tunnel, struct socket_ctx *socket);
static void do_handshake_auth(struct tunnel_ctx *tunnel);
static void do_req_start(struct tunnel_ctx *tunnel);
static void do_req_parse(struct tunnel_ctx *tunnel);
static void do_req_lookup(struct tunnel_ctx *tunnel);
static void do_req_connect_start(struct tunnel_ctx *tunnel);
static void do_req_connect(struct tunnel_ctx *tunnel);
static void do_launch_streaming(struct tunnel_ctx *tunnel);

int tunnel_count = 0;

static bool _init_done_cb(struct tunnel_ctx *tunnel, void *p) {
    struct s5_proxy_ctx *ctx = (struct s5_proxy_ctx *) calloc(1, sizeof(*ctx));
    tunnel->data = ctx;

    tunnel->tunnel_dying = &tunnel_dying;
    tunnel->tunnel_timeout_expire_done = &tunnel_timeout_expire_done;
    tunnel->tunnel_outgoing_connected_done = &tunnel_outgoing_connected_done;
    tunnel->tunnel_read_done = &tunnel_read_done;
    tunnel->tunnel_getaddrinfo_done = &tunnel_getaddrinfo_done;
    tunnel->tunnel_write_done = &tunnel_write_done;
    tunnel->tunnel_get_alloc_size = &tunnel_get_alloc_size;
    tunnel->tunnel_is_in_streaming = &tunnel_is_in_streaming;
    tunnel->tunnel_extract_data = &tunnel_extract_data;

    ctx->parser = s5_ctx_create();
    ctx->state = session_handshake;

    tunnel_count++;

    return true;
}

/* |incoming| has been initialized by listener.c when this is called. */
void s5_tunnel_initialize(struct listener_ctx *lx) {
    uv_tcp_t *server = (uv_tcp_t *)&lx->tcp_handle;
    uv_loop_t *loop = lx->tcp_handle.loop;
    tunnel_initialize(server, lx->idle_timeout, &_init_done_cb, NULL);
}

/* This is the core state machine that drives the client <-> upstream proxy.
 * We move through the initial handshake and authentication steps first and
 * end up (if all goes well) in the proxy state where we're just proxying
 * data between the client and upstream.
 */
static void do_next(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct s5_proxy_ctx *ctx = (struct s5_proxy_ctx *) tunnel->data;
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;

    switch (ctx->state) {
    case session_handshake:
        do_handshake(tunnel, socket);
        break;
    case session_handshake_auth:
        do_handshake_auth(tunnel);
        break;
    case session_req_start:
        do_req_start(tunnel);
        break;
    case session_req_parse:
        do_req_parse(tunnel);
        break;
    case session_req_lookup:
        do_req_lookup(tunnel);
        break;
    case session_req_connect:
        do_req_connect(tunnel);
        break;
    case session_proxy_start:
        ASSERT(incoming->wrstate == socket_done);
        incoming->wrstate = socket_stop;
        do_launch_streaming(tunnel);
        break;
    case session_streaming:
        tunnel_traditional_streaming(tunnel, socket);
        break;
    case session_kill:
        tunnel_shutdown(tunnel);
        break;
    default:
        UNREACHABLE();
    }
}

static void do_handshake(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct s5_proxy_ctx *ctx = (struct s5_proxy_ctx *) tunnel->data;
    enum s5_auth_method methods;
    struct socket_ctx *incoming;
    struct s5_ctx *parser;
    uint8_t *data;
    size_t size;
    enum s5_result err;

    parser = ctx->parser;
    incoming = tunnel->incoming;
    ASSERT(incoming->rdstate == socket_done);
    ASSERT(incoming->wrstate == socket_stop);
    incoming->rdstate = socket_stop;

    if (incoming->result < 0) {
        pr_err("read error: %s", uv_strerror((int)incoming->result));
        tunnel_shutdown(tunnel);
        return;
    }

    data = (uint8_t *)incoming->buf->base;
    size = (size_t)incoming->result;
    err = s5_parse(parser, &data, &size);
    if (err == s5_result_need_more) {
        socket_read(incoming);
        ctx->state = session_handshake;  /* Need more data. */
        return;
    }

    if (size != 0) {
        /* Could allow a round-trip saving shortcut here if the requested auth
        * method is s5_auth_none (provided unauthenticated traffic is allowed.)
        * Requires client support however.
        */
        pr_err("junk in handshake");
        tunnel_shutdown(tunnel);
        return;
    }

    if (err != s5_result_auth_select) {
        pr_err("handshake error: %s", str_s5_result(err));
        tunnel_shutdown(tunnel);
        return;
    }

    methods = s5_get_auth_methods(parser);
    if ((methods & s5_auth_none) && can_auth_none(&incoming->handle.tcp, tunnel)) {
        s5_select_auth(parser, s5_auth_none);
        socket_write(incoming, "\5\0", 2);  /* No auth required. */
        ctx->state = session_req_start;
        return;
    }

    if ((methods & s5_auth_passwd) && can_auth_passwd(&incoming->handle.tcp, tunnel)) {
        /* TODO(bnoordhuis) Implement username/password auth. */
        tunnel_shutdown(tunnel);
        return;
    }

    socket_write(incoming, "\5\377", 2);  /* No acceptable auth. */
    ctx->state = session_kill;
}

/* TODO(bnoordhuis) Implement username/password auth. */
static void do_handshake_auth(struct tunnel_ctx *tunnel) {
    UNREACHABLE();
    tunnel_shutdown(tunnel);
}

static void do_req_start(struct tunnel_ctx *tunnel) {
    struct s5_proxy_ctx *ctx = (struct s5_proxy_ctx *) tunnel->data;
    struct socket_ctx *incoming;

    incoming = tunnel->incoming;
    ASSERT(incoming->rdstate == socket_stop);
    ASSERT(incoming->wrstate == socket_done);
    incoming->wrstate = socket_stop;

    if (incoming->result < 0) {
        pr_err("write error: %s", uv_strerror((int)incoming->result));
        tunnel_shutdown(tunnel);
        return;
    }

    socket_read(incoming);
    ctx->state = session_req_parse;
}

static void do_req_parse(struct tunnel_ctx *tunnel) {
    struct s5_proxy_ctx *ctx = (struct s5_proxy_ctx *) tunnel->data;
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;
    struct s5_ctx *parser;
    uint8_t *data;
    size_t size;
    enum s5_result err;

    parser = ctx->parser;
    incoming = tunnel->incoming;
    outgoing = tunnel->outgoing;

    ASSERT(incoming->rdstate == socket_done);
    ASSERT(incoming->wrstate == socket_stop);
    ASSERT(outgoing->rdstate == socket_stop);
    ASSERT(outgoing->wrstate == socket_stop);
    incoming->rdstate = socket_stop;

    if (incoming->result < 0) {
        pr_err("read error: %s", uv_strerror((int)incoming->result));
        tunnel_shutdown(tunnel);
        return;
    }

    data = (uint8_t *)incoming->buf->base;
    size = (size_t)incoming->result;
    err = s5_parse(parser, &data, &size);
    if (err == s5_result_need_more) {
        socket_read(incoming);
        ctx->state = session_req_parse;  /* Need more data. */
        return;
    }

    if (size != 0) {
        pr_err("junk in request %u", (unsigned)size);
        tunnel_shutdown(tunnel);
        return;
    }

    if (err != s5_result_exec_cmd) {
        pr_err("request error: %s", str_s5_result(err));
        tunnel_shutdown(tunnel);
        return;
    }

    if (s5_get_cmd(parser) == s5_cmd_tcp_bind) {
        /* Not supported but relatively straightforward to implement. */
        pr_warn("BIND requests are not supported.");
        tunnel_shutdown(tunnel);
        return;
    }

    if (s5_get_cmd(parser) == s5_cmd_udp_assoc) {
        /* Not supported.  Might be hard to implement because libuv has no
        * functionality for detecting the MTU size which the RFC mandates.
        */
        pr_warn("UDP ASSOC requests are not supported.");
        tunnel_shutdown(tunnel);
        return;
    }
    ASSERT(s5_get_cmd(parser) == s5_cmd_tcp_connect);

    if (s5_get_address_type(parser) == s5_atyp_host) {
        socket_getaddrinfo(outgoing, (const char *)s5_get_address(parser));
        ctx->state = session_req_lookup;
        return;
    }

    if (s5_get_address_type(parser) == s5_atyp_ipv4) {
        memset(&outgoing->addr.addr4, 0, sizeof(outgoing->addr.addr4));
        outgoing->addr.addr4.sin_family = AF_INET;
        outgoing->addr.addr4.sin_port = htons(s5_get_dport(parser));
        memcpy(&outgoing->addr.addr4.sin_addr,
            s5_get_address(parser),
            sizeof(outgoing->addr.addr4.sin_addr));
    } else if (s5_get_address_type(parser) == s5_atyp_ipv6) {
        memset(&outgoing->addr.addr6, 0, sizeof(outgoing->addr.addr6));
        outgoing->addr.addr6.sin6_family = AF_INET6;
        outgoing->addr.addr6.sin6_port = htons(s5_get_dport(parser));
        memcpy(&outgoing->addr.addr6.sin6_addr,
            s5_get_address(parser),
            sizeof(outgoing->addr.addr6.sin6_addr));
    } else {
        UNREACHABLE();
    }

    do_req_connect_start(tunnel);
}

static void do_req_lookup(struct tunnel_ctx *tunnel) {
    struct s5_proxy_ctx *ctx = (struct s5_proxy_ctx *) tunnel->data;
    struct s5_ctx *parser;
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;

    parser = ctx->parser;
    incoming = tunnel->incoming;
    outgoing = tunnel->outgoing;
    ASSERT(incoming->rdstate == socket_stop);
    ASSERT(incoming->wrstate == socket_stop);
    ASSERT(outgoing->rdstate == socket_stop);
    ASSERT(outgoing->wrstate == socket_stop);

    if (outgoing->result < 0) {
        /* TODO(bnoordhuis) Escape control characters in parser->daddr. */
        pr_err("lookup error for \"%s\": %s",
            s5_get_address(parser),
            uv_strerror((int)outgoing->result));
        /* Send back a 'Host unreachable' reply. */
        socket_write(incoming, "\5\4\0\1\0\0\0\0\0\0", 10);
        ctx->state = session_kill;
        return;
    }

    /* Don't make assumptions about the offset of sin_port/sin6_port. */
    switch (outgoing->addr.addr.sa_family) {
    case AF_INET:
        outgoing->addr.addr4.sin_port = htons(s5_get_dport(parser));
        break;
    case AF_INET6:
        outgoing->addr.addr6.sin6_port = htons(s5_get_dport(parser));
        break;
    default:
        UNREACHABLE();
    }

    do_req_connect_start(tunnel);
}

/* Assumes that cx->outgoing.t.sa contains a valid AF_INET/AF_INET6 address. */
static void do_req_connect_start(struct tunnel_ctx *tunnel) {
    struct s5_proxy_ctx *ctx = (struct s5_proxy_ctx *) tunnel->data;
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;
    int err;

    incoming = tunnel->incoming;
    outgoing = tunnel->outgoing;
    ASSERT(incoming->rdstate == socket_stop);
    ASSERT(incoming->wrstate == socket_stop);
    ASSERT(outgoing->rdstate == socket_stop);
    ASSERT(outgoing->wrstate == socket_stop);

    if (!can_access(&outgoing->handle.tcp, tunnel, &outgoing->addr.addr)) {
        pr_warn("connection not allowed by ruleset");
        /* Send a 'Connection not allowed by ruleset' reply. */
        socket_write(incoming, "\5\2\0\1\0\0\0\0\0\0", 10);
        ctx->state = session_kill;
        return;
    }

    err = socket_connect(outgoing);
    if (err != 0) {
        pr_err("connect error: %s\n", uv_strerror(err));
        tunnel_shutdown(tunnel);
        return;
    }

    ctx->state = session_req_connect;
}

static void do_req_connect(struct tunnel_ctx *tunnel) {
    struct s5_proxy_ctx *ctx = (struct s5_proxy_ctx *) tunnel->data;
    const struct sockaddr_in6 *in6;
    const struct sockaddr_in *in;
    char addr_storage[sizeof(*in6)];
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;
    uint8_t buf[256] = { 0 };
    int addrlen;

    incoming = tunnel->incoming;
    outgoing = tunnel->outgoing;

    ASSERT(incoming->rdstate == socket_stop);
    ASSERT(incoming->wrstate == socket_stop);
    ASSERT(outgoing->rdstate == socket_stop);
    ASSERT(outgoing->wrstate == socket_stop);

    /* Build and send the reply.  Not very pretty but gets the job done. */
    //buf = (uint8_t *)incoming->buf->base;
    if (outgoing->result == 0) {
        /* The RFC mandates that the SOCKS server must include the local port
        * and address in the reply.  So that's what we do.
        */
        addrlen = sizeof(addr_storage);
        CHECK(0 == uv_tcp_getsockname(&outgoing->handle.tcp,
            (struct sockaddr *) addr_storage,
            &addrlen));
        buf[0] = 5;  /* Version. */
        buf[1] = 0;  /* Success. */
        buf[2] = 0;  /* Reserved. */
        if (addrlen == sizeof(*in)) {
            buf[3] = 1;  // IPv4.
            in = (const struct sockaddr_in *) &addr_storage;
            memcpy(buf + 4, &in->sin_addr, 4);
            memcpy(buf + 8, &in->sin_port, 2);
            socket_write(incoming, buf, 10);
        } else if (addrlen == sizeof(*in6)) {
            buf[3] = 4;  // IPv6.
            in6 = (const struct sockaddr_in6 *) &addr_storage;
            memcpy(buf + 4, &in6->sin6_addr, 16);
            memcpy(buf + 20, &in6->sin6_port, 2);
            socket_write(incoming, buf, 22);
        } else {
            UNREACHABLE();
        }
        ctx->state = session_proxy_start;
        return;
    } else {
        struct s5_ctx *parser = ctx->parser;
        char *addr = NULL;
        const char *fmt;

        if (s5_get_address_type(parser) == s5_atyp_host) {
            addr = (char *)s5_get_address(parser);
        } else if (s5_get_address_type(parser) == s5_atyp_ipv4) {
            addr = inet_ntoa(*((struct in_addr *)s5_get_address(parser)));
        } else {
            ASSERT(!"not support ipv6 yet."); // inet_ntop()
        }
        fmt = "upstream connection \"%s\" error: %s\n";
        pr_err(fmt, addr, uv_strerror((int)outgoing->result));
        // Send a 'Connection refused' reply.
        socket_write(incoming, "\5\5\0\1\0\0\0\0\0\0", 10);
        ctx->state = session_kill;
        return;
    }

    UNREACHABLE();
    tunnel_shutdown(tunnel);
}

static void do_launch_streaming(struct tunnel_ctx *tunnel) {
    struct s5_proxy_ctx *ctx = (struct s5_proxy_ctx *) tunnel->data;
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;

    ASSERT(incoming->rdstate == socket_stop);
    ASSERT(incoming->wrstate == socket_stop);
    ASSERT(outgoing->rdstate == socket_stop);
    ASSERT(outgoing->wrstate == socket_stop);

    if (incoming->result < 0) {
        pr_err("write error: %s", uv_strerror((int)incoming->result));
        tunnel_shutdown(tunnel);
        return;
    }

    socket_read(incoming);
    socket_read(outgoing);
    ctx->state = session_streaming;
}

static uint8_t* tunnel_extract_data(struct socket_ctx *socket, void*(*allocator)(size_t size), size_t *size) {
    struct tunnel_ctx *tunnel = socket->tunnel;
    struct s5_proxy_ctx *ctx = (struct s5_proxy_ctx *) tunnel->data;
    struct buffer_t *buf = NULL;
    uint8_t *result = NULL;
    size_t len;

    if (socket==NULL || allocator==NULL || size==NULL) {
        return result;
    }
    *size = 0;

    len = (size_t)socket->result;
    *size = len;
    result = (uint8_t *)allocator(len + 1);
    memcpy(result, socket->buf->base, len);

    return result;
}

static void tunnel_dying(struct tunnel_ctx *tunnel) {
    struct s5_proxy_ctx *ctx = (struct s5_proxy_ctx *) tunnel->data;
    s5_ctx_release(ctx->parser);
    free(ctx);
}

static void tunnel_timeout_expire_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    (void)tunnel;
    (void)socket;
}

static void tunnel_outgoing_connected_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    do_next(tunnel, socket);
}

static void tunnel_read_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    do_next(tunnel, socket);
}

static void tunnel_getaddrinfo_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    do_next(tunnel, socket);
}

static void tunnel_write_done(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    do_next(tunnel, socket);
}

static size_t tunnel_get_alloc_size(struct tunnel_ctx *tunnel, size_t suggested_size) {
    (void)tunnel;
    return suggested_size;
}

static bool tunnel_is_in_streaming(struct tunnel_ctx *tunnel) {
    return false;
//    struct s5_proxy_ctx *ctx = (struct s5_proxy_ctx *) tunnel->data;
//    return (ctx->state == session_streaming);
}


bool can_auth_none(const uv_tcp_t *lx, const struct tunnel_ctx *cx) {
    return true;
}

bool can_auth_passwd(const uv_tcp_t *lx, const struct tunnel_ctx *cx) {
    return false;
}

bool can_access(const uv_tcp_t *lx, const struct tunnel_ctx *cx, const struct sockaddr *addr) {
    const struct sockaddr_in6 *addr6;
    const struct sockaddr_in *addr4;
    const uint32_t *p;
    uint32_t a, b, c, d;

    /* TODO(bnoordhuis) Implement proper access checks.  For now, just reject
    * traffic to localhost.
    */
    if (addr->sa_family == AF_INET) {
        addr4 = (const struct sockaddr_in *) addr;
        d = ntohl(addr4->sin_addr.s_addr);
        return (d >> 24) != 0x7F;
    }

    if (addr->sa_family == AF_INET6) {
        addr6 = (const struct sockaddr_in6 *) addr;
        p = (const uint32_t *)&addr6->sin6_addr.s6_addr;
        a = ntohl(p[0]);
        b = ntohl(p[1]);
        c = ntohl(p[2]);
        d = ntohl(p[3]);
        if (a == 0 && b == 0 && c == 0 && d == 1) {
            return false;  /* "::1" style address. */
        }
        if (a == 0 && b == 0 && c == 0xFFFF && (d >> 24) == 0x7F) {
            return false;  /* "::ffff:127.x.x.x" style address. */
        }
        return true;
    }

    return false;
}
