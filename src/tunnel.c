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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include "common.h"
#include "tunnel.h"
#include "dump_info.h"

static bool tunnel_is_in_streaming_wrapper(struct tunnel_ctx *tunnel);
static bool tunnel_is_dead(struct tunnel_ctx *tunnel);
static void tunnel_add_ref(struct tunnel_ctx *tunnel);
static void tunnel_release(struct tunnel_ctx *tunnel);
static bool socket_cycle(struct socket_ctx *a, struct socket_ctx *b);
static void socket_timer_expire_cb(uv_timer_t *handle);
static void socket_timer_start(struct socket_ctx *c);
static void socket_timer_stop(struct socket_ctx *c);
static void socket_connect_done_cb(uv_connect_t *req, int status);
static void socket_read_done_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
static void socket_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void socket_getaddrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *ai);
static void socket_write_done_cb(uv_write_t *req, int status);
static void socket_close(struct socket_ctx *c);
static void socket_close_done_cb(uv_handle_t *handle);

int uv_stream_fd(const uv_tcp_t *handle) {
#if defined(_WIN32)
    return (int) handle->socket;
#elif defined(__APPLE__)
    int uv___stream_fd(const uv_stream_t* handle);
    return uv___stream_fd((const uv_stream_t *)handle);
#else
    return (handle)->io_watcher.fd;
#endif
}

uint16_t get_socket_port(const uv_tcp_t *tcp) {
    union sockaddr_universal tmp = { 0 };
    int len = sizeof(tmp);
    if (uv_tcp_getsockname(tcp, &tmp.addr, &len) != 0) {
        return 0;
    } else {
        return ntohs(tmp.addr4.sin_port);
    }
}

static bool tunnel_is_in_streaming_wrapper(struct tunnel_ctx *tunnel) {
    return (tunnel && tunnel->tunnel_is_in_streaming && tunnel->tunnel_is_in_streaming(tunnel));
}

static bool tunnel_is_dead(struct tunnel_ctx *tunnel) {
    return (tunnel->terminated != false);
}

static void tunnel_add_ref(struct tunnel_ctx *tunnel) {
    tunnel->ref_count++;
}

static void tunnel_release(struct tunnel_ctx *tunnel) {
    tunnel->ref_count--;
    if (tunnel->ref_count == 0) {
        if (tunnel->tunnel_dying) {
            tunnel->tunnel_dying(tunnel);
        }

        free(tunnel->incoming);

        free(tunnel->outgoing);

        free(tunnel->desired_addr);
        free(tunnel);
    }
}

/* |incoming| has been initialized by listener.c when this is called. */
void tunnel_initialize(uv_tcp_t *listener, unsigned int idle_timeout, bool(*init_done_cb)(struct tunnel_ctx *tunnel, void *p), void *p) {
    struct socket_ctx *incoming;
    struct socket_ctx *outgoing;
    struct tunnel_ctx *tunnel;
    uv_loop_t *loop = listener->loop;

    tunnel = (struct tunnel_ctx *) calloc(1, sizeof(*tunnel));

    tunnel->listener = listener;
    tunnel->ref_count = 0;
    tunnel->desired_addr = (struct socks5_address *)calloc(1, sizeof(struct socks5_address));

    incoming = (struct socket_ctx *) calloc(1, sizeof(*incoming));
    incoming->tunnel = tunnel;
    incoming->result = 0;
    incoming->rdstate = socket_stop;
    incoming->wrstate = socket_stop;
    incoming->idle_timeout = idle_timeout;
    VERIFY(0 == uv_timer_init(loop, &incoming->timer_handle));
    VERIFY(0 == uv_tcp_init(loop, &incoming->handle.tcp));
    VERIFY(0 == uv_accept((uv_stream_t *)listener, &incoming->handle.stream));
    tunnel->incoming = incoming;

    outgoing = (struct socket_ctx *) calloc(1, sizeof(*outgoing));
    outgoing->tunnel = tunnel;
    outgoing->result = 0;
    outgoing->rdstate = socket_stop;
    outgoing->wrstate = socket_stop;
    outgoing->idle_timeout = idle_timeout;
    VERIFY(0 == uv_timer_init(loop, &outgoing->timer_handle));
    VERIFY(0 == uv_tcp_init(loop, &outgoing->handle.tcp));
    tunnel->outgoing = outgoing;

    bool success = false;
    if (init_done_cb) {
        success = init_done_cb(tunnel, p);
    }

    if (success) {
        /* Wait for the initial packet. */
        socket_read(incoming);
    } else {
        tunnel_shutdown(tunnel);
    }
}

void tunnel_shutdown(struct tunnel_ctx *tunnel) {
    if (tunnel_is_dead(tunnel) != false) {
        return;
    }

    /* Try to cancel the request. The callback still runs but if the
    * cancellation succeeded, it gets called with status=UV_ECANCELED.
    */
    if (tunnel->getaddrinfo_pending) {
        uv_cancel(&tunnel->outgoing->t.req);
    }

    socket_close(tunnel->incoming);
    socket_close(tunnel->outgoing);

    tunnel->terminated = true;
}

void tunnel_process_streaming(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;
    struct socket_ctx *write_target = NULL;
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    uint8_t *buffer = NULL;
    size_t len = 0;

    ASSERT(socket == incoming || socket == outgoing);

    socket->rdstate = socket_stop;

    write_target = ((socket == incoming) ? outgoing : incoming);

    ASSERT(tunnel->tunnel_extract_data);
    buffer = tunnel->tunnel_extract_data(socket, &malloc, &len);
    if (buffer && (len > 0)) {
        socket_write(write_target, buffer, len);
    }
    free(buffer);
}

void tunnel_traditional_streaming(struct tunnel_ctx *tunnel, struct socket_ctx *socket) {
    struct socket_ctx *incoming = tunnel->incoming;
    struct socket_ctx *outgoing = tunnel->outgoing;

    ASSERT(socket == incoming || socket == outgoing);

    if (socket_cycle(incoming, outgoing) == false) {
        tunnel_shutdown(tunnel);
        return;
    }

    if (socket_cycle(outgoing, incoming) == false) {
        tunnel_shutdown(tunnel);
        return;
    }
}

static bool socket_cycle(struct socket_ctx *a, struct socket_ctx *b) {
    bool result = true;
    struct tunnel_ctx *tunnel = a->tunnel;

    ASSERT((a->result >= 0) && (b->result >= 0));

    if (a->wrstate == socket_done) {
        a->wrstate = socket_stop;
    }
    // The logic is as follows: read when we don't write and write when we don't read.
    // That gives us back-pressure handling for free because if the peer
    // sends data faster than we consume it, TCP congestion control kicks in.
    if (a->wrstate == socket_stop) {
        if (b->rdstate == socket_stop) {
            socket_read(b);
        } else if (b->rdstate == socket_done) {
            size_t len = 0;
            uint8_t *buf = NULL;
            ASSERT(tunnel->tunnel_extract_data);
            buf = tunnel->tunnel_extract_data(b, &malloc, &len);
            if (buf /* && size > 0 */) {
                socket_write(a, buf, len);
                b->rdstate = socket_stop;  // Triggers the call to socket_read() above.
            } else {
                result = false;
            }
            free(buf);
        }
    }
    return result;
}

static void socket_timer_start(struct socket_ctx *c) {
    VERIFY(0 == uv_timer_start(&c->timer_handle,
        socket_timer_expire_cb,
        c->idle_timeout,
        0));
}

static void socket_timer_stop(struct socket_ctx *c) {
    VERIFY(0 == uv_timer_stop(&c->timer_handle));
}

static void socket_timer_expire_cb(uv_timer_t *handle) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = CONTAINER_OF(handle, struct socket_ctx, timer_handle);
    c->result = UV_ETIMEDOUT;

    tunnel = c->tunnel;

    if (tunnel_is_dead(tunnel)) {
        return;
    }

    if (tunnel->tunnel_timeout_expire_done) {
        tunnel->tunnel_timeout_expire_done(tunnel, c);
    }

    tunnel_shutdown(tunnel);
}

/* Assumes that c->t.sa contains a valid AF_INET or AF_INET6 address. */
int socket_connect(struct socket_ctx *c) {
    ASSERT(c->addr.addr.sa_family == AF_INET || c->addr.addr.sa_family == AF_INET6);
    socket_timer_start(c);
    return uv_tcp_connect(&c->t.connect_req,
        &c->handle.tcp,
        &c->addr.addr,
        socket_connect_done_cb);
}

static void socket_connect_done_cb(uv_connect_t *req, int status) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = CONTAINER_OF(req, struct socket_ctx, t.connect_req);
    c->result = status;

    tunnel = c->tunnel;

    if (tunnel_is_dead(tunnel)) {
        return;
    }

    socket_timer_stop(c);

    if (status < 0 /*status == UV_ECANCELED || status == UV_ECONNREFUSED*/) {
        socket_dump_error_info("connect failed", c);
        tunnel_shutdown(tunnel);
        return;  /* Handle has been closed. */
    }

    ASSERT(tunnel->tunnel_outgoing_connected_done);
    tunnel->tunnel_outgoing_connected_done(tunnel, c);
}

void socket_read(struct socket_ctx *c) {
    ASSERT(c->rdstate == socket_stop);
    VERIFY(0 == uv_read_start(&c->handle.stream, socket_alloc_cb, socket_read_done_cb));
    c->rdstate = socket_busy;
    socket_timer_start(c);
}

static void socket_read_done_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    do {
        c = CONTAINER_OF(handle, struct socket_ctx, handle);
        c->result = nread;
        tunnel = c->tunnel;

        if (tunnel_is_dead(tunnel)) {
            break;
        }

        if (tunnel_is_in_streaming_wrapper(tunnel) == false) {
            uv_read_stop(&c->handle.stream);
        }

        socket_timer_stop(c);

        if (nread == 0) {
            break;
        }
        if (nread < 0) {
            // http://docs.libuv.org/en/v1.x/stream.html
            if (nread != UV_EOF) {
                socket_dump_error_info("recieve data failed", c);
            }
            tunnel_shutdown(tunnel);
            break;
        }

        c->buf = buf;
        if (tunnel_is_in_streaming_wrapper(tunnel) == false) {
            ASSERT(c->rdstate == socket_busy);
        }
        c->rdstate = socket_done;

        ASSERT(tunnel->tunnel_read_done);
        tunnel->tunnel_read_done(tunnel, c);
    } while (0);

    if (buf->base) {
        free(buf->base); // important!!!
    }
    c->buf = NULL;
}

void socket_read_stop(struct socket_ctx *c) {
    uv_read_stop(&c->handle.stream);
    c->rdstate = socket_stop;
}

static void socket_alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = CONTAINER_OF(handle, struct socket_ctx, handle);
    tunnel = c->tunnel;

    if (tunnel_is_in_streaming_wrapper(tunnel) == false) {
        ASSERT(c->rdstate == socket_busy);
    }

    if (tunnel->tunnel_get_alloc_size) {
        size = tunnel->tunnel_get_alloc_size(tunnel, size);
    }

    *buf = uv_buf_init((char *)calloc(size, sizeof(char)), (unsigned int)size);
}

void socket_getaddrinfo(struct socket_ctx *c, const char *hostname) {
    struct addrinfo hints;
    struct tunnel_ctx *tunnel;
    uv_loop_t *loop;

    tunnel = c->tunnel;
    loop = tunnel->listener->loop;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    VERIFY(0 == uv_getaddrinfo(loop,
        &c->t.addrinfo_req,
        socket_getaddrinfo_done_cb,
        hostname,
        NULL,
        &hints));
    socket_timer_start(c);
    tunnel->getaddrinfo_pending = true;
}

static void socket_getaddrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *ai) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = CONTAINER_OF(req, struct socket_ctx, t.addrinfo_req);
    c->result = status;

    tunnel = c->tunnel;
    tunnel->getaddrinfo_pending = false;

    if (tunnel_is_dead(tunnel)) {
        return;
    }

    socket_timer_stop(c);

    if (status < 0) {
        socket_dump_error_info("resolve address failed", c);
        tunnel_shutdown(tunnel);
        return;
    }

    if (status == 0) {
        /* FIXME(bnoordhuis) Should try all addresses. */
        uint16_t port = c->addr.addr4.sin_port;
        if (ai->ai_family == AF_INET) {
            c->addr.addr4 = *(const struct sockaddr_in *) ai->ai_addr;
        } else if (ai->ai_family == AF_INET6) {
            c->addr.addr6 = *(const struct sockaddr_in6 *) ai->ai_addr;
        } else {
            UNREACHABLE();
        }
        c->addr.addr4.sin_port = port;
    }

    uv_freeaddrinfo(ai);

    ASSERT(tunnel->tunnel_getaddrinfo_done);
    tunnel->tunnel_getaddrinfo_done(tunnel, c);
}

void socket_write(struct socket_ctx *c, const void *data, size_t len) {
    uv_buf_t buf;
    struct tunnel_ctx *tunnel = c->tunnel;

    if (tunnel_is_in_streaming_wrapper(tunnel) == false) {
        ASSERT(c->wrstate == socket_stop);
    }
    c->wrstate = socket_busy;

    // It's okay to cast away constness here, uv_write() won't modify the memory.
    buf = uv_buf_init((char *)data, (unsigned int)len);

    uv_write_t *req = (uv_write_t *)calloc(1, sizeof(uv_write_t));
    req->data = c;

    VERIFY(0 == uv_write(req, &c->handle.stream, &buf, 1, socket_write_done_cb));
    socket_timer_start(c);
}

static void socket_write_done_cb(uv_write_t *req, int status) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = (struct socket_ctx *)req->data;
    c->result = status;
    free(req);
    tunnel = c->tunnel;

    if (tunnel_is_dead(tunnel)) {
        return;
    }

    socket_timer_stop(c);

    if (status < 0 /*status == UV_ECANCELED*/) {
        socket_dump_error_info("send data failed", c);
        tunnel_shutdown(tunnel);
        return;  /* Handle has been closed. */
    }

    if (tunnel_is_in_streaming_wrapper(tunnel) == false) {
        ASSERT(c->wrstate == socket_busy);
    }
    c->wrstate = socket_done;

    if (tunnel_is_in_streaming_wrapper(tunnel) == true) {
        // in streaming stage, do nothing and return.
        c->wrstate = socket_stop;
        return;
    }

    ASSERT(tunnel->tunnel_write_done);
    tunnel->tunnel_write_done(tunnel, c);
}

static void socket_close(struct socket_ctx *c) {
    struct tunnel_ctx *tunnel = c->tunnel;
    ASSERT(c->rdstate != socket_dead);
    ASSERT(c->wrstate != socket_dead);
    c->rdstate = socket_dead;
    c->wrstate = socket_dead;
    c->timer_handle.data = c;
    c->handle.handle.data = c;

    tunnel_add_ref(tunnel);
    uv_close(&c->handle.handle, socket_close_done_cb);
    tunnel_add_ref(tunnel);
    uv_close((uv_handle_t *)&c->timer_handle, socket_close_done_cb);
}

static void socket_close_done_cb(uv_handle_t *handle) {
    struct socket_ctx *c;
    struct tunnel_ctx *tunnel;

    c = (struct socket_ctx *) handle->data;
    tunnel = c->tunnel;

    tunnel_release(tunnel);
}

void socket_dump_error_info(const char *title, struct socket_ctx *socket) {
    struct tunnel_ctx *tunnel = socket->tunnel;
    int error = (int)socket->result;
    char addr[256] = { 0 };
    const char *from = NULL;
    if (socket == tunnel->outgoing) {
        socks5_address_to_string(tunnel->desired_addr, addr, sizeof(addr));
        from = "_server_";
    } else {
        union sockaddr_universal tmp;
        int len = sizeof(tmp);
        uv_tcp_getsockname(&socket->handle.tcp, &tmp.addr, &len);
        universal_address_to_string(&tmp, addr, sizeof(addr));
        from = "_client_";
    }
    pr_err("%s about %s \"%s\": %s", title, from, addr, uv_strerror(error));
}
