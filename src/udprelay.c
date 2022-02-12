/*
 * udprelay.c - Setup UDP relay for s5proxy
 *
 * Copyright (C) 2015 - 2020, ssrLive <ssrlivebox@gmail.com>
 *
 * This file is part of the s5proxy.
 *
 * s5proxy is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * s5proxy is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with s5proxy; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
//#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
/*
#ifndef __MINGW32__
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#endif
*/

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#include "udprelay.h"
#include "sockaddr_universal.h"

#include "common.h"
#include "sockaddr_universal.h"
#include "dump_info.h"
#include "s5.h"

#define MAX_UDP_CONN_NUM 512

#define ADDRTYPE_MASK 0xEF

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#define MAX_UDP_PACKET_SIZE (65507)
#define MIN_UDP_TIMEOUT (10 * 1000) // In milliseconds.

#define MODULE_LOCAL 1

#define DEFAULT_PACKET_SIZE MAX_UDP_PACKET_SIZE // 1492 - 1 - 28 - 2 - 64 = 1397, the default MTU for UDP relay

#ifndef max
#define max(a,b) ((a) > (b) ? (a) : (b))
#endif

struct udp_listener_ctx_t {
    uv_udp_t udp;
    uint64_t timeout;  // In milliseconds.
    struct cstl_set *connections;

    size_t packet_size;
    size_t buf_size;

    udp_recv_callback udp_on_recv_data;
};

struct udp_remote_ctx_t {
    uv_udp_t rmt_udp;
    uv_timer_t rmt_expire;
    int addr_header_len;
    char addr_header[384];
    struct socks5_address src_addr;
    struct socks5_address dst_addr;
    struct udp_listener_ctx_t *listener_ctx;
    bool shuting_down;
    int ref_count;
};

static void udp_listener_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf0, const struct sockaddr* addr, unsigned flags);
static void udp_remote_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf0, const struct sockaddr* addr, unsigned flags);
static void udp_remote_timeout_cb(uv_timer_t* handle);

static void udp_remote_shutdown(struct udp_remote_ctx_t *ctx);

static void udp_remote_ctx_add_ref(struct udp_remote_ctx_t* ctx);
static void udp_remote_ctx_release(struct udp_remote_ctx_t* ctx);

static void udp_uv_alloc_buffer(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    char *tmp = (char *) calloc(suggested_size, sizeof(char));
    *buf = uv_buf_init(tmp, (unsigned int)suggested_size);
}

static void udp_uv_release_buffer(uv_buf_t *buf) {
    if (buf->base) {
        free(buf->base);
        buf->base = NULL;
    }
    buf->len = 0;
}

int
udp_create_listener(uv_loop_t *loop, const char *host, uint16_t port, uv_udp_t *udp)
{
    struct addrinfo hints = { 0 };
    struct addrinfo *result = NULL, *rp, *ipv4v6bindall;
    int s, server_sock = 0;
    char str_port[32] = { 0 };

    hints.ai_family   = AF_UNSPEC;               // Return IPv4 and IPv6 choices.
    hints.ai_socktype = SOCK_DGRAM;              // We want a UDP socket.
    hints.ai_flags    = AI_PASSIVE | AI_ADDRCONFIG; // For wildcard IP address.
    hints.ai_protocol = IPPROTO_UDP;

    sprintf(str_port, "%d", port);

    s = getaddrinfo(host, str_port, &hints, &result);
    if (s != 0) {
        pr_err("[udp] getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    uv_udp_init(loop, udp);

    rp = result;

    //
    // On Linux, with net.ipv6.bindv6only = 0 (the default), getaddrinfo(NULL) with
    // AI_PASSIVE returns 0.0.0.0 and :: (in this order). AI_PASSIVE was meant to
    // return a list of addresses to listen on, but it is impossible to listen on
    // 0.0.0.0 and :: at the same time, if :: implies dualstack mode.
    //
    if (!host) {
        ipv4v6bindall = result;

        // Loop over all address infos found until a IPV6 address is found.
        while (ipv4v6bindall) {
            if (ipv4v6bindall->ai_family == AF_INET6) {
                rp = ipv4v6bindall; // Take first IPV6 address available.
                break;
            }
            ipv4v6bindall = ipv4v6bindall->ai_next; // Get next address info, if any
        }
    }

    for (/* rp = result */; rp != NULL; rp = rp->ai_next) {
        int r = uv_udp_bind(udp, rp->ai_addr, UV_UDP_REUSEADDR);
        if (r == 0) {
            break;
        }
        pr_err("[udp] create listener failed: %s\n", uv_strerror(r));
    }

    if (rp == NULL) {
        pr_err("[udp] cannot bind");
        return -1;
    }

    freeaddrinfo(result);

    return server_sock;
}

void upd_remote_sent_cb(uv_udp_send_t* req, int status) {
    uint8_t *dup_data = (uint8_t *) req->data;
    free(dup_data);
    free(req);
}

static void udp_remote_close_done_cb(uv_handle_t* handle) {
    struct udp_remote_ctx_t *ctx = (struct udp_remote_ctx_t *)handle->data;
    udp_remote_ctx_release(ctx);
}

static void udp_remote_shutdown(struct udp_remote_ctx_t *ctx) {
    if (ctx == NULL) {
        return;
    }

    if (ctx->shuting_down) {
        return;
    }
    ctx->shuting_down = true;

    //cstl_set_container_remove(ctx->server_ctx->connections, ctx);
    {
        uv_timer_t *timer = &ctx->rmt_expire;
        uv_timer_stop(timer);
        uv_close((uv_handle_t *)timer, udp_remote_close_done_cb);
        udp_remote_ctx_add_ref(ctx);
    }
    {
        uv_udp_t *udp = &ctx->rmt_udp;
        uv_udp_recv_stop(udp);
        uv_close((uv_handle_t *)udp, udp_remote_close_done_cb);
        udp_remote_ctx_add_ref(ctx);
    }
}

static void udp_remote_ctx_add_ref(struct udp_remote_ctx_t* ctx) {
    ++ctx->ref_count;
}

static void udp_remote_ctx_release(struct udp_remote_ctx_t* ctx) {
    --ctx->ref_count;
    if (ctx->ref_count <= 0) {
        free(ctx);
    }
}

static void udp_remote_ctx_restart_timer(struct udp_remote_ctx_t* ctx) {
    if (ctx && ctx->shuting_down==false) {
        uv_timer_t* timer = &ctx->rmt_expire;
        uv_timer_stop(timer);
        uv_timer_start(timer, timer->timer_cb, ctx->listener_ctx->timeout, 0);
    }
}

static void udp_remote_timeout_cb(uv_timer_t* handle) {
    struct udp_remote_ctx_t *rmt_ctx = CONTAINER_OF(handle, struct udp_remote_ctx_t, rmt_expire);

    pr_info("[udp] connection timeout, shutting down");

    udp_remote_shutdown(rmt_ctx);
}

void udp_remote_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf0, const struct sockaddr* addr, unsigned flags) {
    union sockaddr_universal src_addr = { 0 };
    uv_udp_send_t *send_req;
    uint8_t *dup_data;
    size_t len = 0;
    uv_buf_t sndbuf;
    struct udp_remote_ctx_t *rmt_ctx;

    do {
        rmt_ctx = CONTAINER_OF(handle, struct udp_remote_ctx_t, rmt_udp);
        ASSERT(rmt_ctx);
        ASSERT(rmt_ctx == handle->data);

        if (nread == 0) {
            break;
        }
        if (nread < 0) {
            udp_remote_shutdown(rmt_ctx);
            break;
        }

        udp_remote_ctx_restart_timer(rmt_ctx);

        socks5_address_to_universal(&rmt_ctx->src_addr, &src_addr);

        dup_data = s5_build_udp_datagram(&rmt_ctx->src_addr, (const uint8_t *) buf0->base, (size_t) nread, &malloc, &len);
        sndbuf = uv_buf_init((char *) dup_data, (unsigned int) len);

        send_req = (uv_udp_send_t *) calloc(1, sizeof(*send_req));
        send_req->data = dup_data;
        uv_udp_send(send_req, &rmt_ctx->listener_ctx->udp, &sndbuf, 1, &src_addr.addr, upd_remote_sent_cb);
    } while (0);
    udp_uv_release_buffer((uv_buf_t *)buf0);
}

static void launch_remote_progress(struct udp_listener_ctx_t *listener_ctx,
    const struct socks5_address *src_addr,
    const struct socks5_address *dst_addr,
    const uint8_t*data, size_t len)
{
    uv_udp_send_t *send_req;
    uint8_t *dup_data;
    uv_buf_t sndbuf;
    union sockaddr_universal u_dst_addr = { 0 };
    uv_loop_t *loop;
    uv_udp_t *udp = NULL;

    struct udp_remote_ctx_t *remote_ctx;
    remote_ctx = (struct udp_remote_ctx_t *) calloc(1, sizeof(*remote_ctx));
    remote_ctx->listener_ctx = listener_ctx;
    remote_ctx->src_addr = *src_addr;
    remote_ctx->dst_addr = *dst_addr;

    loop = listener_ctx->udp.loop;
    udp = &remote_ctx->rmt_udp;

    uv_udp_init(loop, udp);
    udp->data = remote_ctx;

    socks5_address_to_universal(dst_addr, &u_dst_addr);

    dup_data = (uint8_t *) calloc(len+1, sizeof(*dup_data));
    memcpy(dup_data, data, len);

    sndbuf = uv_buf_init((char*)dup_data, (unsigned int)len);

    send_req = (uv_udp_send_t *) calloc(1, sizeof(*send_req));
    send_req->data = dup_data;
    uv_udp_send(send_req, udp, &sndbuf, 1, &u_dst_addr.addr, upd_remote_sent_cb);
    uv_udp_recv_start(udp, udp_uv_alloc_buffer, udp_remote_recv_cb);
    {
        uv_timer_t *timer = &remote_ctx->rmt_expire;
        uv_timer_init(loop, timer);
        timer->data = remote_ctx;
        uv_timer_start(timer, udp_remote_timeout_cb, listener_ctx->timeout, 0);
        uv_timer_stop(timer);
    }
    udp_remote_ctx_restart_timer(remote_ctx);
}

static void 
udp_listener_recv_cb(uv_udp_t* handle, ssize_t nread, const uv_buf_t* buf0, const struct sockaddr* addr, unsigned flags)
{
    struct udp_listener_ctx_t *listener_ctx;
    const uint8_t *payload;
    size_t payload_len = 0;
    size_t frag = 0;
    struct socks5_address dst_addr = { 0 };
    struct socks5_address src_addr = { 0 };

    do {
        union sockaddr_universal udp_incoming;
        uint8_t *buf = NULL;
        size_t buf_len = 0;

        if (NULL == addr) {
            break;
        }
        listener_ctx = CONTAINER_OF(handle, struct udp_listener_ctx_t, udp);
        ASSERT(listener_ctx);

        // http://docs.libuv.org/en/v1.x/udp.html#c.uv_udp_recv_cb
        if (nread <= 0) {
            // error on recv
            // simply drop that packet
            pr_err("[udp] incoming recvfrom");
            break;
        } else if (nread > (ssize_t) listener_ctx->packet_size) {
            pr_err("[udp] incoming recvfrom fragmentation");
            break;
        }

        buf = (uint8_t*) buf0->base;
        buf_len = (size_t)nread;

        payload = s5_parse_upd_package(buf, buf_len, &dst_addr, &frag, &payload_len);

        if (frag) {
            pr_err("[udp] drop a message since frag is not 0, but %d", (int)frag);
            break;
        }

        udp_incoming.addr = *addr;
        universal_address_to_socks5(&udp_incoming, &src_addr);

        launch_remote_progress(listener_ctx, &src_addr, &dst_addr, payload, payload_len);
    } while(false);

    udp_uv_release_buffer((uv_buf_t *)buf0);
}

struct udp_listener_ctx_t *
udprelay_begin(uv_loop_t *loop,
    const char *bind_host, uint16_t bind_port,
    int mtu, int timeout)
{
    struct udp_listener_ctx_t *server_ctx;
    int serverfd;
    //struct server_info_t server_info = { 0 };

    size_t packet_size = DEFAULT_PACKET_SIZE;
    size_t buf_size = DEFAULT_PACKET_SIZE * 2;

    // Initialize MTU
    if (mtu > 0) {
        packet_size = mtu - 1 - 28 - 2 - 64;
        buf_size    = packet_size * 2;
    }

    // ////////////////////////////////////////////////
    // Setup server context

    server_ctx = (struct udp_listener_ctx_t *)calloc(1, sizeof(struct udp_listener_ctx_t));

    server_ctx->buf_size = buf_size;
    server_ctx->packet_size = packet_size;

    // Bind to port
    serverfd = udp_create_listener(loop, bind_host, bind_port, &server_ctx->udp);
    if (serverfd < 0) {
        pr_err("[udp] bind() error");
    }

    server_ctx->timeout = (uint64_t)((timeout > 0) ? timeout : MIN_UDP_TIMEOUT);
    //server_ctx->connections = cstl_set_container_create(tunnel_ctx_compare_for_c_set, NULL);

    uv_udp_recv_start(&server_ctx->udp, udp_uv_alloc_buffer, udp_listener_recv_cb);
    return server_ctx;
}

/*
static void udp_local_listener_close_done_cb(uv_handle_t* handle) {
    struct udp_listener_ctx_t *server_ctx = CONTAINER_OF(handle, struct udp_listener_ctx_t, io);
    cstl_set_container_destroy(server_ctx->connections);
    free(server_ctx);
}

void connection_release(const void *obj, void *p) {
    (void)p;
    udp_remote_shutdown((struct udp_remote_ctx_t *)obj);
}

void udprelay_shutdown(struct udp_listener_ctx_t *server_ctx) {
    if (server_ctx == NULL) {
        return;
    }
    cstl_set_container_traverse(server_ctx->connections, &connection_release, NULL);
    uv_close((uv_handle_t *)&server_ctx->udp, udp_local_listener_close_done_cb);
}
*/

void udp_relay_set_recv_callback(struct udp_listener_ctx_t *udp_ctx, udp_recv_callback callback) {
    if (udp_ctx) {
        udp_ctx->udp_on_recv_data = callback;
    }
}

uv_loop_t * udp_relay_context_get_loop(struct udp_listener_ctx_t *udp_ctx) {
    return udp_ctx->udp.loop;
}

void udp_on_recv_data(struct udp_listener_ctx_t *udp_ctx, const union sockaddr_universal *src_addr, const uint8_t *data, size_t data_len) {
    uv_loop_t *loop = udp_relay_context_get_loop(udp_ctx);
    /*
    struct server_env_t *env = (struct server_env_t *)loop->data;
    struct server_config *config = env->config;
    struct tunnel_ctx *tunnel = tunnel_initialize(loop, NULL, config->idle_timeout, &init_done_cb, env);
    struct client_ctx *ctx = (struct client_ctx *) tunnel->data;
    struct socket_ctx *socket = tunnel->incoming;
    ctx->udp_tunnel = true;
    if (src_addr) {
        ctx->udp_src_addr = *src_addr;
    }
    buffer_replace(ctx->udp_data, data);
    //do_next(tunnel, socket);
    */
    (void)loop;
}

