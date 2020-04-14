/*
 * udprelay.h - Define UDP relay's buffers and callbacks
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

#ifndef __UDPRELAY_H__
#define __UDPRELAY_H__

#include <uv.h>

struct ss_host_port;
struct udp_listener_ctx_t;
struct cipher_env_t;
union sockaddr_universal;

struct udp_listener_ctx_t * udprelay_begin(uv_loop_t *loop,
    const char *bind_host, uint16_t bind_port,
    int mtu, int timeout);

void udprelay_shutdown(struct udp_listener_ctx_t *server_ctx);

typedef void (*udp_recv_callback)(struct udp_listener_ctx_t *udp_ctx, const union sockaddr_universal *src_addr, const uint8_t *data, size_t data_len);
void udp_relay_set_recv_callback(struct udp_listener_ctx_t *udp_ctx, udp_recv_callback callback);
uv_loop_t * udp_relay_context_get_loop(struct udp_listener_ctx_t *udp_ctx);

void udp_on_recv_data(struct udp_listener_ctx_t *udp_ctx, const union sockaddr_universal *src_addr, const uint8_t *data, size_t data_len);

#endif // _UDPRELAY_H
