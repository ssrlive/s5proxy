#include <uv.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "web_request.h"

#if !defined(CONTAINER_OF)
#define CONTAINER_OF(ptr, type, field) ((type *) ((char *) (ptr) - ((char *) &((type *) 0)->field)))
#endif // !defined(CONTAINER_OF)

struct web_request_t {
    uv_tcp_t socket;
    char *host;
    int port;
    char *request_head;
    recv_data_callback recv_cb;
    void *recv_p;
    request_completion_callback compl_cb;
    void *compl_p;
    int status;
};

static void web_getaddrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs);
static void web_uv_connect_cb(uv_connect_t *req, int status);
static void web_uv_write_cb(uv_write_t* req, int status);
static void web_uv_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf);
static void web_uv_read_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf);
static void web_uv_close_cb(uv_handle_t* handle);
static void web_request_shutdown(struct web_request_t *req);
static void web_request_release(struct web_request_t *req);

void launch_web_request(uv_loop_t *loop,
    const char *host, int port,
    const char *request_head,
    recv_data_callback recv_cb, void *recv_p,
    request_completion_callback compl_cb, void *compl_p)
{
    struct web_request_t *web_req;
    uv_getaddrinfo_t *req;
    struct addrinfo hints = { 0 };
    char tmp[300] = { 0 };

    assert(host);
    sprintf(tmp, HTTP_REQUEST_HEADER, host);

    web_req = (struct web_request_t *)calloc(1, sizeof(struct web_request_t));
    uv_tcp_init(loop, &web_req->socket);
    web_req->host = strdup(host);
    web_req->port = port;
    web_req->request_head = strdup(request_head ? request_head : tmp);
    web_req->recv_cb = recv_cb;
    web_req->recv_p = recv_p;
    web_req->socket.data = web_req;
    web_req->compl_cb = compl_cb;
    web_req->compl_p = compl_p;

    req = (uv_getaddrinfo_t *)calloc(1, sizeof(*req));
    req->data = web_req;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    web_req->status = uv_getaddrinfo(loop, req, web_getaddrinfo_done_cb, host, NULL, &hints);
    if (web_req->status != 0) {
        // log("getaddrinfo: %s", uv_strerror(web_req->status));
        free(req);
        web_request_release(web_req);
        return;
    }
}

static void web_getaddrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
    struct web_request_t *web_req;
    uv_connect_t *connect;

    char addrbuf[INET6_ADDRSTRLEN + 1];
    struct addrinfo *ai;
    const void *addrv = NULL;

    union {
        struct sockaddr_in6 addr6;
        struct sockaddr_in addr4;
        struct sockaddr addr;
    } s;

    web_req = (struct web_request_t *) req->data;
    web_req->status = status;

    free(req);

    if (status < 0) {
        // log("getaddrinfo(\"%s\"): %s", web_req->host, uv_strerror(status));
        uv_freeaddrinfo(addrs);
        web_request_release(web_req);
        return;
    }

    for (ai = addrs; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) {
            continue;
        }

        if (ai->ai_family == AF_INET) {
            s.addr4 = *(const struct sockaddr_in *) ai->ai_addr;
            s.addr4.sin_port = htons(web_req->port);
            addrv = &s.addr4.sin_addr;
            break;
        } else if (ai->ai_family == AF_INET6) {
            s.addr6 = *(const struct sockaddr_in6 *) ai->ai_addr;
            s.addr6.sin6_port = htons(web_req->port);
            addrv = &s.addr6.sin6_addr;
            break;
        }
    }
    uv_freeaddrinfo(addrs);

    if (addrv == NULL) {
        web_req->status = -1;
        web_request_release(web_req);
        return;
    }

    web_req->status = uv_inet_ntop(s.addr.sa_family, addrv, addrbuf, sizeof(addrbuf));
    if (web_req->status != 0) {
        web_request_release(web_req);
        return;
    }

    connect = (uv_connect_t *)calloc(1, sizeof(uv_connect_t));

    web_req->status = uv_tcp_connect(connect, &web_req->socket, &s.addr, web_uv_connect_cb);
    if (0 != web_req->status) {
        free(connect);
        web_request_release(web_req);
    }
}

static void web_uv_connect_cb(uv_connect_t *req, int status) {
    uv_tcp_t *tcp = (uv_tcp_t *) req->handle;
    struct web_request_t *web_req = (struct web_request_t *) tcp->data;
    uv_write_t* wr_req;
    uv_buf_t buf;
    char *tmp;

    free(req);
    if (status < 0) {
        web_req->status = status;
        web_request_shutdown(web_req);
        return;
    }

    tmp = strdup(web_req->request_head);
    buf = uv_buf_init(tmp, (unsigned int)strlen(tmp));

    wr_req = (uv_write_t*) calloc(1, sizeof(*wr_req));
    wr_req->data = tmp;

    status = uv_write(wr_req, (uv_stream_t*)tcp, &buf, 1, web_uv_write_cb);
    if (status != 0) {
        web_req->status = status;
        web_request_shutdown(web_req);
    }
}

static void web_uv_write_cb(uv_write_t* req, int status) {
    char *tmp = (char*)req->data;
    uv_stream_t *tcp = (uv_stream_t *) req->handle;
    struct web_request_t *web_req = (struct web_request_t *) tcp->data;

    free(tmp);
    free(req);

    if (status == 0) {
        status = uv_read_start(tcp, web_uv_alloc_cb, web_uv_read_cb);
    }
    if (status != 0) {
        web_req->status = status;
        web_request_shutdown(web_req);
    }
}

static void web_uv_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
    *buf = uv_buf_init((char *)calloc(suggested_size, sizeof(char)), (unsigned int)suggested_size);
}

static void web_uv_read_cb(uv_stream_t *handle, ssize_t nread, const uv_buf_t *buf) {
    struct web_request_t *web_req = (struct web_request_t *) CONTAINER_OF(handle, struct web_request_t, socket);
    do {
        if (nread == 0) {
            break;
        }
        if (nread < 0) {
            uv_read_stop(handle);
            // http://docs.libuv.org/en/v1.x/stream.html
            if (nread != UV_EOF) {
                // log("receive data failed", c);
            }
            web_req->status = (nread == UV_EOF) ? 0 : (int)nread;
            web_request_shutdown(web_req);
            break;
        }

        if (web_req->recv_cb) {
            web_req->recv_cb((const uint8_t*)buf->base, (size_t)nread, web_req->recv_p);
        }
    } while (0);
    free(buf->base);
}

static void web_request_shutdown(struct web_request_t *req) {
    uv_close((uv_handle_t *)&req->socket, &web_uv_close_cb);
}

static void web_uv_close_cb(uv_handle_t* handle) {
    struct web_request_t *web_req = (struct web_request_t *) ((uv_tcp_t *)handle)->data;
    web_request_release(web_req);
}

static void web_request_release(struct web_request_t *req) {
    if (req) {
        if (req->compl_cb) {
            req->compl_cb(req->status, req->compl_p);
        }
        free(req->host);
        free(req->request_head);
        free(req);
    }
}
