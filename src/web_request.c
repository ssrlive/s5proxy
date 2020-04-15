#include <uv.h>
#include <stdlib.h>
#include <string.h>
#include "web_request.h"

struct web_request_t {
    uv_tcp_t socket;
    char *request_head;
    FN_recv_data cb;
    void *p;
};

static void web_uv_connect_cb(uv_connect_t *req, int status);
static void web_uv_close_cb(uv_handle_t* handle);
static void web_request_shutdown(struct web_request_t *req);
static void web_request_release(struct web_request_t *req);

void launch_web_request(uv_loop_t *loop, const char *host, int port, const char *request_head, FN_recv_data cb, void *p)
{
    struct web_request_t *req;
    uv_connect_t *connect;
    struct sockaddr_in dest;

    req = (struct web_request_t *)calloc(1, sizeof(struct web_request_t));
    uv_tcp_init(loop, &req->socket);
    req->request_head = request_head ? strdup(request_head) : NULL;
    req->cb = cb;
    req->p = p;
    req->socket.data = req;

    connect = (uv_connect_t *)calloc(1, sizeof(uv_connect_t));

    uv_ip4_addr(host, port, &dest);

    if (0 != uv_tcp_connect(connect, &req->socket, (const struct sockaddr *)&dest, web_uv_connect_cb)) {
        free(connect);
        web_request_release(req);
    }
}

static void web_uv_connect_cb(uv_connect_t *req, int status) {
    uv_tcp_t *tcp = (uv_tcp_t *) req->handle;
    struct web_request_t *web_req = (struct web_request_t *) tcp->data;

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
        free(req->request_head);
        free(req);
    }
}
