
#include <stdlib.h>
#include <uv.h>

#define HTTP_REQUEST_HEADER "GET / HTTP/1.0\r\nHost: %s\r\n\r\n"

typedef void (*recv_data_callback)(const uint8_t *data, size_t len, void *p);
typedef void (*request_completion_callback)(int status, void *p);

void launch_web_request(uv_loop_t *loop,
    const char *host, int port,
    const char *request_head,
    recv_data_callback recv_cb, void *recv_p,
    request_completion_callback compl_cb, void *compl_p);
