
#include <stdlib.h>
#include <uv.h>

typedef void (*FN_recv_data)(uint8_t *data, size_t len, void *p);

void launch_web_request(uv_loop_t *loop, const char *host, int port, const char *request_head, FN_recv_data cb, void *p);
