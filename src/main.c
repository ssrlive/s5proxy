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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dump_info.h"
#include "daemon_wrapper.h"

#if defined(_MSC_VER)
#ifndef _CRTDBG_MAP_ALLOC
#define _CRTDBG_MAP_ALLOC
#endif // _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#define MEM_CHECK_BEGIN() do { _CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF ); } while(0)
#define MEM_CHECK_DUMP_LEAKS() do { _CrtDumpMemoryLeaks(); } while(0)
#else
#define MEM_CHECK_BEGIN() do { ; } while(0)
#define MEM_CHECK_DUMP_LEAKS() do { ; } while(0)
#endif

int _onexit_func(void) {
    MEM_CHECK_DUMP_LEAKS();
    return 0;
}

#if HAVE_UNISTD_H
#include <unistd.h>  /* getopt */
#endif

#define DEFAULT_BIND_HOST     "0.0.0.0"
#define DEFAULT_BIND_PORT     1080

#if defined(NDEBUG)
#define DEFAULT_IDLE_TIMEOUT  (6 * 1000)
#define DEFAULT_IDLE_TIMEOUT_STR  "6"
#else
#define DEFAULT_IDLE_TIMEOUT  (60 * 1000)
#define DEFAULT_IDLE_TIMEOUT_STR  "60"
#endif

static void parse_opts(struct server_config *cf, int argc, char * const argv[]);
static void usage(void);

int main(int argc, char **argv) {
    struct server_config *config;
    int err;

#if defined(_MSC_VER)
    MEM_CHECK_BEGIN();
    onexit(_onexit_func);
#endif

    set_app_name(argv[0]);

    config = (struct server_config *) calloc(1, sizeof(*config));
    config->bind_host = strdup(DEFAULT_BIND_HOST);
    config->bind_port = DEFAULT_BIND_PORT;
    config->idle_timeout = DEFAULT_IDLE_TIMEOUT;
    parse_opts(config, argc, argv);
    if (config->fatal_error) {
        usage();
        free(config);
        return -1;
    }

    if (config->daemon_flag) {
        char param[257] = { 0 };
        sprintf(param, "-b \"%s\"  -p %d  -t %d", 
            config->bind_host, config->bind_port, config->idle_timeout/1000);
        daemon_wrapper(argv[0], param);
    }

    err = listener_run(config);
    if (err) {
        return (1);
    }

    return 0;
}

static void parse_opts(struct server_config *cf, int argc, char * const argv[]) {
    int opt;

    while (-1 != (opt = getopt(argc, argv, "b:p:t:duh"))) {
        switch (opt) {
        case 'b':
            if (cf->bind_host) {
                free(cf->bind_host);
            }
            cf->bind_host = strdup(optarg);
            break;
        case 'd':
            cf->daemon_flag = true;
            break;
        case 'u':
            cf->public_ip = true;
            break;
        case 'p':
            if (1 != sscanf(optarg, "%hu", &cf->bind_port)) {
                pr_err("bad port number: %s", optarg);
                cf->fatal_error = true;
                return;
            }
            break;
        case 't':
            if (1 != sscanf(optarg, "%ud", &cf->idle_timeout)) {
                pr_err("bad idle timeout: %s", optarg);
                cf->fatal_error = true;
                return;
            }
            cf->idle_timeout *= 1000;
            break;
        case 'h':
        default:
            cf->fatal_error = true;
            return;
        }
    }
}

static void usage(void) {
    printf("Usage:\n"
        "\n"
        "  %s [-b <address>] [-d] [-h] [-t <timeout>] [-p <port>] [-u]\n"
        "\n"
        "Options:\n"
        "\n"
        "  -b <hostname|address>  Bind to this address or hostname.  Default: \"" DEFAULT_BIND_HOST "\"\n"
        "  -h                     Show this help message.\n"
        "  -p <port>              Bind to this port number.  Default: 1080\n"
        "  -t <timeout>           Idle timeout.  Default: " DEFAULT_IDLE_TIMEOUT_STR " seconds\n"
        "  -d                     Run in background as a daemon.\n"
        "  -u                     This host has a public IP.\n"
        "",
        get_app_name());
}
