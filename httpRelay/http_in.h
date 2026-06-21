#ifndef HTTPRELAY_HTTP_IN_H
#define HTTPRELAY_HTTP_IN_H

#include "session.h"

typedef struct {
    sock_t fd;
    char* buf;
    size_t cap, len, off;
    sess_t* sess;       /* associated session for activity timeout, may be NULL */
    int64_t start_ms;   /* initial read timestamp when sess is NULL */
    int init_timeout;   /* first-request timeout in seconds when sess is NULL, 0=unlimited */
} httpin_t;

#endif
