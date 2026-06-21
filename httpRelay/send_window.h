#ifndef HTTPRELAY_SEND_WINDOW_H
#define HTTPRELAY_SEND_WINDOW_H

#include "log.h"

typedef struct {
    mutex_t lk;
    cond_t cv;
    char* buf;
    size_t cap, len;
    uint64_t base;    /* buf[0] absolute offset */
    uint64_t high;    /* highest produced offset */
    uint64_t acked;   /* peer-confirmed offset */
    uint64_t sent;    /* sent offset on current peer connection */
} sw_t;

static void swi(sw_t* s) {
    mutex_init(&s->lk);
    cond_init(&s->cv);
    s->buf = NULL;
    s->cap = s->len = 0;
    s->base = s->high = s->acked = s->sent = 0;
}

static void swf(sw_t* s) {
    free(s->buf);
    cond_destroy(&s->cv);
    mutex_destroy(&s->lk);
}

static int sw_append(sw_t* s, const void* d, size_t n, size_t mx, uint64_t* off,
    volatile int* closing) {
    if (!d || n == 0) return 0;

    mutex_lock(&s->lk);

    while (s->len + n > mx && !*closing) {
        LOG("sw_append: buffer full (%zu + %zu > %zu), waiting for ACK...",
            s->len, n, mx);
        cond_wait_ms(&s->cv, &s->lk, 1000);
        if (*closing) {
            mutex_unlock(&s->lk);
            return -1;
        }
    }

    if (*closing) {
        mutex_unlock(&s->lk);
        return -1;
    }

    if (s->len + n > s->cap) {
        size_t c = s->cap ? s->cap : 65536;
        while (c < s->len + n) c *= 2;
        char* nb = (char*)realloc(s->buf, c);
        if (!nb) {
            mutex_unlock(&s->lk);
            return -1;
        }
        s->buf = nb;
        s->cap = c;
    }

    *off = s->high;
    memcpy(s->buf + s->len, d, n);
    s->len += n;
    s->high += n;

    mutex_unlock(&s->lk);
    return 0;
}

static void sw_drop_to(sw_t* s, uint64_t off) {
    mutex_lock(&s->lk);
    if (off > s->base && off <= s->high) {
        size_t d = (size_t)(off - s->base);
        if (d <= s->len) {
            memmove(s->buf, s->buf + d, s->len - d);
            s->len -= d;
        }
        else {
            s->len = 0;
        }
        s->base = off;
        if (off > s->acked) s->acked = off;
        cond_signal(&s->cv);
    }
    mutex_unlock(&s->lk);
}

#endif
