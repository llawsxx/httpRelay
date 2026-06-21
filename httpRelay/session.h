#ifndef HTTPRELAY_SESSION_H
#define HTTPRELAY_SESSION_H

#include "send_window.h"

typedef struct sess_t {
    sock_t app_fd;            /* application side: A=client, B=target */
    sock_t peer_fd;           /* A<->B TCP, BADSOCK when down */
    mutex_t peer_lk;
    sw_t out;                 /* our -> peer send window */
    uint64_t recv_off;        /* offset of data we have contiguously received from peer */
    mutex_t recv_lk;
    volatile int closing;     /* session terminating */
    volatile int terminated;
    volatile int peer_close_requested; /* sender must flush DATA before MSG_CLOSE */
    volatile int peer_close_sent;      /* MSG_CLOSE sent; keep peer read side open for peer EOF */
    mutex_t term_lk;
    int64_t down_since;       /* time (ms) the peer link went down, 0 if up */
    int is_initiator;         /* 1 = A side */
    char ph[256], pp[32];     /* peer host/port (A side only) */
    uint64_t sid;
    char* open_pl;
    uint32_t open_len;        /* OPEN payload (A side only) */
    volatile int opened;

    mutex_t   send_lk;
    cond_t    send_cv;
    volatile int send_dirty;
    thread_t  send_thr;
    volatile int send_running;

    mutex_t   ref_lk;
    int       refcnt;

    mutex_t   hb_lk;
    int64_t   peer_last_rx;
    uint64_t  peer_gen;

    char my_host[256];
    char my_port[32];
    char target_host[256];
    char target_port[32];

    char* resp_header_buf;
    size_t resp_header_cap;
    size_t resp_header_len;
    volatile int resp_header_complete; /* 0=not complete, 1=complete, -1=no rewrite */

    mutex_t   act_lk;
    int64_t   last_activity;
    int       app_io_timeout;
} sess_t;

typedef struct {
    sess_t* s;
    uint64_t gen;
} heartbeat_arg_t;

#endif
