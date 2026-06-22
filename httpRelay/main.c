#define _CRT_SECURE_NO_WARNINGS
/*
 * httprelay.c -- Peer-to-peer HTTP relay with reconnect + in-memory resume buffering (cross-platform, IPv6).
 *
 * Build (Linux / gcc):
 *   gcc -O2 -o httprelay main.c -lssl -lcrypto -lpthread
 *
 * Build (Windows / MinGW-w64):
 *   gcc -O2 -o httprelay.exe main.c -lssl -lcrypto -lws2_32
 *
 * Build (Windows / MSVC):
 *   cl /O2 main.c /link libssl.lib libcrypto.lib ws2_32.lib
 *
 * Run:
 *   httprelay [-p port] [-b max_buffer_bytes] [-t reconnect_timeout_sec] [-i reconnect_ms]
 *
 * Both host A and host B run the SAME program, both listening on the same port (default 8080).
 *
 * A client connects to A using:
 *   http://A:8080/relay/<peerHost:peerPort>/<targetHost:targetPort>/original/path
 * e.g.
 *   http://127.0.0.1:8080/relay/188.241.219.163:8080/127.0.0.1:9090/download/wechat.exe
 *
 * Flow:
 *   client --HTTP--> A relay --[reliable session protocol over TCP, reconnectable]--> B relay --HTTP--> target
 *
 * IPv6 addresses in the URL must be bracketed:
 *   /relay/[2001:db8::1]:8080/[fe80::2]:9090/path
 *
 * Behaviour:
 *   - The A<->B TCP link may drop. As long as the client (A side) and the target (B side)
 *     connections stay alive, A keeps reconnecting and resumes the byte stream from where it
 *     left off (data is buffered in memory and re-sent based on byte offsets), so the transfer
 *     appears uninterrupted.
 *   - If the buffer exceeds the limit, or reconnection does not succeed within the timeout,
 *     both HTTP ends are torn down.
 *   - The A side parses each HTTP request (supports keep-alive request pipelining on one
 *     connection): every request's path and Host header are rewritten for the target.
 *   - Only the Host header is rewritten; all other headers are forwarded as-is.
 *
 * NOTE: This relay performs no authentication and acts as an open relay. Use only on trusted
 * networks or add your own allow-list / token check.
 */

#include "platform.h"
#include <limits.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include "log.h"

 /* ============================================================
  *  Configurable parameters
  * ============================================================ */
static int    g_port = 8080;
static size_t g_max_buffer = 64 * 1024 * 1024;  /* max in-flight buffer per direction */
static int    g_reconnect_timeout = 60;            /* seconds before giving up reconnection */
static int    g_reconnect_ms = 500;           /* delay between reconnect attempts */
static int    g_client_connect_timeout = 10;    /* 客户端连接目标超时 (秒) */
static int    g_client_io_timeout = 120;         /* 客户端 I/O 超时 (秒) */
static int    g_peer_connect_timeout = 10;      /* Peer 间连接超时 (秒) */
static int    g_peer_io_timeout = 20;           /* Peer 间 I/O 超时 (秒) */
static int    g_heartbeat_interval = 5;         /* Peer 心跳发送间隔 (秒) */
static int    g_crypto_enabled = 0;             /* A<->B payload AES-CTR encryption */
static int    g_insecure_upstream_tls = 0;      /* skip B-side HTTPS target certificate verification */
static uint8_t g_crypto_key[16];
static char   g_cacert_path[1024] = "cacert.pem";
#define IO_CHUNK 32768
#define APP_POLL_INTERVAL_SEC 2
#define CRYPTO_BLOCK_SIZE 16

#include "protocol.h"
#include "session.h"
#include "http_in.h"

static uint64_t splitmix64_next(uint64_t* state);

static void init_cacert_path(const char* argv0) {
    char exe[1024];
    exe[0] = 0;

#ifdef _WIN32
    DWORD n = GetModuleFileNameA(NULL, exe, (DWORD)sizeof exe);
    if (n == 0 || n >= sizeof exe) exe[0] = 0;
#else
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n > 0) exe[n] = 0;
    else exe[0] = 0;
#endif

    if (!exe[0] && argv0 && *argv0) {
        snprintf(exe, sizeof exe, "%s", argv0);
    }

    char* slash = strrchr(exe, '/');
#ifdef _WIN32
    char* backslash = strrchr(exe, '\\');
    if (!slash || (backslash && backslash > slash)) slash = backslash;
#endif

    if (slash) {
        size_t dir_len = (size_t)(slash - exe + 1);
        if (dir_len + strlen("cacert.pem") < sizeof g_cacert_path) {
            memcpy(g_cacert_path, exe, dir_len);
            strcpy(g_cacert_path + dir_len, "cacert.pem");
            return;
        }
    }

    strcpy(g_cacert_path, "cacert.pem");
}

static void put64be(uint8_t* p, uint64_t v) {
    for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)v; v >>= 8; }
}

static uint64_t get64be(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static uint64_t g_crypto_nonce_state = 0;

static uint64_t crypto_next_nonce(void) {
    if (g_crypto_nonce_state == 0) {
        uint64_t seed = (uint64_t)now_ms() ^ ((uint64_t)time(NULL) << 32) ^ (uint64_t)(uintptr_t)&g_crypto_nonce_state;
#ifdef _WIN32
        seed ^= ((uint64_t)GetCurrentProcessId()) << 24;
#else
        seed ^= ((uint64_t)getpid()) << 24;
#endif
        g_crypto_nonce_state = seed ? seed : 0x63727970746f6e63ULL;
    }
    return splitmix64_next(&g_crypto_nonce_state);
}

static void crypto_make_iv(uint64_t nonce, uint8_t iv[CRYPTO_BLOCK_SIZE]) {
    memset(iv, 0, CRYPTO_BLOCK_SIZE);
    put64be(iv, nonce);
}

static int crypto_aes128_ctr(const uint8_t* in, size_t in_len, uint8_t* out, const uint8_t iv[CRYPTO_BLOCK_SIZE]) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, g_crypto_key, iv);
    int out_len = 0;
    int total = 0;
    if (ok == 1 && in_len > 0) {
        if (in_len > (size_t)INT_MAX) ok = 0;
        else if (EVP_EncryptUpdate(ctx, out, &out_len, in, (int)in_len) != 1) ok = 0;
        else total = out_len;
    }
    if (ok == 1) {
        if (EVP_EncryptFinal_ex(ctx, out + total, &out_len) != 1) ok = 0;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok == 1 ? 0 : -1;
}

static void crypto_set_password(const char* password) {
    uint64_t st = 0x6a09e667f3bcc909ULL;
    const unsigned char* p = (const unsigned char*)password;
    while (*p) {
        st ^= (uint64_t)(*p++);
        st = splitmix64_next(&st);
    }
    put64be(g_crypto_key, splitmix64_next(&st));
    put64be(g_crypto_key + 8, splitmix64_next(&st));
    g_crypto_enabled = 1;
}

static const uint64_t CRYPTO_MAGIC = 0x4854524c41594531ULL; /* HTRLAYE1 */

static void crypto_auth_response(uint64_t challenge, uint8_t out[16]) {
    uint8_t plain[16], iv[CRYPTO_BLOCK_SIZE];
    put64be(plain, 0x4854524c41555448ULL); /* HTRLAUTH */
    put64be(plain + 8, challenge);
    memset(iv, 0, sizeof iv);
    if (crypto_aes128_ctr(plain, sizeof plain, out, iv) < 0) memset(out, 0, 16);
}

/* 判断当前 sockerrno 是否为 "超时/可重试" (用于 SO_RCVTIMEO/SO_SNDTIMEO) */
static int sock_is_timeout(void) {
#ifdef _WIN32
    int e = WSAGetLastError();
    return e == WSAETIMEDOUT || e == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == ETIMEDOUT;
#endif
}
static int sock_is_eintr(void) {
#ifdef _WIN32
    return WSAGetLastError() == WSAEINTR;
#else
    return errno == EINTR;
#endif
}


static int wfull(sock_t fd, const void* b, size_t n) {
    const char* p = (const char*)b;
    size_t s = 0;
    while (s < n) {
        int w = send(fd, p + s, (int)(n - s), MSG_NOSIGNAL);
        if (w < 0) {
            if (sock_is_eintr()) continue;   /* 仅 EINTR 重试 */
            return -1;                        /* 超时/真错误都算失败, 触发重连 */
        }
        s += (size_t)w;
    }
    return 0;
}

static int rfull(sock_t fd, void* b, size_t n) {
    char* p = (char*)b;
    size_t g = 0;
    while (g < n) {
        int r = recv(fd, p + g, (int)(n - g), 0);
        if (r == 0) return 0;
        if (r < 0) {
            if (sock_is_eintr()) continue;
            return -1;
        }
        g += (size_t)r;
    }
    return 1;
}



static void nodelay_on(sock_t fd) { int o = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&o, sizeof o); }

static int is_peer_msg_type(uint8_t t) {
    return (t >= MSG_OPEN && t <= MSG_PONG) ||
        t == MSG_AUTH_REQ || t == MSG_AUTH_OK || t == MSG_AUTH_FAIL;
}

static int send_frame_raw(sock_t fd, uint8_t t, uint64_t v, const void* pl, uint32_t pn) {
    struct fhdr h; h.type = t; h.r1 = 0; h.r2 = 0; h.value = sw64(v); h.plen = sw32(pn);
    if (wfull(fd, &h, sizeof h) < 0) return -1;
    if (pn && pl) return wfull(fd, pl, pn);
    return 0;
}

static int recv_frame_raw(sock_t fd, struct fhdr* h, char** pl) {
    int r = rfull(fd, h, sizeof * h); if (r <= 0) return r;
    h->value = sw64(h->value); h->plen = sw32(h->plen); *pl = NULL;
    if (h->plen) {
        if (h->plen > 64u * 1024 * 1024) return -1;
        *pl = (char*)malloc(h->plen); if (!*pl) return -1;
        r = rfull(fd, *pl, h->plen); if (r <= 0) { free(*pl); *pl = NULL; return r ? r : -1; }
    }
    return 1;
}

static int send_frame(sock_t fd, uint8_t t, uint64_t v, const void* pl, uint32_t pn) {
    char* enc = NULL;
    uint32_t wire_pn = pn;
    const void* wire_pl = pl;

    if (g_crypto_enabled) {
        if (pn > 64u * 1024 * 1024 - 16u) return -1;
        wire_pn = pn + 16;
        enc = (char*)malloc(wire_pn);
        if (!enc) return -1;
        uint64_t nonce = crypto_next_nonce();
        put64be((uint8_t*)enc, nonce);
        put64be((uint8_t*)enc + 8, CRYPTO_MAGIC);
        if (pn && pl) memcpy(enc + 16, pl, pn);
        uint8_t iv[CRYPTO_BLOCK_SIZE];
        crypto_make_iv(nonce, iv);
        if (crypto_aes128_ctr((const uint8_t*)enc + 8, pn + 8, (uint8_t*)enc + 8, iv) < 0) {
            free(enc);
            return -1;
        }
        wire_pl = enc;
    }

    int rc = send_frame_raw(fd, t, v, wire_pl, wire_pn);
    free(enc);
    return rc;
}

static int wait_peer_close(sock_t fd) {
    char buf[512];
    for (;;) {
        int r = recv(fd, buf, sizeof buf, 0);
        if (r == 0) return 0;
        if (r > 0) continue;
        if (sock_is_eintr()) continue;
        if (sock_is_timeout()) return 0;
        return -1;
    }
}

static int send_close_and_wait_peer(sock_t fd, uint64_t sid) {
    int rc = send_frame(fd, MSG_CLOSE, sid, 0, 0);
    if (rc == 0) {
        shutdown(fd, SHUT_WR);
        wait_peer_close(fd);
    }
    return rc;
}

static int recv_frame(sock_t fd, struct fhdr* h, char** pl) {
    int r = recv_frame_raw(fd, h, pl); if (r <= 0) return r;
    if (g_crypto_enabled) {
        if (h->plen < 16 || !*pl) { free(*pl); *pl = NULL; return -1; }
        uint64_t nonce = get64be((const uint8_t*)*pl);
        uint32_t plain_len = h->plen - 16;
        uint8_t iv[CRYPTO_BLOCK_SIZE];
        crypto_make_iv(nonce, iv);
        if (crypto_aes128_ctr((const uint8_t*)*pl + 8, plain_len + 8, (uint8_t*)*pl + 8, iv) < 0) {
            free(*pl); *pl = NULL; return -1;
        }
        if (get64be((const uint8_t*)*pl + 8) != CRYPTO_MAGIC) {
            LOG("encrypted peer frame authentication failed");
            free(*pl); *pl = NULL; return -1;
        }
        if (plain_len > 0) memmove(*pl, *pl + 16, plain_len);
        h->plen = plain_len;
    }
    return 1;
}

static int peer_auth_client(sock_t fd) {
    if (!g_crypto_enabled) return 0;
    uint64_t challenge = crypto_next_nonce();
    if (send_frame_raw(fd, MSG_AUTH_REQ, challenge, 0, 0) < 0) return -1;

    struct fhdr h; char* pl = NULL;
    int r = recv_frame_raw(fd, &h, &pl);
    if (r <= 0) { free(pl); return -1; }
    if (h.type != MSG_AUTH_OK || h.value != challenge || h.plen != 16 || !pl) {
        free(pl); return -1;
    }
    uint8_t expected[16];
    crypto_auth_response(challenge, expected);
    int ok = memcmp(pl, expected, sizeof expected) == 0;
    free(pl);
    return ok ? 0 : -1;
}

static int peer_auth_server(sock_t fd, struct fhdr* first, char** first_pl) {
    int r = recv_frame_raw(fd, first, first_pl);
    if (r <= 0) {
        LOG("peer auth/server: failed to read first frame");
        return r;
    }

    if (first->type == MSG_AUTH_REQ) {
        free(*first_pl); *first_pl = NULL;
        if (!g_crypto_enabled) {
            LOG("peer auth/server: client requires password but server has no -k configured");
            send_frame_raw(fd, MSG_AUTH_FAIL, first->value, 0, 0);
            return -2;
        }
        uint8_t resp[16];
        crypto_auth_response(first->value, resp);
        if (send_frame_raw(fd, MSG_AUTH_OK, first->value, resp, sizeof resp) < 0) {
            LOG("peer auth/server: failed to send auth response");
            return -1;
        }
        r = recv_frame(fd, first, first_pl);
        if (r <= 0) LOG("peer auth/server: authenticated but failed to read encrypted first frame");
        return r;
    }

    if (g_crypto_enabled) {
        send_frame_raw(fd, MSG_AUTH_FAIL, 0, 0, 0);
        free(*first_pl); *first_pl = NULL;
        LOG("peer auth/server: encrypted server requires MSG_AUTH_REQ before type=%u", (unsigned)first->type);
        return -2;
    }
    return 1;
}

static void wait_peer_close_after_auth_fail(sock_t fd) {
    char c;
    int64_t end = now_ms() + 2000;
    while (now_ms() < end) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        int remain = (int)(end - now_ms());
        if (remain <= 0) break;
        struct timeval tv;
        tv.tv_sec = remain / 1000;
        tv.tv_usec = (remain % 1000) * 1000;
        int sr = select((int)fd + 1, &rfds, NULL, NULL, &tv);
        if (sr <= 0) return;
        int r = recv(fd, &c, 1, 0);
        if (r == 0) return;
        if (r < 0) {
            if (sock_is_eintr()) continue;
            return;
        }
    }
}

static void* sender_thread(void* arg);
static void session_addref(sess_t* s);
static void session_release(sess_t* s);

static void session_request_peer_close(sess_t* s) {
    mutex_lock(&s->send_lk);
    s->peer_close_requested = 1;
    s->send_dirty = 1;
    cond_signal(&s->send_cv);
    mutex_unlock(&s->send_lk);
}

static void peer_touch_rx(sess_t* s) {
    mutex_lock(&s->hb_lk);
    s->peer_last_rx = now_ms();
    mutex_unlock(&s->hb_lk);
}

static int peer_gen_matches(sess_t* s, uint64_t gen) {
    mutex_lock(&s->hb_lk);
    int ok = (s->peer_gen == gen);
    mutex_unlock(&s->hb_lk);
    return ok;
}

static uint64_t peer_next_gen(sess_t* s) {
    mutex_lock(&s->hb_lk);
    s->peer_gen++;
    s->peer_last_rx = now_ms();
    uint64_t gen = s->peer_gen;
    mutex_unlock(&s->hb_lk);
    return gen;
}

static void* heartbeat_thread(void* arg) {
    heartbeat_arg_t* ha = (heartbeat_arg_t*)arg;
    sess_t* s = ha->s;
    uint64_t gen = ha->gen;
    free(ha);

    for (;;) {
        if (s->closing || g_heartbeat_interval <= 0 || g_peer_io_timeout <= 0) break;
        sleep_ms(g_heartbeat_interval * 1000);
        if (s->closing || !peer_gen_matches(s, gen)) break;

        int64_t last_rx;
        mutex_lock(&s->hb_lk);
        last_rx = s->peer_last_rx;
        mutex_unlock(&s->hb_lk);

        int64_t idle_ms = now_ms() - last_rx;
        if (idle_ms >= (int64_t)g_peer_io_timeout * 1000) {
            mutex_lock(&s->peer_lk);
            if (!s->closing && s->peer_fd != BADSOCK && peer_gen_matches(s, gen)) {
                LOG("peer heartbeat timeout sid=%llu", (unsigned long long)s->sid);
                closesock(s->peer_fd);
                s->peer_fd = BADSOCK;
                peer_next_gen(s);
                if (!s->down_since) s->down_since = now_ms();
            }
            mutex_unlock(&s->peer_lk);
            break;
        }

        if (idle_ms < (int64_t)g_heartbeat_interval * 1000) {
            continue;
        }

        mutex_lock(&s->peer_lk);
        if (s->closing || s->peer_fd == BADSOCK || !peer_gen_matches(s, gen)) {
            mutex_unlock(&s->peer_lk);
            break;
        }
        LOG("peer send heartbeat sid=%llu", (unsigned long long)s->sid);
        if (send_frame(s->peer_fd, MSG_PING, (uint64_t)now_ms(), 0, 0) < 0) {
            if (s->peer_fd != BADSOCK && peer_gen_matches(s, gen)) {
                LOG("peer heartbeat send failed sid=%llu", (unsigned long long)s->sid);
                closesock(s->peer_fd);
                s->peer_fd = BADSOCK;
                peer_next_gen(s);
                if (!s->down_since) s->down_since = now_ms();
            }
            mutex_unlock(&s->peer_lk);
            break;
        }
        mutex_unlock(&s->peer_lk);
    }

    session_release(s);
    return NULL;
}

static void start_heartbeat_for_gen(sess_t* s, uint64_t gen) {
    if (!s->is_initiator) return;
    if (g_heartbeat_interval <= 0 || g_peer_io_timeout <= 0) return;
    heartbeat_arg_t* ha = (heartbeat_arg_t*)malloc(sizeof(*ha));
    if (!ha) return;
    ha->s = s;
    ha->gen = gen;
    session_addref(s);
    thread_t t;
    if (thread_create(&t, heartbeat_thread, ha) == 0) {
        thread_detach(t);
    }
    else {
        session_release(s);
        free(ha);
    }
}

static void peer_install_locked(sess_t* s, sock_t fd) {
    s->peer_fd = fd;
    uint64_t gen = peer_next_gen(s);
    start_heartbeat_for_gen(s, gen);
}

static void peer_close_locked(sess_t* s) {
    if (s->peer_fd != BADSOCK) {
        closesock(s->peer_fd);
        s->peer_fd = BADSOCK;
        peer_next_gen(s);
    }
    if (!s->down_since) s->down_since = now_ms();
}

static void session_init(sess_t* s) {
    swi(&s->out);
    mutex_init(&s->peer_lk);
    mutex_init(&s->recv_lk);
    mutex_init(&s->send_lk);
    mutex_init(&s->term_lk);
    mutex_init(&s->act_lk); 
    mutex_init(&s->hb_lk);
    cond_init(&s->send_cv);
    s->send_dirty = 0;
    s->refcnt = 1;                 /* owner持有的引用 */
    mutex_init(&s->ref_lk);
    s->target_host[0] = 0; 
    s->target_port[0] = 0;
    s->target_tls = 0;
    s->app_tls = 0;
    s->app_ssl = NULL;
    s->app_ssl_ctx = NULL;
    s->my_host[0] = 0;
    s->my_port[0] = 0;
    s->resp_header_buf = NULL;
    s->resp_header_cap = 0;
    s->resp_header_len = 0;
    s->resp_header_complete = 0;
    s->last_activity = now_ms();
    s->app_io_timeout = 0;
    s->peer_last_rx = now_ms();
    s->peer_gen = 0;
}




static void session_start_sender(sess_t* s) {
    s->send_running = 1;
    thread_create(&s->send_thr, sender_thread, s);
}
static void session_stop_sender(sess_t* s) {
    /* 确保发送线程能醒来退出 */
    mutex_lock(&s->send_lk);
    cond_signal(&s->send_cv);
    mutex_unlock(&s->send_lk);
    if (s->send_running) { thread_join(s->send_thr); s->send_running = 0; }
}
static void session_uninit(sess_t* s) {
    swf(&s->out);
    mutex_destroy(&s->peer_lk);
    mutex_destroy(&s->recv_lk);
    mutex_destroy(&s->send_lk);
    mutex_destroy(&s->term_lk);
    mutex_destroy(&s->act_lk);
    mutex_destroy(&s->hb_lk);
    cond_destroy(&s->send_cv);
    if (s->open_pl) {
        free(s->open_pl);
        s->open_pl = NULL;
        s->open_len = 0;
    }
    if (s->resp_header_buf) {
        free(s->resp_header_buf);
        s->resp_header_buf = NULL;
    }
}

/* 更新 app 侧最后活动时间 (recv/send 成功时调用) */
static void sess_touch_activity(sess_t* s) {
    if (!s) return;
    mutex_lock(&s->act_lk);
    s->last_activity = now_ms();
    mutex_unlock(&s->act_lk);
}

/* 检查 app 侧是否已超时。返回 1=超时, 0=未超时。
 * app_io_timeout<=0 时永不超时(返回0)。 */
static int sess_app_timed_out(sess_t* s) {
    if (!s || s->app_io_timeout <= 0) return 0;
    mutex_lock(&s->act_lk);
    int64_t la = s->last_activity;
    mutex_unlock(&s->act_lk);
    return (now_ms() - la) >= (int64_t)s->app_io_timeout * 1000;
}

static int app_recv(sess_t* s, void* buf, size_t len) {
    if (s->app_tls && s->app_ssl) return SSL_read((SSL*)s->app_ssl, buf, (int)len);
    return recv(s->app_fd, buf, (int)len, 0);
}

static int app_send(sess_t* s, const void* buf, size_t len) {
    if (s->app_tls && s->app_ssl) return SSL_write((SSL*)s->app_ssl, buf, (int)len);
    return send(s->app_fd, buf, (int)len, MSG_NOSIGNAL);
}

static int app_io_should_retry(sess_t* s, int rc) {
    if (s->app_tls && s->app_ssl) {
        int err = SSL_get_error((SSL*)s->app_ssl, rc);
        return err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE;
    }
    return sock_is_timeout();
}

static void app_shutdown(sess_t* s) {
    if (s->app_tls && s->app_ssl) SSL_shutdown((SSL*)s->app_ssl);
    if (s->app_fd != BADSOCK) shutdown(s->app_fd, SHUT_RDWR);
}

static void app_close(sess_t* s) {
    if (s->app_ssl) {
        SSL_free((SSL*)s->app_ssl);
        s->app_ssl = NULL;
    }
    if (s->app_ssl_ctx) {
        SSL_CTX_free((SSL_CTX*)s->app_ssl_ctx);
        s->app_ssl_ctx = NULL;
    }
    if (s->app_fd != BADSOCK) closesock(s->app_fd);
    s->app_fd = BADSOCK;
}

static int app_start_tls(sess_t* s, const char* server_name) {
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        LOG("upstream TLS: SSL_CTX_new failed");
        return -1;
    }

    if (g_insecure_upstream_tls) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }
    else {
        if (SSL_CTX_load_verify_locations(ctx, g_cacert_path, NULL) != 1) {
            LOG("upstream TLS: failed to load CA bundle %s; trying OpenSSL default paths", g_cacert_path);
            if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
                LOG("upstream TLS: default CA paths also failed; put cacert.pem next to the program or use --insecure-upstream-tls");
                SSL_CTX_free(ctx);
                return -1;
            }
        }
        else {
            LOG("upstream TLS: loaded CA bundle %s", g_cacert_path);
        }
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    }

    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        LOG("upstream TLS: SSL_new failed");
        return -1;
    }

    SSL_set_fd(ssl, (int)s->app_fd);
    if (server_name && *server_name) SSL_set_tlsext_host_name(ssl, server_name);

    int rc = SSL_connect(ssl);
    if (rc != 1) {
        unsigned long err = ERR_get_error();
        LOG("upstream TLS handshake failed host=%s err=%lu", server_name ? server_name : "", err);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return -1;
    }

    if (!g_insecure_upstream_tls) {
        long verify = SSL_get_verify_result(ssl);
        if (verify != X509_V_OK) {
            LOG("upstream TLS verify failed host=%s verify=%ld", server_name ? server_name : "", verify);
            SSL_free(ssl);
            SSL_CTX_free(ctx);
            return -1;
        }
    }

    s->app_tls = 1;
    s->app_ssl = ssl;
    s->app_ssl_ctx = ctx;
    return 0;
}

/* Terminate a session: set closing and unblock threads that may be blocked in recv(). */
/* 终止会话: 置 closing, shutdown 以唤醒阻塞在 recv/send 的线程。
 * 幂等。绝不 closesock —— fd 的关闭留到所有线程 join 之后由收尾代码统一做。
 * 不清空 s->app_fd / s->peer_fd —— 收尾代码还要用它们来 close。 */
static void session_terminate(sess_t* s) {
    mutex_lock(&s->term_lk);
    if (s->terminated) { mutex_unlock(&s->term_lk); return; }
    s->terminated = 1;
    s->closing = 1;
    mutex_unlock(&s->term_lk);

    LOG("%c session terminate sid=%llu", s->is_initiator ? 'A': 'B', (unsigned long long)s->sid);

    /* app 侧: 双向关闭唤醒 t_app2peer 的 recv 和 handle_frame 的 wfull */
    app_shutdown(s);

    /* peer 侧: 唤醒 peer_recv_loop 的 recv */
    mutex_lock(&s->peer_lk);
    if (s->peer_fd != BADSOCK && !s->peer_close_requested && !s->peer_close_sent) shutdown(s->peer_fd, SHUT_RDWR);
    mutex_unlock(&s->peer_lk);

    /* 唤醒发送线程 */
    mutex_lock(&s->send_lk);
    cond_signal(&s->send_cv);
    mutex_unlock(&s->send_lk);
}

/* 增加引用（调用者已确保 s 当前有效，通常在表锁内调用）*/
static void session_addref(sess_t* s) {
    mutex_lock(&s->ref_lk);
    s->refcnt++;
    mutex_unlock(&s->ref_lk);
}

/* 释放引用，降到 0 时真正销毁 */
static void session_release(sess_t* s) {
    mutex_lock(&s->ref_lk);
    int n = --s->refcnt;
    mutex_unlock(&s->ref_lk);
    if (n == 0) {
        /* 此刻没有任何人持有 s，安全销毁 */
        app_close(s);
        if (s->peer_fd != BADSOCK) closesock(s->peer_fd);
        session_uninit(s);          /* 销毁 recv_lk/peer_lk/send_lk/send_cv/out 等 */
        mutex_destroy(&s->ref_lk);
        LOG("%c session_release ok sid=%llu",s->is_initiator ? 'A' : 'B', s->sid);
        free(s);
    }
}


/* 向 app_fd 写满 n 字节，带 "活动超时" 语义。
 * 成功(0): 任何成功的 send 都会刷新活动时间。
 * 超时返回 send 阻塞但 last_activity(可能被对向 recv 刷新)未到总超时, 则继续。
 * 返回 0 成功, -1 失败/真超时/会话关闭。 */
static int wfull_app(sess_t* s, const void* b, size_t n) {
    const char* p = (const char*)b;
    size_t snt = 0;
    while (snt < n) {
        if (s->closing) return -1;
        int w = app_send(s, p + snt, n - snt);
        if (w > 0) {
            snt += (size_t)w;
            sess_touch_activity(s);   /* send 成功 -> 刷新活动 */
            continue;
        }
        if (w == 0) return -1;
        if (sock_is_eintr()) continue;
        if (app_io_should_retry(s, w)) {
            /* 本次 send 超时窗口内没成功; 但只要整体活动未超时就继续 */
            if (sess_app_timed_out(s)) {
                LOG("app send activity timeout sid=%llu", (unsigned long long)s->sid);
                return -1;
            }
            continue;   /* 续命, 重试 */
        }
        return -1;      /* 真错误 */
    }
    return 0;
}

/* 生产者调用：标记有新数据并唤醒发送线程 (不阻塞) */
static void notify_send(sess_t* s) {
    mutex_lock(&s->send_lk);
    s->send_dirty = 1;
    cond_signal(&s->send_cv);
    mutex_unlock(&s->send_lk);
}

/* 真正执行一次 flush: 把 out 缓冲里 [sent, high) 尚未发送的数据发出去。
 * 成功返回 0；peer 写失败返回 -1 (调用方负责处理 peer 断开)。 */
static int sw_flush_locked_peer(sess_t* s) {
    /* 调用前必须已持有 peer_lk */
    for (;;) {
        mutex_lock(&s->out.lk);
        if (s->out.sent < s->out.base) s->out.sent = s->out.base;
        uint64_t from = s->out.sent, high = s->out.high;
        if (high <= from) { mutex_unlock(&s->out.lk); return 0; }   /* 没有待发数据 */
        size_t tl = (size_t)(high - from);
        /* 单帧别发太大，分块发，避免一次 malloc 巨大缓冲 */
        if (tl > IO_CHUNK) tl = IO_CHUNK;
        size_t boff = (size_t)(from - s->out.base);
        char* tmp = (char*)malloc(tl);
        if (!tmp) { mutex_unlock(&s->out.lk); return -1; }
        memcpy(tmp, s->out.buf + boff, tl);
        uint64_t send_off = from;
        mutex_unlock(&s->out.lk);

        int rc = (s->peer_fd != BADSOCK) ? send_frame(s->peer_fd, MSG_DATA, send_off, tmp, (uint32_t)tl) : -1;
        free(tmp);
        if (rc < 0) return -1;

        mutex_lock(&s->out.lk);
        if (send_off + tl > s->out.sent) s->out.sent = send_off + tl;
        mutex_unlock(&s->out.lk);
        /* 循环继续，直到 sent 追上 high */
    }
}

/* 专用发送线程：等待信号 -> flush。每个会话一个。 */
static void* sender_thread(void* arg) {
    sess_t* s = (sess_t*)arg;
    for (;;) {
        /* 等待有数据或被唤醒 */
        mutex_lock(&s->send_lk);
        while (!s->send_dirty && !s->closing && !s->peer_close_requested) {
            cond_wait_ms(&s->send_cv, &s->send_lk, 1000);   /* 1s 超时以便周期性检查 closing */
        }
        int closing = s->closing;
        int close_requested = s->peer_close_requested;
        s->send_dirty = 0;          /* 清标记 (在锁内清, 避免丢唤醒) */
        mutex_unlock(&s->send_lk);

        if (closing && !close_requested) break;

        /* 执行 flush。peer_fd 可能为 BADSOCK(断开中)，那就什么都不发，
           等重连后 a_peer_thread/resume 会重置 sent 并 notify。 */
        mutex_lock(&s->peer_lk);
        if (s->peer_fd != BADSOCK) {
            if (sw_flush_locked_peer(s) < 0) {
                peer_close_locked(s);
            }
            else if (close_requested && !s->peer_close_sent) {
                if (send_frame(s->peer_fd, MSG_CLOSE, s->sid, 0, 0) == 0) {
                    s->peer_close_sent = 1;
                    shutdown(s->peer_fd, SHUT_WR);
                }
                else {
                    peer_close_locked(s);
                }
            }
        }
        mutex_unlock(&s->peer_lk);

        if (close_requested) break;
    }
    return NULL;
}

/* ============================================================
 *  Socket timeout helpers
 * ============================================================ */

 /* 设置 socket 接收超时 */
static void set_recv_timeout(sock_t fd, int seconds) {
    if (fd == BADSOCK) return;
#ifdef _WIN32
    DWORD timeout = (DWORD)(seconds * 1000);
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv));
#endif
}

/* 设置 socket 发送超时 */
static void set_send_timeout(sock_t fd, int seconds) {
    if (fd == BADSOCK) return;
#ifdef _WIN32
    DWORD timeout = (DWORD)(seconds * 1000);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const void*)&tv, sizeof(tv));
#endif
}

/* 设置连接超时（非阻塞 connect + select） */
static sock_t connect_with_timeout(const char* h, const char* p, int timeout_sec) {
    if (timeout_sec <= 0) timeout_sec = 30;  /* 默认 30 秒 */

    struct addrinfo hi, * r = NULL, * rp;
    memset(&hi, 0, sizeof hi);
    hi.ai_family = AF_UNSPEC;
    hi.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(h, p, &hi, &r) != 0) return BADSOCK;

    sock_t fd = BADSOCK;
    for (rp = r; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == BADSOCK) continue;

#ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(fd, FIONBIO, &mode);
#else
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif

        int rc = connect(fd, rp->ai_addr, (int)rp->ai_addrlen);
        if (rc == 0) {
#ifdef _WIN32
            mode = 0;
            ioctlsocket(fd, FIONBIO, &mode);
#else
            fcntl(fd, F_SETFL, flags);
#endif
            break;
        }

#ifdef _WIN32
        if (WSAGetLastError() == WSAEWOULDBLOCK) {
#else
        if (errno == EINPROGRESS) {
#endif
            fd_set writefds, exceptfds;
            struct timeval tv;
            tv.tv_sec = timeout_sec;
            tv.tv_usec = 0;

            FD_ZERO(&writefds);
            FD_ZERO(&exceptfds);
            FD_SET(fd, &writefds);
            FD_SET(fd, &exceptfds);
            /*
             * Windows: select() 的第一个参数在 Windows 上被忽略，
             * 但为了代码兼容性，传递 (int)fd + 1
             */
            rc = select((int)fd + 1, NULL, &writefds, &exceptfds, &tv);
            if (rc > 0 && FD_ISSET(fd, &writefds)) {
                int error = 0;
                socklen_t len = sizeof(error);
#ifdef _WIN32
                getsockopt(fd, SOL_SOCKET, SO_ERROR, (char*)&error, &len);
#else
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len);
#endif
                if (error == 0) {
#ifdef _WIN32
                    mode = 0;
                    ioctlsocket(fd, FIONBIO, &mode);
#else
                    fcntl(fd, F_SETFL, flags);
#endif
                    break;
                }
            }
        }

        closesock(fd);
        fd = BADSOCK;
    }

    freeaddrinfo(r);
    return fd;
}

/* ============================================================
 *  Address resolution / connect / listen
 * ============================================================ */
 /* Client 端连接目标服务器 (B 侧连接最终目标) */

/* Peer 间连接 (A 连接 B) */
static sock_t connect_peer(const char* h, const char* p) {
    sock_t fd = connect_with_timeout(h, p, g_peer_connect_timeout);
    if (fd != BADSOCK) {
        nodelay_on(fd);
        set_recv_timeout(fd, g_peer_io_timeout);
        set_send_timeout(fd, g_peer_io_timeout);
    }
    return fd;
}


/* 为客户端 socket 设置超时 (A 侧接收客户端连接) */
static void setup_client_socket(sock_t fd) {
    if (fd == BADSOCK) return;
    nodelay_on(fd);
    /* 用短轮询间隔, 真正的超时判断交给 last_activity 逻辑 */
    set_recv_timeout(fd, APP_POLL_INTERVAL_SEC);
    set_send_timeout(fd, APP_POLL_INTERVAL_SEC);
}

/* 为 peer socket 设置超时 (B 侧接收 peer 连接) */
static void setup_peer_socket(sock_t fd) {
    if (fd == BADSOCK) return;
    nodelay_on(fd);
    set_recv_timeout(fd, g_peer_io_timeout);
    set_send_timeout(fd, g_peer_io_timeout);
}

static sock_t listen_on(int port) {
    char portstr[16]; snprintf(portstr, sizeof portstr, "%d", port);
    sock_t fd = socket(AF_INET6, SOCK_STREAM, 0);
    int o = 1;
    if (fd != BADSOCK) {
        int v6 = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&v6, sizeof v6);
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&o, sizeof o);

        struct sockaddr_in6 a; memset(&a, 0, sizeof a);
        a.sin6_family = AF_INET6; a.sin6_addr = in6addr_any; a.sin6_port = htons((unsigned short)port);
        if (bind(fd, (struct sockaddr*)&a, sizeof a) == 0 && listen(fd, 128) == 0) return fd;
        closesock(fd);
    }
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == BADSOCK)return BADSOCK;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&o, sizeof o);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = INADDR_ANY; a.sin_port = htons((unsigned short)port);
    if (bind(fd, (struct sockaddr*)&a, sizeof a) < 0 || listen(fd, 128) < 0) {
        closesock(fd);
        return BADSOCK;
    }
    return fd;
}

/* ============================================================
 *  Small string helpers
 * ============================================================ */
static int istart(const char* l, const char* k) { return strncasecmp(l, k, strlen(k)) == 0; }

static const char* strcasestr_compat(const char* hay, const char* needle) {
    size_t nl = strlen(needle); if (!nl)return hay;
    for (; *hay; hay++) if (strncasecmp(hay, needle, nl) == 0) return hay;
    return NULL;
}

/* parse "host:port", "[v6]:port", or bare "v6". returns 1 if port is explicit. */
static int parse_hp_ex(const char* s, char* host, char* port) {
    if (*s == '[') {
        const char* e = strchr(s, ']');
        if (e) {
            size_t l = (size_t)(e - s - 1); memcpy(host, s + 1, l); host[l] = 0;
            const char* c = strchr(e, ':'); snprintf(port, 32, "%s", c ? c + 1 : "80"); return c ? 1 : 0;
        }
    }
    const char* c = strrchr(s, ':');
    if (c && strchr(s, ':') == c) { size_t l = (size_t)(c - s); memcpy(host, s, l); host[l] = 0; snprintf(port, 32, "%s", c + 1); return 1; }
    snprintf(host, 256, "%s", s); strcpy(port, "80"); return 0;
}

static void parse_hp(const char* s, char* host, char* port) {
    (void)parse_hp_ex(s, host, port);
}

/* ============================================================
 *  Request parsing / rewriting
 *
 *  Parse the request line "<METHOD> /relay/<peer>/<target>/path <VER>",
 *  extract peer/target, and build the rewritten request header block
 *  (rewritten request line + headers with Host replaced by target).
 * ============================================================ */
static int rewrite_request(const char* hdr, size_t he,
    char* ph, char* pp, char* th, char* tp,
    int* out_target_tls, char** out_rw, uint32_t* out_rl) {
    char* h = (char*)malloc(he + 1); if (!h)return -1; memcpy(h, hdr, he); h[he] = 0;
    char* eol = strstr(h, "\r\n"); if (!eol) { free(h); return -1; } *eol = 0;
    char m[16], uri[4096], v[16];
    if (sscanf(h, "%15s %4095s %15s", m, uri, v) != 3) { free(h); return -1; }
    if (strncmp(uri, "/relay/", 7)) { free(h); return -1; }
    /* URL 形如: /relay/<peer>/<target>/<path...>
       <peer> 和 <target> 形如 host:port 或 [ipv6]:port (本身不含 '/') */
    char* rest = uri + 7;            /* "<peer>/<target>/path..." */
    char peer_s[1024], targ_s[1024], rp[4096];

    /* 第 1 段: peer，到第一个 '/' 为止 */
    char* sl1 = strchr(rest, '/');
    if (!sl1) { free(h); return -1; }                 /* 缺少 target 段 */
    size_t pl = (size_t)(sl1 - rest);
    if (pl == 0 || pl >= sizeof peer_s) { free(h); return -1; }
    memcpy(peer_s, rest, pl); peer_s[pl] = 0;

    int target_tls = 0;

    /* 第 2 段: target，从 sl1+1 到下一个 '/'(或字符串结尾) */
    char* tstart = sl1 + 1;
    if (strncmp(tstart, "http://", 7) == 0) {
        tstart += 7;
    }
    else if (strncmp(tstart, "https://", 8) == 0) {
        target_tls = 1;
        tstart += 8;
    }
    char* sl2 = strchr(tstart, '/');
    if (sl2) {
        size_t tl = (size_t)(sl2 - tstart);
        if (tl == 0 || tl >= sizeof targ_s) { free(h); return -1; }
        memcpy(targ_s, tstart, tl); targ_s[tl] = 0;
        snprintf(rp, sizeof rp, "%s", sl2);           /* 剩余转发路径, 以 '/' 开头 */
    }
    else {
        size_t tl = strlen(tstart);
        if (tl == 0 || tl >= sizeof targ_s) { free(h); return -1; }
        memcpy(targ_s, tstart, tl); targ_s[tl] = 0;
        strcpy(rp, "/");                              /* 没有额外路径, 默认 "/" */
    }

    parse_hp(peer_s, ph, pp);
    int target_port_explicit = parse_hp_ex(targ_s, th, tp);
    if (target_tls && !target_port_explicit) strcpy(tp, "443");
    if (out_target_tls) *out_target_tls = target_tls;

    size_t cap = he + 512; char* ob = (char*)malloc(cap); if (!ob) { free(h); return -1; } size_t ol = 0;
    ol += (size_t)snprintf(ob + ol, cap - ol, "%s %s %s\r\n", m, rp, v);
    const char* line = strstr(hdr, "\r\n"); if (line)line += 2;
    int v6 = strchr(th, ':') != NULL;
    while (line && line < hdr + he) {
        const char* e = strstr(line, "\r\n"); if (!e)break;
        size_t ll = (size_t)(e - line); if (!ll)break;
        if (istart(line, "Host:")) {
            if (v6) ol += (size_t)snprintf(ob + ol, cap - ol, "Host: [%s]:%s\r\n", th, tp);
            else   ol += (size_t)snprintf(ob + ol, cap - ol, "Host: %s:%s\r\n", th, tp);
        }
        else {
            if (ol + ll + 4 > cap) { cap = cap * 2 + ll + 8; char* nb = (char*)realloc(ob, cap); if (!nb) { free(ob); free(h); return -1; } ob = nb; }
            memcpy(ob + ol, line, ll); ol += ll; memcpy(ob + ol, "\r\n", 2); ol += 2;
        }
        line = e + 2;
    }
    memcpy(ob + ol, "\r\n", 2); ol += 2;
    *out_rw = ob; *out_rl = (uint32_t)ol; free(h); return 0;
}

/*
 * 从响应头中提取 Location 头的值
 * 返回: Location 的值（指向原始缓冲内部），或 NULL
 */
static const char* find_location_header(const char* resp, size_t resp_len, size_t* loc_len) {
    const char* line = resp;
    const char* end = resp + resp_len;

    /* 跳过状态行 */
    const char* crlf = (const char*)memmem(resp, resp_len, "\r\n", 2);
    if (!crlf) return NULL;
    line = crlf + 2;

    /* 查找 Location 头 */
    while (line < end) {
        const char* next_crlf = (const char*)memmem(line, (size_t)(end - line), "\r\n", 2);
        if (!next_crlf) break;

        size_t line_len = (size_t)(next_crlf - line);
        if (line_len == 0) break;  /* 空行，头部结束 */

        if (strncasecmp(line, "Location:", 9) == 0) {
            const char* val = line + 9;
            /* 跳过冒号后的空格 */
            while (val < next_crlf && (*val == ' ' || *val == '\t')) val++;
            *loc_len = (size_t)(next_crlf - val);
            return val;
        }

        line = next_crlf + 2;
    }

    return NULL;
}

/*
 * 检查是否是重定向响应 (3xx)
 */
static int is_redirect_response(const char* resp, size_t resp_len) {
    /* 格式: "HTTP/1.x NNN ..." */
    if (resp_len < 12) return 0;

    const char* status_start = (const char*)memmem(resp, resp_len, " ", 1);
    if (!status_start) return 0;
    status_start++;

    int code = atoi(status_start);
    return (code >= 300 && code < 400);
}


/*
 * 重写 Location 头
 * 格式: http://peer_host:peer_port/b_side/target_host:target_port/path
 *
 * 其中:
 *   peer_host:peer_port = A 侧地址（客户端连接的地址）
 *   b_side = B 侧地址 (relay-b:port)
 *   target_host:target_port = 最终目标地址
 *   path = 重定向目标的路径
 */
static int rewrite_location(
    const char* a_peer_host, const char* a_peer_port,
    const char* b_side_host, const char* b_side_port,
    const char* target_host, const char* target_port, int target_tls,
    const char* location, size_t loc_len,
    char* out_buf, size_t out_bufsize)
{
    const char* path = NULL;
    size_t path_len = 0;
    int is_absolute = 0;
    const char* host_path_start = NULL;
    size_t host_path_len = 0;
    int loc_https = 0;
    /* 检查是否是绝对 URL */
    if (strncasecmp(location, "http://", 7) == 0 ||
        (loc_https = strncasecmp(location, "https://", 8) == 0)) {
        const char* scheme_end = (const char*)memmem(location, loc_len, "://", 3);
        if (!scheme_end) {
            if (loc_len >= out_bufsize) return -1;
            memcpy(out_buf, location, loc_len);
            out_buf[loc_len] = 0;
            return (int)loc_len;
        }

        /* 跳过 "://"，保留 "host:port/path" 部分 */
        host_path_start = scheme_end + 3;
        host_path_len = loc_len - (host_path_start - location);

        is_absolute = 1;
    }
    else if (*location == '/') {
        /* 相对路径 */
        path = location;
        path_len = loc_len;
    }
    else {
        /* 其他格式，原样返回 */
        if (loc_len >= out_bufsize) return -1;
        memcpy(out_buf, location, loc_len);
        out_buf[loc_len] = 0;
        return (int)loc_len;
    }

    /* 检查 IPv6 */
    int v6_a_peer = strchr(a_peer_host, ':') != NULL;
    int v6_b_side = strchr(b_side_host, ':') != NULL;

    int pos = 0;
    int ret = 0;

    /* 第一部分: http://a_peer_host:a_peer_port/ */
    if (v6_a_peer) {
        ret = snprintf(out_buf, out_bufsize, "http://[%s]:%s/",
            a_peer_host, a_peer_port);
    }
    else {
        ret = snprintf(out_buf, out_bufsize, "http://%s:%s/",
            a_peer_host, a_peer_port);
    }
    if (ret < 0 || (size_t)ret >= out_bufsize) return -1;
    pos = ret;

    /* 第二部分: relay/ */
    ret = snprintf(out_buf + pos, out_bufsize - pos, "relay/");
    if (ret < 0 || (size_t)(pos + ret) >= out_bufsize) return -1;
    pos += ret;

    /* 第三部分: b_side_host:b_side_port/ */
    if (v6_b_side) {
        ret = snprintf(out_buf + pos, out_bufsize - pos, "[%s]:%s/",
            b_side_host, b_side_port);
    }
    else {
        ret = snprintf(out_buf + pos, out_bufsize - pos, "%s:%s/",
            b_side_host, b_side_port);
    }
    if (ret < 0 || (size_t)(pos + ret) >= out_bufsize) return -1;
    pos += ret;

    /* 绝对 URL：追加 scheme://host:port/path（去掉客户端访问 A 的 scheme） */
    if (is_absolute) {
        ret = snprintf(out_buf + pos, out_bufsize - pos, "%s://", loc_https ? "https" : "http");
        if (ret < 0 || (size_t)(pos + ret) >= out_bufsize) return -1;
        pos += ret;
        if ((size_t)pos + host_path_len >= out_bufsize) return -1;
        memcpy(out_buf + pos, host_path_start, host_path_len);
        pos += (int)host_path_len;
        out_buf[pos] = 0;
        return pos;
    }

    /* 相对路径：需要插入 target scheme/host/port，然后追加路径 */
    ret = snprintf(out_buf + pos, out_bufsize - pos, "%s://", target_tls ? "https" : "http");
    if (ret < 0 || (size_t)(pos + ret) >= out_bufsize) return -1;
    pos += ret;

    int v6_target = strchr(target_host, ':') != NULL;
    if (v6_target) {
        ret = snprintf(out_buf + pos, out_bufsize - pos, "[%s]:%s",
            target_host, target_port);
    }
    else {
        ret = snprintf(out_buf + pos, out_bufsize - pos, "%s:%s",
            target_host, target_port);
    }
    if (ret < 0 || (size_t)(pos + ret) >= out_bufsize) return -1;
    pos += ret;

    /* 追加路径部分 */
    if (path_len > 0) {
        if ((size_t)pos + path_len >= out_bufsize) return -1;
        memcpy(out_buf + pos, path, path_len);
        pos += (int)path_len;
    }

    out_buf[pos] = 0;
    return pos;
}


/*
 * 重写响应头中的 Location 头
 * 返回: 修改后的响应头（malloc），需要 free；或 NULL 表示无需修改
 */
 static char* rewrite_response_location(
     const char* resp, size_t resp_len,
     const char* a_peer_host, const char* a_peer_port,
     const char* b_side_host, const char* b_side_port,
     const char* target_host, const char* target_port, int target_tls)
 {
     if (!is_redirect_response(resp, resp_len)) {
         return NULL;
     }

     size_t loc_len = 0;
     const char* location = find_location_header(resp, resp_len, &loc_len);
     if (!location) {
         return NULL;
     }

     char new_location[4096];
     int new_loc_len = rewrite_location(
         a_peer_host, a_peer_port,
         b_side_host, b_side_port,
         target_host, target_port, target_tls,
         location, loc_len,
         new_location, sizeof new_location
     );

     if (new_loc_len < 0) {
         /* 无需修改或出错 */
         LOG("WARNING: Location rewrite failed, location_len=%zu",
             loc_len);
         return NULL;
     }

     LOG("Location rewrite: %.*s -> %s",
         (int)loc_len, location, new_location);

     /* 构造新的响应头 */
     size_t new_resp_len = resp_len - loc_len + (size_t)new_loc_len + 100;
     char* new_resp = (char*)malloc(new_resp_len);
     if (!new_resp) return NULL;

     const char* crlf = (const char*)memmem(resp, resp_len, "\r\n", 2);
     if (!crlf) {
         free(new_resp);
         return NULL;
     }

     size_t status_line_len = (size_t)(crlf - resp) + 2;
     memcpy(new_resp, resp, status_line_len);
     size_t pos = status_line_len;

     const char* line = resp + status_line_len;
     const char* end = resp + resp_len;

     while (line < end) {
         const char* next_crlf = (const char*)memmem(line, (size_t)(end - line), "\r\n", 2);
         if (!next_crlf) {
             size_t remaining = (size_t)(end - line);
             if (pos + remaining <= new_resp_len) {
                 memcpy(new_resp + pos, line, remaining);
                 pos += remaining;
             }
             break;
         }

         size_t line_len = (size_t)(next_crlf - line);

         if (strncasecmp(line, "Location:", 9) == 0) {
             /* 重写 Location 行 */
             int write_len = snprintf(new_resp + pos, new_resp_len - pos,
                 "Location: %s\r\n", new_location);
             if (write_len > 0) {
                 pos += (size_t)write_len;
             }
         }
         else{
             // 所有行（包括空行）原样复制
             if (pos + line_len + 2 <= new_resp_len) {
                 memcpy(new_resp + pos, line, line_len);
                 pos += line_len;
                 memcpy(new_resp + pos, "\r\n", 2);
                 pos += 2;
             }
         }

         line = next_crlf + 2;
     }
     new_resp[pos] = 0;
     return new_resp;
 }


/* Used by B side (target->B->A) and as a generic app->peer pump. */
 static void* t_app2peer(void* a) {
     sess_t* s = (sess_t*)a; char* c = (char*)malloc(IO_CHUNK);
     for (;;) {
         if (s->closing) break;
         int r = app_recv(s, c, IO_CHUNK);
         if (r > 0) {
             sess_touch_activity(s);             /* recv 成功 -> 刷新活动 */
             uint64_t off;
             int rc = sw_append(&s->out, c, (size_t)r, g_max_buffer, &off,
                 (volatile int*)&s->closing);
             if (rc < 0) break;
             notify_send(s);
             continue;
         }
         if (r == 0) break;                      /* 对端正常关闭 */
         /* r < 0 */
         if (sock_is_eintr()) continue;
         if (app_io_should_retry(s, r)) {
             if (sess_app_timed_out(s)) {
                 LOG("app recv activity timeout sid=%llu", (unsigned long long)s->sid);
                 break;
             }
             continue;                            /* 续命 */
         }
         break;                                   /* 真错误 */
     }
     free(c);
     session_request_peer_close(s);
     session_terminate(s);
     return NULL;
 }

static int process_response_data_a_side(sess_t* s, const char* data, size_t data_len) {
    /* A 侧处理响应数据，检测响应头并重写 Location */

    if (!s->is_initiator) {
        /* B 侧直接转发 */
        return wfull_app(s, data, data_len);
    }

    /* 如果响应头还没处理完 */
    if (s->resp_header_complete == 0) {
        /* 缓冲数据以查找完整的响应头 */
        if (!s->resp_header_buf) {
            s->resp_header_cap = 16384;
            s->resp_header_buf = (char*)malloc(s->resp_header_cap);
            if (!s->resp_header_buf) return -1;
        }

        /* 检查缓冲大小 */
        if (s->resp_header_len + data_len > s->resp_header_cap) {
            size_t new_cap = s->resp_header_cap * 2;
            while (new_cap < s->resp_header_len + data_len) new_cap *= 2;
            if (new_cap > 10 * 1024 * 1024) {
                /* 太大，放弃重写，发送已缓冲的数据 */
                s->resp_header_complete = -1;
                LOG("response header too large, giving up Location rewrite");
                if (wfull_app(s, s->resp_header_buf, s->resp_header_len) < 0) {
                    return -1;
                }
                free(s->resp_header_buf);
                s->resp_header_buf = NULL;
                s->resp_header_len = 0;
                return wfull_app(s, data, data_len);
            }
            char* new_buf = (char*)realloc(s->resp_header_buf, new_cap);
            if (!new_buf) return -1;
            s->resp_header_buf = new_buf;
            s->resp_header_cap = new_cap;
        }

        /* 追加新数据 */
        memcpy(s->resp_header_buf + s->resp_header_len, data, data_len);
        s->resp_header_len += data_len;

        /* 查找响应头结束 */
        char* header_end = (char*)memmem(s->resp_header_buf, s->resp_header_len, "\r\n\r\n", 4);
        if (!header_end) {
            /* 还没接收完整响应头 */
            return 0;
        }

        /* 找到完整响应头 */
        size_t header_size = (size_t)(header_end - s->resp_header_buf) + 4;

        /* 尝试重写 Location */
        char* rewritten = rewrite_response_location(
            s->resp_header_buf, header_size,
            s->my_host, s->my_port,
            s->ph, s->pp,
            s->target_host, s->target_port, s->target_tls
        );

        const char* to_send = rewritten ? rewritten : s->resp_header_buf;
        size_t to_send_len = rewritten ? strlen(rewritten) : header_size;

        /* 发送响应头 */
        if (wfull_app(s, to_send, to_send_len) < 0) {
            if (rewritten) free(rewritten);
            return -1;
        }

        if (rewritten) free(rewritten);

        /* 发送响应头之后的 body 数据 */
        size_t body_in_buf = s->resp_header_len - header_size;
        if (body_in_buf > 0) {
            if (wfull_app(s, s->resp_header_buf + header_size, body_in_buf) < 0) {
                return -1;
            }
        }

        /* 清理缓冲 */
        free(s->resp_header_buf);
        s->resp_header_buf = NULL;
        s->resp_header_len = 0;
        s->resp_header_complete = 1;

        return 0;
    }

    /* 响应头已处理，直接转发数据 */
    return wfull_app(s, data, data_len);
}


static void get_socket_address(sock_t fd, char* host, char* port) {
    struct sockaddr_storage ss;
    socklen_t len = sizeof ss;

    if (getsockname(fd, (struct sockaddr*)&ss, &len) == 0) {
        char hbuf[256];
        char pbuf[32];

        // 处理 IPv4-mapped IPv6
        if (ss.ss_family == AF_INET6) {
            struct sockaddr_in6* sin6 = (struct sockaddr_in6*)&ss;
            if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
                struct sockaddr_in sin4;
                memset(&sin4, 0, sizeof sin4);
                sin4.sin_family = AF_INET;
                sin4.sin_port = sin6->sin6_port;
                memcpy(&sin4.sin_addr, &sin6->sin6_addr.s6_addr[12], 4);

                if (getnameinfo((struct sockaddr*)&sin4, sizeof sin4,
                    hbuf, sizeof hbuf, pbuf, sizeof pbuf,
                    NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
                    snprintf(host, 256, "%s", hbuf);
                    snprintf(port, 32, "%s", pbuf);
                    return;
                }
            }
        }

        if (getnameinfo((struct sockaddr*)&ss, len, hbuf, sizeof hbuf,
            pbuf, sizeof pbuf, NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
            snprintf(host, 256, "%s", hbuf);
            snprintf(port, 32, "%s", pbuf);
            return;
        }
    }

    snprintf(host, 256, "localhost");
    snprintf(port, 32, "8080");
}


static int handle_frame(sess_t* s, struct fhdr* h, char* pl) {
    switch (h->type) {
    case MSG_DATA: {
        uint64_t off = h->value; uint32_t dl = h->plen;
        mutex_lock(&s->recv_lk); uint64_t want = s->recv_off; mutex_unlock(&s->recv_lk);
        const char* d = pl; uint32_t use; uint64_t newoff;
        if (off > want) {
            /* 出现空洞：理论上不该发生（发送端保证单调） */
            LOG("WARNING: gap in stream, off=%llu want=%llu sid=%llu",
                (unsigned long long)off, (unsigned long long)want, (unsigned long long)s->sid);
        }
        if ((uint64_t)off + dl <= want) { use = 0; newoff = want; }       /* 完全重复 */
        else { uint64_t sk = want - off; d += (size_t)sk; use = (uint32_t)(dl - sk); newoff = off + dl; }

        if (use) {
            int rc;
            if (s->is_initiator && use > 0) {
                rc = process_response_data_a_side(s, d, (size_t)use);
            }
            else {
                rc = wfull_app(s, d, (size_t)use);
            }

            if (rc < 0) {
                free(pl);
                session_terminate(s);
                return 0;
            }
        }
        mutex_lock(&s->recv_lk); if (newoff > s->recv_off)s->recv_off = newoff;
        uint64_t ack = s->recv_off; mutex_unlock(&s->recv_lk);
        mutex_lock(&s->peer_lk);
        if (s->peer_fd != BADSOCK) {
            send_frame(s->peer_fd, MSG_ACK, ack, 0, 0);

        }
        mutex_unlock(&s->peer_lk);
        free(pl); return 1;
    }
    case MSG_ACK: 
        sw_drop_to(&s->out, h->value); free(pl); return 1;
    case MSG_CLOSE:
        free(pl); session_terminate(s);
        return 0;
    case MSG_AUTH_FAIL:
        LOG("peer authentication rejected sid=%llu", (unsigned long long)s->sid);
        free(pl);
        session_terminate(s);
        return 0;
    case MSG_PING:
        mutex_lock(&s->peer_lk);
        if (s->peer_fd != BADSOCK && send_frame(s->peer_fd, MSG_PONG, h->value, 0, 0) < 0) {
            LOG("peer pong send failed sid=%llu", (unsigned long long)s->sid);
            peer_close_locked(s);
        }
        mutex_unlock(&s->peer_lk); free(pl); return 1;
    case MSG_PONG: free(pl); return 1;
    default: free(pl); return 1;
    }
}

/* Receive frames until the peer link drops (return -1) or session ends (return 0). */
static int peer_recv_loop(sess_t* s) {
    for (;;) {
        struct fhdr h; char* pl = NULL; int r = recv_frame(s->peer_fd, &h, &pl);
        if (r <= 0) { free(pl); return -1; }
        peer_touch_rx(s);
        int rc = handle_frame(s, &h, pl);
        if (rc == 0 || s->closing) return 0;
    }
}


/* ============================================================
 *  B side global session table (for RESUME lookup)
 * ============================================================ */
#define MAXS 4096
static sess_t* g_tbl[MAXS]; static int g_tbln = 0;
static mutex_t g_tbl_lk;
static void b_register(sess_t* s) {
    mutex_lock(&g_tbl_lk);
    if (g_tbln < MAXS) { g_tbl[g_tbln++] = s; session_addref(s); }  /* 表持有 +1 */
    else {
        LOG("ERROR: session table full (MAXS=%d), cannot register sid=%llu", MAXS, (unsigned long long)s->sid);
    }
    mutex_unlock(&g_tbl_lk);
}

static void b_unregister(sess_t* s) {
    int found = 0;
    mutex_lock(&g_tbl_lk);
    for (int i = 0; i < g_tbln; i++) {
        if (g_tbl[i] == s) { g_tbl[i] = g_tbl[--g_tbln]; found = 1; break; }
    }
    mutex_unlock(&g_tbl_lk);
    if (found) session_release(s);    /* 释放"表持有"的那个引用 */
}

static sess_t* b_find(uint64_t sid) {
    sess_t* r = NULL;
    mutex_lock(&g_tbl_lk);
    for (int i = 0; i < g_tbln; i++) {
        if (g_tbl[i]->sid == sid) {
            r = g_tbl[i];
            session_addref(r);          /* 表锁内 addref：保证返回后 s 不会被 free */
            break;
        }
    }
    mutex_unlock(&g_tbl_lk);
    return r;                    /* 调用方用完必须 session_release */
}

/* ============================================================
 *  A side: streaming HTTP request reader (keep-alive aware)
 * ============================================================ */
static void hin_init(httpin_t* h, sock_t fd) {
    h->fd = fd; h->cap = 8192; h->len = 0; h->off = 0; h->sess = NULL;
    h->start_ms = now_ms();
    h->init_timeout = g_client_io_timeout;
    h->buf = (char*)malloc(h->cap);
}
static void hin_free(httpin_t* h) { free(h->buf); h->buf = NULL; }
static void hin_compact(httpin_t* h) {
    if (h->off > 0) { memmove(h->buf, h->buf + h->off, h->len - h->off); h->len -= h->off; h->off = 0; }
}

/* 从 in->fd 读一次数据到 buf 末尾, 带活动超时语义。
 * 返回 >0 读到的字节数; 0 对端关闭; -1 真错误/超时/关闭 */
static int hin_recv_once(httpin_t* h) {
    for (;;) {
        if (h->sess && h->sess->closing) return -1;
        int r = recv(h->fd, h->buf + h->len, (int)(h->cap - h->len - 1), 0);
        if (r > 0) {
            if (h->sess) {
                sess_touch_activity(h->sess);     /* 有 sess: 刷新会话活动时间 */
            }
            else {
                h->start_ms = now_ms();           /* 无 sess: 刷新首请求计时基准 */
            }
            return r;
        }
        if (r == 0) return 0;
        if (sock_is_eintr()) continue;
        if (sock_is_timeout()) {
            if (h->sess) {
                /* 有会话: 用会话级活动超时判断 */
                if (!sess_app_timed_out(h->sess)) continue;   /* 续命 */
                LOG("app recv activity timeout sid=%llu", (unsigned long long)h->sess->sid);
                return -1;                                    /* 真超时 */
            }
            else {
                /* 无会话(首请求阶段): 用 init_timeout 判断 */
                if (h->init_timeout <= 0) continue;           /* 不限 -> 继续等 */
                if (now_ms() - h->start_ms >= (int64_t)h->init_timeout * 1000) {
                    LOG("first request read timeout");
                    return -1;                                /* 首请求超时 */
                }
                continue;                                     /* 未超时 -> 继续等 */
            }
        }
        return -1;   /* 真错误 */
    }
}

/* Ensure at least 'need' unconsumed bytes are buffered (reading from socket). */
static int hin_need(httpin_t* h, size_t need) {
    while (h->len - h->off < need) {
        hin_compact(h);
        if (h->len + 1 >= h->cap) {
            size_t nc = h->cap * 2; while (nc < h->len + need + 1) nc *= 2;
            if (nc > 64u * 1024 * 1024) return -1;
            char* nb = (char*)realloc(h->buf, nc); if (!nb)return -1; h->buf = nb; h->cap = nc;
        }
        int r = hin_recv_once(h);
        if (r <= 0) return -1;
        h->len += (size_t)r;
    }
    return 0;
}
/* Read one full header block (up to CRLFCRLF). *hdr points inside h->buf, *he = header length. */
static int hin_read_headers(httpin_t* h, char** hdr, size_t* he) {
    for (;;) {
        char* base = h->buf + h->off;
        size_t avail = h->len - h->off;
        char* p = (char*)memmem(base, avail, "\r\n\r\n", 4);
        if (p) { 
            *hdr = base; 
            *he = (size_t)(p - base) + 4; 
            return 0; 
        }
        hin_compact(h);
        if (h->len + 1 >= h->cap) {
            size_t nc = h->cap * 2; if (nc > 1024 * 1024) return -1;
            char* nb = (char*)realloc(h->buf, nc); if (!nb)return -1; h->buf = nb; h->cap = nc;
        }
        int r = hin_recv_once(h);
        if (r <= 0) return -1;
        h->len += (size_t)r;
    }
}
/* Read one line (including CRLF) without consuming off. */
static int hin_read_line(httpin_t* in, char** line, size_t* len) {
    for (;;) {
        char* base = in->buf + in->off; size_t avail = in->len - in->off;
        char* p = (char*)memmem(base, avail, "\r\n", 2);
        if (p) { *line = base; *len = (size_t)(p - base) + 2; return 0; }
        if (hin_need(in, avail + 1) < 0) return -1;
    }
}
/* Find a header value (case-insensitive). Returns 0 if found. */
static int header_value(const char* hdr, size_t he, const char* name, char* out, size_t outsz) {
    size_t nl = strlen(name);
    const char* line = (const char*)memmem(hdr, he, "\r\n", 2);
    if (!line) return -1;
    line += 2;
    while (line < hdr + he) {
        const char* e = (const char*)memmem(line, (size_t)(hdr + he - line), "\r\n", 2);
        if (!e) break;
        size_t ll = (size_t)(e - line);
        if (ll == 0) break;
        if (ll > nl && strncasecmp(line, name, nl) == 0 && line[nl] == ':') {
            const char* v = line + nl + 1;
            while (v < e && (*v == ' ' || *v == '\t')) v++;
            size_t vl = (size_t)(e - v); if (vl >= outsz) vl = outsz - 1;
            memcpy(out, v, vl); out[vl] = 0;
            return 0;
        }
        line = e + 2;
    }
    return -1;
}

/* ============================================================
 *  A side: inject rewritten request bytes into the send window
 * ============================================================ */
static int a_inject(sess_t* s, const void* data, size_t n) {
    uint64_t off;
    int rc = sw_append(&s->out, data, n, g_max_buffer, &off,
        (volatile int*)&s->closing);
    if (rc < 0) {
        LOG("inject: append failed or closing, sid=%llu",
            (unsigned long long)s->sid);
        session_terminate(s);
        return -1;
    }
    notify_send(s);
    return 0;
}

/* Forward the body of one request (Content-Length or chunked). */
static int a_forward_body(sess_t* s, httpin_t* in, const char* hdr, size_t he) {
    char cl[64], te[64];
    int has_cl = header_value(hdr, he, "Content-Length", cl, sizeof cl) == 0;
    int chunked = header_value(hdr, he, "Transfer-Encoding", te, sizeof te) == 0
        && strcasestr_compat(te, "chunked") != NULL;

    if (chunked) {
        for (;;) {
            char* line; size_t ll;
            if (hin_read_line(in, &line, &ll) < 0) return -1;
            if (a_inject(s, line, ll) < 0) return -1;          /* forward chunk-size line */
            unsigned long long sz = strtoull(line, NULL, 16);
            in->off += ll;
            if (sz == 0) {
                /* last chunk; forward the trailing CRLF (assumes no trailers) */
                if (hin_need(in, 2) < 0) return -1;
                if (a_inject(s, in->buf + in->off, 2) < 0) return -1;
                in->off += 2;
                break;
            }
            size_t remain = (size_t)sz + 2;                    /* data + CRLF */
            while (remain > 0) {
                if (hin_need(in, 1) < 0) return -1;
                size_t avail = in->len - in->off; if (avail > remain)avail = remain;
                if (a_inject(s, in->buf + in->off, avail) < 0) return -1;
                in->off += avail; remain -= avail;
            }
        }
    }
    else if (has_cl) {
        unsigned long long n = strtoull(cl, NULL, 10);
        while (n > 0) {
            if (hin_need(in, 1) < 0) return -1;
            size_t avail = in->len - in->off; if ((unsigned long long)avail > n)avail = (size_t)n;
            if (a_inject(s, in->buf + in->off, avail) < 0) return -1;
            in->off += avail; n -= avail;
        }
    }
    return 0;
}

/* ============================================================
 *  A side: peer connection management + response relay
 * ============================================================ */
static mutex_t g_gen_sid_lk;

static uint64_t splitmix64_next(uint64_t* state) {
    uint64_t z = (*state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}

static uint64_t gen_sid(void) {
    mutex_lock(&g_gen_sid_lk);
    static uint64_t state = 0;
    if (state == 0) {
        uint64_t seed = (uint64_t)now_ms() ^ ((uint64_t)time(NULL) << 32);
        seed ^= (uint64_t)(uintptr_t)&state;
#ifdef _WIN32
        seed ^= ((uint64_t)GetCurrentProcessId()) << 16;
#else
        seed ^= ((uint64_t)getpid()) << 16;
#endif
        state = seed ? seed : 0x72656c6179736964ULL;
    }
    uint64_t v = splitmix64_next(&state);
    if (v == 0) v = splitmix64_next(&state);
    mutex_unlock(&g_gen_sid_lk);
    return v;
}

static void normalize_timeouts(void) {
    if (g_peer_io_timeout < 0) g_peer_io_timeout = 0;

    if (g_heartbeat_interval < 1) {
        LOG("adjust heartbeat interval from %ds to minimum 1s", g_heartbeat_interval);
        g_heartbeat_interval = 1;
    }

    int min_peer_io = g_heartbeat_interval * 3;
    if (g_peer_io_timeout < min_peer_io) {
        LOG("adjust peer io timeout from %ds to %ds (heartbeat interval %ds x 3)",
            g_peer_io_timeout, min_peer_io, g_heartbeat_interval);
        g_peer_io_timeout = min_peer_io;
    }
}


static sock_t peer_connect_and_hs(sess_t* s, int resume) {
    sock_t fd = connect_peer(s->ph, s->pp); if (fd == BADSOCK) return BADSOCK;
    if (peer_auth_client(fd) < 0) {
        LOG("peer authentication failed sid=%llu", (unsigned long long)s->sid);
        closesock(fd);
        return BADSOCK;
    }
    if (!resume) {
        if (send_frame(fd, MSG_OPEN, s->sid, s->open_pl, s->open_len) < 0) { closesock(fd); return BADSOCK; }
        /* OPEN 分支: 先重置 sent=base, 再(由调用方)装 peer_fd */
        mutex_lock(&s->out.lk);
        s->out.sent = s->out.base;
        mutex_unlock(&s->out.lk);
        return fd;
    }
    else {
        mutex_lock(&s->recv_lk); uint64_t rv = s->recv_off; mutex_unlock(&s->recv_lk);
        uint64_t be = sw64(rv);
        if (send_frame(fd, MSG_RESUME, s->sid, &be, 8) < 0) { closesock(fd); return BADSOCK; }
        struct fhdr h; char* pl = NULL; int r = recv_frame(fd, &h, &pl);
        if (r <= 0 || h.type != MSG_RESUME_ACK || h.plen < 8) { free(pl); closesock(fd); return BADSOCK; }
        uint64_t peer_recv = sw64(*(uint64_t*)pl); free(pl);

        /* 关键: 在装上 peer_fd 之前, 先把 sent 重置到 peer_recv。
           且整个"重置 sent + 装 peer_fd"要在 peer_lk 下原子完成。 */
        sw_drop_to(&s->out, peer_recv);
        mutex_lock(&s->peer_lk);
        mutex_lock(&s->out.lk);
        s->out.sent = (peer_recv > s->out.base) ? peer_recv : s->out.base;
        mutex_unlock(&s->out.lk);
        peer_install_locked(s, fd);         /* 装上连接, 此刻 sent 已正确 */
        mutex_unlock(&s->peer_lk);
        notify_send(s);                     /* 叫发送线程从正确的 sent 重发 */
        return fd;
    }
}

static void* a_peer_thread(void* arg) {
    sess_t* s = (sess_t*)arg;
    for (;;) {
        if (s->closing)break;
        if (s->peer_fd == BADSOCK) {
            if (s->closing)break;
            if (s->down_since && (now_ms() - s->down_since) / 1000 >= g_reconnect_timeout) {
                LOG("reconnect timeout (%ds), closing sid=%llu", g_reconnect_timeout, (unsigned long long)s->sid);
                session_terminate(s); break;
            }
            int resume = s->opened;
            sock_t fd = peer_connect_and_hs(s, resume);
            if (fd == BADSOCK) { if (s->closing) break; sleep_ms(g_reconnect_ms); continue; }

            if (resume) {
                /* resume 分支: peer_connect_and_hs 内部已在 peer_lk 下装好 peer_fd + 重置 sent + notify */
                s->down_since = 0;
                LOG("peer reconnected sid=%llu (resume)", (unsigned long long)s->sid);
            }
            else {
                /* open 分支: 这里负责装 peer_fd (sent 已在函数内重置为 base) */
                mutex_lock(&s->peer_lk);
                if (s->closing) { mutex_unlock(&s->peer_lk); closesock(fd); break; }
                peer_install_locked(s, fd);
                mutex_unlock(&s->peer_lk);
                s->down_since = 0;
                s->opened = 1;
                notify_send(s);                  /* 把首连前 append 的数据发出去 */
                LOG("peer connected sid=%llu (open)", (unsigned long long)s->sid);
            }
        }
        int r = peer_recv_loop(s);
        if (s->closing) break;
        if (r == 0) { session_terminate(s); break; }
        mutex_lock(&s->peer_lk);
        peer_close_locked(s);
        mutex_unlock(&s->peer_lk);
        LOG("peer link down, will reconnect sid=%llu", (unsigned long long)s->sid);
    }
    return NULL;
}


/* ============================================================
 *  A side: client handler (keep-alive aware)
 * ============================================================ */
static void* handle_client(void* arg) {
    sock_t cfd = (sock_t)(intptr_t)arg; nodelay_on(cfd);
    /* 设置客户端 socket 超时 */
    setup_client_socket(cfd);

    httpin_t in; hin_init(&in, cfd);

    char* hdr; size_t he;
    if (hin_read_headers(&in, &hdr, &he) < 0) { hin_free(&in); closesock(cfd); return 0; }

    char ph[256], pp[32], th[256], tp[32]; int target_tls = 0; char* rw = NULL; uint32_t rl = 0;
    if (rewrite_request(hdr, he, ph, pp, th, tp, &target_tls, &rw, &rl) < 0) {
        const char* e = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        wfull(cfd, e, strlen(e)); hin_free(&in); closesock(cfd); return 0;
    }

    sess_t* s = (sess_t*)calloc(1, sizeof * s);
    session_init(s);
    s->app_fd = cfd; s->peer_fd = BADSOCK; s->is_initiator = 1; s->sid = gen_sid();
    snprintf(s->ph, sizeof s->ph, "%s", ph); snprintf(s->pp, sizeof s->pp, "%s", pp);

    /* 保存原始信息用于重定向重写 */
    get_socket_address(cfd, s->my_host, s->my_port);
    snprintf(s->target_host, sizeof s->target_host, "%s", th);
    snprintf(s->target_port, sizeof s->target_port, "%s", tp);
    s->target_tls = target_tls;

    char tgt[416]; int v6 = strchr(th, ':') != NULL;
    if (v6) snprintf(tgt, sizeof tgt, "%s [%s]:%s\n", target_tls ? "https" : "http", th, tp);
    else snprintf(tgt, sizeof tgt, "%s %s:%s\n", target_tls ? "https" : "http", th, tp);
    size_t tl = strlen(tgt);
    s->open_len = (uint32_t)(tl + rl); s->open_pl = (char*)malloc(s->open_len);
    memcpy(s->open_pl, tgt, tl); memcpy(s->open_pl + tl, rw, rl);
    free(rw);

    LOG("new client session sid=%llu -> peer %s:%s target %s://%s:%s",
        (unsigned long long)s->sid, ph, pp, target_tls ? "https" : "http", th, tp);

    s->app_io_timeout = g_client_io_timeout;   /* 启用活动超时 */
    sess_touch_activity(s);                     /* 初始化活动时间 */
    in.sess = s;                                /* 让后续 hin_* 读走活动超时逻辑 */

    session_start_sender(s);

    /* First request header is carried in the OPEN payload; consume it and forward its body. */
    in.off += he;
    if (a_forward_body(s, &in, hdr, he) < 0) s->closing = 1;

    thread_t prt;
    thread_create(&prt, a_peer_thread, s);

    /* Loop over subsequent keep-alive requests. */
    while (!s->closing) {
        char* h2; size_t he2;
        if (hin_read_headers(&in, &h2, &he2) < 0) {
            session_request_peer_close(s);
            break;
        }
        char ph2[256], pp2[32], th2[256], tp2[32]; int target_tls2 = 0; char* rw2 = NULL; uint32_t rl2 = 0;
        if (rewrite_request(h2, he2, ph2, pp2, th2, tp2, &target_tls2, &rw2, &rl2) < 0) {
            const char* e = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            wfull(cfd, e, strlen(e));
            in.off += he2;
            continue;
        }
        if (strcmp(ph2, ph) || strcmp(pp2, pp) || strcmp(th2, th) || strcmp(tp2, tp) || target_tls2 != target_tls) {
            free(rw2);
            const char* e = "HTTP/1.1 421 Misdirected Request\r\nContent-Length: 0\r\n\r\n";
            wfull(cfd, e, strlen(e)); break;
        }
        in.off += he2;
        s->resp_header_complete = 0;
        if (a_inject(s, rw2, rl2) < 0) { free(rw2); break; }
        free(rw2);
        if (a_forward_body(s, &in, h2, he2) < 0) break;
    }

    session_terminate(s);
    thread_join(prt);
    session_stop_sender(s);
    session_release(s);
    hin_free(&in);
    return 0;
}

/* ============================================================
 *  B side: peer handler
 * ============================================================ */
static void* handle_peer(void* arg) {
    sock_t pfd = (sock_t)(intptr_t)arg; nodelay_on(pfd);
    /* 设置 peer socket 超时 */
    setup_peer_socket(pfd);

    struct fhdr h; char* pl = NULL; int r = peer_auth_server(pfd, &h, &pl);
    if (r <= 0) {
        LOG("peer/server: connection rejected before OPEN/RESUME");
        if (r == -2) wait_peer_close_after_auth_fail(pfd);
        free(pl); closesock(pfd); return 0;
    }

    if (h.type == MSG_OPEN) {
        char* nl = (char*)memchr(pl, '\n', h.plen);
        if (!nl) { LOG("peer/server: invalid OPEN payload"); free(pl); closesock(pfd); return 0; }
        size_t addrlen = (size_t)(nl - pl); char addr[400];
        if (addrlen >= sizeof addr)addrlen = sizeof addr - 1;
        memcpy(addr, pl, addrlen); addr[addrlen] = 0;
        int target_tls = 0;
        const char* addrp = addr;
        if (strncmp(addrp, "https ", 6) == 0) { target_tls = 1; addrp += 6; }
        else if (strncmp(addrp, "http ", 5) == 0) { addrp += 5; }
        char th[256], tp[32]; parse_hp(addrp, th, tp);

        sock_t tfd = connect_with_timeout(th, tp, g_client_connect_timeout);
        if (tfd == BADSOCK) {
            LOG("connect to target %s://%s:%s failed", target_tls ? "https" : "http", th, tp); free(pl);
            send_close_and_wait_peer(pfd, h.value); closesock(pfd); return 0;
        }
        nodelay_on(tfd);

        sess_t* s = (sess_t*)calloc(1, sizeof * s);
        session_init(s);
        s->app_fd = tfd; s->peer_fd = BADSOCK; s->is_initiator = 0; s->sid = h.value; s->target_tls = target_tls;
        /* 目标连接(app 侧)用活动超时, 短轮询间隔 */
        s->app_io_timeout = g_client_io_timeout;
        set_recv_timeout(tfd, APP_POLL_INTERVAL_SEC);
        set_send_timeout(tfd, APP_POLL_INTERVAL_SEC);
        sess_touch_activity(s);

        if (target_tls && app_start_tls(s, th) < 0) {
            free(pl);
            session_release(s);
            send_close_and_wait_peer(pfd, h.value); closesock(pfd); return 0;
        }

        char* req = nl + 1; size_t reqlen = h.plen - addrlen - 1;
        if (wfull_app(s, req, reqlen) < 0) { free(pl); session_release(s); closesock(pfd); return 0; }
        free(pl);

        LOG("passive session sid=%llu target %s://%s:%s", (unsigned long long)s->sid, target_tls ? "https" : "http", th, tp);
        b_register(s);
        mutex_lock(&s->peer_lk);
        peer_install_locked(s, pfd);
        mutex_unlock(&s->peer_lk);
        session_start_sender(s);

        thread_t th2; thread_create(&th2, t_app2peer, s);
        for (;;) {
            if (s->closing) break;
            if (s->peer_fd == BADSOCK) {
                if (s->closing)break;
                if (s->down_since && (now_ms() - s->down_since) / 1000 >= g_reconnect_timeout) {
                    LOG("B side reconnect timeout, closing sid=%llu", (unsigned long long)s->sid);
                    break;
                }
                sleep_ms(g_reconnect_ms); continue;
            }
            int rr = peer_recv_loop(s);
            if (s->closing) break;
            if (rr == 0) break;
            mutex_lock(&s->peer_lk);
            peer_close_locked(s);
            mutex_unlock(&s->peer_lk);
            LOG("B side peer link down, waiting for reconnect sid=%llu", (unsigned long long)s->sid);
        }
        session_terminate(s);
        thread_join(th2);
        session_stop_sender(s);
        b_unregister(s);
        session_release(s);
        return 0;
    }
    else if (h.type == MSG_RESUME) {
        uint64_t sid = h.value;
        uint64_t peer_recv = (h.plen >= 8) ? sw64(*(uint64_t*)pl) : 0;
        free(pl);
        sess_t* s = b_find(sid);
        if (!s) {
            LOG("RESUME: session not found sid=%llu", (unsigned long long)sid);
            send_close_and_wait_peer(pfd, sid); closesock(pfd); return 0;
        }
        mutex_lock(&s->recv_lk); uint64_t myrecv = s->recv_off; mutex_unlock(&s->recv_lk);
        uint64_t be = sw64(myrecv);
        if (send_frame(pfd, MSG_RESUME_ACK, sid, &be, 8) < 0) {
            session_release(s);
            closesock(pfd);
            return 0;
        }
        sw_drop_to(&s->out, peer_recv);
        mutex_lock(&s->peer_lk);              /* 原子: 重置 sent + 换 peer_fd */
        mutex_lock(&s->out.lk);
        s->out.sent = (peer_recv > s->out.base) ? peer_recv : s->out.base;
        mutex_unlock(&s->out.lk);
        sock_t old = s->peer_fd;
        peer_install_locked(s, pfd);
        mutex_unlock(&s->peer_lk);
        if (old != BADSOCK) closesock(old);
        s->down_since = 0;
        notify_send(s);
        LOG("B side session sid=%llu buffer accumulation len=%llu", (unsigned long long)sid, (unsigned long long)s->out.len);
        session_release(s);
        return 0;
    }
    LOG("peer/server: unsupported first frame type=%u", (unsigned)h.type);
    free(pl); closesock(pfd); return 0;
}

/* ============================================================
 *  Connection dispatch (peek first byte: HTTP vs frame)
 * ============================================================ */
static void* dispatch(void* arg) {
    sock_t fd = (sock_t)(intptr_t)arg;
    char c; int r = recv(fd, &c, 1, MSG_PEEK);
    if (r <= 0) { closesock(fd); return 0; }
    if (is_peer_msg_type((uint8_t)c))
        handle_peer((void*)(intptr_t)fd);
    else
        handle_client((void*)(intptr_t)fd);
    return 0;
}

static void print_help(const char* prog) {
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\n"
        "A peer-to-peer HTTP relay with reconnect and in-memory resume buffering.\n"
        "Supports IPv6 and cross-platform (Linux/Windows).\n"
        "\n"
        "OPTIONS:\n"
        "  -p PORT              Listen port (default: 8080)\n"
        "  -b BYTES             Max buffer size per direction in bytes (default: 64MB)\n"
        "  -t SECONDS           Reconnect timeout in seconds (default: 60s)\n"
        "  -i MILLISECONDS      Delay between reconnect attempts (default: 500ms)\n"
        "\n"
        "  Client-side timeout (HTTP client <-> relay, relay <-> target):\n"
        "  -cc SECONDS          Client connect timeout (default: 10s)\n"
        "  -cio SECONDS         Client I/O timeout (default: 120s)\n"
        "\n"
        "  Peer-side timeout (relay <-> relay):\n"
        "  -pc SECONDS          Peer connect timeout (default: 10s)\n"
        "  -pio SECONDS         Peer I/O and heartbeat timeout (default: 20s)\n"
        "  -hi SECONDS          Peer heartbeat interval, minimum 1s (default: 5s)\n"
        "  -k PASSWORD          Encrypt A<->B peer payloads with AES-CTR\n"
        "  --insecure-upstream-tls\n"
        "                        Disable certificate verification for B->HTTPS target\n"
        "                        Otherwise place cacert.pem next to the program\n"
        "\n"
        "  -h, --help           Show this help message\n"
        "\n"
        "EXAMPLES:\n"
        "  # Listen on port 8080 with default settings\n"
        "  %s -p 8080\n"
        "\n"
        "  # Client side: fast timeout for local connections, Peer side: slow timeout for WAN\n"
        "  %s -p 8080 -cc 5 -cio 10 -pc 60 -pio 120\n"
        "\n"
        "  # Large buffer for slow peer, tight timeouts for clients\n"
        "  %s -p 8080 -b 1073741824 -pc 60 -pio 180 -cc 5 -cio 15\n"
        "\n"
        "QUICK START:\n"
        "  1. Start relay on Host A (listening on port 8080):\n"
        "     Host_A$ %s -p 8080\n"
        "\n"
        "  2. Start relay on Host B (same port):\n"
        "     Host_B$ %s -p 8080\n"
        "\n"
        "  3. Client connects to A:\n"
        "     http://HOST_A:8080/relay/HOST_B:8080/TARGET_HOST:TARGET_PORT/path\n"
        "\n"
        "  Example (IPv4):\n"
        "     http://192.168.1.1:8080/relay/192.168.1.2:8080/10.0.0.5:9090/download/file.zip\n"
        "\n"
        "  Example (IPv6):\n"
        "     http://[::1]:8080/relay/[2001:db8::1]:8080/[fe80::2]:9090/path\n"
        "\n"
        "URL FORMAT:\n"
        "  /relay/<PEER_HOST:PEER_PORT>/<TARGET_HOST:TARGET_PORT>/<ORIGINAL_PATH>\n"
        "\n"
        "  PEER_HOST:PEER_PORT       Address of the other relay (B side)\n"
        "  TARGET_HOST:TARGET_PORT   Address of the actual target server\n"
        "  /ORIGINAL_PATH            Path to forward to the target\n"
        "\n"
        "FEATURES:\n"
        "  Automatic reconnection with in-memory buffering\n"
        "  Supports HTTP keep-alive and request pipelining\n"
        "  Optional AES-CTR encryption for relay-to-relay payloads\n"
        "  IPv4 and IPv6 dual-stack support\n"
        "  Cross-platform: Linux (gcc) and Windows (MinGW/MSVC)\n"
        "  Only Host header is rewritten; other headers forwarded as-is\n"
        "\n"
        "BEHAVIOR:\n"
        "  Both A and B run the same program on the same port\n"
        "  Client connects to A with the relay peer address (B) and target in the URL\n"
        "  A connects to B, B connects to the target\n"
        "  If A-B link drops, A automatically reconnects and resumes from last byte\n"
        "  Data is buffered in RAM; if buffer fills or reconnect times out, connections close\n"
        "\n"
        "SECURITY NOTE:\n"
        "  Use -k with the same password on both relays to encrypt peer payloads.\n"
        "  Without -k, relay-to-relay payloads are sent in plaintext.\n"
        "\n",
        prog, prog, prog, prog, prog, prog
    );
}

/* ============================================================
 *  main
 * ============================================================ */
int main(int argc, char** argv) {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }
#else
    signal(SIGPIPE, SIG_IGN);
#endif
    mutex_init(&g_tbl_lk);
    mutex_init(&g_gen_sid_lk);
    init_cacert_path(argv[0]);

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p") && i + 1 < argc)
            g_port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-b") && i + 1 < argc)
            g_max_buffer = (size_t)strtoull(argv[++i], 0, 10);
        else if (!strcmp(argv[i], "-t") && i + 1 < argc)
            g_reconnect_timeout = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-i") && i + 1 < argc)
            g_reconnect_ms = atoi(argv[++i]);
        /* Client 超时 */
        else if (!strcmp(argv[i], "-cc") && i + 1 < argc)
            g_client_connect_timeout = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-cio") && i + 1 < argc)
            g_client_io_timeout = atoi(argv[++i]);
        /* Peer 超时 */
        else if (!strcmp(argv[i], "-pc") && i + 1 < argc)
            g_peer_connect_timeout = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-pio") && i + 1 < argc)
            g_peer_io_timeout = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-hi") && i + 1 < argc)
            g_heartbeat_interval = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-k") && i + 1 < argc)
            crypto_set_password(argv[++i]);
        else if (!strcmp(argv[i], "--insecure-upstream-tls"))
            g_insecure_upstream_tls = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_help(argv[0]);
            return 0;
        }
        else {
            fprintf(stderr, "Usage: %s [-p port] [-b max_buffer_bytes] [-t reconnect_timeout_sec] [-i reconnect_ms]\n"
                "          [-cc client_connect_timeout] [-cio client_io_timeout]\n"
                "          [-pc peer_connect_timeout] [-pio peer_io_timeout]\n"
                "          [-hi heartbeat_interval] [-k password] [--insecure-upstream-tls]\n", argv[0]);
            return 1;
        }
    }

    normalize_timeouts();

    sock_t lfd = listen_on(g_port);
    if (lfd == BADSOCK) {
        fprintf(stderr, "failed to listen on port %d (err=%d)\n", g_port, sockerrno);
        return 1;
    }
    LOG("httprelay listening on :%d  max_buffer=%zu reconnect_timeout=%ds",
        g_port, g_max_buffer, g_reconnect_timeout);
    LOG("client timeout: connect=%ds, io=%ds", g_client_connect_timeout, g_client_io_timeout);
    LOG("peer timeout: connect=%ds, io=%ds", g_peer_connect_timeout, g_peer_io_timeout);
    LOG("peer heartbeat: interval=%ds, timeout follows peer io timeout", g_heartbeat_interval);
    LOG("peer encryption: %s", g_crypto_enabled ? "AES-CTR enabled" : "disabled");
    LOG("upstream TLS verification: %s", g_insecure_upstream_tls ? "disabled (insecure)" : "enabled");
    if (!g_insecure_upstream_tls) LOG("upstream TLS CA bundle: put cacert.pem next to the program (%s)", g_cacert_path);

    for (;;) {
        sock_t fd = accept(lfd, NULL, NULL);
        if (fd == BADSOCK) {
            if (sockerrno == SOCK_EINTR)continue;
            fprintf(stderr, "accept failed (err=%d)\n", sockerrno);
            break;
        }
        thread_t t;
        if (thread_create(&t, dispatch, (void*)(intptr_t)fd) == 0)
            thread_detach(t);
        else
            closesock(fd);
    }

    mutex_destroy(&g_tbl_lk);
    mutex_destroy(&g_gen_sid_lk);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}
