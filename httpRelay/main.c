#define _CRT_SECURE_NO_WARNINGS
/*
 * httprelay.c -- Peer-to-peer HTTP relay with reconnect + in-memory resume buffering (cross-platform, IPv6).
 *
 * Build (Linux / gcc):
 *   gcc -O2 -o httprelay httprelay.c -lpthread
 *
 * Build (Windows / MinGW-w64):
 *   gcc -O2 -o httprelay.exe httprelay.c -lws2_32
 *
 * Build (Windows / MSVC):
 *   cl /O2 httprelay.c        (ws2_32 is linked automatically via pragma)
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

 /* ============================================================
  *  Platform abstraction layer
  * ============================================================ */
#ifdef _WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600   /* Vista+ : IPv6 / getaddrinfo */
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <process.h>
#pragma comment(lib, "ws2_32.lib")

typedef SOCKET sock_t;
#define BADSOCK INVALID_SOCKET
#define closesock closesocket
#ifndef SHUT_RDWR
#define SHUT_RDWR SD_BOTH
#endif
#define sockerrno WSAGetLastError()
#define SOCK_EINTR  WSAEINTR
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

typedef HANDLE thread_t;
typedef CRITICAL_SECTION mutex_t;
static int  mutex_init(mutex_t* m) { InitializeCriticalSection(m); return 0; }
static void mutex_lock(mutex_t* m) { EnterCriticalSection(m); }
static void mutex_unlock(mutex_t* m) { LeaveCriticalSection(m); }
static void mutex_destroy(mutex_t* m) { DeleteCriticalSection(m); }

typedef struct { void* (*fn)(void*); void* arg; } thr_wrap_t;
static unsigned __stdcall thr_trampoline(void* p) {
    thr_wrap_t* w = (thr_wrap_t*)p; void* (*fn)(void*) = w->fn; void* a = w->arg; free(w);
    fn(a); return 0;
}
static int thread_create(thread_t* t, void* (*fn)(void*), void* arg) {
    thr_wrap_t* w = (thr_wrap_t*)malloc(sizeof(*w)); if (!w)return -1; w->fn = fn; w->arg = arg;
    uintptr_t h = _beginthreadex(NULL, 0, thr_trampoline, w, 0, NULL);
    if (!h) { free(w); return -1; }
    *t = (HANDLE)h; return 0;
}
static void thread_join(thread_t t) { WaitForSingleObject(t, INFINITE); CloseHandle(t); }
static void thread_detach(thread_t t) { CloseHandle(t); }
static void sleep_ms(int ms) { Sleep(ms); }

typedef CONDITION_VARIABLE cond_t;
static int  cond_init(cond_t* c) { InitializeConditionVariable(c); return 0; }
static void cond_destroy(cond_t* c) { (void)c; /* no-op on Windows */ }
static void cond_signal(cond_t* c) { WakeConditionVariable(c); }
static int  cond_wait_ms(cond_t* c, mutex_t* m, int ms) {
    /* mutex_t 在 Windows 是 CRITICAL_SECTION */
    BOOL ok = SleepConditionVariableCS(c, m, (DWORD)ms);
    return ok ? 0 : 1;   /* 超时/失败返回非0 */
}

static void* memmem_compat(const void* h, size_t hl, const void* n, size_t nl) {
    if (nl == 0) return (void*)h;
    if (hl < nl) return NULL;
    const unsigned char* hp = (const unsigned char*)h;
    const unsigned char* np = (const unsigned char*)n;
    for (size_t i = 0; i + nl <= hl; i++)
        if (hp[i] == np[0] && memcmp(hp + i, np, nl) == 0) return (void*)(hp + i);
    return NULL;
}

#define memmem memmem_compat

#ifdef _MSC_VER
#define strncasecmp _strnicmp
#endif

#else  /* ---------------- POSIX (Linux) ---------------- */
#define _GNU_SOURCE
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>

typedef int sock_t;
#define BADSOCK (-1)
#define closesock close
#define sockerrno errno
#define SOCK_EINTR EINTR

typedef pthread_t thread_t;
typedef pthread_mutex_t mutex_t;
static int  mutex_init(mutex_t* m) { return pthread_mutex_init(m, NULL); }
static void mutex_lock(mutex_t* m) { pthread_mutex_lock(m); }
static void mutex_unlock(mutex_t* m) { pthread_mutex_unlock(m); }
static void mutex_destroy(mutex_t* m) { pthread_mutex_destroy(m); }
static int  thread_create(thread_t* t, void* (*fn)(void*), void* arg) { return pthread_create(t, NULL, fn, arg); }
static void thread_join(thread_t t) { pthread_join(t, NULL); }
static void thread_detach(thread_t t) { pthread_detach(t); }
static void sleep_ms(int ms) { usleep(ms * 1000); }

typedef pthread_cond_t  cond_t;
static int  cond_init(cond_t* c) { return pthread_cond_init(c, NULL); }
static void cond_destroy(cond_t* c) { pthread_cond_destroy(c); }
static void cond_signal(cond_t* c) { pthread_cond_signal(c); }
/* 在持有 mutex 的情况下等待，带超时(毫秒)，超时返回非0 */
static int  cond_wait_ms(cond_t* c, mutex_t* m, int ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += ms / 1000;
    ts.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    return pthread_cond_timedwait(c, m, &ts);
}
#endif

/* ============================================================
 *  Common headers
 * ============================================================ */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>

 /* ============================================================
  *  Configurable parameters
  * ============================================================ */
static int    g_port = 8080;
static size_t g_max_buffer = 64 * 1024 * 1024;  /* max in-flight buffer per direction */
static int    g_reconnect_timeout = 60;            /* seconds before giving up reconnection */
static int    g_reconnect_ms = 500;           /* delay between reconnect attempts */
#define IO_CHUNK 32768

static int64_t now_ms(void) {
#ifdef _WIN32
    return (int64_t)GetTickCount64();
#else
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
#endif
}

#define LOG(f,...) do{ fprintf(stderr,"[%lld] " f "\n",(long long)now_ms(),##__VA_ARGS__); }while(0)

/* ============================================================
 *  A<->B frame protocol
 * ============================================================ */
enum {
    MSG_OPEN = 1, MSG_RESUME = 2, MSG_RESUME_ACK = 3, MSG_DATA = 4,
    MSG_ACK = 5, MSG_CLOSE = 6, MSG_PING = 7, MSG_PONG = 8
};

#pragma pack(push,1)
struct fhdr { uint8_t type, r1; uint16_t r2; uint64_t value; uint32_t plen; };
#pragma pack(pop)

static uint64_t sw64(uint64_t v) {
    uint64_t r; uint8_t* p = (uint8_t*)&r;
    p[0] = (uint8_t)(v >> 56); p[1] = (uint8_t)(v >> 48); p[2] = (uint8_t)(v >> 40); p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24); p[5] = (uint8_t)(v >> 16); p[6] = (uint8_t)(v >> 8); p[7] = (uint8_t)v; return r;
}
static uint32_t sw32(uint32_t v) { return((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >> 8) & 0xff00) | ((v >> 24) & 0xff); }

static int wfull(sock_t fd, const void* b, size_t n) {
    const char* p = (const char*)b; size_t s = 0;
    while (s < n) {
        int w = send(fd, p + s, (int)(n - s), MSG_NOSIGNAL);
        if (w < 0) { if (sockerrno == SOCK_EINTR)continue; return -1; } s += (size_t)w;
    }
    return 0;
}
static int rfull(sock_t fd, void* b, size_t n) {
    char* p = (char*)b; size_t g = 0;
    while (g < n) {
        int r = recv(fd, p + g, (int)(n - g), 0);
        if (r == 0) return 0; if (r < 0) { if (sockerrno == SOCK_EINTR) continue; return -1; } g += (size_t)r;
    }
    return 1;
}
static void nodelay_on(sock_t fd) { int o = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (const char*)&o, sizeof o); }

static int send_frame(sock_t fd, uint8_t t, uint64_t v, const void* pl, uint32_t pn) {
    struct fhdr h; h.type = t; h.r1 = 0; h.r2 = 0; h.value = sw64(v); h.plen = sw32(pn);
    if (wfull(fd, &h, sizeof h) < 0) return -1;
    if (pn && pl)return wfull(fd, pl, pn);
    return 0;
}

static int recv_frame(sock_t fd, struct fhdr* h, char** pl) {
    int r = rfull(fd, h, sizeof * h); if (r <= 0) return r;
    h->value = sw64(h->value); h->plen = sw32(h->plen); *pl = NULL;
    if (h->plen) {
        if (h->plen > 64u * 1024 * 1024) return -1;
        *pl = (char*)malloc(h->plen); if (!*pl) return -1;
        r = rfull(fd, *pl, h->plen); if (r <= 0) { free(*pl); *pl = NULL; return r ? r : -1; }
    }
    return 1;
}

/* ============================================================
 *  Send window (retransmit buffer)
 * ============================================================ */
typedef struct {
    mutex_t lk;
    cond_t cv;
    char* buf; size_t cap, len;
    uint64_t base;    /* buf[0] 的绝对偏移 = acked */
    uint64_t high;    /* 已产生数据的最高偏移 */
    uint64_t acked;   /* 对端已确认偏移 */
    uint64_t sent;    /* 已发送到当前 peer 连接的偏移 (重连时重置为 base 或 peer_recv) */
}sw_t;
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

/*
 * Append data to send window. Block if buffer would exceed limit.
 *
 * Return:
 *   0      : success, *off = absolute offset of appended data
 *  -1      : session closing or error
 *  -2      : timeout (not used in this version, returns -1 on timeout)
 */
static int sw_append(sw_t* s, const void* d, size_t n, size_t mx, uint64_t* off,
    volatile int* closing) {
    if (!d || n == 0) return 0;

    mutex_lock(&s->lk);

    /* Wait until there's space in buffer or closing signal */
    while (s->len + n > mx && !*closing) {
        LOG("sw_append: buffer full (%zu + %zu > %zu), waiting for ACK...",
            s->len, n, mx);
        int rc = cond_wait_ms(&s->cv, &s->lk, 1000);  /* 1s timeout per wait */
        if (*closing) {
            mutex_unlock(&s->lk);
            return -1;
        }
        /* 即使超时也继续等待，除非 closing 被设置 */
    }

    if (*closing) {
        mutex_unlock(&s->lk);
        return -1;
    }

    /* Now we have space (or are closing) */
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

/*
 * Signal that data has been ACKed, wake up waiters in sw_append
 */
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

        /*  Wake up any threads blocked in sw_append */
        cond_signal(&s->cv);
    }
    mutex_unlock(&s->lk);
}

/* ============================================================
 *  Session
 * ============================================================ */
typedef struct {
    sock_t app_fd;            /* application side: A=client, B=target */
    sock_t peer_fd;           /* A<->B TCP, BADSOCK when down */
    mutex_t peer_lk;
    sw_t out;                 /* our -> peer send window */
    uint64_t recv_off;        /* offset of data we have contiguously received from peer */
    mutex_t recv_lk;
    volatile int closing;     /* session terminating */
    volatile int terminated;  // 是否已完成终止
    mutex_t term_lk;          // 终止专用锁
    int64_t down_since;       /* time (ms) the peer link went down, 0 if up */
    int is_initiator;         /* 1 = A side */
    char ph[256], pp[32];      /* peer host/port (A side only) */
    uint64_t sid;
    char* open_pl; uint32_t open_len;   /* OPEN payload (A side only) */
    volatile int opened;

    /* ---- 发送线程相关 ---- */
    mutex_t   send_lk;        /* 配合 send_cv 使用 */
    cond_t    send_cv;        /* 有新数据可发 / 需要 flush 的信号 */
    volatile int send_dirty;  /* 标记: 有待发送数据 (避免丢失唤醒) */
    thread_t  send_thr;       /* 发送线程句柄 */
    volatile int send_running;

    mutex_t   ref_lk;       /* 保护 refcnt（也可用原子操作替代）*/
    int       refcnt;       /* 引用计数 */
}sess_t;

static void* sender_thread(void* arg);

static void session_init(sess_t* s) {
    swi(&s->out);
    mutex_init(&s->peer_lk);
    mutex_init(&s->recv_lk);
    mutex_init(&s->send_lk);
    mutex_init(&s->term_lk);
    cond_init(&s->send_cv);
    s->send_dirty = 0;
    s->refcnt = 1;                 /* owner持有的引用 */
    mutex_init(&s->ref_lk);
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
    cond_destroy(&s->send_cv);
    if (s->open_pl) {
        free(s->open_pl);
        s->open_pl = NULL;
        s->open_len = 0;
    }
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

    LOG("session terminate sid=%llu", (unsigned long long)s->sid);

    /* app 侧: 双向关闭唤醒 t_app2peer 的 recv 和 handle_frame 的 wfull */
    if (s->app_fd != BADSOCK) shutdown(s->app_fd, SHUT_RDWR);

    /* peer 侧: 唤醒 peer_recv_loop 的 recv */
    mutex_lock(&s->peer_lk);
    if (s->peer_fd != BADSOCK) shutdown(s->peer_fd, SHUT_RDWR);
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
        if (s->app_fd != BADSOCK) closesock(s->app_fd);
        if (s->peer_fd != BADSOCK) closesock(s->peer_fd);
        session_uninit(s);          /* 销毁 recv_lk/peer_lk/send_lk/send_cv/out 等 */
        mutex_destroy(&s->ref_lk);
        LOG("session_release ok sid=%llu", s->sid);
        free(s);
    }
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
        while (!s->send_dirty && !s->closing) {
            cond_wait_ms(&s->send_cv, &s->send_lk, 1000);   /* 1s 超时以便周期性检查 closing */
        }
        int closing = s->closing;
        s->send_dirty = 0;          /* 清标记 (在锁内清, 避免丢唤醒) */
        mutex_unlock(&s->send_lk);

        if (closing) break;

        /* 执行 flush。peer_fd 可能为 BADSOCK(断开中)，那就什么都不发，
           等重连后 a_peer_thread/resume 会重置 sent 并 notify。 */
        mutex_lock(&s->peer_lk);
        if (s->peer_fd != BADSOCK) {
            if (sw_flush_locked_peer(s) < 0) {
                closesock(s->peer_fd); s->peer_fd = BADSOCK;
                if (!s->down_since)s->down_since = now_ms();
            }
        }
        mutex_unlock(&s->peer_lk);
    }
    return NULL;
}




/* ============================================================
 *  Address resolution / connect / listen
 * ============================================================ */
static sock_t connect_host(const char* h, const char* p) {
    struct addrinfo hi, * r = NULL, * rp; memset(&hi, 0, sizeof hi);
    hi.ai_family = AF_UNSPEC; hi.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(h, p, &hi, &r) != 0)return BADSOCK;
    sock_t fd = BADSOCK;
    for (rp = r; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd == BADSOCK)continue;
        if (connect(fd, rp->ai_addr, (int)rp->ai_addrlen) == 0)break;
        closesock(fd); fd = BADSOCK;
    }
    freeaddrinfo(r);
    if (fd != BADSOCK)nodelay_on(fd);
    return fd;
}
static sock_t listen_on(int port) {
    char portstr[16]; snprintf(portstr, sizeof portstr, "%d", port);
    sock_t fd = socket(AF_INET6, SOCK_STREAM, 0);
    int o = 1;
    if (fd != BADSOCK) {
        int v6 = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&v6, sizeof v6); /* dual stack */
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
    if (bind(fd, (struct sockaddr*)&a, sizeof a) < 0 || listen(fd, 128) < 0) { closesock(fd); return BADSOCK; }
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

/* parse "host:port" or "[v6]:port" */
static void parse_hp(const char* s, char* host, char* port) {
    if (*s == '[') {
        const char* e = strchr(s, ']');
        if (e) {
            size_t l = (size_t)(e - s - 1); memcpy(host, s + 1, l); host[l] = 0;
            const char* c = strchr(e, ':'); snprintf(port, 32, "%s", c ? c + 1 : "80"); return;
        }
    }
    const char* c = strrchr(s, ':');
    if (c) { size_t l = (size_t)(c - s); memcpy(host, s, l); host[l] = 0; snprintf(port, 32, "%s", c + 1); }
    else { snprintf(host, 256, "%s", s); strcpy(port, "80"); }
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
    char** out_rw, uint32_t* out_rl) {
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

    /* 第 2 段: target，从 sl1+1 到下一个 '/'(或字符串结尾) */
    char* tstart = sl1 + 1;
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
    parse_hp(targ_s, th, tp);

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


/* Used by B side (target->B->A) and as a generic app->peer pump. */
static void* t_app2peer(void* a) {
    sess_t* s = (sess_t*)a; char* c = (char*)malloc(IO_CHUNK);
    for (;;) {
        int r = recv(s->app_fd, c, IO_CHUNK, 0);
        if (r <= 0) { break; }
        uint64_t off;
        int rc = sw_append(&s->out, c, (size_t)r, g_max_buffer, &off,
            (volatile int*)&s->closing);
        if (rc < 0) {
            break;
        }
        notify_send(s);
    }
    free(c);
    mutex_lock(&s->peer_lk);
    if (s->peer_fd != BADSOCK) send_frame(s->peer_fd, MSG_CLOSE, s->sid, 0, 0);
    mutex_unlock(&s->peer_lk);
    session_terminate(s);
    return NULL;
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
            if (wfull(s->app_fd, d, use) < 0) { 
                free(pl); session_terminate(s); return 0; 
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
    case MSG_CLOSE: free(pl); session_terminate(s); return 0;
    case MSG_PING:
        mutex_lock(&s->peer_lk);
        if (s->peer_fd != BADSOCK) send_frame(s->peer_fd, MSG_PONG, h->value, 0, 0);
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
typedef struct {
    sock_t fd;
    char* buf;
    size_t cap, len, off;
} httpin_t;

static void hin_init(httpin_t* h, sock_t fd) {
    h->fd = fd; h->cap = 8192; h->len = 0; h->off = 0; h->buf = (char*)malloc(h->cap);
}
static void hin_free(httpin_t* h) { free(h->buf); h->buf = NULL; }
static void hin_compact(httpin_t* h) {
    if (h->off > 0) { memmove(h->buf, h->buf + h->off, h->len - h->off); h->len -= h->off; h->off = 0; }
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
        int r = recv(h->fd, h->buf + h->len, (int)(h->cap - h->len - 1), 0);
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
        int r = recv(h->fd, h->buf + h->len, (int)(h->cap - h->len - 1), 0);
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

static uint64_t gen_sid(void) {
    static uint64_t c = 0;
    mutex_lock(&g_gen_sid_lk);
    uint64_t v = (((uint64_t)now_ms()) << 16) ^ (++c);
    mutex_unlock(&g_gen_sid_lk);
    return v;
}


static sock_t peer_connect_and_hs(sess_t* s, int resume) {
    sock_t fd = connect_host(s->ph, s->pp); if (fd == BADSOCK) return BADSOCK;
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
        s->peer_fd = fd;                    /* 装上连接, 此刻 sent 已正确 */
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
                s->peer_fd = fd;
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
        if (s->peer_fd != BADSOCK) { closesock(s->peer_fd); s->peer_fd = BADSOCK; }
        mutex_unlock(&s->peer_lk);
        if (!s->down_since)s->down_since = now_ms();
        LOG("peer link down, will reconnect sid=%llu", (unsigned long long)s->sid);
    }
    return NULL;
}


/* ============================================================
 *  A side: client handler (keep-alive aware)
 * ============================================================ */
static void* handle_client(void* arg) {
    sock_t cfd = (sock_t)(intptr_t)arg; nodelay_on(cfd);
    httpin_t in; hin_init(&in, cfd);

    char* hdr; size_t he;
    if (hin_read_headers(&in, &hdr, &he) < 0) { hin_free(&in); closesock(cfd); return 0; }

    char ph[256], pp[32], th[256], tp[32]; char* rw = NULL; uint32_t rl = 0;
    if (rewrite_request(hdr, he, ph, pp, th, tp, &rw, &rl) < 0) {
        const char* e = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
        wfull(cfd, e, strlen(e)); hin_free(&in); closesock(cfd); return 0;
    }

    sess_t* s = (sess_t*)calloc(1, sizeof * s);
    session_init(s);
    s->app_fd = cfd; s->peer_fd = BADSOCK; s->is_initiator = 1; s->sid = gen_sid();
    snprintf(s->ph, sizeof s->ph, "%s", ph); snprintf(s->pp, sizeof s->pp, "%s", pp);

    char tgt[400]; int v6 = strchr(th, ':') != NULL;
    if (v6)snprintf(tgt, sizeof tgt, "[%s]:%s\n", th, tp); else snprintf(tgt, sizeof tgt, "%s:%s\n", th, tp);
    size_t tl = strlen(tgt);
    s->open_len = (uint32_t)(tl + rl); s->open_pl = (char*)malloc(s->open_len);
    memcpy(s->open_pl, tgt, tl); memcpy(s->open_pl + tl, rw, rl);
    free(rw);

    LOG("new client session sid=%llu -> peer %s:%s target %s:%s",
        (unsigned long long)s->sid, ph, pp, th, tp);

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
            send_frame(s->peer_fd, MSG_CLOSE, s->sid, 0, 0);
            break;
        }
        char ph2[256], pp2[32], th2[256], tp2[32]; char* rw2 = NULL; uint32_t rl2 = 0;
        if (rewrite_request(h2, he2, ph2, pp2, th2, tp2, &rw2, &rl2) < 0) {
            const char* e = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n";
            wfull(cfd, e, strlen(e));
            in.off += he2;
            continue;
        }
        if (strcmp(ph2, ph) || strcmp(pp2, pp) || strcmp(th2, th) || strcmp(tp2, tp)) {
            free(rw2);
            const char* e = "HTTP/1.1 421 Misdirected Request\r\nContent-Length: 0\r\n\r\n";
            wfull(cfd, e, strlen(e)); break;
        }
        in.off += he2;
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
    struct fhdr h; char* pl = NULL; int r = recv_frame(pfd, &h, &pl);
    if (r <= 0) { free(pl); closesock(pfd); return 0; }

    if (h.type == MSG_OPEN) {
        char* nl = (char*)memchr(pl, '\n', h.plen);
        if (!nl) { free(pl); closesock(pfd); return 0; }
        size_t addrlen = (size_t)(nl - pl); char addr[400];
        if (addrlen >= sizeof addr)addrlen = sizeof addr - 1;
        memcpy(addr, pl, addrlen); addr[addrlen] = 0;
        char th[256], tp[32]; parse_hp(addr, th, tp);

        sock_t tfd = connect_host(th, tp);
        if (tfd == BADSOCK) {
            LOG("connect to target %s:%s failed", th, tp); free(pl);
            send_frame(pfd, MSG_CLOSE, h.value, 0, 0); closesock(pfd); return 0;
        }
        nodelay_on(tfd);

        char* req = nl + 1; size_t reqlen = h.plen - addrlen - 1;
        if (wfull(tfd, req, reqlen) < 0) { free(pl); closesock(tfd); closesock(pfd); return 0; }
        free(pl);

        sess_t* s = (sess_t*)calloc(1, sizeof * s);
        session_init(s);
        s->app_fd = tfd; s->peer_fd = pfd; s->is_initiator = 0; s->sid = h.value;
        LOG("passive session sid=%llu target %s:%s", (unsigned long long)s->sid, th, tp);
        b_register(s);
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
            if (s->peer_fd != BADSOCK) { closesock(s->peer_fd); s->peer_fd = BADSOCK; }
            mutex_unlock(&s->peer_lk);
            if (!s->down_since)s->down_since = now_ms();
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
            send_frame(pfd, MSG_CLOSE, sid, 0, 0); closesock(pfd); return 0;
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
        sock_t old = s->peer_fd; s->peer_fd = pfd;
        mutex_unlock(&s->peer_lk);
        if (old != BADSOCK) closesock(old);
        s->down_since = 0;
        notify_send(s);
        LOG("B side session sid=%llu buffer accumulation len=%llu", (unsigned long long)sid, (unsigned long long)s->out.len);
        session_release(s);
        return 0;
    }
    free(pl); closesock(pfd); return 0;
}

/* ============================================================
 *  Connection dispatch (peek first byte: HTTP vs frame)
 * ============================================================ */
static void* dispatch(void* arg) {
    sock_t fd = (sock_t)(intptr_t)arg;
    char c; int r = recv(fd, &c, 1, MSG_PEEK);
    if (r <= 0) { closesock(fd); return 0; }
    if ((unsigned char)c >= MSG_OPEN && (unsigned char)c <= MSG_PONG)
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
        "                       Examples: 104857600 (100MB), 1073741824 (1GB)\n"
        "  -t SECONDS           Reconnect timeout in seconds (default: 60s)\n"
        "  -i MILLISECONDS      Delay between reconnect attempts (default: 500ms)\n"
        "  -h, --help           Show this help message\n"
        "\n"
        "EXAMPLES:\n"
        "  # Listen on port 8080 with default settings\n"
        "  %s -p 8080\n"
        "\n"
        "  # Set buffer to 512MB, reconnect timeout to 120s\n"
        "  %s -p 8080 -b 536870912 -t 120\n"
        "\n"
        "  # Aggressive reconnect: try every 100ms, timeout after 30s\n"
        "  %s -p 8080 -i 100 -t 30\n"
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
        "  This relay performs NO authentication. Use only on trusted networks or\n"
        "  add your own allow-list / token check in the code.\n"
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
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { fprintf(stderr, "WSAStartup failed\n"); return 1; }
#else
    signal(SIGPIPE, SIG_IGN);
#endif
    mutex_init(&g_tbl_lk);
    mutex_init(&g_gen_sid_lk);

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-p") && i + 1 < argc)g_port = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-b") && i + 1 < argc)g_max_buffer = (size_t)strtoull(argv[++i], 0, 10);
        else if (!strcmp(argv[i], "-t") && i + 1 < argc)g_reconnect_timeout = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-i") && i + 1 < argc)g_reconnect_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            print_help(argv[0]);
            return 0;
        }
        else { fprintf(stderr, "Usage: %s [-p port] [-b max_buffer_bytes] [-t reconnect_timeout_sec] [-i reconnect_ms]\n", argv[0]); return 1; }
    }

    sock_t lfd = listen_on(g_port);
    if (lfd == BADSOCK) { fprintf(stderr, "failed to listen on port %d (err=%d)\n", g_port, sockerrno); return 1; }
    LOG("httprelay listening on :%d  max_buffer=%zu reconnect_timeout=%ds",
        g_port, g_max_buffer, g_reconnect_timeout);

    for (;;) {
        sock_t fd = accept(lfd, NULL, NULL);
        if (fd == BADSOCK) {
            if (sockerrno == SOCK_EINTR)continue;
            fprintf(stderr, "accept failed (err=%d)\n", sockerrno); break;
        }
        thread_t t;
        if (thread_create(&t, dispatch, (void*)(intptr_t)fd) == 0) thread_detach(t);
        else closesock(fd);
    }

    mutex_destroy(&g_tbl_lk);
    mutex_destroy(&g_gen_sid_lk);
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}