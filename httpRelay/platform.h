#ifndef HTTPRELAY_PLATFORM_H
#define HTTPRELAY_PLATFORM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <time.h>

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
#ifndef SHUT_WR
#define SHUT_WR SD_SEND
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
static void cond_destroy(cond_t* c) { (void)c; }
static void cond_signal(cond_t* c) { WakeConditionVariable(c); }
static int  cond_wait_ms(cond_t* c, mutex_t* m, int ms) {
    BOOL ok = SleepConditionVariableCS(c, m, (DWORD)ms);
    return ok ? 0 : 1;
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

#else
#define _GNU_SOURCE
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <signal.h>
#include <fcntl.h>

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

typedef pthread_cond_t cond_t;
static int  cond_init(cond_t* c) { return pthread_cond_init(c, NULL); }
static void cond_destroy(cond_t* c) { pthread_cond_destroy(c); }
static void cond_signal(cond_t* c) { pthread_cond_signal(c); }
static int  cond_wait_ms(cond_t* c, mutex_t* m, int ms) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += ms / 1000;
    ts.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    return pthread_cond_timedwait(c, m, &ts);
}
#endif

#endif
