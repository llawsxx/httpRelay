#ifndef HTTPRELAY_LOG_H
#define HTTPRELAY_LOG_H

#include "platform.h"

static int64_t now_ms(void) {
#ifdef _WIN32
    return (int64_t)GetTickCount64();
#else
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
#endif
}

static void format_log_time(char* buf, size_t len) {
#ifdef _WIN32
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(buf, len, "%04u-%02u-%02u %02u:%02u:%02u.%03u",
        (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay,
        (unsigned)st.wHour, (unsigned)st.wMinute, (unsigned)st.wSecond,
        (unsigned)(st.wMilliseconds));
#else
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tmv;
    localtime_r(&ts.tv_sec, &tmv);
    snprintf(buf, len, "%04d-%02d-%02d %02d:%02d:%02d.%03ld",
        tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
        tmv.tm_hour, tmv.tm_min, tmv.tm_sec, ts.tv_nsec / 1000000L);
#endif
}

#define LOG(f,...) do{ char _log_ts[32]; format_log_time(_log_ts,sizeof(_log_ts)); fprintf(stderr,"[%s] " f "\n",_log_ts,##__VA_ARGS__); }while(0)

#endif
