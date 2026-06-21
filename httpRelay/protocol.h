#ifndef HTTPRELAY_PROTOCOL_H
#define HTTPRELAY_PROTOCOL_H

#include "platform.h"

enum {
    MSG_OPEN = 1, MSG_RESUME = 2, MSG_RESUME_ACK = 3, MSG_DATA = 4,
    MSG_ACK = 5, MSG_CLOSE = 6, MSG_PING = 7, MSG_PONG = 8,
    MSG_AUTH_REQ = 250, MSG_AUTH_OK = 251, MSG_AUTH_FAIL = 252
};

#pragma pack(push,1)
struct fhdr {
    uint8_t type, r1;
    uint16_t r2;
    uint64_t value;
    uint32_t plen;
};
#pragma pack(pop)

static uint64_t sw64(uint64_t v) {
    uint64_t r;
    uint8_t* p = (uint8_t*)&r;
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)v;
    return r;
}

static uint32_t sw32(uint32_t v) {
    return ((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >> 8) & 0xff00) | ((v >> 24) & 0xff);
}

#endif
