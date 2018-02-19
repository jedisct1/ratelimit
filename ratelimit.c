
#include <sys/types.h>
#include <sys/socket.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>

#include "ratelimit.h"

int
ratelimiter_init(RateLimiter *rate_limiter, size_t slots_len, size_t period,
                 const unsigned char key[16])
{
    if ((rate_limiter->slots =
         calloc(slots_len, sizeof *rate_limiter->slots)) == NULL) {
        return -1;
    }
    if (period < slots_len) {
        period = slots_len;
    }
    rate_limiter->slots_mask = slots_len - (uint64_t) 1U;
    rate_limiter->period = period;
    rate_limiter->pos = (size_t) 0U;
    memcpy(&rate_limiter->v0, &key[0], 8);
    memcpy(&rate_limiter->v1, &key[8], 8);

    return 0;
}

void
ratelimiter_free(RateLimiter *rate_limiter)
{
    free(rate_limiter->slots);
    memset(rate_limiter, 0, sizeof *rate_limiter);
    rate_limiter->slots = NULL;
}

#define ROTL64(X, B) rotl64((X), (B))
static inline uint64_t
rotl64(const uint64_t x, const int b)
{
    return (x << b) | (x >> (64 - b));
}

#define SIPROUND             \
    do {                     \
        v0 += v1;            \
        v1 = ROTL64(v1, 13); \
        v1 ^= v0;            \
        v0 = ROTL64(v0, 32); \
        v2 += v3;            \
        v3 = ROTL64(v3, 16); \
        v3 ^= v2;            \
        v0 += v3;            \
        v3 = ROTL64(v3, 21); \
        v3 ^= v0;            \
        v2 += v1;            \
        v1 = ROTL64(v1, 17); \
        v1 ^= v2;            \
        v2 = ROTL64(v2, 32); \
    } while (0)

static void
ratelimiter_hashes(uint64_t *i, uint64_t *j, const unsigned char ip[16],
                   uint64_t v0, uint64_t v1)
{
    uint64_t v2 = 0x736f6d6570736575ULL ^ 0x6c7967656e657261ULL ^ v0;
    uint64_t v3 = 0x646f72616e646f6dULL ^ 0x7465646279746573ULL ^ v1;
    uint64_t m;

    memcpy(&m, &ip[0], 8);
    v3 ^= m; SIPROUND; v0 ^= m;
    memcpy(&m, &ip[8], 8);
    v3 ^= m; SIPROUND; v0 ^= m;
    v2 ^= 0xff;
    SIPROUND;
    SIPROUND;
    SIPROUND;
    *i = v0 ^ v1 ^ v2 ^ v3;
    SIPROUND;
    *j = v0 ^ v1 ^ v2 ^ v3;
}

static int
ratelimit_sa_to_ip(unsigned char ip[16], const struct sockaddr *sa)
{
    struct sockaddr_in  in;
    struct sockaddr_in6 in6;

    if (sa->sa_family == AF_INET) {
        memcpy(&in, sa, sizeof in);
        memset(ip, 0, 12);
        memcpy(&ip[12], &in.sin_addr.s_addr, 4);
    } else if (sa->sa_family == AF_INET6) {
        memcpy(&in6, sa, sizeof in6);
        memcpy(ip, &in6.sin6_addr.s6_addr, 16);
    } else {
        return -1;
    }
    return 0;
}

int
ratelimiter_hit(RateLimiter *rate_limiter, const struct sockaddr *sa,
                uint64_t peak)
{
    unsigned char ip[16];
    uint64_t      slot_i, slot_j;
    int           ret;

    if (ratelimit_sa_to_ip(ip, sa) != 0) {
        return -1;
    }
    if (rate_limiter->pos <= rate_limiter->slots_mask) {
        rate_limiter->slots[rate_limiter->pos] /= 2U;
    }
    rate_limiter->pos++;
    if (rate_limiter->pos >= rate_limiter->period) {
        rate_limiter->pos = 0U;
    }
    ratelimiter_hashes(&slot_i, &slot_j, ip,
                       rate_limiter->v0, rate_limiter->v1);
    slot_i &= rate_limiter->slots_mask;
    slot_j &= rate_limiter->slots_mask;
    if (rate_limiter->slots[slot_i] < peak) {
        rate_limiter->slots[slot_i]++;
        ret = 0;
    } else {
        ret = 1;
    }
    if (rate_limiter->slots[slot_j] < peak) {
        rate_limiter->slots[slot_j]++;
        ret = 0;
    }
    return ret;
}

void
ratelimiter_rekey(RateLimiter *rate_limiter)
{
    static unsigned char tmp[16] = { 0U };

    ratelimiter_hashes(&rate_limiter->v0, &rate_limiter->v1, tmp,
                       rate_limiter->v0, rate_limiter->v1);
}
