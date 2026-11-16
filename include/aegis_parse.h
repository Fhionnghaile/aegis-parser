#ifndef AEGIS_PARSE_H
#define AEGIS_PARSE_H
#include <stddef.h>

/* A view into the caller's buffer — no copy, no ownership, no NUL assumption. */
typedef struct { const char *p; size_t n; } slice_t;

typedef struct {
    slice_t remote_addr, remote_user, time_local;
    slice_t method, path, protocol;   /* split out of the quoted request */
    slice_t referer, user_agent;
    long    status;       /* -1 if absent / non-numeric */
    long    body_bytes;   /* -1 if "-" or non-numeric   */
} access_log_t;

enum {
    AEGIS_OK          =  0,
    AEGIS_ERR_SHORT   = -1,   /* truncated before a field completed */
    AEGIS_ERR_FORMAT  = -2,   /* structural: missing quote/bracket  */
    AEGIS_ERR_REQUEST = -3    /* request not exactly method path proto */
};

/* Parse ONE combined-log line. Returns 0 on success, negative on malformed.
   Never reads past buf[len). Writes only into *out. Zero allocation. */
int aegis_parse_access_log(const char *buf, size_t len, access_log_t *out);

#endif
