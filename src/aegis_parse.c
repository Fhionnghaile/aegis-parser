#include "aegis_parse.h"
#include <string.h>

/* bounded, NUL-free integer parse over [s,e): -1 on empty/non-numeric. */
static long parse_long(const char *s, const char *e) {
    if (s >= e) return -1;
    const char *p = s; int neg = 0;
    if (*p == '-') { neg = 1; p++; }
    else if (*p == '+') { p++; }
    if (p >= e) return -1;
    long v = 0;
    for (; p < e; p++) {
        if (*p < '0' || *p > '9') return -1;
        v = v * 10 + (*p - '0');
    }
    return neg ? -v : v;
}

/* read a space-delimited token into *sl; advance *pp. returns 0 ok, -1 if empty-at-end. */
static int token(const char **pp, const char *e, slice_t *sl) {
    const char *s = *pp;
    while (*pp < e && **pp != ' ') (*pp)++;
    sl->p = s; sl->n = (size_t)(*pp - s);
    return sl->n == 0 ? -1 : 0;
}

static void skip_sp(const char **pp, const char *e) {
    while (*pp < e && **pp == ' ') (*pp)++;
}

/* read a delimited field: expect open, capture until close (not consumed-past-end). */
static int delimited(const char **pp, const char *e, char open, char close, slice_t *sl) {
    if (*pp >= e || **pp != open) return AEGIS_ERR_FORMAT;
    (*pp)++;
    const char *s = *pp;
    while (*pp < e && **pp != close) (*pp)++;
    if (*pp >= e) return AEGIS_ERR_SHORT;   /* no closing delimiter */
    sl->p = s; sl->n = (size_t)(*pp - s);
    (*pp)++;                                 /* consume close */
    return AEGIS_OK;
}

int aegis_parse_access_log(const char *buf, size_t len, access_log_t *out) {
    memset(out, 0, sizeof(*out));
    const char *p = buf, *e = buf + len;
    slice_t tmp;

    if (token(&p, e, &out->remote_addr) != 0) return AEGIS_ERR_SHORT;
    skip_sp(&p, e);
    if (token(&p, e, &tmp) != 0) return AEGIS_ERR_SHORT;        /* identd (%l) — ignored */
    skip_sp(&p, e);
    if (token(&p, e, &out->remote_user) != 0) return AEGIS_ERR_SHORT;
    if (out->remote_user.n == 1 && out->remote_user.p[0] == '-') out->remote_user.n = 0;
    skip_sp(&p, e);

    int rc = delimited(&p, e, '[', ']', &out->time_local);
    if (rc != AEGIS_OK) return rc;
    skip_sp(&p, e);

    slice_t req;
    rc = delimited(&p, e, '"', '"', &req);
    if (rc != AEGIS_OK) return rc;
    {   /* split request into exactly method path protocol */
        const char *q = req.p, *re = req.p + req.n, *t;
        t = q; while (q < re && *q != ' ') q++; if (q == re) return AEGIS_ERR_REQUEST;
        out->method = (slice_t){ t, (size_t)(q - t) }; q++;
        t = q; while (q < re && *q != ' ') q++; if (q == re) return AEGIS_ERR_REQUEST;
        out->path = (slice_t){ t, (size_t)(q - t) }; q++;     /* query string kept intact */
        t = q; while (q < re && *q != ' ') q++;
        out->protocol = (slice_t){ t, (size_t)(q - t) };
        if (out->protocol.n == 0 || q != re) return AEGIS_ERR_REQUEST;  /* <3 or >3 tokens */
    }
    skip_sp(&p, e);

    if (token(&p, e, &tmp) != 0) return AEGIS_ERR_SHORT;
    out->status = parse_long(tmp.p, tmp.p + tmp.n);           /* non-numeric -> -1 */
    skip_sp(&p, e);

    if (token(&p, e, &tmp) != 0) return AEGIS_ERR_SHORT;
    out->body_bytes = (tmp.n == 1 && tmp.p[0] == '-') ? -1 : parse_long(tmp.p, tmp.p + tmp.n);
    skip_sp(&p, e);

    rc = delimited(&p, e, '"', '"', &out->referer);
    if (rc != AEGIS_OK) return rc;
    skip_sp(&p, e);

    rc = delimited(&p, e, '"', '"', &out->user_agent);
    if (rc != AEGIS_OK) return rc;

    return AEGIS_OK;
}
