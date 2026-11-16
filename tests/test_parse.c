#include "aegis_parse.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static int checks = 0;
static int eq(slice_t s, const char *lit) { return s.n == strlen(lit) && memcmp(s.p, lit, s.n) == 0; }
#define CK(c) do { checks++; if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); return 1; } } while (0)

static const char *FULL =
  "203.0.113.7 - alice [07/Nov/2026:10:00:00 +0000] "
  "\"GET /login?next=/ HTTP/1.1\" 401 232 \"https://x/\" \"curl/8.5.0\"";

int main(void) {
    access_log_t o;

    /* valid full line */
    CK(aegis_parse_access_log(FULL, strlen(FULL), &o) == 0);
    CK(eq(o.remote_addr, "203.0.113.7"));
    CK(eq(o.remote_user, "alice"));
    CK(eq(o.method, "GET"));
    CK(eq(o.path, "/login?next=/"));      /* query kept */
    CK(eq(o.protocol, "HTTP/1.1"));
    CK(o.status == 401);
    CK(o.body_bytes == 232);
    CK(eq(o.user_agent, "curl/8.5.0"));

    /* absent user and body (dash) */
    const char *d = "10.0.0.1 - - [07/Nov/2026:10:00:00 +0000] \"POST /a HTTP/2\" 204 - \"-\" \"-\"";
    CK(aegis_parse_access_log(d, strlen(d), &o) == 0);
    CK(o.remote_user.n == 0);
    CK(o.body_bytes == -1);
    CK(o.status == 204);

    /* non-numeric status -> -1, not an error */
    const char *ns = "1.1.1.1 - - [x] \"GET / HTTP/1.1\" FOO 0 \"-\" \"-\"";
    CK(aegis_parse_access_log(ns, strlen(ns), &o) == 0);
    CK(o.status == -1);

    /* malformed: request has <3 tokens */
    const char *br = "1.1.1.1 - - [x] \"GET /only\" 200 1 \"-\" \"-\"";
    CK(aegis_parse_access_log(br, strlen(br), &o) == AEGIS_ERR_REQUEST);

    /* structural: missing closing quote on UA */
    const char *mq = "1.1.1.1 - - [x] \"GET / HTTP/1.1\" 200 1 \"-\" \"oops";
    CK(aegis_parse_access_log(mq, strlen(mq), &o) == AEGIS_ERR_SHORT);

    /* truncation fuzz: every prefix of FULL must return cleanly (0 or negative), never crash */
    size_t L = strlen(FULL);
    for (size_t n = 0; n <= L; n++) {
        int rc = aegis_parse_access_log(FULL, n, &o);
        CK(rc <= 0);   /* 0 or an error code, but defined behaviour (ASan proves no OOB) */
    }

    printf("%d checks, ALL PASS\n", checks);
    return 0;
}
