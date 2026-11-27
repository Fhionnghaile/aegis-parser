#include "aegis_parse.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Naive baseline: copy the line and strtok it (allocating) — the thing we beat. */
static long naive(const char *line, size_t len) {
    char *buf = (char *)malloc(len + 1);
    memcpy(buf, line, len); buf[len] = 0;
    long acc = 0;
    for (char *t = strtok(buf, " "); t; t = strtok(NULL, " ")) acc += (long)t[0];
    free(buf);
    return acc;
}

int main(void) {
    const char *L =
      "203.0.113.7 - alice [07/Nov/2026:10:00:00 +0000] "
      "\"GET /login?next=/ HTTP/1.1\" 401 232 \"https://x/\" \"curl/8.5.0\"";
    size_t len = strlen(L);
    const long N = 5000000;

    struct timespec a, b;
    volatile long sink = 0;

    clock_gettime(CLOCK_MONOTONIC, &a);
    for (long i = 0; i < N; i++) { access_log_t o; if (aegis_parse_access_log(L, len, &o) == 0) sink += o.status; }
    clock_gettime(CLOCK_MONOTONIC, &b);
    double zc = (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9;

    clock_gettime(CLOCK_MONOTONIC, &a);
    for (long i = 0; i < N; i++) sink += naive(L, len);
    clock_gettime(CLOCK_MONOTONIC, &b);
    double nv = (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9;

    printf("zero-copy : %8.2f M lines/s  (%.1f ns/line)\n", N / zc / 1e6, zc / N * 1e9);
    printf("naive copy: %8.2f M lines/s  (%.1f ns/line)\n", N / nv / 1e6, nv / N * 1e9);
    printf("speedup   : %.1fx   (sink=%ld)\n", nv / zc, sink);
    return 0;
}
