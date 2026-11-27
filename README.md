# Aegis Parser (C)

<!-- at-a-glance -->
> **A high-speed log parser in C — the hot path that normalises raw lines before anything else sees them.**  
> **Result:** 129 test checks pass under AddressSanitizer + UBSan; built with `-Wall -Wextra`.  
> **Reproduce:** the one-line `cc … && ./test_parse` command under **Build & test** below  
> ![CI](https://github.com/fhionnghaile/aegis-parser/actions/workflows/ci.yml/badge.svg) [![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Fhionnghaile/aegis-parser/badge)](https://scorecard.dev/viewer/?uri=github.com/Fhionnghaile/aegis-parser)
>
> **What this is worth:** Parsing is a cost paid on every event: this parser allocates nothing, runs 2.5 to 3.1 times faster than a naive parser on two machines tested, and passes 129 checks under memory sanitizers.


A **zero-copy, allocation-free** parser for the nginx/Apache *combined* access-log format — the kind the
Aegis gateway shreds on its hot path. Two words that rarely meet: **fast *and* memory-safe**.

```
203.0.113.7 - alice [07/Nov/2026:10:00:00 +0000] "GET /login?next=/ HTTP/1.1" 401 232 "https://x/" "curl/8.5.0"
```

## Safe by construction
- Every field is a `slice_t` — a `{ptr, len}` **view into the caller's buffer**. No copies, no `malloc`,
  no `strlen` / NUL assumption.
- Every scan stops at `buf+len`; a truncated or garbage line returns a negative error, **never an
  out-of-bounds read**. Proven, not promised: the test suite runs under **AddressSanitizer**, and a
  **libFuzzer** target hammers arbitrary input.

## Build & test
```bash
cc -std=c11 -Wall -Wextra -fsanitize=address,undefined -fno-sanitize-recover=undefined -Iinclude src/aegis_parse.c tests/test_parse.c -o test_parse && ./test_parse
cc -O2 -Iinclude src/aegis_parse.c bench/bench.c -o bench_parse && ./bench_parse   # 'bench' is the source folder, so the binary needs another name
# fuzz (clang): clang -O1 -fsanitize=fuzzer,address -Iinclude src/aegis_parse.c fuzz/fuzz_parse.c -o fuzz && ./fuzz -max_total_time=60
```

## Benchmark
`bench` parses one line 5,000,000 times vs a `strtok`-on-a-copy baseline and prints lines/sec and the
speedup. Measured here (one core):

| parser | throughput | per line |
|---|---|---|
| **zero-copy (this)** | **15.9 M lines/s** | **62.8 ns** |
| naive strtok-on-a-copy | 5.1 M lines/s | 194.6 ns |

**3.1× faster**, zero allocation. (Re-run 26 Nov 2026 on a second machine, a Linux VM: 9.8 M vs 3.9 M lines/s, **2.5×**. Absolute throughput depends on the hardware; the advantage held.) And **129 assertions pass under AddressSanitizer + UBSan** (including
a truncation sweep over every prefix of a valid line) — fast *and* memory-safe, demonstrated.

## Contract
`include/aegis_parse.h` — a clean C ABI (`aegis_parse_access_log(buf, len, &out)`), ready to call from
the Go gateway via cgo or a tiny sidecar.

## License
MIT.

## Key decisions

- C for control over allocation and throughput on the hottest path.
- Bounds-checked parsing — a parser that segfaults on hostile input is itself the vulnerability.
- Isolated as its own component so the memory-unsafe surface is small and auditable.

## Scope & limits

- Hand-written for the target log formats; a new format is new code (by design, for speed).
- Memory safety rests on tests + review; a fuzzing campaign would harden it further.

