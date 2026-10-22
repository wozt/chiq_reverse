# QJY/NetRange static review

## Scope

- `customer.img` / `app.cfg` configuration
- `MSLIB.img` → `libqjyPost.so` (ARM ELF, 14,968 bytes)
- No firmware modification or malformed request

## Findings

All QJY portal/widget entries launch the same `/applications/QJY/qjyBrowser` binary. They set `CURL_CA_BUNDLE_PATH=/applications/QJY/Resource/certs/cacert.pem` and `QJY_CERTS_DIR=/applications/QJY/Resource/certs`. `ResetQJY` is marked `param_from_argv=y`, so its caller can supply application arguments; this is an argv surface, not a shell sink.

`libqjyPost.so` exports `postTVInfo`, `allowPostTVInfo`, and HTTPS helpers. It hard-codes `https://app.dcc.ninja/browser/data/index.php` and an `iscount` action, builds telemetry fields (model, country, software version, launch counters, and setup counters), and uses libcurl/OpenSSL with the shipped CA bundle. The library imports no `system()`, `exec*()`, `popen()`, or direct file-write primitive.

Static review found one conditional memory-safety candidate in the libcurl callback: `qjyCurlWriteCB(void *ptr, size_t size, size_t nmemb, ...)` prints `ptr` with `%s`, then calls `strcmp()` and `atoi()` without using the supplied length. libcurl write buffers are not guaranteed to be NUL-terminated. A response chunk without a NUL can therefore cause an out-of-bounds read or crash in the QJY process. The request target is hard-coded and TLS verification is enabled when the configured CA bundle is available; no live response manipulation or crash test was attempted. This is not a confirmed LAN-to-root path.

The endpoint was contacted only with DNS/HEAD metadata. It answered `200` on 2026-10-23, but its TLS certificate expired on 2026-10-20. No POST body was sent. This is an availability/configuration issue, not evidence of an exploitable flaw.

The `qjyBrowser` executable and its `Resource` tree are not present in the recovered partition images, so its command-line parser and renderer/native bridge cannot yet be audited. No NetRange-specific entry point was identified.
