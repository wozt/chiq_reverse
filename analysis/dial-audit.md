# DIAL launcher audit

Date: 2026-10-22

## Static result

`analysis/appfs/dial/dialserver` imports `fork()` and `execv()`. The only `execv()` call is in a forked helper that receives an executable path and an argv vector; it does not invoke a shell and has no `system()`/`popen()` import. The main setup path calls `DIAL_create()`, registers the applications from `dialappsetting.ini`, starts DIAL, and enters `run_ssdp()`.

The deployed application table restricts the known entries to Netflix, YouTube, BBC apps, and `AmazonInstantVideo`. Amazon has `allowed_origin=atv-ext.amazon.com`, `payload_prefix=--dialpayload`, and no executable path. The DIAL payload is therefore an application argument/data channel, not an advertised path-selection field. The Netflix entry stores its payload in `/dev/shm/dial_argv`; this is volatile tmpfs, not persistent storage.

The local `execv()` helper has no direct call from the visible main path; it is likely legacy/callback code supplied to the DIAL support library. No shell metacharacter expansion or network-controlled executable path was established. Live DIAL tests previously confirmed reversible app start/stop but did not expose an additional route.

## DIAL support-library audit (2026-10-22)

The request-handling library was extracted from the recovered `MSLIB.img` as
`analysis/dial-libs/libdialapm.so` (ARM ELF, 53,060 bytes). This is the library
that implements the HTTP/DIAL paths behind the small `dialserver` launcher.
SHA-256: `b518694e70205f03f63188f0de5a43ff19853111060dba957f0a71339a19113c`.

The library imports socket/HTTP, `dlopen`, and file I/O functions, but no
`system()`, `exec*()`, `popen()`, or `fork()`. Its exported launch path calls
`APM_RequestToRunWithParam()` and application callbacks. The configured payload
is treated as application data/arguments; it is not converted into a shell
command or an executable path.

The HTTP body read uses a 4096-byte limit into a larger stack frame, and the
reviewed parameter builders use bounded `strncpy()`/`snprintf()` operations.
This does not prove the parser bug-free, but no direct overwrite or command
execution primitive was established from the static review. The Netflix
payload file remains `/dev/shm/dial_argv`, a volatile path.

The library contains permissive CORS/Origin handling and unauthenticated DIAL
app-control routes. That is a real access-control weakness on the LAN, but it
currently provides reversible app launch/stop rather than root shell access or
persistent modification. No malformed request was sent to the TV.

## Candidate heap-overflow in `dial_data` parser (offline only)

The POST `/apps/<app>/dial_data` path reaches `parse_params()`. The recovered
ARM code allocates both destination buffers with `malloc(strlen(token))`, then
calls the unbounded format `sscanf(token, "%[^=]=%s", key, value)` (format at
`.rodata+0x14f8`). A token without `=` makes `%[^=]` copy the complete token
and its terminating NUL into a buffer one byte too small. A local ASan harness
reproducing this exact pattern reports a heap-buffer-overflow; see
`analysis/dial-parse-harness.c`.

This is a confirmed memory-safety defect in the recovered library's parser
logic, but its exploitability on the TV is unverified: the route's app lookup,
method/origin checks, allocator layout, and downstream use still need to be
established. No malformed body was sent to the TV, and no crash test is
authorized.

### Safe live reachability check (2026-10-22)

Valid short POST bodies (`a=b`) to `/apps/HbbTV/dial_data` and
`/apps/AmazonInstantVideo/dial_data` both returned `403 Forbidden`. The parser
was not reached. A subsequent read-only Amazon status request returned `200`
with state `stopped`; no service instability was observed.

## Security boundary

DIAL remains a useful app-control surface, but the recovered evidence does not show a network-to-root shell or persistent-write primitive. No payload was used to alter executable paths or launch unknown binaries.
