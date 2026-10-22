# CHiQ U43H7L — Software Findings

## Scope

- Target: CHiQ U43H7L at `192.168.2.211`
- Software-only, non-destructive assessment
- No hardware disassembly, soldering, flashing, or persistent changes
- The full device serial is intentionally omitted

## Confirmed network surface

| Port | Service | Status |
|---:|---|---|
| 3697/tcp | MStar WebUI WebSocket | Open |
| 7681/tcp | SRAF/HbbTV WebSocket | Open |
| 56789/tcp | DIAL 2.1 | Open; SmartCenter path returned `404` |
| 56790/tcp | HTTP service | Open; root request returned `404` |

No SSH, Telnet, or ADB listener was found.

## Finding 2 — Empty root password in the recovered root filesystem

**Severity:** High if a login service or local console is reachable
**Status:** Confirmed in the extracted `v1.1.8` recovery image; not verified against the installed `v1.1.9` image

`analysis/rootfs/etc/passwd` contains:

```text
root::0:0:root:/root:/bin/bash
```

No `/etc/shadow` file was present in the extracted root filesystem. The image also contains a root shell on `ttyS0` through `/etc/inittab` and a commented `/bin/telnetd -l /bin/sh` startup line. The live TV currently exposes neither TCP/22 nor TCP/23, so this is not a demonstrated LAN login path. It is nevertheless a concrete credential/configuration weakness and would turn any future telnet/serial/console exposure into unauthenticated root access.

TCP/7681 is the HbbTV App2App/Companion Screen service; it is not evidence of a Miracast video-mirroring endpoint. No separate Miracast-specific listener was identified in the tested surface.

## Finding 1 — Unauthenticated LAN access to MStar WebUI API

**Severity:** High  
**Status:** Confirmed

The service on TCP/3697 accepts WebSocket connections from the LAN using:

- `Sec-WebSocket-Protocol: mstar-webui-c2s`
- `Sec-WebSocket-Protocol: mstar-webui-s2c`

It does not enforce the WebSocket `Origin` header. Session validation is bypassed by registering the public, fixed owner URL:

```json
{"sn":0,"name":"RegisterSessionOwner","args":{"url":"file:///index.html"}}
```

Confirmed response:

```json
{"sn":0,"name":"RegisterSessionOwner","args":{"res":0}}
```

After registration, an unauthenticated LAN client can invoke the WebUI API. Confirmed read-only calls include:

- `GetApiVersion` → WebUI API `0.3`
- `GetNetworkInfo`
- `GetAppList`
- `GetSourceList`
- `GetCurrentInputSource`
- `GetUsbInfo`
- `GetUIConfig`
- `GetDtvTime`
- `Echo`

The same sequence was executed from JavaScript inside the TV browser via `ws://127.0.0.1:3697`. The browser identified itself as Chromium `47.0.2526.106`, SRAF `4.0`, OB `v1.1`; the API returned WebUI `0.3`, network status, and `Sraf OpenBrowser`.

State-changing methods exposed by the same API include:

- `OpenApp`
- `OpenNativeUI`
- `SetInputSource`
- `ReturnToInputSource`

`OpenApp` was accepted for `Sraf OpenBrowser`, but arbitrary URL loading through its `deepLink` argument did not occur. Offline disassembly shows special deeplink handling for Netflix, Cobalt YouTube, and YouTube Kids; `Sraf OpenBrowser` is launched from its fixed `Openinet` configuration and ignored the supplied URL. The browser can load a LAN-hosted page and execute JavaScript when navigated manually.

**Impact:** Any host on the same LAN can query TV state and invoke UI/application controls without authentication.

Static inspection of `OpenNativeUI` shows it prepends the fixed `open_from_webui: ` event prefix and forwards the string through APM; no `system`, `exec`, or shell expansion is present in this path. A generic native-command injection is not evidenced.

`GetSymbolAddress` is present in the WebUI binary and internally wraps `dlopen`/`dlsym`, but static inspection of the command-table construction shows exactly 15 registered names: `RegisterSessionOwner`, `Echo`, `GetApiVersion`, `OpenApp`, `GetNFXTiles`, `GetSourceList`, `ReturnToInputSource`, `SetInputSource`, `GetCurrentInputSource`, `GetNetworkInfo`, `GetUsbInfo`, `OpenNativeUI`, `GetAppList`, `GetUIConfig`, and `GetDtvTime`. `GetSymbolAddress`, `LoadSharedObject`, and `UnloadSharedObject` are not registered WebUI commands. The loader is used internally by `TVClient` for a WAN-status symbol lookup. Five read-only remote variants produced no response; the session remained healthy and normal API calls continued to work. No remote shared-object or symbol primitive is confirmed.

## Firmware analysis

### Finding 3 — World-writable root-executed persistence hook

**Severity:** High after any local file-write primitive
**Status:** Confirmed in the recovered `v1.1.8` image; not verified against the installed `v1.1.9` image

`/etc/init.d/rcS` mounts `/Customer` and executes `chmod 777 /Customer`. It then executes `/Customer/bootlogo/FastLogo.sh` as root whenever that path exists, without checking its executable bit. The `/etc/profile` symlink points to `/Customer/profile`, whose root branch runs executable `/Customer/setup.sh`. The same profile checks `/Customer/enable_mount_config_rw` and mounts `CONFIG` read-write when that marker exists. Any unprivileged component able to create or replace files in `/Customer` would therefore gain a root-executed boot hook after reboot/login. No network file-write primitive has been demonstrated and no TV file was modified.

Evidence: [analysis/persistence-audit.md](/home/wozt/dev/chiqtvhack/analysis/persistence-audit.md).

### Finding 4 — Plaintext private RSA key shipped in rootfs

**Severity:** Medium; impact depends on the consumer
**Status:** Confirmed in the recovered `v1.1.8` image

`/etc/mheg5/m5key.pem` is a world-readable, plaintext 1024-bit RSA private key (`0775`). The consuming MHEG5 component was not included in the extracted tree, so key reuse and forgery impact remain unconfirmed. It is not the firmware-update signing key.

The official recovery package identifies the platform as:

- SoC: MStar/MediaTek `m7322`
- OS: embedded Linux, not standard Android
- Firmware package: `HLS90FJ-V3.12078`
- Package OTA version: `v1.1.8`
- Installed TV version: `v1.1.9`

The recovery package is older than the installed firmware and must not be flashed.

### Embedded key bank

Offline extraction from `analysis/partitions/MBOOT.img` recovered only three public RSA keys (`RSAboot`, `RSAimage`, and `RSAupgrade`) plus AES material. All three public keys differ from the public keys bundled with the open-source MStar tool; the corresponding private keys are not present in the TV image. The tool's default private keys therefore cannot produce an update accepted by this MBOOT.

### USB-update feasibility (offline only)

The extracted MStar bootloader (`MBOOT-1106.0.10.402c9561`, dated 2020-04-14) contains a USB update path (`do_usb_bin_check`, `ota_zip_check_usb`, `do_usb_partial_upgrade_to_emmc`) and explicit integrity/authentication routines: CRC checks, SHA-256, RSA-2048, public-key/signature loading, `CheckSignature`, and raw-data/filesystem authentication. This strongly indicates that a modified image would be rejected unless the package format and required authenticity checks are satisfied; the exact acceptance path is not yet fully mapped.

The official `ChiefUpgrade_m7322_dvb.bin` script is a full reflash, not a safe incremental update: it removes and recreates `certificate`, `customer`, `brickbackup`, `brickreserve`, `CONFIG`, `APP`, `MSLIB`, `cusdata`, and other partitions before writing them. Each payload has CRC checks, and protected partitions call `store_secure_info` for signatures. A package assembled from this script cannot be considered non-bricking without an exact matching signer and a validated recovery path.

Offline disassembly also found a command-interpreter boundary in the upgrade handlers. `setUpgradeFileName()` formats `setenv UpgradeImage %s` with a caller-supplied filename and passes the result to the MBOOT command dispatcher; that dispatcher supports command separators (`;`) and variable expansion. The `do_nstar`/`do_bstar`/`do_ostar` handlers then load and execute script lines, but the script path includes `check_script_crc` and filesystem/header validation. This is a credible MBOOT command-injection lead, not a confirmed TV exploit: the automatic USB path still appears to select fixed names such as `/MstarUpgrade.bin`/`ChiefUpgrade_m7322_dvb.bin`, and no USB filename or update package was tested.

The firmware manifest assigns the `UPDATE` hotkey to native apps (`Jarves` and `Topaz`). The boot profile mounts `APP` and `CONFIG` read-only during normal startup. The recovered root filesystem contains `gdbserver`, BusyBox `telnetd`, and `sshd`/`telnetd` account entries, but no standalone `sshd`, Dropbear, or telnet daemon binary was found. `/etc/init.d/rcS` contains the exact commented startup command `/bin/telnetd -l /bin/sh`. Enabling it would require a write or code-execution primitive to change startup state or launch the command; it is not a configuration-only switch.

The writable `/Customer` partition is mounted before application startup. The root profile executes `/Customer/setup.sh` when it is executable, and starts APM using `/Customer/app.cfg`. These are high-value post-exploitation persistence points, but no tested network service provides file upload or arbitrary file-write access to them.

**Assessment:** technically possible only if a valid update package can be produced or an existing authenticity check is bypassed. It is not safe to test by inserting a modified USB package. No package was built or applied.

The official CHiQ service portal distributes firmware by serial number and warns that firmware is intended for troubleshooting; it specifically advises against updating a functioning TV when the available version may be identical or older: <https://aftersales.changhong.cz/firmwaresearch/>.

Relevant components recovered for offline analysis:

- `WebUIService-0.3`
- SRAF Chromium-derived browser
- Cobalt browser using SpiderMonkey 45
- DIAL 2.1 server
- `app.cfg` application manifest

The SRAF browser is launched with `--disable-web-security` only; no explicit `--no-sandbox` or `--disable-seccomp-filter-sandbox` flag is present. Its binary is a 32-bit ARM build identified as `chromium_v47.sraf`, built 2020-05-06 from a custom Seraphic branch. The Linux seccomp sandbox code is present, but runtime sandbox activation is not yet confirmed. The SRAF browser and `Sraf_Monitor` are configured as UID/GID `10020` with `CAP_SYS_NICE` only. Cobalt contains debugger-related code, but no remotely reachable debugger has been confirmed.

`chrome://sandbox` is not available in the TV browser (the browser returned a 404 page), so it cannot be used for runtime sandbox verification.

Static inspection of `sraf_browser_bin` found Chromium DevTools HTTP/WebSocket code and the hard-coded route `:9222/sraf` (`/json`, `/devtools/`, `DevToolsActivePort`). The launch configuration passes no remote-debugging flag, and TCP/9222 currently refuses connections. This is a compiled capability, not an exposed service on the current boot.

A local JavaScript probe also attempted `file:///etc/passwd` and `file:///proc/self/status`. Both returned status `0`, zero bytes, and a network error. No local file content was exposed.

## Current software paths

1. Determine the SRAF renderer sandbox state without triggering an exploit.
2. Review public Chromium 47-compatible bugs for ARM/Linux applicability.
3. Characterize the exposed SRAF/HbbTV WebSocket on TCP/7681.
4. Confirm or reject arbitrary URL launch through the WebUI `deepLink` path.
5. Investigate browser-to-native boundaries only after a credible browser foothold is established.
6. Reverse-engineer the update container and verification flow offline before considering any image modification.
7. Map the native HbbTV/DIAL Binder launch path and determine where URL/security validation is enforced.
8. Verify whether the HbbTV endpoint token generation is predictable without attempting token recovery.
9. Compare the SRAF Chromium fork against its shipped launch arguments; `app.cfg` exposes no shell, Telnet, SSH, or maintenance executable.

## Candidate vulnerability areas

- **WebUI WebSocket:** LAN authentication is already bypassed. The binary contains internal `LoadSharedObject`, `UnloadSharedObject`, and `GetSymbolAddress` helpers backed by `dlopen`/`dlsym`, but the statically constructed 15-entry command table does not include them. The helpers are called from an internal `TVClient` WAN-status path, not from the WebUI dispatcher. No remote shared-object primitive is confirmed.
- **Shell enablement path:** BusyBox provides `telnetd`, and `rcS` includes the exact commented startup command `/bin/telnetd -l /bin/sh`. This is a useful post-exploitation endpoint, not an exploit: no tested LAN API can currently write `/etc/init.d/rcS` or execute an arbitrary program.
- **NetworkService local Binder:** the always-started `NetworkService` binary registers `mstar.networkservice` through the local Binder service manager and contains several `snprintf` → `system()` paths (`ifconfig`, IPv6 route/sysctl, DHCP/DNS helpers). The only `bind()` found is for a Unix-domain `/tmp/wpa_ctrl_<pid>-<id>` control socket used by `wpa_supplicant`; no TCP/UDP listener is present. These remain local Binder/API attack-surface leads, not LAN endpoints; no Binder transaction was sent and no WebUI method exposes them.
- **NetworkService command-injection candidate (offline, 2026-10-22):** `BnNSManager::onTransact()` dispatches transaction `20` (`StartWpaSupplicant`) after only `Parcel::checkInterface`; no caller-UID or permission check is visible. It reads a 256-byte argument and calls the native handler, which validates characters with the generic mode-3 whitelist. That whitelist explicitly accepts `&`, spaces, `/`, `=`, `.`, `_`, `-`, and alphanumerics, then formats `wpa_supplicant %s` and passes it to `system()`. `/etc/cap_control.ini` runs this service as UID/GID `2901` with `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_NET_BIND_SERVICE`, and `CAP_SYS_TIME`, so successful local abuse would be materially privileged even without root. This remains a local Binder candidate: the service is not exposed on the LAN, the browser is a separate UID `10020`, and no transaction was sent. Related `StartWpaCli` transaction `22` also reaches `system("wpa_cli %s")`, but its mode-4 whitelist only exposes a redirection character (`>`), not a demonstrated code-execution path.
- **TvManager Binder shell primitive (offline, 2026-10-22):** `TvManagerService::instantiate()` registers `mstar.TvManager`. `BpTvManager::executeShellCmd(android::String8)` sends transaction `0x53` (83); `BnTvManager::onTransact()` checks only the interface token before dispatching it, with no visible caller-UID or permission check. The service implementation passes the caller-supplied `String8` into `MSrv_Control_common::Command_execv`; the ARM literal table shows it builds `argv = {"sh", "-c", <caller String8>, NULL}`, and that helper forks and calls `execv("/system/bin/sh", ...)`. The service runs inside `tvos` (UID/GID `2900`, with `CAP_SYS_NICE|CAP_SYS_TIME|CAP_WAKE_ALARM|CAP_SYS_BOOT|CAP_KILL`). `WebUIService` links `libtvmanager.so` and runs with supplementary group `2900`, but its registered WebUI command table does not reference `executeShellCmd`; no other extracted executable imports the client method. No LAN-to-Binder path or live transaction was tested. This is a high-value local IPC candidate for shell access, not a confirmed remote exploit.
- **APM/appmgr local execution bridge:** `appmgr` registers the local Binder service `mstar.appmanager`, launches configured applications with `execve`, and uses `system()` for internal maintenance actions such as `cp -f`, mount, and umount. Its launch path also connects to the Unix socket `/dev/shm/BigBang_Socket`; the command buffer is assembled from the static `/Customer/app.cfg` application records and bounded to 5120 bytes before sending. No TCP/UDP listener, WebUI command, or DIAL route reaches this socket, and no arbitrary path or shell command input was identified. This is a post-compromise/local IPC surface, not a usable LAN jailbreak primitive.
- **APM argument path:** `OpenApp` forwards `deepLink` as an application parameter for selected apps. The configured `param_from_argv` targets are `resetNetflix`, `qjyBrowser`, `Vudu`, and `Amazon`; APM uses `execve` for application launch. For these targets the parameter is appended as raw argv text, enabling application-flag injection but not a shell command by itself. No shell binary or command interpreter is registered as an app.
- **SRAF Chromium fork:** Chromium `47.0.2526.106` is very old. Upstream Chrome 47 received dozens of security fixes, including high-severity memory-safety and cross-origin issues; applicability to this custom 2020 ARM fork must be established offline before any browser test.
- **SRAF DevTools:** DevTools support and a `:9222/sraf` route are compiled in, but no launch flag or listener was found. Current probing observed `connection refused`; no debugger protocol was used.
- **Cobalt/HomePortal debug surface:** `vibra_lite` contains WebDriver/remote-debugging settings and a `/tmp/browser_server.socket` debug socket, but the shipped `config.ini`/`app.cfg` sets no remote port and no additional LAN listener was found. This is local IPC/configuration evidence, not a confirmed network entry point.
- **SRAF/HbbTV service (TCP/7681):** `HbbTV.json` explicitly configures WebSocket port `7681`, Wall Clock UDP `7682`, and CSS endpoints `/hbbtv`, `/remote/hbbtv/`, `/css-cii`, and `/css-ts`. Static analysis of `libsraf_hbbtv_wsserver.so` shows path matching for `/css-cii` and `/css-ts`; incoming frame bytes are copied into `std::string` objects and queued to application callbacks, with no parser or authentication in this library. Plain HTTP requests hang; an upgrade outside the registered paths or without a valid path returns `403` from `libwebsockets`. No application frame was sent and the accepted subprotocol is not yet identified.
- **HbbTV Wall Clock UDP (configured port 7682): confirmed memory-safety bug in the shipped binary:** `SrafCSSWCServer::startWCServer()` zeroes a 128-byte stack buffer, calls `recvfrom(..., 128, ...)`, then passes that buffer directly to unbounded `strcmp()` without adding a NUL terminator. An exactly 128-byte datagram containing no NUL therefore causes an out-of-bounds read and is a credible remote crash/DoS primitive when the listener is exposed. `StringToSrafWCMessage` also ignores the supplied length, but its fixed reads through offset 28 remain within the buffer. This is not evidence of code execution. The extracted image is v1.1.8 while the TV reports v1.1.9; UDP/7682 was closed on the tested boot and no datagram was sent. Detailed evidence: `analysis/hbbtv-wallclock-audit.md`.
- **Native HbbTV/DIAL Binder layer:** `libcs.so` registers the local Binder service name `CSS_DIAL_SERVICE_NAME` and exposes `CreateHbbTVApplication`, `SetAppLaunchURL`, `LaunchHbbTVApplication`, status, hide, and stop methods. The native launch wrapper accepts a URL string and forwards it to the WebTV service; no scheme/host validation is visible in this wrapper. The Binder transaction handler visibly checks only the interface token; no caller-UID/permission check was found in this layer. Separate APIs exist to add, remove, or clear the HbbTV security whitelist. This is an offline local attack-surface lead only: Binder is not exposed over the tested LAN ports, deeper WebTV validation is not yet mapped, and no launch call was made.
- **HbbTV DIAL/App2App endpoint (TCP/7681):** unauthenticated `GET /apps/HbbTV` returns the current HbbTV state and exposes a nominally tokenized `ws://.../remote/hbbtv/<token>/` URL. Its CORS response reflects an arbitrary `Origin`; read-only handshakes returned `101 Switching Protocols` with `Origin: https://attacker.example` for both `/remote/hbbtv/*` and `/local/hbbtv/*`, including arbitrary suffixes (`deadbeef`, `random-token`, `foo`). No subprotocol or additional authentication was required. Static analysis of `MediaSyncServer::handlePairingConnection` shows that the routine stores the suffix supplied by the first client and pairs a `local` and `remote` client when both present the same suffix; it does not visibly compare that suffix with the generated `m_local_random`/`m_remote_random` values. When pairing is enabled, `handlePairingMsg` forwards the complete incoming payload to the opposite socket with `lws_write`; no message parser, schema check, origin check, or per-message authorization is visible in this relay path. However, `m_enablePairing` is initialized to `0`, and no write to `1` or setter was found in this library. The binary contains `pairingcompleted`, `local paired`, and `remote paired` responses, but the relay path appears dormant in the tested build. The companion CSS-CII URL was advertised but returned `403` to the same handshake. HbbTV specifies local and remote endpoints to be paired between an HbbTV app and a Companion Screen; accepting both endpoint classes from arbitrary LAN clients is therefore an access-control weakness. Control impact and message authorization remain unconfirmed. Reference: <https://www.etsi.org/deliver/etsi_ts/102700_102799/102796/01.04.01_60/ts_102796v010401p.pdf>.
- **HbbTV endpoint-token generation:** `MediaSyncServer::createRandom()` seeds the process-wide PRNG with `srand(time(NULL))`; its helper hashes successive `rand()` outputs with MD5 and stores the hex digest as the endpoint suffix. MD5 does not add entropy, and second-resolution seeding makes tokens potentially predictable if the process start time and PRNG sequence are known. No token prediction was attempted. The endpoint also accepts arbitrary suffixes at the handshake layer, so token unpredictability is not currently an effective access-control boundary.
- **Live pairing check:** two controlled tests opened simultaneous `local` and `remote` WebSockets with the same attacker-chosen suffix (both connection orders). All four handshakes returned `101 Switching Protocols`; no server frame (`pairingcompleted` or otherwise) and no forced close was observed during a four-second receive window. Dynamic pairing is therefore not confirmed in the current TV state, despite the static relay/pairing logic above. No application payload was sent.
- **Screencast/Miracast:** separate Wi‑Fi Direct/display-casting path; it does not expose a shell, SSH, Telnet, or a confirmed LAN code-execution primitive. Dropped from the shell-access plan.
- **DIAL service (TCP/56789):** `libdialapm.so` hard-codes the Mongoose listener to port `56789` and implements `GET, POST, OPTIONS` under `/apps/`. `GET /apps/YouTube` and `GET /apps/Netflix` return application state without authentication. The status response formats `Access-Control-Allow-Origin: %s` from the request origin; live tests confirmed reflection of arbitrary origins, despite per-application `allowed_origin` entries in `dialappsetting.ini`. This confirms a CORS policy weakness for read-only status endpoints; the separate launch/overflow test is documented below.
- **DIAL Amazon status (read-only, 2026-10-22):** `GET /apps/AmazonInstantVideo` returns `200 OK`, `state=stopped`, and `allowStop=true`. The configured DIAL name is `AmazonInstantVideo` (not `AMAZON`); its launch payload prefix is `--dialpayload` and its allowlisted origin is `atv-ext.amazon.com`. Supplying `Origin: https://attacker.example` still produces `Access-Control-Allow-Origin: https://attacker.example`, confirming the same unauthenticated CORS reflection for Amazon status. No POST, DELETE, or launch request was sent.
- **DIAL payload-length lead (offline):** `dial_start_app` builds the launch argument in a fixed 6144-byte stack buffer using bounded `snprintf`, but several paths add the formatter's would-be output length to the running offset without clamping it to the bytes actually written. A DIAL payload longer than the remaining buffer could therefore make the next `6144 - offset` size calculation underflow and turn a later `snprintf` into an overwrite. The request-body path accepts an 8192-byte working buffer, so the condition appears reachable in principle. This is an unconfirmed crash/code-execution lead; the controlled 3000/4000-byte tests below did not reproduce it.
- **DIAL Amazon launch path (offline, 2026-10-22):** Ghidra decompilation confirms `dial_start_app()` URL-encodes the Amazon payload according to `payload_urlEncoded=1`, appends the configured `--dialpayload` prefix, and then calls `APM_RequestToRunWithParam()` with the resulting argument string when no app-library override is configured. This is an argument-injection surface into the Amazon executable, not a shell invocation; no POST was sent and no launch was attempted during this review.
- **Live overflow attempt:** after reboot, TCP/56789 was reachable. A 7000-byte neutral POST was rejected by the HTTP parser with `413 Request Entity Too Large`. Two accepted Netflix POSTs containing 3000 and 4000 `%` characters returned `201 Created`, started Netflix, and left DIAL/HTTP alive; the applications were then stopped via the normal DIAL `DELETE` route. No crash or service restart occurred. The suspected internal overflow was not reproduced, and no shell or code-execution primitive was obtained.
- Final scan after cleanup: `3697`, `7681`, `56789`, and `56790` open; `22`, `23`, `7682`, and `9222` closed.
- Control-route probes (`/run`, `/hide`, `/dial_data`) were not accepted with safe `GET`/`OPTIONS`/`DELETE` requests; no control-origin bypass has been demonstrated.
- Static DIAL parsing extracts one application path segment and URL-encodes it before `dial_data` file access. No path-traversal primitive was established from this code path.
- **Update parser/bootloader:** high-value offline lead. The filename-to-`setenv` path reaches a shell-like MBOOT dispatcher, and upgrade scripts are executed after CRC/filesystem checks. Reachability from the automatic USB filename scanner and the effect of the current signature checks remain unconfirmed; probing it with a modified package is unsafe. A public older MStar advisory describes a similar USB-upgrade filename command-injection class: <https://seclists.org/bugtraq/2018/May/5>.

No code-execution or persistence payload has been sent, and no persistence has been attempted.

## Safety notes

- No firmware was installed.
- No persistent TV file was modified.
- No destructive command was sent.
- Tests performed against the TV were limited to protocol negotiation, read-only API calls, and reversible `OpenApp` requests.
- HbbTV testing used only handshakes, ping/pong, and one minimal benign App2App text frame; no CSS control frame or HbbTV launch/hide/stop frame was sent. The separate DIAL test used only reversible Netflix start/stop requests.
- All temporary LAN HTTP probe servers were stopped after testing.
- No USB update package was created, inserted, or executed.

## Latest non-destructive network baseline (2026-10-22)

The TV was reachable at `192.168.2.211`. TCP `3697` remained open and returned HTTP `403` to non-WebSocket probes. TCP `7681` remained open but behaved as a WebSocket-only endpoint. TCP `7682`, `9222`, `56789`, and `56790` were closed at scan time; the DIAL/HTTP services are therefore state-dependent in this boot. No malformed UDP datagram, WebSocket application frame, DIAL control request, browser exploit, or firmware operation was attempted.

### Active protocol verification

- TCP `3697` accepted the standard `mstar-webui-c2s` and `mstar-webui-s2c` handshakes. `RegisterSessionOwner` succeeded on both channels (`res: 0`). Read-only `GetApiVersion`, `GetNetworkInfo`, `GetCurrentInputSource`, `GetUsbInfo`, and `Echo` calls all returned normally. No state-changing method was sent.
- TCP `7681` returned `101 Switching Protocols` for `/remote/hbbtv/test` and `/local/hbbtv/test` with an arbitrary suffix and no subprotocol. `/hbbtv` returned `403`; this specific handshake check sent no application frame.
- A neutral WebSocket `ping/pong` check succeeded on both `/remote/hbbtv/ping-test` and `/local/hbbtv/ping-test`; both sessions then closed cleanly with code `1000`. No application message was sent.
- One minimal App2App text frame (`{"type":"ping"}`) was sent to `/remote/hbbtv/benign-test`. The TV returned no application message or error during a four-second observation window; TCP `7681` remained open afterward. No paired client was present and no control action was triggered.
- A controlled pairing check opened `/local/hbbtv/pair-probe-2026` and `/remote/hbbtv/pair-probe-2026` simultaneously, then sent the same benign ping from the remote side. Both handshakes succeeded, but the local side received no relayed frame or pairing event. Both sockets closed cleanly; pairing remains unconfirmed/inactive.
- Offline ARM disassembly confirms `MediaSyncServer::onMessage` first calls the pairing relay, then passes the raw frame (length-bounded `std::string`) to registered CSS-CII/TS observers when the socket has a known client ID. The observer handlers perform no visible JSON/schema parsing in this library; they queue the raw bytes to the local event dispatcher. Unknown client IDs and zero-length frames are dropped. This is an unauthenticated raw-message path, but no native action or shell primitive is exposed by the inspected code.
- WebUI read-only enumeration returned one runtime app (`Sraf OpenBrowser`), the configured UI app list (Netflix, Cobalt YTTV, Amazon, widgets, Screen Cast, and Sraf OpenBrowser), and normal input sources. No shell, terminal, maintenance, SSH, or Telnet app was exposed. `GetDtvTime` returned an unset epoch-like value (`1970-01-01`), which is unrelated to shell access.
- A direct remote `GetSymbolAddress` request (using plausible module/symbol fields) produced no response, while a fresh session immediately returned normal `GetApiVersion` and `GetNetworkInfo` responses. This is consistent with the helper being compiled but absent from the registered WebUI command table; no loader or symbol lookup was reached.

After the TV restart, TCP `56789` (DIAL) and `56790` (HTTP companion service) returned to `open`; TCP `3697` and `7681` also remained open. TCP `22`, `23`, `7682`, and `9222` remained closed.

A full TCP scan (`1-65535`, 2026-10-22) confirmed the same four open ports (`3697`, `7681`, `56789`, `56790`); 69 ports were filtered and all remaining ports were refused. No additional remote service was found.

TCP/56790 identifies only as `tcpwrapped`. Read-only requests to `/`, `/apps/`, `/status`, `/json`, `/device`, and `/dial_data` all returned the same `HTTP/1.1 404 Not Found` response (`Error 404: Not Found`). No unauthenticated file, upload, debug, or shell route was identified.

### Static APM/appmgr review (2026-10-22)

`appmgr` exposes the local Binder service `mstar.appmanager`, launches configured applications with `execve`, and contains internal `system()` calls for maintenance commands (`cp -f`, mount, and umount). Its local launch bridge connects to `/dev/shm/BigBang_Socket`; the command buffer is assembled from `/Customer/app.cfg` records and checked against a 5120-byte limit before sending. No network listener or WebUI/DIAL route reaches this Unix socket, and no arbitrary shell input was found. This remains a local/post-compromise surface, not a direct software-only LAN jailbreak path.

### Static HbbTV CSM callback review (2026-10-22)

`libsraf_hbbtv_adaptor.so` exports `Sraf_CSM_LaunchCSApp`, `Sraf_CSM_SetAppLaunchURL`, and related Companion Screen Management functions. `LaunchCSApp` only packages an operation code and invokes a previously registered callback; `SetAppLaunchURL` copies a caller-provided string into a `std::string`. No `system()`, `exec*`, file-write, or shell operation is present in these wrappers.

The only observed `SetAppLaunchURL` caller is an internal JSON/IPC handler in the adaptor (it reads the `app_launch_url` field). The WebSocket implementation is a separate library and has no direct call to these CSM exports; no registration or network path from TCP/7681 to the callback was established. This remains an internal app-control surface, not a demonstrated LAN-to-shell primitive.

The current live check found `3697`, `7681`, `56789`, and `56790` open; `22`, `23`, `7682`, and `9222` closed. Read-only requests to thirteen common paths on `56790` all returned the identical 30-byte `404 Not Found` response. No secondary HTTP, upload, debug, or shell route was identified.

The adaptor also contains SSDP/DIAL discovery constants and UDP `sendto`/`recvfrom` calls, but no TCP listener, dynamic loading of `libcs.so`, or network-to-Binder bridge. This discovery code does not change the conclusion: HbbTV DIAL remains local Binder-only on this firmware.

The current read-only `GET /apps/HbbTV` still reports `stopped`; its advertised remote App2App URL accepts a WebSocket handshake, while the advertised CSS-CII and CSS-TS URLs returned `403`. No application frame or control operation was sent.

### Chromium/SRAF native boundary review (2026-10-22)

`/Customer/app.cfg` launches the browser as:

`--sraf-app=HbbTV --enable-plugin-in-process --disable-web-security`

No `--no-sandbox`, remote-debugging, SSH, Telnet, or shell flag is present. The binary contains Chromium 47 sandbox/zygote code and imports `chroot`, `clone`, `prctl`, `execv`, `execve`, and `system`; these imports are not evidence that page-controlled input reaches a command sink.

The renderer/browser IPC surface includes `FrameMsg_SrafExtensionExecuteRequest` and `_IpcMessageHandlerClass::OnSrafExtensionExecuteRequest`. The browser links `libsrafcustomjs.so` and imports `srafExternInit`, `srafExternFinalize`, and `srafGlobalInitializePerRender`; the library was missing from the initially extracted tree but is present inside `APP.img` and was recovered for offline inspection.

The missing `libsrafcustomjs.so` was recovered read-only from `APP.img` and inspected. It registers two demo classes (`mtvapiA` and `mtvapiB`) with names such as `getIp`, `setNetwork`, `addEventListener`, `setCarBrand`, `getPersonalInfo`, `flyTo`, and `goHome`. Its dynamic imports are limited to C++ runtime, memory movement, time, logging, and pthread functions; it has no `system`, `exec*`, socket, file-open, or file-write import. The custom-JS layer therefore does not expose an obvious shell or persistence primitive.

The visible `SrafPluginUnittest` and `SrafPluginControllerUnittest` objects are test-style wrappers. Their registered names (`add`, `minus`, `trigger`, `getController`, `print`, `printArray`, `printObject`, `printVector`, `hello`, `world`) and inspected ARM bodies operate on counters, strings, V8 objects, and containers. No `system()`, `exec*`, file-write, socket, or update operation is present in these methods. They are not a shell primitive.

`libbrowser_client.so` also exports `detect_process(const char*)`, which formats `ps | grep -c %s` / `ps w|grep -c %s` into a buffer and calls `popen()`. The only observed browser-client call passes the fixed literal `sraf_browser_bin`; no URL, WebSocket field, JavaScript argument, or DIAL value reaches this function in the inspected call path. The duplicate APM-server helper has the same fixed-process-check role. This is a hardening issue and a future audit target, not a demonstrated command-injection route.

The browser's only direct `system()` call is in `sraf::MsgHandleContext::HandleAsyncIPCOnUI(Json::Value)`. Its argument resolves to the fixed literal `./sraf_input_engine &`; the surrounding JSON/UI state selects the asynchronous IME task but does not build the command string. The `execv()` call site similarly forks and launches a locally derived executable path after checking local filesystem state; no page-controlled command string was identified. These native process calls are therefore not a demonstrated JavaScript-to-shell bridge.

The browser configuration disables web-security checks, so a renderer foothold could reach local HTTP/WebSocket services more easily than a normal Chromium page. Existing file-URL probes still returned zero bytes/network errors, and DevTools port `9222` remained closed. No browser exploit, renderer escape, arbitrary native message, or shell/persistence path has been demonstrated. The remaining useful static work is to audit `sraf_js_get_app_user_js` and the `OnSrafExtensionExecuteRequest` dispatcher; sending exploit JavaScript or malformed IPC is not justified by the current evidence.

`libsraf_core.so` exposes `sraf_js_get_app_user_js(std::string&)`. For the active app it loads built-in JavaScript and calls `js_get_custom_bufs`, which constructs resource paths of the form `<resource-dir>/javascripts/<AppID>.dat`; the shipped archive contains encrypted files such as `Twitter.dat`, `Facebook.dat`, and `Picasa.dat`. A separate branch reads a plain file only when the per-app integer setting `EnableCustomPlainJs` is enabled, using the configured `CustomJsPath` value. The only matching shipped configuration is `sraf/config/NRGPortal.json`, where `EnableCustomPlainJs` is `0` and `CustomJsPath` is empty. No network setter for these settings was found. This is a local script-loading/customization feature, not a shell or persistence primitive; even if enabled, the browser reads the file as UID/GID `10020` and does not execute it as a native process.

The shipped `/etc/cap_control.ini` assigns `SrafBrowserEngine` UID/GID `10020` with only `CAP_SYS_NICE`. The boot profile starts `appmgr` in `--enable_no_root` mode when the capability-control setup is present. Therefore a Chromium renderer compromise would, by design, be an unprivileged foothold; a separate local privilege-escalation or appmanager/Binder escape would still be required for root-level persistence or enabling `telnetd`.

The `SrafPluginClient` vtable was also mapped offline. It contains only seven small methods (plus the destructor entries); the ARM bodies are trivial return/initialization stubs and do not call `sraf_config_set_*`, `sraf_ipc_client_*`, `open`, `write`, `system`, or `exec*`. This JS-visible client object does not provide a file-write, configuration-mutation, or command-execution bridge in the shipped browser.

A fresh passive SYN scan found the same service state: `3697`, `7681`, `56789`, and `56790` open; `22`, `23`, `7682`, and `9222` closed. No SSH/Telnet/DevTools listener has appeared.

### External vulnerability research (2026-10-22)

- A public MStar advisory documents command injection through malicious USB-upgrade filenames on some MStar set-top boxes: <https://github.com/Ivan-Markovic/Command-injections-via-USB-upgrade-in-MSTAR-Set-Top-box>. Our firmware contains a related MBOOT/update parser lead, but model-specific applicability is unconfirmed. Testing would require USB insertion and reboot and remains out of scope because of brick risk.
- CHiQ's official service portal requires the device serial number and warns that firmware is intended for repair; no public U43H7L package matching this build was found: <https://aftersales.changhong.cz/de/firmwaresearch/>.

The same portal was queried read-only with the reported serial `G21F01B9CZE0001462` on the German, English, French, Czech, and Belgian endpoints. All five returned “software not found for this serial number.” No public package matching `1.0.3.0.20210319160335_5.1.3_CHiQ_U43H7L_v.1.1.9` was located.

### Exact-version public search (2026-10-22)

Internet Archive metadata searches for `U43H7L`, `HLS90FJ`, `CHIQ_U43H7L`, `JUC7.820.00242703`, and `1.0.3.0.20210319` returned zero items. Chinese repair indexes contain unrelated Changhong packages for other chassis (for example LM38i, ZLH/ZLS, or MT9216); none matches `HLS90FJ-iU`, `m7322`, or the reported 2021 build. These packages must not be treated as interchangeable firmware.

The local official `ChiefUpgrade_m7322_dvb.bin` is an older `v.1.1.8` package for chip `m7322` (the TV reports `v.1.1.9`). Its 64-KiB plain-text MBOOT script contains `force_overwrite`/partition recreation commands for certificate, customer, MBOOT, rootfs, APP, and other partitions, followed by CRC and secure-signature records. It is useful for offline parser comparison only; modifying or installing it would be a full-flash operation, not a safe shell-enablement update.

### Browser source and Prime version search (2026-10-22)

The matching upstream Chromium source is public at the official Chromium mirror, including tag `47.0.2526.106`: <https://github.com/chromium/chromium>, <https://chromium.googlesource.com/chromium/src/%2B/47.0.2526.106/>. This is upstream Chromium only; the TV runs a vendor SRAF/CHiQ fork, and no public source tree or patch set for that fork was found.

Public U43H7L product pages confirm Prime Video support but do not publish an app build number: <https://device.report/chiq/u43h7l>. No public Prime/Amazon package matching this TV or its `v.1.1.9` firmware was found. The exact Prime version therefore requires either a matching firmware filesystem/package or a read-only version display exposed by the TV; current LAN APIs do not expose it.

The exact upstream snapshot is stored locally at `analysis/chromium-47.0.2526.106/`; its compressed archive SHA-256 is `2e6e210860097d25a79015024636ab80a44b5d48abad4389cc6e1c1037133d1f`. The source audit is in `analysis/chromium47-source-audit.md`. The large source snapshot is intentionally excluded from Git; only the audit and hash are tracked.

### Safe browser feature probe (2026-10-22)

`analysis/probes/chromium47-safe-probe.html` fingerprints the reported Chromium version, PDF MIME/plugin presence, selected JavaScript features, and iframe sandbox API. It performs no file reads, socket/WebSocket connections, PDF loads, malformed input, or persistent change.

The TV-side result reported Chromium `47.0.2526.106`, one browser plugin, `27` MIME types, no exposed `application/pdf` MIME handler, no WebAssembly or Proxy, but Symbol, Uint8Array, WebSocket, postMessage, and the iframe sandbox API. This is a feature fingerprint only.

### Offline Chromium marker audit (2026-10-22)

`analysis/probes/chromium47-offline-audit.py` reads the extracted ARM binary without executing it. The target is ELF32 ARM, 36,935,984 bytes, SHA-256 `3dfbd071c242d6fa10e502dd2d1f1e5f79c5f9a99108593fd730a6118897a74c`. Printable markers include `application/pdf`, `PPB_PDF;1`, V8/Blink symbols, and `FrameMsg_SrafExtensionExecuteRequest`; no `WebAssembly` marker was found. The binary contains strings for sandbox command-line switches, including `--no-sandbox`, but `/Customer/app.cfg` does not enable them. These are component/feature markers only and do not establish a reachable vulnerability or exploit path.

### Root console / telnet check (2026-10-22)

The extracted rootfs has a physical serial console configured: `/etc/inittab` respawns `-/bin/sh` on `ttyS0`, and the boot environment sets `console=ttyS0,115200`. This is a UART path, not a LAN service. `/etc/init.d/rcS` contains a commented `/bin/telnetd -l /bin/sh` line, but no `telnetd` binary or BusyBox `telnetd` applet was found in the extracted rootfs; only the BusyBox telnet client is present. No software-only route to enable that shell was identified.

The same browser binary also contains Chromium DevTools protocol code and the `remote-debugging-port` switch. The active `SrafBrowserEngine` entry does not pass that switch, and the TV-side scan found no port `9222`. `OpenApp` exposes only `appName` and `deepLink`; `SrafBrowserEngine` is not marked `param_from_argv=y` in `app.cfg`, so the static configuration gives no supported way to inject a DevTools argument.

### Public board photos (2026-10-22)

Public parts listings identify the U43H7L mainboard as `JUC7.820.00242703 / C430Y19-7N / HLS90FJ-iU`; the photographed board has the same markings and a matching U43H7L label: <https://www.ebay.de/itm/285943464271>, <https://vareza.de/u43h7n-juc7-820-00242703-c430y19-7n-hls90fj-iu-mainboard.html?language=de>. The available top-side photos do not expose a clearly labeled UART header or pad. They confirm board identity only; they do not identify the `UART-TX`/`UART-RX` physical pads.

The available mainboard schematic (`analysis/schematics/mainboard-page-8.png`, sheet 8/15) marks separate `UART-TX` and `UART-RX` nets next to the HDMI2 block, inside a green `ISP debug` annotation. The arrows point to schematic page 2; they are net cross-references, not HDMI connector pin numbers. This page provides no physical test-pad reference, voltage, or UART ground pin, so the exact board header cannot be identified from the supplied documentation. HDMI2 pins must not be used as UART pins.

### Neutral WebSocket canary (2026-10-22)

On TCP/7681, a WebSocket handshake to `/remote/hbbtv/safe-canary-20261022` returned `101 Switching Protocols`. One 66-byte masked text frame was then sent: `{"type":"probe","marker":"chiqtvhack-safe-canary","action":"none"}`. The TV returned no application response during a two-second observation window; the client sent a normal close (`1000`). Ports `7681`, `3697`, `56789`, and `56790` remained reachable afterward. No exploit syntax, malformed frame, file path, command, or state-changing control message was sent.

### WebUI/APM deep dive (2026-10-22)

The ARM disassembly reconstructs the WebUI dispatcher as a fixed hash table. `RegisterSessionOwner` is handled separately; the dispatcher contains the other 14 public methods. The strings `GetSymbolAddress`, `LoadSharedObject`, and `UnloadSharedObject` are present only as internal helper/debug strings and are not registered network commands.

`OpenApp(appName, deepLink)` passes the selected application and a length-counted parameter to APM (`APM_RequestToRun`/`APM_RequestToRunWithParam`). The input is built with `std::string`; no shell formatter, `system()`, `exec*`, or fixed-size copy is present in this WebUI path. Netflix, Cobalt YouTube, and YouTube Kids receive fixed prefixes; other app names are resolved by APM's configured application table.

`OpenNativeUI(command)` prepends the fixed event prefix `open_from_webui: ` and sends it through APM event/request APIs. The command length is calculated with `strlen()` and passed as an event size; no shell invocation is present in this function. The shipped UI configuration exposes only `open_miracast: default`, `open_media_player: main`, and `open_settings: default` native actions.

The complete handler review found no WebUI import of `system`, `exec*`, or `popen`. `SendEventToApp()` clears a fixed 0x108-byte APM record, then stores the caller-controlled string pointer and `strlen()+1` in the record; no local length cap is visible. This is a possible APM receiver length/DoS audit lead, not a code-execution primitive. No oversized event was sent.

The destination is the APM default application (`HomePortal`, configured as `/applications/webui/engine/vibra_lite`), not a Unix command interpreter. The event wrapper uses a fixed 0x108-byte stack structure and `APM_SendEventEx`; the only WebUI-side event parser found is for the unrelated `set_focus: ` notification. The HomePortal executable contains generic deep-link/event code but no literal `open_from_webui` handler or shell import; receiver behavior remains unconfirmed without sending a state-changing native-UI request.

`GetAppNameFromUrl()` uses an exact URL-map lookup, not a prefix or wildcard match. The fixed `file:///index.html` owner registration therefore bypasses session ownership but does not provide arbitrary URL-to-app mapping.

A fresh live check confirmed the distinction: `file:///not-mapped.html` returned `res:1`, `file:///index.html` returned `res:0`, and `GetApiVersion` then returned `0.3` on the same connection.

Live read-only verification reached all getter methods normally. A direct `GetSymbolAddress` request produced no response, while a fresh session continued to answer `GetApiVersion` and `GetNetworkInfo`; no remote loader or symbol lookup was observed. The remaining useful WebUI work is receiver-side parsing of the APM `open_from_webui:` event, which requires offline inspection only; no state-changing WebUI method was sent in this review.

### WebUI event receiver audit (2026-10-22)

`SendEventToApp()` creates a fixed 0x108-byte APM record (event type `12`) and calls `APM_SendEventEx` for the configured default app. `OpenNativeUI()` supplies the fixed `open_from_webui: ` prefix and only falls back to `APM_RequestToRun`/`APM_PostEventEx` if that send fails. There is no shell formatter or executable path in this route.

`vibra_lite` has generic Cobalt `OnApplicationEvent()`/`OnDeepLinkEvent()` code and only imports APM input APIs. It contains no `open_from_webui` string and no `system()`/`exec*` import. The shipped HomePortal JavaScript does not register an application/deep-link callback; the platform-side consumer of event type 12 is therefore not identified. No live native-UI event was sent because that would change TV state.

### SRAF APM input bridge audit (2026-10-22)

`libbrowser_client.so` uses a fixed input loop (`APM_WaitInputEvent` -> `APM_HasInputEvent` -> `APM_GetInputNonBlock`) with a 516-byte buffer. It accepts raw input categories `0`, `1`, `3`, `15`, and `17`; other categories are discarded. Accepted records are converted to `SrafInputEvent` key, pointer, or platform data. The converter has no string parsing, file operation, `system()`, or `exec*` call.

This is the SRAF browser input path, not the HomePortal receiver for WebUI event type `12`. It rules out the shared browser input normalizer as a command sink, but does not identify the final event-12 consumer. No live event was sent.

### APM privilege and launch configuration (2026-10-22)

`/Customer/profile` starts `bigbang` with `--enable_no_root` when `/etc/cap_control.ini` is present. The configured identities are `APPMGR` UID/GID `2900` with `CAP_SYS_NICE|CAP_KILL`, `WebUIService`/`HomePortal` UID/GID `2903` with `CAP_SYS_NICE`, and `SrafBrowserEngine` UID/GID `10020` with `CAP_SYS_NICE` only. The active SRAF command line contains only `--sraf-app=HbbTV --enable-plugin-in-process --disable-web-security`.

The only MstarLauncher remote-inspector option is commented out in `app.cfg`; no active launch entry enables it. A browser compromise would therefore still require a separate local privilege or IPC escape before it could reach the APM shell or persistence paths.

### WebUI APM argument-target cross-check (2026-10-22)

`OpenApp` accepts an application name before passing it to APM, so the static `param_from_argv=y` entries were checked against the actual `APP.img`. The configured `RESET_QJY` and `Vudu` executables are absent from the shipped image and appear to be stale configuration; they do not provide a usable launch target. The active `Netflix_resetNetflix` target only implements Netflix reset/cache operations. `AMAZON` is present and accepts application parameters, but its visible command-line markers are app-specific (`--deeplink`, `--dial-payload`, `--js-args`); no shell or executable-path argument is exposed. The binary also contains inspector/WebSocket code and imports `system()`/`popen()`, but no data flow from APM parameters to those calls or active inspector listener was established. This leaves an app-argument launch surface for further offline review, not a demonstrated WebUI-to-shell path.

### Amazon Lua command sinks (2026-10-22)

Static decompilation identifies the `system()` wrapper at `0x00963828` as a Lua `os.execute`-style handler: it obtains argument 1 as a string, passes it directly to `system()`, and returns the status. The `popen()` wrapper at `0x0096294c` matches Lua `io.popen`, including the command string and optional mode. These are real local command sinks inside `ignition`, but no WebUI/JavaScript binding, deep-link conversion, or remote inspector route to the Lua state was established. Treat this as an offline candidate only; no Amazon launch was attempted.

`JSScriptHost::_executeScript()` and `LuaScriptHost::_executeScript()` both resolve a plugin-relative path through `PluginPath::getPath()` before execution; the former invokes the JavaScript engine and the latter calls `LuaState::doFile()`. The JS/Lua bridge found in `JsObjectToLuaTableConverter` converts values but does not execute Lua source. This makes the `os.execute`/`io.popen` sinks local plugin-script capabilities, not a demonstrated remote-WebUI primitive.

### Amazon plugin and OTA trust boundary (2026-10-22)

The APP image contains Amazon Ignition plugins under `/applications/Amazon/plugins`, including Lua/JavaScript sources and per-plugin JSON manifests. The image metadata marks these files owner `10045`, group `2900`, mode `0550`; `/Customer/profile` mounts the APP filesystem read-only during normal boot. This is not an application-writable persistence location.

The OTA framework is present as a dependency and uses a production HTTPS inventory endpoint (`https://softwareupdates.amazon.com/software/inventory/thirdparty`). Downloaded packages are staged under `user://.../workspace/`, then checked by `PackageExpander::_validateSignature()` through `ValidationFacility`; the plugin contains a bundled `internal/assets/ota.pub` public key. `DefaultLuaSignatureValidator::validate()` and `DefaultJsSignatureValidator::validate()` accept only paths in the installed plugin group without text validation; other script paths are passed through `IG01TextValidation`. This makes an unsigned replacement package or user-cache script insufficient by itself.

The shipped Stark app does fetch remote `index.js` over HTTPS and executes it with `eval()`. Its local bootstrap accepts `--js-args="--blastHost=..."`; `_passFlagsToJsEnvironment()` separately exposes `--deeplink`, `--dial-payload`, and `--js-args`.

Static APM disassembly shows `RequestToRunWithParam` passing the caller string through `CheckParameterIsFromArgv` into `ExecuteProgram` (`FUN_0001a0ec`); `FUN_000180f0` appends it raw to the command sent to BigBang, which parses argv and calls `execve`. This creates a credible WebUI-to-Amazon-flag path (not a shell injection); a controlled attempt returned a reversible `OpenApp` response but produced no request to the local HTTP canary, so live exploitability remains unconfirmed.

### Ignition JavaScript file bindings (2026-10-22)

The `Amazon/bin/ignition` binary contains a `fileSystem` namespace with a `getFileContentsAsString` binding. The binding accepts one JavaScript string, obtains the current compartment's extension, and calls `LinuxFileSystemFacade::openFile(path, mode=2)`, `getFileSize(path)`, and `FileHandle::read()`. The reviewed method has no visible `PluginPath` group check or canonicalisation before opening the supplied path. This is a potential arbitrary-file-read primitive for JavaScript running inside Ignition; it is not a shell or write primitive.

`PluginJavaScriptBinder::setFileSystemExtension()` stores the extension at binder slot `this+0x54`; `bindNonStaticExtensions()` conditionally registers that slot and defines its JS function. Static inspection confirms the binding/registration path exists, but does not prove that a remotely supplied Stark script can reach it on this firmware.

The related `network.http.data.createFileConsumer(path)` binding is more restricted. The binary's `PluginFileGroup` table maps group `2` to `USER_VAR` and group `4` to `TEST_DATA`; `HttpResponseConsumerFactory::createFileConsumer()` accepts only those groups and otherwise returns a null consumer. Stark's normal downloader first resolves a basename under `user://.../web-cache/`, so the observed HTTP fetch path is a cache write, not an arbitrary filesystem write.

No JavaScript, file path, or file-read probe was sent to the TV. The prior controlled `--blastHost` attempts produced no local canary request, so the remote reachability of these bindings remains unverified.

### Potential OS-information reads (offline only)

The shipped `/etc/passwd` assigns `AMAZON` and `RESET_AMAZON` UID/GID `10045`. Boot code creates `/Customer/AMAZON`, mounts it separately, and applies mode `0700` plus owner `10045:10045`. If the `fileSystem` binding were reachable from a running Amazon script, likely readable targets would include `/proc/self/status`, `/proc/self/cmdline`, `/proc/self/mounts`, `/etc/passwd`, and Amazon-owned `/Customer/AMAZON/*`. Access to root-only files, other app-private directories, or kernel-sensitive paths would still depend on normal Linux permissions and procfs policy. This remains a static capability assessment; no path was requested from the TV.

### Stark remote-index execution boundary (2026-10-22)

The Stark bootstrap fetches `/index.js`, then executes the response with `eval(indexJsContents)` before calling `BlastIgnition.getBlastConfig()`. It takes the returned `files` array and, when the first entry has `location === 'local'`, immediately calls `launchBlast()`. JavaScript resources are then executed with `include(resource.filepath, true)`; Lua resources are passed to the stylesheet loader. Otherwise the listed resources are downloaded into `user://.../web-cache/` and then included. This means a reachable, attacker-controlled `index.js` would already be arbitrary Ignition-JavaScript execution; the `fileSystem` binding is an additional read primitive, not the first execution step. The exact validation performed by `BlastIgnition.getBlastConfig()` is not present in the extracted Stark scripts, and the `blastHost` route was not live-confirmed.

### Safe `/proc` read probe attempt (2026-10-22)

A temporary local server served an `index.js` that would read only `/proc/self/status` and report the `Uid:` line through a second local request. The WebUI session registered successfully and one `OpenApp(AMAZON, --js-args=--blastHost=...)` call returned `res:0`, but the TV made no request for `/index.js` or `/report`. Later Amazon launches returned `res:4` and `GetAppList` continued to show only `Sraf OpenBrowser`. Therefore no script executed and no OS file was read; the temporary server and probe were removed.

### Reversible DIAL launch/canary test (2026-10-22)

`POST /apps/AmazonInstantVideo` with the neutral body `probe=1` returned `201 Created`; a read-only status check showed `running`. The advertised `DELETE /apps/AmazonInstantVideo/run` route returned `200`, and status returned to `stopped`. A second reversible launch used `--js-args=--blastHost=http://192.168.2.100:8000` while a local server served a no-op `BlastIgnition.getBlastConfig()` definition. The POST again returned `201`, but the server received no `/index.js` request during observation. Amazon was stopped normally afterward. This confirms DIAL can start the app, but does not confirm that the supplied `--js-args` reaches Stark or enables a remote index.

A separate WebUI launch with the same canary was observed for 35 seconds; it returned `res:0`, Amazon reached `running`, and the canary still received no request. The app was stopped via the normal DIAL route.

The user then opened Amazon from the TV UI and confirmed that its interface was visible. During that foreground observation, DIAL still reported `stopped` and WebUI `GetAppList` still returned only `Sraf OpenBrowser`; these status APIs do not reliably track the native Amazon process.

A subsequent normal WebUI relaunch (`OpenApp("AMAZON", null)`) returned `res:0`; the DIAL status immediately reported `running`. No deep-link, payload, or stop request was used in this relaunch.

While Amazon remained in the foreground, a read-only network check found only TCP `3697`, `56789`, and `56790` open; HbbTV TCP `7681` was closed. DIAL `GET /apps/AmazonInstantVideo/run` returned `501`, `/dial_data` returned `403`, and no additional Amazon network route appeared.

### Ignition argument parser cross-check (2026-10-22)

The shipped `utils/commandLine.js` documents the exact syntax `--js-args="--myString=foo"`; `parseArgs()` exposes the inner key through `commandLine.args`. Native `ApplicationJsCompartment::_passFlagsToJsEnvironment()` recognizes `js-args`, `dial-payload`, and `deeplink`, while `setDialPayload()` only stores `commandLine.dialPayload`. The DIAL configuration uses `payload_prefix=--dialpayload` (without the hyphen used by Ignition's registered `--dial-payload` option). A reversible WebUI launch using both quoted and unquoted `--js-args=--blastHost=...` returned `res:0` and started Amazon, but a local canary still received no `/index.js`; the argument-to-Stark path remains unconfirmed.

### Chromium 47 JavaScript API probe (2026-10-22)

The browser reported Chrome `47.0.2526.106` with `eval`, `Function`, `JSON`, URL objects, Web Storage, iframe sandbox/postMessage, WebSocket, fetch, Promise, and typed arrays available. `Proxy` and WebAssembly were absent. The probe only fingerprinted APIs and sent its text result to the local harness; it did not read files, load PDF data, send malformed input, or persist state. These results identify browser features only.

### SRAF JavaScript bridge probe (2026-10-22)

The browser exposes `window.sraf` plus global SRAF wrappers and constants. `sraf_ext` contains native `send`/`sendSync` methods and `ui`, `browser`, `tabs`, and `view` namespaces. Read-only calls from the page succeeded: `browser.isEnableCORS()` returned `false`; `ui.getHomepageUrl()` returned an empty string; `ui.getKeyboardStatus()` returned `undefined`. The WebUI WebSocket on TCP `3697` accepted a handshake, while HbbTV `7681` rejected it. No mutating wrapper, command payload, navigation, file access, or persistence operation was invoked. This is a confirmed browser-to-native UI bridge, not yet an OS or shell escape.

### SRAF custom JavaScript extension audit (2026-10-22)

`libsrafcustomjs.so` registers global constructors `mtvapiA` and `mtvapiB`. Their prototypes expose demo methods (`getIp`, `getPersonalInfo`, `setNetwork`, `changeWeight`, `flyTo`, `goHome`, etc.). Safe getter calls returned only demo values (`undefined`, `true,false,true`, and `My Ip 192.168.0.2`). The library imports no shell, file, socket, or process-execution APIs, so these objects are not an OS bridge.

The common SRAF JavaScript buffer also contains a dormant `inject_ajax_code()` helper that would append an external HTTP jQuery script, but the extracted buffer contains only its definition; no call site was found. No external script was loaded.

### SRAF custom-script loading audit (2026-10-22)

`libsraf_core.so` resolves custom JavaScript by taking the resource directory, appending `/javascripts/<AppID>.dat`, and either AES-decrypting or reading that file. The shipped APP image contains only four encrypted `.dat` files (`FLINGO`, `Facebook`, `Picasa`, and `Twitter`). The only configuration exposing `EnableCustomPlainJs`/`CustomJsPath` is `NRGPortal.json`, where the feature is disabled (`0`) and the path is empty. No WebUI/DIAL write or download path to these APP resources was found; the image is mounted read-only during normal boot. This is therefore a static resource-loading feature, not a practical network-to-persistent-JS injection path.

An extended APP-image audit recovered `libsraf_core.so`, `libsrafcustomjs.so`,
`libadaptor_ipc.so`, and the HbbTV APM client/server libraries. Decompilation
of `sraf_js_get_app_user_js()` confirms that the plain-file branch is gated by
`EnableCustomPlainJs == 1`, then reads only the configured `CustomJsPath` as
the browser user. The shipped configuration keeps that branch disabled.

The HbbTV APM client/server IPC uses local Unix-domain sockets
(`/domain_data/sraf_apm_named_domain_socket` and
`/OAD/data/seraphic_browser/sraf_named_domain_socket`). The server imports
`dlopen`/`dlsym` and `popen`, but no TCP listener or network-controlled loader
argument was identified; its `detect_process` helper is an internal process
presence check. `libsrafcustomjs.so` itself has no file, socket, shell, or
process-execution imports. These components do not add a LAN-to-shell path.

### SRAF IPC dispatcher audit (2026-10-22)

The stripped browser binary still exposes `sraf::MsgHandleContext::HandleSyncIPCOnUI` and `HandleAsyncIPCOnUI`. The asynchronous dispatcher reads an integer selector, accepts only seven consecutive values (`1001`–`1007`), and routes them to fixed UI virtual methods; the synchronous path handles the same small selector set and serializes the result through the SRAF IPC client. The inspected handlers consume bounded JSON integer fields and call browser/UI objects. No `system`, `exec*`, `popen`, `dlopen`, or `dlsym` import is present in `sraf_browser_bin`, and no file/process primitive is reached from these dispatchers. This confirms that `sraf_ext.send/sendSync` is an IPC-backed browser/UI command bridge, not an exposed shell or library-loader interface.

### Deep JavaScript surface probe (2026-10-22)

`analysis/probes/chromium47-js-probe.html` now performs presence-only checks for Web MIDI, PDF MIME handling, IndexedDB, workers, MediaSource, Web Audio, WebRTC, WebCrypto, Service Worker, SharedArrayBuffer, Atomics, canvas/WebGL, and frame/origin state. It also enumerates SRAF command constants and native-looking global function descriptors without invoking them. Existing read-only WebSocket handshakes and SRAF getter calls remain unchanged. No file, PDF, MIDI request, malformed input, command, navigation, or persistent write is attempted.

The TV loaded the updated probe and reported: Web MIDI present; PDF MIME handler absent; IndexedDB, workers, MediaSource, Web Audio, WebRTC, WebCrypto, Service Worker, canvas, and WebGL present; SharedArrayBuffer and Atomics absent. The page was top-level at the LAN HTTP origin. The page exposed SRAF command constants including load/reload/tab/view operations and helper functions such as `sraf_load_url_from_link`, but these were only read through descriptors/source text. The read-only SRAF getters returned the same values as before; the WebUI handshake opened and HbbTV returned an error. No native mutator was called.

### WebUI dynamic-loader call-graph check (2026-10-22)

The only call to `MstarSharedObjectManager::GetSymbolAddress()` in `WebUIService-0.3` is `TVClient::IsWanAvailable(bool&)`. Its arguments are compiled constants: `libnetworkmanager.so` and `_ZN14NetworkManager12GetWanStatusEv`; the returned pointer is stored at `TVClient+0xe0` and called only for WAN-status reporting. No JSON field, WebSocket string, or command-table entry reaches this loader. The generic `LoadSharedObject`/`GetSymbolAddress` helpers therefore remain internal implementation code, and the LAN WebUI still has no confirmed path to arbitrary `dlopen`/`dlsym`, TvManager shell execution, or flash operations.

### SRAF browser-client command bridge audit (2026-10-22)

`libbrowser_client.so` exports `sraf_browser_client_general_cmd(std::string const&)`, but it only forwards the string to `libsraf_client.so`. That library encodes it as a `general_cmd` field and sends it through `libsraf_ipc.so`, which uses local SysV message queues (`msgget`, `msgsnd`, `msgrcv`, `msgctl`), not TCP. The WebUI command table does not register this API, and no LAN-to-IPC route was found.

The same library imports `popen()`, but its only call site is `detect_process()`. It builds fixed process-presence checks (`ps | grep -c %s` / `ps w | grep -c %s`) and the observed caller passes the compiled constant `sraf_browser_bin`; this is not a caller-controlled shell sink. No `system()`/`exec*()` path was found through the browser-client bridge. Detailed evidence is in `analysis/browser-client-audit.md`.

### DIAL launcher audit (2026-10-22)

`dialserver` imports `fork()` and `execv()`, but the call is a non-shell helper receiving an executable path and argv vector. The visible main path only creates DIAL, registers the configured applications, starts the server, and calls `run_ssdp()`. `dialappsetting.ini` exposes fixed app names and origins; the Amazon entry has a payload prefix but no executable path. The Netflix payload file is `/dev/shm/dial_argv` (volatile tmpfs). No direct main-path call or network-controlled executable path was established, and no shell import exists. DIAL remains an app-control surface, not a confirmed root execution path. Detailed evidence is in `analysis/dial-audit.md`.

### APM `system()` call-site review (2026-10-22)

`appmgr` imports `system()`, but its eight call sites are lifecycle/storage helpers. The embedded command templates are `cp -f %s %s`, `sync`, `mkdir -p`, `mount -o loop`, and `umount`; the surrounding code supplies paths from internal app/config and tmpfs handling. The app configuration's `kill_list_*` values are resolved as registered application names and used for lifecycle control, not concatenated into these shell strings. No `APM_SendEventEx`/WebUI event-data path to `system()` was found in the reviewed call sites. This removes another apparent APM-to-shell shortcut; the remaining event-12 receiver is still unidentified offline.

### USB/media-player surface audit (2026-10-22)

HomePortal maps the `media` input to the native event `open_media_player: main`. `OpenNativeUI()` wraps it as `open_from_webui: ...` and sends it through APM; the reviewed path has no `system()`, `exec*()`, or shell expansion. USB automount mounts `/dev/sd*` under `/usb/sd*` for `vfat`/`ntfs` and does not execute mounted files.

The MSLIB image contains the native media stack (`libvdplayer`, `libmdmpplayer`, `libOMX.MStar`, subtitle and USB mass-storage Binder services). `libvdplayer` exposes demux/parser markers for MP4, ASF, RM, FLV, SWF, OGM, MKV, AVI, TS, MPG, DSS, JPEG/MPO, and subtitles; `media_codecs.xml` advertises MStar AVC/HEVC/MPEG-2/VP8/VP9/VC-1/MJPEG/AVS/AVS2/RealVideo and many audio decoders. The reviewed player library imports file I/O and decoder APIs but no shell execution primitive.

The selected ARM media libraries have no `__stack_chk_fail` reference and no `GNU_RELRO` segment; their `GNU_STACK` is non-executable (`RW`). This is a confirmed hardening weakness in the recovered `v1.1.8` image, not a proven parser overflow or jailbreak. It would make a separately confirmed memory-corruption bug easier to exploit.

This is a credible local native-parser crash/RCE surface, not a demonstrated shell path. A parser compromise would still require a media-process escape and a privilege boundary crossing. No malformed media was created or sent. Detailed evidence is in `analysis/media-player-audit.md`.

`libmmplayerservice.so` registers a Binder service named `mstar.mmplayer` with media-item creation, file-process callbacks, partial-payload, metadata/thumbnail, subtitle, and shared-memory operations. USB and subtitle services are Binder-only and the reviewed service libraries import no socket or shell execution APIs. This is a sizeable local IPC surface, but no direct LAN path or WebUI Binder transaction was identified.

### DIAL support-library audit (2026-10-22)

The HTTP/DIAL implementation was extracted from the recovered `MSLIB.img` as
[`analysis/dial-libs/libdialapm.so`](analysis/dial-libs/libdialapm.so). It is an
ARM ELF (53,060 bytes) with socket/HTTP and file-I/O imports, but no
`system()`, `exec*()`, `popen()`, or `fork()` imports. Launch handling calls
APM/application callbacks; the payload remains app data/arguments rather than
an executable path or shell command.

The reviewed HTTP body read is limited to 4096 bytes within a larger stack
frame, and parameter construction uses bounded `strncpy()`/`snprintf()` calls.
No direct overwrite, command-execution, or persistent-write primitive was
established. The Netflix payload path is `/dev/shm/dial_argv` (volatile).

Unauthenticated LAN app-control and permissive CORS/Origin handling remain
security weaknesses, but current evidence supports reversible app launch/stop,
not a root shell. No malformed request was sent to the TV.

### DIAL `dial_data` parser candidate (offline only)

The POST `/apps/<app>/dial_data` path reaches `parse_params()`, which allocates
`strlen(token)` bytes and then uses unbounded `sscanf("%[^=]=%s", ...)`. A
token without `=` causes the first conversion to copy its terminating NUL one
byte past the allocation. An ASan harness reproducing the recovered code
confirms the heap-buffer-overflow locally ([harness](analysis/dial-parse-harness.c)).

This is a confirmed static memory-safety defect in the recovered DIAL library,
not yet a confirmed TV crash or RCE. Route reachability, allocator layout, and
post-parse use remain unverified. No malformed body was sent to the TV.

Safe live reachability checks using the valid body `a=b` returned `403
Forbidden` for both `/apps/HbbTV/dial_data` and
`/apps/AmazonInstantVideo/dial_data`. The parser was not reached; Amazon
remained stopped and the DIAL service stayed healthy.

### HbbTV `libcs.so` reachability audit (2026-10-22)

The configured HbbTV library [`libcs.so`](analysis/dial-libs/libcs.so) exposes
Binder-only create/launch/stop/status methods. It has no shell/process imports
or TCP listener; its `socket()` use is for local interface discovery. The
configuration sets `auto_register_app=0`, with `/tmp/dial_data` only in that
disabled HbbTV block. This explains the live `403` results and leaves the
`libdialapm.so` parser bug as an offline candidate rather than a reachable
LAN exploit. No Binder call was attempted.

### NetRange/QJY public-surface review (2026-10-23)

Public searches found no NetRange, `QJY NETRANGE`, `qjyBrowser`, or `NETRANGEMMH` CVE/advisory. Public material describes NetRange as a cloud/white-label portal delivered through a TV browser, while Seraphic documents NetRange Portal running on Sraf HTML5 Browser; this points to the browser/SRAF/HbbTV stack as the local attack surface, not a standalone NetRange daemon ([NetRange/ACCESS](https://netrange.com/access-and-netrange-set-new-standards-interacive-entertainment-smart-tvs-launch-integrated-hbbtv), [Seraphic TV Portal datasheet](https://www.seraphic-corp.com/Download.aspx?filer=%2FUpload%2FFile%2F&url=2018-06-29%2F201806291408123092.pdf%7CSERAPHIC_TVPortal_datasheet.pdf)).

The firmware's opaque NetRange hostname resolves to `lb.netrange.com`; plain HTTP returns `403`, while HTTPS requests without a client certificate are rejected. No probing beyond DNS and one header request was performed. No NetRange-specific entry point was identified.

The recovered `MSLIB.img` also contains [`analysis/qjy-post-audit.md`](analysis/qjy-post-audit.md). `libqjyPost.so` is a telemetry uploader for `app.dcc.ninja`, not the NetRange portal and not a shell bridge. The QJY browser executable itself is missing from the recovered partition set, so its argument parser and native bridge remain the main unresolved QJY-specific items.

The same audit found a conditional QJY telemetry crash candidate: its libcurl write callback treats the response buffer as a NUL-terminated C string and calls `%s`, `strcmp()`, and `atoi()` without using the callback length. A non-NUL-terminated response could trigger an out-of-bounds read, but the endpoint is hard-coded, TLS verification is normally enabled, and no response manipulation or live crash test was attempted.

### Official U43H7L firmware cross-check (2026-10-23)

The existing artifact `artifacts/official/ChiefUpgrade_m7322_dvb.bin` was unpacked offline with an `mscompress7` LZMA extractor. Its reconstructed `APP`, `CONFIG`, `MSLIB`, and `customer` partitions are byte-identical to the previously recovered images (same SHA-256 for each). This confirms the downloaded package is the same firmware image already under analysis, not a newer QJY-enabled build.

The image contains `sraf/bin/sraf_browser_bin` and `libqjyPost.so`, but no `qjyBrowser` executable. `CONFIG` sets `QJY_BROWSER_ENABLE=0`; the remaining qjyBrowser entries in `customer` are commented configuration examples. `SECURE_BOOTING_ENABLE=1`, `ENCRYPTED_NETWORK_UPGRADE_ENABLE=1`, and `OAD_UPGRADE_WITH_USB=0` are also present. The update script removes/recreates partitions, so it was not installed or modified.

### RFS console/telnet configuration audit (2026-10-23)

The official RFS image contains `etc/inittab` with `ttyS0::respawn:-/bin/sh`, so the stock system is configured for an interactive shell on the serial console. `CONFIG` also contains `BOOT_DISABLEUART=0`. This confirms a UART shell path in software, subject to board access and wiring.

`etc/init.d/rcS` contains a commented template line, `#/bin/telnetd -l /bin/sh`, but no `telnetd` executable or symlink was found in RFS; only `usr/bin/telnet -> ../../bin/busybox` is present. The stock image therefore does not expose a network telnet service. No file or firmware modification was made.

### Telnet-enable update feasibility (2026-10-23)

Uncommenting the `rcS` line would not be sufficient: the referenced `/bin/telnetd` is absent, and the BusyBox image has no `telnetd` applet marker. The RFS update is also followed by `store_secure_info ROOTFSSign`; with `SECURE_BOOTING_ENABLE=1`, changing one byte in the SquashFS invalidates the signed partition. A usable update would require the OEM signing key and matching vendor tooling, neither of which is present in the artifact. No modified or flashable update was generated.

The signature records decode as `SECURITY` structures (`ROOTFSSign`, `kernelSign`, and `keySetSign`). The associated `keySet` payload is 0x524 bytes of `0xff`, not a usable private/public key bundle. No OEM private key is present in the firmware artifact.
