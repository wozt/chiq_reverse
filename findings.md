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
- **HbbTV Wall Clock UDP (configured port 7682):** `SrafCSSWCServer` binds a UDP socket and receives up to 128 bytes. The receive path then calls unbounded `strcmp()` on the receive buffer without visibly adding a NUL terminator; a full 128-byte datagram containing no NUL could cause a read beyond the buffer and a crash. `StringToSrafWCMessage` also ignores the supplied length and reads fixed fields through offset 28, but those reads remain within the 128-byte buffer. This is a credible malformed-datagram crash/DoS lead, not confirmed code execution. No UDP payload was sent.
- **Native HbbTV/DIAL Binder layer:** `libcs.so` registers the local Binder service name `CSS_DIAL_SERVICE_NAME` and exposes `CreateHbbTVApplication`, `SetAppLaunchURL`, `LaunchHbbTVApplication`, status, hide, and stop methods. The native launch wrapper accepts a URL string and forwards it to the WebTV service; no scheme/host validation is visible in this wrapper. The Binder transaction handler visibly checks only the interface token; no caller-UID/permission check was found in this layer. Separate APIs exist to add, remove, or clear the HbbTV security whitelist. This is an offline local attack-surface lead only: Binder is not exposed over the tested LAN ports, deeper WebTV validation is not yet mapped, and no launch call was made.
- **HbbTV DIAL/App2App endpoint (TCP/7681):** unauthenticated `GET /apps/HbbTV` returns the current HbbTV state and exposes a nominally tokenized `ws://.../remote/hbbtv/<token>/` URL. Its CORS response reflects an arbitrary `Origin`; read-only handshakes returned `101 Switching Protocols` with `Origin: https://attacker.example` for both `/remote/hbbtv/*` and `/local/hbbtv/*`, including arbitrary suffixes (`deadbeef`, `random-token`, `foo`). No subprotocol or additional authentication was required. Static analysis of `MediaSyncServer::handlePairingConnection` shows that the routine stores the suffix supplied by the first client and pairs a `local` and `remote` client when both present the same suffix; it does not visibly compare that suffix with the generated `m_local_random`/`m_remote_random` values. When pairing is enabled, `handlePairingMsg` forwards the complete incoming payload to the opposite socket with `lws_write`; no message parser, schema check, origin check, or per-message authorization is visible in this relay path. However, `m_enablePairing` is initialized to `0`, and no write to `1` or setter was found in this library. The binary contains `pairingcompleted`, `local paired`, and `remote paired` responses, but the relay path appears dormant in the tested build. The companion CSS-CII URL was advertised but returned `403` to the same handshake. HbbTV specifies local and remote endpoints to be paired between an HbbTV app and a Companion Screen; accepting both endpoint classes from arbitrary LAN clients is therefore an access-control weakness. Control impact and message authorization remain unconfirmed. Reference: <https://www.etsi.org/deliver/etsi_ts/102700_102799/102796/01.04.01_60/ts_102796v010401p.pdf>.
- **HbbTV endpoint-token generation:** `MediaSyncServer::createRandom()` seeds the process-wide PRNG with `srand(time(NULL))`; its helper hashes successive `rand()` outputs with MD5 and stores the hex digest as the endpoint suffix. MD5 does not add entropy, and second-resolution seeding makes tokens potentially predictable if the process start time and PRNG sequence are known. No token prediction was attempted. The endpoint also accepts arbitrary suffixes at the handshake layer, so token unpredictability is not currently an effective access-control boundary.
- **Live pairing check:** two controlled tests opened simultaneous `local` and `remote` WebSockets with the same attacker-chosen suffix (both connection orders). All four handshakes returned `101 Switching Protocols`; no server frame (`pairingcompleted` or otherwise) and no forced close was observed during a four-second receive window. Dynamic pairing is therefore not confirmed in the current TV state, despite the static relay/pairing logic above. No application payload was sent.
- **Screencast/Miracast:** separate Wi‑Fi Direct/display-casting path; it does not expose a shell, SSH, Telnet, or a confirmed LAN code-execution primitive. Dropped from the shell-access plan.
- **DIAL service (TCP/56789):** `libdialapm.so` hard-codes the Mongoose listener to port `56789` and implements `GET, POST, OPTIONS` under `/apps/`. `GET /apps/YouTube` and `GET /apps/Netflix` return application state without authentication. The status response formats `Access-Control-Allow-Origin: %s` from the request origin; live tests confirmed reflection of arbitrary origins, despite per-application `allowed_origin` entries in `dialappsetting.ini`. This confirms a CORS policy weakness for read-only status endpoints; the separate launch/overflow test is documented below.
- **DIAL payload-length lead (offline):** `dial_start_app` builds the launch argument in a fixed 6144-byte stack buffer using bounded `snprintf`, but several paths add the formatter's would-be output length to the running offset without clamping it to the bytes actually written. A DIAL payload longer than the remaining buffer could therefore make the next `6144 - offset` size calculation underflow and turn a later `snprintf` into an overwrite. The request-body path accepts an 8192-byte working buffer, so the condition appears reachable in principle. This is an unconfirmed crash/code-execution lead; the controlled 3000/4000-byte tests below did not reproduce it.
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

- The shipped Chromium `47.0.2526.106` predates the fix for **CVE-2016-1629**, which Google fixed in `48.0.2564.116` and described as a critical Blink same-origin bypass plus Chrome sandbox escape: <https://chromereleases.googleblog.com/2016/02/stable-channel-update_18.html>. This is a strong version-level candidate, but the original bug details were kept restricted and no reliable public PoC was found. Applicability to this ARM/SRAF build is therefore unconfirmed; no exploit was sent to the TV.
- Google also fixed multiple Chromium/V8/PDFium issues in Chrome 48, including CVE-2016-1612 and CVE-2016-1613: <https://chromereleases.googleblog.com/2016/01/stable-channel-update_20.html>. These are renderer-level leads, not a demonstrated root or shell path.
- A public MStar advisory documents command injection through malicious USB-upgrade filenames on some MStar set-top boxes: <https://github.com/Ivan-Markovic/Command-injections-via-USB-upgrade-in-MSTAR-Set-Top-box>. Our firmware contains a related MBOOT/update parser lead, but model-specific applicability is unconfirmed. Testing would require USB insertion and reboot and remains out of scope because of brick risk.
- CHiQ's official service portal requires the device serial number and warns that firmware is intended for repair; no public U43H7L package matching this build was found: <https://aftersales.changhong.cz/de/firmwaresearch/>.

The local official `ChiefUpgrade_m7322_dvb.bin` is an older `v.1.1.8` package for chip `m7322` (the TV reports `v.1.1.9`). Its 64-KiB plain-text MBOOT script contains `force_overwrite`/partition recreation commands for certificate, customer, MBOOT, rootfs, APP, and other partitions, followed by CRC and secure-signature records. It is useful for offline parser comparison only; modifying or installing it would be a full-flash operation, not a safe shell-enablement update.

The supplied Tenable reference is useful but does not directly match this TV: plugin 87245 checks **Chrome `<47.0.2526.80`** and recommends `47.0.2526.80` or later. The TV reports Chromium `47.0.2526.106`, so that specific vulnerability bundle is not proven applicable by version alone. The plugin is also a Windows local assessment and lists many generic Chrome CVEs; it does not establish exploitability on this ARM Linux/SRAF build: <https://www.tenable.com/plugins/nessus/87245>.

The exact `.106` build is nevertheless below the next stable security line. Google Chrome `48.0.2564.82` fixed CVE-2016-1612 (V8 bad cast) and CVE-2016-1613 (PDFium use-after-free); both records list Chrome versions through `47.0.2526.106` as affected. These are credible renderer-crash/memory-corruption leads, but the public descriptions do not provide a working ARM PoC or prove a shell. Separately, CVE-2016-1629 was fixed only in `48.0.2564.116` and was described by Google as a critical Blink same-origin bypass plus Chrome sandbox escape. The build is therefore a valid research target, but a live exploit attempt would still be speculative and could simply crash/restart the browser.

Offline strings confirm that the shipped browser contains PDFium-related interfaces (`application/pdf`, `PPB_PDF`), so CVE-2016-1613 cannot be dismissed as an obviously absent component. No crafted PDF was opened against the TV.

### Safe browser probe (2026-10-22)

`analysis/probes/chromium47-safe-probe.html` fingerprints the reported Chromium version, PDF MIME/plugin presence, selected JavaScript features, and iframe sandbox API. It performs no file reads, socket/WebSocket connections, PDF loads, malformed input, exploit attempt, or persistent change. Its output cannot prove whether CVE-2016-1612, CVE-2016-1613, or CVE-2016-1629 is patched; a crash-free result is expected.

The TV-side result reported Chromium `47.0.2526.106`, one browser plugin, `27` MIME types, no exposed `application/pdf` MIME handler, no WebAssembly or Proxy, but Symbol, Uint8Array, WebSocket, postMessage, and the iframe sandbox API. This means a normal web page cannot reach a registered PDF plugin through `application/pdf`; it does not prove that PDFium code is absent from the firmware. The result is a fingerprint, not a CVE verdict.

### Offline Chromium marker audit (2026-10-22)

`analysis/probes/chromium47-offline-audit.py` reads the extracted ARM binary without executing it. The target is ELF32 ARM, 36,935,984 bytes, SHA-256 `3dfbd071c242d6fa10e502dd2d1f1e5f79c5f9a99108593fd730a6118897a74c`. Printable markers include `application/pdf`, `PPB_PDF;1`, V8/Blink symbols, and `FrameMsg_SrafExtensionExecuteRequest`; no `WebAssembly` marker was found. The binary contains strings for sandbox command-line switches, including `--no-sandbox`, but `/Customer/app.cfg` does not enable them. These are component/feature markers only and do not establish a reachable vulnerability or exploit path.

### Root console / telnet check (2026-10-22)

The extracted rootfs has a physical serial console configured: `/etc/inittab` respawns `-/bin/sh` on `ttyS0`, and the boot environment sets `console=ttyS0,115200`. This is a UART path, not a LAN service. `/etc/init.d/rcS` contains a commented `/bin/telnetd -l /bin/sh` line, but no `telnetd` binary or BusyBox `telnetd` applet was found in the extracted rootfs; only the BusyBox telnet client is present. No software-only route to enable that shell was identified.

The same browser binary also contains Chromium DevTools protocol code and the `remote-debugging-port` switch. The active `SrafBrowserEngine` entry does not pass that switch, and the TV-side scan found no port `9222`. `OpenApp` exposes only `appName` and `deepLink`; `SrafBrowserEngine` is not marked `param_from_argv=y` in `app.cfg`, so the static configuration gives no supported way to inject a DevTools argument.

### Public board photos (2026-10-22)

Public parts listings identify the U43H7L mainboard as `JUC7.820.00242703 / C430Y19-7N / HLS90FJ-iU`; the photographed board has the same markings and a matching U43H7L label: <https://www.ebay.de/itm/285943464271>, <https://vareza.de/u43h7n-juc7-820-00242703-c430y19-7n-hls90fj-iu-mainboard.html?language=de>. The available top-side photos do not expose a clearly labeled UART header or pad. They confirm board identity only; they do not identify the `UART-TX`/`UART-RX` physical pads.

The available mainboard schematic (`analysis/schematics/mainboard-page-8.png`, sheet 8/15) marks separate `UART-TX` and `UART-RX` nets next to the HDMI2 block, inside a green `ISP debug` annotation. The arrows point to schematic page 2; they are net cross-references, not HDMI connector pin numbers. This page provides no physical test-pad reference, voltage, or UART ground pin, so the exact board header cannot be identified from the supplied documentation. HDMI2 pins must not be used as UART pins.

### Upstream CVE record check (2026-10-22)

The public Chromium record for CVE-2016-1612 is issue `497632`; its fix was merged to the 4.7 branch as V8 `4.7.80.29`. The extracted browser contains the string `4.7.80.25`, which is an additional version-level indication that this V8 fix is absent, but it is not a live proof or an exploit. The upstream report describes a renderer crash and the details are not a safe TV test. CVE-2016-1613 remains a crafted-PDF PDFium use-after-free; no public, reliable ARM reproduction was found. CVE-2016-1629 remains an unspecified Blink/sandbox issue with restricted details. References: <https://bugs.chromium.org/p/chromium/issues/detail?id=497632>, <https://nvd.nist.gov/vuln/detail/cve-2016-1613>, <https://nvd.nist.gov/vuln/detail/cve-2016-1629>.

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
