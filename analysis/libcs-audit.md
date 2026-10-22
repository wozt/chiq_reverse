# HbbTV `libcs.so` audit

Date: 2026-10-22

## Result

`libcs.so` is the configured HbbTV DIAL application library in
`dialappsetting.ini` (`app_library_path=/mslib/libcs.so`). It exposes Binder
methods for creating, launching, hiding, stopping, and querying the HbbTV
application. `CSS_DIAL_Service_Instantiate()` starts a detached Binder thread
and registers the service with Android's service manager.
SHA-256: `5c1dc67c4cefa6fab49139a276f6bb2a19da62af92c4bb22b0f178b458435fe5`.

The library has no `system()`, `exec*()`, `popen()`, `fork()`, `bind()`,
`listen()`, or TCP accept loop. Its `socket()` use belongs to local interface
discovery; the control API is Binder-only. A LAN caller would need a separate
Binder bridge, which was not found in DIAL, WebUI, or HbbTV WebSocket paths.

The HbbTV DIAL configuration sets `auto_register_app=0`, while the only
`dial_data_path` is `/tmp/dial_data` in that disabled auto-registration block.
This matches the live result: valid POST requests to both HbbTV and Amazon
`/dial_data` returned `403 Forbidden`. The vulnerable `libdialapm.so` parser
therefore remains an offline candidate, not a currently reachable TV path.

No Binder transaction or malformed DIAL request was sent to the TV.

## SRAF/CSM bridge review

`libsraf_hbbtv_adaptor.so` depends on the HbbTV WebSocket, IPC, and platform
libraries, but not on `libcs.so`; it has no `dlopen`/`dlsym` import and contains
no `system()`, `exec*()`, `popen()`, or `fork()` import. Its CSM exports
(`Sraf_CSM_LaunchCSApp`, `Sraf_CSM_SetAppLaunchURL`, and discovery helpers)
operate through internal callbacks and IPC.

The adaptor contains SSDP/DIAL discovery constants (`239.255.255.250:1900`,
`M-SEARCH`, `urn:dial-multiscreen-org:service:dial:1`) and UDP
`sendto`/`recvfrom` calls. This is discovery traffic, not a TCP listener or a
network-to-Binder bridge. The WebSocket library has no direct call to the CSM
exports, and no registration path from TCP/7681 to `CSS_DIAL_SERVICE` was
identified.

**Conclusion:** the disabled HbbTV DIAL library remains a local Binder
component. The recovered SRAF/CSM code does not provide a LAN path to activate
it or to obtain shell/file-write access.

## Read-only live check

`GET /apps/HbbTV` still returns `state=stopped` and advertises a remote App2App
URL plus CSS-CII/TS URLs. The advertised remote App2App URL accepts a WebSocket
upgrade; the advertised CSS-CII and CSS-TS URLs returned `403 Forbidden` during
a handshake-only check. No application frame or control operation was sent.
