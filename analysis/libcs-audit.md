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
