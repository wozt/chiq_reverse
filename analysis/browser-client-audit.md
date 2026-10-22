# SRAF browser-client audit

Date: 2026-10-22

## Result

`libbrowser_client.so` exports `sraf_browser_client_general_cmd(std::string const&)`, but this is only a wrapper around `sraf_mas_client_general_cmd()` in `libsraf_client.so`. The latter serializes the supplied string as the `general_cmd` field of a local SRAF IPC message (`appID`, `general_cmd`, `subcmd`). `libsraf_ipc.so` implements that transport with SysV message queues (`msgget`, `msgsnd`, `msgrcv`, `msgctl`), not TCP or a browser socket.

The library imports `popen()`, but the only call is in `detect_process(const char*)`. Both call sites build fixed commands equivalent to `ps | grep -c %s` / `ps w | grep -c %s`; the only observed caller supplies the compiled constant `sraf_browser_bin`. This is an internal boot/process-presence check, not a WebUI-controlled command path.

No SRAF binary reviewed imports `system()` or `exec*()` through this browser-client path. No undefined consumer of `sraf_browser_client_general_cmd()` was found outside the browser-client wrapper itself. The WebUI command table contains no registration for `general_cmd`, and no LAN route to the SRAF SysV IPC queue was identified.

## Security boundary

The API is potentially powerful for a local native caller that already has access to SRAF IPC, but the recovered evidence does not connect it to TCP/3697, TCP/7681, DIAL, or JavaScript. No live command was sent.
