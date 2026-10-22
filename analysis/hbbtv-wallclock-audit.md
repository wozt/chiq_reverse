# HbbTV Wall Clock UDP audit

## Result

`analysis/appfs/sraf/lib/libsraf_hbbtv_wsserver.so` contains a confirmed out-of-bounds-read condition in `SrafCSSWCServer::startWCServer()`.

The configured Wall Clock listener is UDP/7682 (`analysis/appfs/sraf/config/HbbTV.json`). The ARM code at `0x94ba` initializes a stack buffer at `sp+0x17c` with 128 zero bytes, then calls:

```text
recvfrom(fd, sp+0x17c, 128, 0, ...)
```

At `0x9750` it immediately calls:

```text
strcmp(sp+0x17c, configured_string)
```

There is no NUL terminator write based on the returned length. A datagram of exactly 128 bytes with no NUL overwrites the complete initialized buffer; `strcmp()` then reads past the 128-byte object. The likely direct impact is a malformed-datagram crash/DoS. This is not evidence of code execution.

`StringToSrafWCMessage()` is also called with the received buffer and length, but its fixed reads through offset 28 remain within the 128-byte buffer; the unbounded `strcmp()` is the primary flaw.

## Exposure status

- Firmware/config provenance: extracted `v1.1.8` recovery image; the TV reports `v1.1.9`.
- The config declares UDP/7682, but the tested TV boot had UDP/7682 closed.
- A one-byte UDP probe received `ECONNREFUSED`; the TCP services on 3697, 7681, 56789, and 56790 remained reachable afterward.
- No malformed 128-byte datagram was sent to the TV.

## Evidence

- Binary SHA-256: `ef478bf10b2088a90303ebbe489791791639ffaef1c09e228af216252a39233d`
- Relevant symbols: `SrafCSSWCServer::startWCServer` at `0x9461`, `SrafWallClock::StringToSrafWCMessage` at `0xacd9`.
- Relocations include `recvfrom@GLIBC_2.4` and `strcmp@GLIBC_2.4`.
