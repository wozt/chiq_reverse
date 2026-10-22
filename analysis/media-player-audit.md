# USB/media-player surface audit

Date: 2026-10-22

## Static evidence

- HomePortal maps the `media` input to the native event `open_media_player: main`.
- `OpenNativeUI()` wraps that string as `open_from_webui: ...` and sends it through APM. The reviewed path contains no `system()`, `exec*()`, or shell expansion. The WebUI exposes only the fixed command route; it is not an arbitrary native executable launcher.
- USB automount uses `/dev/sd*` and mounts under `/usb/sd*`, with special handling for `vfat` and `ntfs`. It does not execute files from the mounted volume.
- The MSLIB image contains the native media stack: `libvdplayer.so`, `libmdmpplayer.so`, `libOMX.MStar.so`, `libsubtitlemanager.so`, `libusbmassstoragemanager.so`, and related Binder services.
- `libvdplayer.so` contains demux/parse paths and format markers for MP4, ASF, RM, FLV, SWF, OGM, MKV, AVI, TS, MPG, DSS, JPEG/MPO, and subtitles. `media_codecs.xml` advertises MStar AVC, HEVC, MPEG-2, VP8/VP9, VC-1, MJPEG, AVS/AVS2, RealVideo, and numerous audio decoders.
- The extracted media libraries import file I/O and MStar decoder APIs. The reviewed `libvdplayer.so` imports no `system`, `exec*`, `popen`, or `dlopen`; `libOMX.MStar.so` imports `dlopen`, but its visible use is codec/component loading.
- The selected ARM media shared libraries have no `__stack_chk_fail` reference and no `GNU_RELRO` segment; their `GNU_STACK` is non-executable (`RW`). This is a confirmed hardening weakness in the recovered `v1.1.8` image, not by itself a memory-corruption bug or a working jailbreak. It would make a separately proven parser overflow easier to exploit.

## Assessment

This is a credible local crash/RCE surface because many old native parsers and hardware codecs process USB-controlled bytes, especially containers, subtitles, JPEG/MPO, and codec extradata. It is separate from Chromium and does not automatically provide a shell: a parser compromise would still need to escape the media process and then cross the platform privilege boundary.

No malformed media was generated or sent to the TV. The safe next step is offline analysis of these ARM libraries and their Binder interfaces; an active malformed-file test should only be considered with a recovery plan because it can hang or reboot the TV.

## Binder reachability

`libmmplayerservice.so` registers a Binder service named `mstar.mmplayer`. Its interface includes `MM_CreateMediaItem`, `MM_SetFileProcessInfo`, `MM_PushPayloadPartial`, metadata/thumbnail operations, subtitle controls, and shared-memory buffer operations. `libusbmassstoragemanagerservice.so` similarly exposes a Binder-only USB mount list, and the subtitle/player service libraries contain no socket, `exec*`, `system`, or `popen` imports.

This confirms a sizeable local IPC attack surface, but not a LAN entry point. The current WebUI command table does not expose Binder transactions directly, and no network socket is imported by the reviewed media services.
