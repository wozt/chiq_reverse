# Chromium 47 source audit

Date: 2026-10-22

## Snapshot

- Upstream tag: `47.0.2526.106`
- Archive: `chromium-47.0.2526.106.tar.gz`
- SHA-256: `2e6e210860097d25a79015024636ab80a44b5d48abad4389cc6e1c1037133d1f`
- Local source: `analysis/chromium-47.0.2526.106/`
- Official source URL: <https://chromium.googlesource.com/chromium/src/+archive/refs/tags/47.0.2526.106.tar.gz>

## Findings

1. `chrome/VERSION` exactly matches the TV-reported browser version: `47.0.2526.106`.
2. The upstream tree contains no SRAF, `FrameMsg_SrafExtensionExecuteRequest`, `mtvapiA`, or CHiQ-specific browser code. Those strings occur only in the TV vendor binary/libraries, confirming a proprietary integration layer outside upstream Chromium.
3. Upstream defines `remote-debugging-port`, `no-sandbox`, and `disable-web-security` switches. Their presence in source is not evidence that the TV enables them; the extracted TV configuration and live scan showed no exposed DevTools port `9222`.
4. The TV's Amazon configuration contains only the hosted URL and the device identifier `A3T3XXY42KZQNP`; it contains no Prime application version. `version=mstar` is a hosting parameter, not an app build number.
5. Chromium source can therefore support offline source-level comparison, but cannot reveal CHiQ's SRAF patches or the installed Prime version. No browser exploit or malformed test was run.
