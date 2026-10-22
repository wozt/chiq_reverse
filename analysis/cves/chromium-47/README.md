# Chromium 47 CVE source snapshots

This directory contains Chromium source snapshots downloaded from the official
Chromium Gitiles repository for offline, static comparison only. No exploit,
PoC, malformed input, or browser payload is included or executed.

## Snapshot layout

- `47.0.2526.69/`: pre-Chrome-47.0.2526.73 AppCache baseline.
- `47.0.2526.73/`: AppCache fixes shipped in the Chrome 47.0.2526.73 line.
- `47.0.2526.106/`: WebCursor and MIDI fixes shipped in the TV's reported
  upstream version.

The files are flattened by basename; the original Chromium paths are:

| File | Chromium path |
|---|---|
| `webcursor*.cc/h` | `content/common/cursors/` |
| `appcache_*.cc` | `content/browser/appcache/` |
| `midi_manager*.cc` | `media/midi/` |

## Patch observations

- CVE-2015-6765, CVE-2015-6766, and CVE-2015-6767 are AppCache lifetime bugs.
  The `.69` → `.73` comparison adds weak-pointer callback ownership,
  failed-entry bookkeeping, and hard checks that fetchers are gone before an
  update job is destroyed. The affected files are unchanged between `.73` and
  `.106`.
- CVE-2015-8664 is the `WebCursor::Deserialize` integer-overflow issue. The
  `.106` source requires the RGBA byte length to equal exactly
  `width * height * 4`; `.73` only rejected shorter buffers. The TV browser
  contains the `.106` diagnostic string
  `WebCursor's data length and image size mismatch`, which is strong evidence
  that this fix was compiled into the shipped fork.
- CVE-2015-6792 is the MIDI send-handling issue. The `.106` source keeps the
  client-membership lock across the acknowledgement and routes the ALSA
  callback through `MidiManagerAlsa`; `.69`/`.73` use the older callback path.
  The TV binary contains Web MIDI (`requestMIDIAccess`, `MidiHost`) and ALSA
  markers, so the component is compiled in, but the exact patched function
  cannot be proven from the stripped ARM binary without executing or rebuilding
  it.

## Provenance

Source base URL: `https://chromium.googlesource.com/chromium/src/+/TAG/PATH?format=TEXT`

The complete source-file SHA-256 list is in `SHA256SUMS`. The target binary
used for marker comparison is
`analysis/appfs/sraf/bin/sraf_browser_bin` (SHA-256:
`3dfbd071c242d6fa10e502dd2d1f1e5f79c5f9a99108593fd730a6118897a74c`).
