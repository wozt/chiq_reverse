# DIAL launcher audit

Date: 2026-10-22

## Static result

`analysis/appfs/dial/dialserver` imports `fork()` and `execv()`. The only `execv()` call is in a forked helper that receives an executable path and an argv vector; it does not invoke a shell and has no `system()`/`popen()` import. The main setup path calls `DIAL_create()`, registers the applications from `dialappsetting.ini`, starts DIAL, and enters `run_ssdp()`.

The deployed application table restricts the known entries to Netflix, YouTube, BBC apps, and `AmazonInstantVideo`. Amazon has `allowed_origin=atv-ext.amazon.com`, `payload_prefix=--dialpayload`, and no executable path. The DIAL payload is therefore an application argument/data channel, not an advertised path-selection field. The Netflix entry stores its payload in `/dev/shm/dial_argv`; this is volatile tmpfs, not persistent storage.

The local `execv()` helper has no direct call from the visible main path; it is likely legacy/callback code supplied to the DIAL support library. No shell metacharacter expansion or network-controlled executable path was established. Live DIAL tests previously confirmed reversible app start/stop but did not expose an additional route.

## Security boundary

DIAL remains a useful app-control surface, but the recovered evidence does not show a network-to-root shell or persistent-write primitive. No payload was used to alter executable paths or launch unknown binaries.
