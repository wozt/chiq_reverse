# Persistence and credential audit

Date: 2026-10-22

## World-writable boot hook

- `/etc/init.d/rcS` mounts `customer` at `/Customer` and runs `chmod 777 /Customer`.
- The same script executes `/Customer/bootlogo/FastLogo.sh` as root when the path exists; it does not check the file's executable bit.
- `/etc/profile` is a symlink to `/Customer/profile`.
- `/Customer/profile` runs `/Customer/setup.sh` as UID 0 whenever that file is executable.
- `/Customer/enable_mount_config_rw` controls whether the `CONFIG` partition is mounted read-write on the next boot.

This creates a local persistence/privilege-escalation chain if an unprivileged process can write or replace a file in `/Customer`: it can create `bootlogo/FastLogo.sh`, replace `setup.sh`, or create `enable_mount_config_rw`, and obtain root-executed startup behavior after reboot/login. No LAN file-write primitive has been demonstrated, and no file was modified on the TV.

## Exposed private key

`/etc/mheg5/m5key.pem` is a plaintext 1024-bit RSA private key with mode `0775`. Its consumer was not present in the extracted filesystem, so its signing/authentication role is unconfirmed. If used by the MHEG5/HbbTV stack, distribution of the private key would permit offline forgery of whatever artifacts that stack accepts.

## Root account

The recovered image contains `root::0:0:root:/root:/bin/bash` and no `/etc/shadow`. This is an empty root password in the recovered `v1.1.8` image; the installed `v1.1.9` filesystem was not available for comparison.
