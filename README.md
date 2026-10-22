# CHiQ U43H7L research notes

Research target: personally owned CHiQ U43H7L television on the local network.

Safety rule for the initial phase: observation and low-impact identification only. Do not
send remote-control commands, upload firmware, alter settings, attempt authentication,
or write to the television.

## Identified device

- Address during the initial survey: `192.168.2.211`
- DHCP/local hostname: `chiq-smart-tv.home`
- The device MAC address and full serial are intentionally omitted from this public repository.
- Model shown by the television: `CHiQ U43H7L`
- UI software version: `v.1.1.9`
- Software string: `1.0.3.0.20210319160335_5.1.3_CHiQ_U43H7L_v.1.1.9`
- Module: `1121`

The observed UI and network services point to the Linux/Netrange variant rather than
an Android TV build. Product listings for this model are contradictory, so this remains
a high-confidence inference rather than a confirmed platform identification.

## Initial network survey (2026-10-22)

A full TCP connect scan found four open ports:

| Port | Observation | Likely role |
| --- | --- | --- |
| `3697/tcp` | Returns a generic HTTP 403 to many non-HTTP probes; normal GET remains silent | Unknown embedded web service |
| `7681/tcp` | WebSocket upgrade reaches `libwebsockets` but `/` is rejected with HTTP 403 | Likely Vestel Smart Center event WebSocket with a specific path/origin |
| `56789/tcp` | Minimal HTTP server; DIAL 2.1 responses for YouTube and Netflix | DIAL / possible Smart Center control endpoint |
| `56790/tcp` | Minimal HTTP server; root returns 404 | Secondary DIAL service |

All other TCP ports were closed, including common shell/debug endpoints such as SSH,
Telnet and ADB. Avahi/mDNS and a low-impact SSDP discovery did not return an announcement.

Read-only DIAL checks:

- `GET /apps/YouTube` on port 56789: DIAL 2.1, application stopped, `allowStop=true`.
- `GET /apps/Netflix` on port 56789: DIAL 2.1, application stopped, `allowStop=true`.
- `OPTIONS /apps/SmartCenter` on port 56789 advertises `GET, POST, OPTIONS`.
- No POST request was sent.

## Reproduction commands

```sh
nmap -Pn -sT -p- -T3 --max-retries 1 --host-timeout 240s 192.168.2.211
nmap -Pn -sV --version-all -p 3697,7681,56789,56790 \
  --script=banner,http-title,http-headers -T3 192.168.2.211
curl --noproxy '*' -i http://192.168.2.211:56789/apps/YouTube
curl --noproxy '*' -i http://192.168.2.211:56789/apps/Netflix
curl --noproxy '*' -X OPTIONS -i http://192.168.2.211:56789/apps/SmartCenter
```

## Safest next steps

1. Photograph the rear label (model, serial, chassis/main-board revision) while redacting
   the serial before publishing anything.
2. Obtain the official firmware from the Changhong/CHiQ service portal using the serial,
   but do not install it. Hash it and inspect it offline first.
3. Look through the TV settings for `Virtual Remote`, `Smart Center`, or a developer/debug
   option. Do not enable or change anything until the platform is confirmed.
4. If needed later, capture traffic from the official remote app and compare it with the
   documented Vestel Smart Center protocol. This can identify the API without guessing.
5. Treat service-menu codes and USB flashing as a later, higher-risk phase. Record every
   original value before any change.
