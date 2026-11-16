# Changelog

## Unreleased

- Enabled dual-stack resolution at standalone quri-relay startup; importing
  core outbounds without loading core configuration previously rejected IPv6
  relay endpoints with an IP-version error.

- Added HTTP/3 CONNECT and CONNECT-UDP with connection-bound TLS-exporter HMAC
  authentication and an external website backend for ordinary requests.
- Added HTTP/2 CONNECT fallback; UDP uses reliable ordered DATAGRAM capsules
  and therefore shares TCP head-of-line blocking.
- Added immutable per-connection routes, transport racing, bounded reconnect
  backoff and UDP association rebinding. Lost TCP streams are closed.
- Added quri:// profile import/export, bounded binary capsule parsing, fuzzing,
  leak checks, Linux race CI and lint checks for the new HTTP packages.
- Added private QR PNG export, a Linux archive builder and a staged systemd
  installer with configuration validation and a separate service account.
- Added the miray client outbound and optional quri-relay host executable with
  VLESS/TLS, VLESS/REALITY and HY2 outbounds. Server rules remain client-side.
- Added local QUIC path migration that retains existing TCP/UDP tunnels,
  retires inactive sockets and recovers a failed path before reconnecting.
- Replaced duplicate fixed health timers with jittered checks at 10–25 seconds.
- Reused capsule parsing scratch space and native direct UDP addresses;
  full-path UDP allocation acceptance remains open.
- Restored the QUIC library's bounded receive-window autotuning instead of
  capping every stream's receive window at 64 KiB.
- Corrected default NewReno loss reduction and exposed HTTP/3 DATAGRAM deadlines
  through published fork pins.

The CLI and SDK use h3/h2; the old quri/1 API, wire format and application
fragmentation were removed. Website backends are explicit external HTTP(S)
services. External certificate files reload without dropping active sessions.

Still incomplete: full UDP-path zero-allocation targets, remote port rotation,
startup padding, a measured Chrome transport-parameter profile and BBR evaluation.
Live ACME issuance, service operation on a real host, and 24-hour tests on wired
and two mobile networks have not been performed. CI tests the staged installer;
it does not start a production service or publish releases.
