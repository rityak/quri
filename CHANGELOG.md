# Changelog

## Unreleased

- Added HTTP/3 CONNECT and CONNECT-UDP with connection-bound TLS-exporter HMAC
  authentication and an external website backend for ordinary requests.
- Added HTTP/2 CONNECT fallback; UDP uses reliable ordered DATAGRAM capsules
  and therefore shares TCP head-of-line blocking.
- Added immutable per-connection routes, transport racing, bounded reconnect
  backoff and UDP association rebinding. Lost TCP streams are closed.
- Added quri:// profile import/export, bounded binary capsule parsing, fuzzing,
  leak checks, Linux race CI and lint checks for the new HTTP packages.
- Corrected default NewReno loss reduction and exposed HTTP/3 DATAGRAM deadlines
  through published fork pins.

The CLI and SDK use h3/h2; the old quri/1 API, wire format and application
fragmentation were removed. Website backends are explicit external HTTP(S)
services. External certificate files reload without dropping active sessions.

Still unverified: complete UDP-path allocation targets, production core config
wiring, deployment UX, live ACME issuance, and M4 field tests.
