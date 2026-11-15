# Changelog

## Unreleased

- Added HTTP/3 CONNECT and CONNECT-UDP with connection-bound TLS-exporter HMAC
  authentication and a local static website on unauthenticated requests.
- Added HTTP/2 CONNECT fallback; UDP uses reliable ordered DATAGRAM capsules
  and therefore shares TCP head-of-line blocking.
- Added immutable per-connection routes, transport racing, bounded reconnect
  backoff and UDP association rebinding. Lost TCP streams are closed.
- Added quri:// profile import/export, bounded binary capsule parsing, fuzzing,
  leak checks, Linux race CI and lint checks for the new HTTP packages.
- Corrected default NewReno loss reduction and exposed HTTP/3 DATAGRAM deadlines
  through published fork pins.

The legacy root SDK and CLI still use quri/1 until their callers are migrated.
M0–M4 acceptance is incomplete: full UDP-path allocation measurements, complete
lint migration, miray route wiring, ACME/deployment UX and M4 field tests remain.
