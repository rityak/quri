# quri HTTP profile

QUIC v1, TLS 1.3, ALPN `h3`; TCP fallback uses TLS 1.3 with ALPN `h2`.
No 0-RTT application data or custom multiplexing layer is used.

## Connection state

TLS handshake → HTTP authentication → one immutable configuration → flows.
The client verifies the relay certificate and hostname before authentication.

Authentication is GET `/` with cookie `session` carrying base64url without
padding of HMAC-SHA256(token, exporter). The exporter label is
`EXPORTER-quri-auth`, context is empty, output length is 32 bytes. The static
32–256 byte credential is never transmitted. Proofs authorize only the current
TLS connection. Repeating a proof on that connection is harmless; another TLS
connection produces a different exporter. No clocks or timestamps are involved.

The authentication response is the external website response. Failure or an
absent proof does not produce a quri authentication error. The valid proof
cookie is removed before the request reaches the website backend.

An authorized client POSTs `/api/session` with bounded UTF-8 JSON:
`{"namespace":"direct","version":1,"payload":{}}`. The host authorizes
and constructs one fixed outbound. Success is HTTP 204; repeated configuration
is rejected. Authenticated HEAD `/api/session` is a relay-only health check.

## TCP

HTTP CONNECT authority identifies `host:port`. The server establishes the
outbound before returning 200. HTTP DATA carries the byte stream. END_STREAM/FIN
closes one direction; opposite-direction upload/download may continue.
Closing a flow sends FIN before aborting its receive direction. An h2 client
waits for the request body and END_STREAM to be flushed before cancelling the
response, bounded by the open-operation budget. Connection shutdown still aborts
active flows. A response-side HTTP request cancellation does not close the entire
TCP target; stream errors and connection termination own that cleanup.
With h2, an expired client-side deadline aborts that request because the pinned
client API does not expose resumable stream deadlines. Neighboring requests
remain usable.

## UDP

RFC 9298 Extended CONNECT uses protocol `connect-udp`, URI template
`/.well-known/masque/udp/{target_host}/{target_port}/` and `Capsule-Protocol: ?1`.
Each destination has a bounded independent tunnel within an association.

For h3, RFC 9297 HTTP Datagrams use the library's quarter-stream-ID prefix,
then context ID zero, then one entire UDP payload. Datagrams larger than the
configured limit or current path MTU are dropped. There is no fragmentation,
reassembly, retransmission, or reliable capsule fallback for h3 payloads.
The default application limit is 65507 bytes, the IPv4 UDP payload maximum;
the actual h3 capacity remains bounded by its dynamically discovered QUIC PMTU.
An application limit below 1200 bytes prevents forwarding QUIC Initial packets.

For h2, a type-zero DATAGRAM capsule carries its varint length, context zero,
and UDP payload in the dedicated CONNECT-UDP HTTP DATA stream. This delivery
is reliable and ordered over TCP. Unknown bounded capsules/contexts are skipped;
malformed or oversized capsules terminate their tunnel.

## Website and lifecycle

The relay terminates TLS/HTTP and proxies ordinary requests to an explicit
external website handler. Responses retain normal HTTP semantics, including
404 or backend failure. Malformed HTTP is handled by the HTTP implementation;
there is no promise of HTTP 200 for invalid protocol frames.

Handshake and initial configuration have finite budgets. Stream admission,
connections, UDP targets and queues are bounded by `config.Config`. Initial
QUIC packet size is 1200. Reconnection races endpoint/transport candidates,
closes losers, applies backoff with jitter and recreates UDP associations.
Previously established TCP streams are never replayed or resumed.

Configured clients send authenticated HEAD health checks at independently
randomized intervals between 10 and 25 seconds. Only HTTP 204 is success.
The QUIC stack's fixed-period keepalive is disabled. Connection idle timeout
defaults to 60 seconds and is separate from individual UDP tunnel idle limits.

Local-address migration uses a fresh socket, PATH_CHALLENGE/PATH_RESPONSE,
reserved destination connection IDs, and an authenticated round trip before
retiring the previous socket. TLS, configuration, TCP streams and UDP tunnels
belong to the same connection throughout. An unvalidated candidate is discarded
without replacing the working path. If verification after switching fails,
the session closes and the manager reconnects. No application stream resumes
across reconnection. This mechanism does not rotate the remote server port.
