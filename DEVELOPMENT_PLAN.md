# nghttp3 PHP Extension Development Plan

## Goal

Provide a PHP extension that exposes a minimal HTTP/3 client on top of `nghttp3`, `ngtcp2`, and OpenSSL, and can be installed through PIE with the extension sources living under `ext/`.

## Build Environment

The expected build environment is:

```sh
export PKG_CONFIG_PATH="$PREFIX/lib64/pkgconfig:$PREFIX/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$PREFIX/lib64:$PREFIX/lib:$LD_LIBRARY_PATH"
pkg-config --modversion libngtcp2 libngtcp2_crypto_ossl libnghttp3 openssl
```

The extension build should resolve its compiler and linker flags through `pkg-config`.

## Minimum Scope

1. Extension packaging
   - Add `composer.json` metadata for PIE.
   - Keep the build path under `ext`.
2. Minimal client API
   - Expose `Nghttp3\Client`.
   - Main request entrypoint: `Nghttp3\Client::get(string $url): array`.
   - Constructor: `__construct(int $timeoutMs = 30000)`.
   - Support HTTPS URLs only.
   - Execute a single HTTP/3 GET request and return:
     - `status`
     - `headers`
     - `body`
     - `http_version`
3. Protocol plumbing
   - Keep the request lifecycle in `ext/client.c` aligned with the current ngtcp2/nghttp3 reference flow.
   - Initialize UDP socket, TLS 1.3, QUIC transport, HTTP/3 control streams, and a single bidirectional request stream.
4. Verification
   - Build with `phpize`, `./configure`, and `make`.
   - Verify the module loads and `Nghttp3\Client` is visible.

## Recommended Extension Layout

- `ext/nghttp3.c`
  - Module entry, MINIT, MINFO, and class registration orchestration.
- `ext/client.c`
  - `Nghttp3\Client` implementation and the shared HTTP/3 client transport logic.
- `ext/server.c`
  - `Nghttp3\Server` skeleton registration and future server implementation.
- `ext/php_nghttp3.h`
  - Shared declarations for module and class registration.

This layout keeps transport-heavy code out of the module entry file and leaves a clean slot for a future server class without forcing another large refactor.

## Minimal Server Implementation Plan

This plan keeps the first server milestone intentionally small and now maps directly to the current `ext/server.c` implementation.

### Target behavior

- Expose `Nghttp3\Server` as a blocking HTTP/3 server for a single connection.
- Accept one client connection over UDP + QUIC + HTTP/3.
- Return a fixed response once the request stream reaches end-of-stream.
- Exit after the first request/response cycle completes.

### Proposed first PHP API

1. Construction and configuration
   - `Nghttp3\Server::__construct(int $port = 4433)`
   - `Nghttp3\Server::setTls(string $certFile, string $keyFile): void`
   - `Nghttp3\Server::setResponse(string $body, int $status = 200, array $headers = []): void`
2. Execution
   - `Nghttp3\Server::serveOnce(): void`

This API mirrors the current server lifecycle:
- choose a UDP port
- load certificate and private key
- serve a single fixed response
- stop after one exchange

### Scope for the first server milestone

- IPv4 only.
- One listening socket.
- One accepted peer address at a time.
- One QUIC connection lifecycle.
- One fixed in-memory response body.
- No PHP callback dispatch.
- No concurrent connections.
- No graceful multi-request loop yet.

### Implementation Mapping

1. Socket and listener setup
   - Reuse `setup_socket()` as the basis for `listen` behavior inside `serveOnce()`.
   - Keep UDP bind + nonblocking socket semantics.
2. TLS server context
   - Reuse `setup_ssl_ctx()` for certificate and key loading.
   - Move cert/key paths into server object state.
3. QUIC connection acceptance
   - Reuse `create_server_conn()` and `q_recv_client_initial_cb()`.
   - Preserve the current single-peer model by pinning the first accepted remote address.
4. HTTP/3 server connection
   - Reuse `setup_h3()` and `bind_h3_unidirectional_streams()`.
   - Keep current control stream and QPACK stream setup unchanged.
5. Request lifecycle
   - Reuse `h3_recv_header_cb()` and `h3_end_stream_cb()`.
   - Keep minimal request handling: request headers may be stored for debugging, but no user routing logic is needed in the first step.
6. Response submission
   - Reuse `submit_pending_responses()` and `read_resp_data_cb()`.
   - Replace the current static `RESP_BODY` with server object properties for body, status, and headers.
7. Event loop
   - Reuse `read_udp_once()`, `drive_tx()`, and `run()`.
   - Keep a blocking `serveOnce()` API rather than introducing background threads or event integration.

### Internal implementation phases

1. Define the PHP object shape in `ext/server.c`
   - port
   - certificate path
   - private key path
   - response status
   - response headers
   - response body
2. Keep the server runtime in `ext/server.c` and refine it incrementally
   - Keep server-only transport code in `ext/server.c` initially.
   - Extract shared utilities into common files only if client/server duplication becomes hard to manage.
3. Bridge runtime state to the PHP object
   - Keep the internal runtime struct allocated per `serveOnce()` or `serve()` call.
   - Convert `stream_ctx` linked-list handling as-is for the first milestone.
4. Add argument validation and failure paths
   - Require TLS files before `serveOnce()`.
   - Reject invalid port ranges.
   - Reject calling `serveOnce()` without a configured response.
5. Verify with a single client request
   - Start `Nghttp3\Server`.
   - Hit it with `Nghttp3\Client`.
   - Confirm status, headers, and body match the configured response.

### Verified localhost workflow

The current minimal implementation has been verified with a localhost round-trip using a temporary self-signed certificate.

1. Generate a localhost certificate

```sh
openssl req -x509 -newkey rsa:2048 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" \
  -keyout /tmp/nghttp3-localhost.key \
  -out /tmp/nghttp3-localhost.crt \
  -days 1
```

2. Start the server

```sh
export LD_LIBRARY_PATH="$PREFIX/lib64:$PREFIX/lib:$LD_LIBRARY_PATH"

php -d extension=/home/masakielastic/php-ext-nghttp3/ext/modules/nghttp3.so \
  /home/masakielastic/php-ext-nghttp3/examples/server_once.php \
  18443 /tmp/nghttp3-localhost.crt /tmp/nghttp3-localhost.key
```

3. Run the client

```sh
export LD_LIBRARY_PATH="$PREFIX/lib64:$PREFIX/lib:$LD_LIBRARY_PATH"
export SSL_CERT_FILE=/tmp/nghttp3-localhost.crt
export SSL_CERT_DIR=/etc/ssl/certs

php -d extension=/home/masakielastic/php-ext-nghttp3/ext/modules/nghttp3.so \
  /home/masakielastic/php-ext-nghttp3/examples/client_get.php \
  https://localhost:18443/ 10000
```

Expected result:
- status `200`
- `http_version` is `3`
- `content-type: application/json`
- response body from `Nghttp3\Server::setResponse()`

The current `Nghttp3\Server::serve(int $maxRequests = 0)` implementation has also been verified with `maxRequests = 2`, serving two sequential localhost client connections before returning.

### Deliberately deferred after the first milestone

- Request handler callbacks from PHP.
- Per-request dynamic responses.
- Multiple requests over the same connection.
- Multiple concurrent clients.
- IPv6 support.
- Certificate hot reload.
- Graceful shutdown hooks.
- Integration with external event loops.

## Constraints For This Minimal Version

- GET only.
- HTTPS only.
- IPv4 only, matching the sample client's conservative networking path.
- No redirects, request body streaming, or connection reuse.
- Error handling favors clear exceptions over recovering from advanced transport states.

## Next Phases

1. Stabilize the API surface.
   - Decide whether to keep the procedural API or introduce a client object for connection reuse.
2. Expand request features.
   - Custom headers
   - POST/PUT request bodies
   - Timeout and certificate options
3. Improve transport behavior.
   - IPv6 support
   - Better close diagnostics
   - Optional qlog / debug hooks
4. Add tests.
   - Basic module load test
   - URL validation coverage
   - Integration test against a reachable HTTP/3 endpoint in CI or a local fixture
