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
   - Reuse the request lifecycle from `sample_client.c`.
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
