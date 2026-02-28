# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog.

## [Unreleased]

### Added

- Added `Nghttp3\Qpack` with minimal encode/decode, encoder stream, decoder stream, and per-stream reset APIs.
- Added `examples/qpack_roundtrip.php` for a local QPACK roundtrip example.
- Added PHPT coverage for:
  - QPACK roundtrip and validation
  - client/server localhost roundtrip
  - server loop handling for sequential requests
  - client/server validation failures
- Added `ext/tests/server_client.inc` to share localhost integration test helpers.

### Changed

- Updated the README with QPACK usage and PHPT test instructions.
- Updated the extension build to compile `ext/qpack.c`.

## [0.1.0] - 2026-02-28

### Added

- Added the initial `Nghttp3\Client` implementation for minimal HTTP/3 GET requests.
- Added the initial `Nghttp3\Server` implementation for blocking localhost/server response handling.
- Added sequential server request handling through `Nghttp3\Server::serve(int $maxRequests = 0)`.
- Added example scripts for client, single-response server, and looping server flows.
- Added project README and PIE installation metadata.
