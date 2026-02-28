# masakielastic/nghttp3

Minimal PHP HTTP/3 extension built on top of `nghttp3`, `ngtcp2`, and OpenSSL.

The extension source lives under `ext/` and is prepared for PIE installation through `composer.json`.

## Status

Current scope:

- `Nghttp3\Client` for a minimal HTTP/3 GET request
- `Nghttp3\Qpack` for minimal QPACK encode/decode roundtrips
- `Nghttp3\Server` for a minimal blocking HTTP/3 server
- sequential server-side request handling through `serve(int $maxRequests = 0)`

Current constraints:

- PHP 8.1+
- HTTPS only
- IPv4 only
- client supports GET only
- no redirects, request body upload, or connection reuse yet
- server returns a fixed response body

## Requirements

Expected build environment:

```sh
export PKG_CONFIG_PATH="$PREFIX/lib64/pkgconfig:$PREFIX/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$PREFIX/lib64:$PREFIX/lib:$LD_LIBRARY_PATH"
pkg-config --modversion libngtcp2 libngtcp2_crypto_ossl libnghttp3 openssl
```

Required libraries:

- `libngtcp2`
- `libngtcp2_crypto_ossl`
- `libnghttp3`
- `openssl`
- PHP development headers with `phpize`

## Build

```sh
cd ext
phpize
./configure --enable-nghttp3
make
```

Load the built extension:

```sh
php -d extension=/absolute/path/to/ext/modules/nghttp3.so -m | grep nghttp3
```

## PIE Metadata

`composer.json` is configured for PIE:

- package name: `masakielastic/nghttp3`
- extension name: `nghttp3`
- build path: `ext`

You can install the extension with PIE by running:

```sh
pie install masakielastic/nghttp3
```

## API

### Client

```php
<?php

$client = new Nghttp3\Client(10000);
$result = $client->get("https://nghttp2.org/httpbin/get");

var_dump($result["status"]);
var_dump($result["http_version"]);
var_dump($result["headers"]);
echo $result["body"];
```

Return shape:

- `status`
- `headers`
- `body`
- `http_version`

### Server

```php
<?php

$server = new Nghttp3\Server(4433);
$server->setTls("/path/to/server.crt", "/path/to/server.key");
$server->setResponse("hello\n", 200, [
    "content-type" => "text/plain",
]);

$server->serveOnce();
```

Available methods:

- `Nghttp3\Server::__construct(int $port = 4433)`
- `Nghttp3\Server::setTls(string $certFile, string $keyFile): void`
- `Nghttp3\Server::setResponse(string $body, int $status = 200, array $headers = []): void`
- `Nghttp3\Server::serveOnce(): void`
- `Nghttp3\Server::serve(int $maxRequests = 0): void`

`serve(0)` keeps serving sequential connections until the process is stopped.

### Qpack

```php
<?php

$qpack = new Nghttp3\Qpack();

$encoded = $qpack->encode([
    ['name' => ':method', 'value' => 'GET'],
    ['name' => ':scheme', 'value' => 'https'],
    ['name' => ':authority', 'value' => 'example.com'],
    ['name' => ':path', 'value' => '/'],
]);

$qpack->feedEncoder($encoded['encoder_stream']);

$decoded = $qpack->decode(0, $encoded['prefix'] . $encoded['header_block'], true);
var_dump($decoded['headers']);

$decoderStream = $qpack->flushDecoder();
if ($decoderStream !== '') {
    $qpack->feedDecoder($decoderStream);
}
```

Available methods:

- `Nghttp3\Qpack::__construct(int $hardMaxTableCapacity = 4096, int $maxBlockedStreams = 0, int $encoderMaxTableCapacity = 4096)`
- `Nghttp3\Qpack::encode(array $headers, int $streamId = 0): array`
- `Nghttp3\Qpack::feedEncoder(string $bytes): void`
- `Nghttp3\Qpack::decode(int $streamId, string $bytes, bool $fin = false): array`
- `Nghttp3\Qpack::flushDecoder(): string`
- `Nghttp3\Qpack::feedDecoder(string $bytes): void`
- `Nghttp3\Qpack::resetStream(int $streamId): void`

## Examples

Example scripts live under `examples/`.

Start a single-response server:

```sh
php -d extension=/absolute/path/to/ext/modules/nghttp3.so \
  /absolute/path/to/examples/server_once.php \
  18443 /tmp/nghttp3-localhost.crt /tmp/nghttp3-localhost.key
```

Start a looping server:

```sh
php -d extension=/absolute/path/to/ext/modules/nghttp3.so \
  /absolute/path/to/examples/server_loop.php \
  18443 /tmp/nghttp3-localhost.crt /tmp/nghttp3-localhost.key 0
```

Run the client:

```sh
SSL_CERT_FILE=/tmp/nghttp3-localhost.crt \
SSL_CERT_DIR=/etc/ssl/certs \
php -d extension=/absolute/path/to/ext/modules/nghttp3.so \
  /absolute/path/to/examples/client_get.php \
  https://localhost:18443/ 10000
```

Run the QPACK roundtrip example:

```sh
php -d extension=/absolute/path/to/ext/modules/nghttp3.so \
  /absolute/path/to/examples/qpack_roundtrip.php
```

Generate a temporary localhost certificate if needed:

```sh
openssl req -x509 -newkey rsa:2048 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost" \
  -keyout /tmp/nghttp3-localhost.key \
  -out /tmp/nghttp3-localhost.crt \
  -days 1
```

## Tests

Run the focused QPACK tests:

```sh
cd ext
env LD_LIBRARY_PATH="$PREFIX/lib64:$PREFIX/lib:$LD_LIBRARY_PATH" \
php run-tests.php \
  -d extension=/absolute/path/to/ext/modules/nghttp3.so \
  tests/qpack_roundtrip.phpt \
  tests/qpack_validation.phpt
```

Run the full extension test target:

```sh
cd ext
env LD_LIBRARY_PATH="$PREFIX/lib64:$PREFIX/lib:$LD_LIBRARY_PATH" make test
```

## Development Notes

Implementation files:

- `ext/nghttp3.c`: module entry and class registration
- `ext/client.c`: HTTP/3 client implementation
- `ext/qpack.c`: QPACK encoder/decoder implementation
- `ext/server.c`: HTTP/3 server implementation
- `ext/php_nghttp3.h`: shared declarations

The longer implementation plan is in `DEVELOPMENT_PLAN.md`.
