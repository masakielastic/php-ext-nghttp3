--TEST--
Nghttp3 client and server validation failures
--SKIPIF--
<?php
if (!extension_loaded('nghttp3')) {
    echo 'skip nghttp3 extension is not loaded';
}
?>
--FILE--
<?php
try {
    new Nghttp3\Client(0);
} catch (Throwable $e) {
    echo get_class($e), ':', $e->getMessage(), "\n";
}

try {
    (new Nghttp3\Client())->get('');
} catch (Throwable $e) {
    echo get_class($e), ':', $e->getMessage(), "\n";
}

try {
    new Nghttp3\Server(0);
} catch (Throwable $e) {
    echo get_class($e), ':', $e->getMessage(), "\n";
}

try {
    (new Nghttp3\Server())->serveOnce();
} catch (Throwable $e) {
    echo get_class($e), ':', $e->getMessage(), "\n";
}

try {
    (new Nghttp3\Server())->setResponse('body', 99);
} catch (Throwable $e) {
    echo get_class($e), ':', $e->getMessage(), "\n";
}

try {
    (new Nghttp3\Server())->setTls('/no/such/cert', '/no/such/key');
} catch (Throwable $e) {
    echo get_class($e), ':', $e->getMessage(), "\n";
}
?>
--EXPECT--
ValueError:Nghttp3\Client::__construct(): Argument #1 ($timeout_ms) must be greater than 0
ValueError:Nghttp3\Client::get(): Argument #1 ($url) must not be empty
ValueError:Nghttp3\Server::__construct(): Argument #1 ($port) must be between 1 and 65535
Exception:TLS certificate and key must be configured before serving
ValueError:Nghttp3\Server::setResponse(): Argument #2 ($status) must be between 100 and 999
ValueError:Nghttp3\Server::setTls(): Argument #1 ($cert_file) must point to an existing file
