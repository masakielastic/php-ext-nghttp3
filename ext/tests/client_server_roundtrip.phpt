--TEST--
Nghttp3\Client and Nghttp3\Server roundtrip
--SKIPIF--
<?php
if (!extension_loaded('nghttp3')) {
    echo 'skip nghttp3 extension is not loaded';
    return;
}
if (!function_exists('proc_open')) {
    echo 'skip proc_open is required';
    return;
}
exec('openssl version 2>&1', $output, $exitCode);
if ($exitCode !== 0) {
    echo 'skip openssl CLI is required';
}
?>
--FILE--
<?php
require getcwd() . '/tests/server_client.inc';

$tmpDir = nghttp3_test_make_temp_dir();
$proc = null;
$pipes = [];
$previousCertFile = getenv('SSL_CERT_FILE');
$previousCertDir = getenv('SSL_CERT_DIR');

try {
    [$cert, $key] = nghttp3_test_generate_cert($tmpDir);
    $port = nghttp3_test_pick_udp_port();
    [$proc, $pipes] = nghttp3_test_start_server($tmpDir, $port, $cert, $key, "roundtrip response\n");
    nghttp3_test_wait_for_server_ready($proc, $pipes[2]);

    putenv("SSL_CERT_FILE=$cert");
    putenv('SSL_CERT_DIR=/etc/ssl/certs');

    $result = nghttp3_test_client_get_with_retry("https://localhost:$port/");

    echo 'status:', $result['status'], "\n";
    echo 'http_version:', $result['http_version'], "\n";
    echo 'headers:', count($result['headers']), "\n";
    foreach ($result['headers'] as $header) {
        if ($header['name'] === 'content-type') {
            echo 'content-type:', $header['value'], "\n";
        }
    }
    echo 'body:', trim($result['body']), "\n";

    $server = nghttp3_test_finish_server($proc, $pipes);
    echo 'server_exit:', $server['exit'], "\n";
} finally {
    if ($previousCertFile === false) {
        putenv('SSL_CERT_FILE');
    } else {
        putenv("SSL_CERT_FILE=$previousCertFile");
    }

    if ($previousCertDir === false) {
        putenv('SSL_CERT_DIR');
    } else {
        putenv("SSL_CERT_DIR=$previousCertDir");
    }

    nghttp3_test_terminate_server($proc, $pipes);
    nghttp3_test_cleanup_dir($tmpDir);
}
?>
--EXPECT--
status:200
http_version:3
headers:1
content-type:text/plain
body:roundtrip response
server_exit:0
