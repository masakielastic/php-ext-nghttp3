--TEST--
Nghttp3\Server serve loop handles sequential clients
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
    [$proc, $pipes] = nghttp3_test_start_server(
        $tmpDir,
        $port,
        $cert,
        $key,
        "loop response\n",
        'loop',
        2
    );
    nghttp3_test_wait_for_server_ready($proc, $pipes[2]);

    putenv("SSL_CERT_FILE=$cert");
    putenv('SSL_CERT_DIR=/etc/ssl/certs');

    for ($i = 1; $i <= 2; $i++) {
        $result = nghttp3_test_client_get_with_retry("https://localhost:$port/");
        echo 'request', $i, ':', $result['status'], ':', trim($result['body']), "\n";
    }

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
request1:200:loop response
request2:200:loop response
server_exit:0
