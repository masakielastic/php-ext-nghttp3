<?php

function nghttp3_test_extension_path(): string
{
    return getcwd() . '/modules/nghttp3.so';
}

function nghttp3_test_make_temp_dir(): string
{
    $dir = sys_get_temp_dir() . '/nghttp3-phpt-' . bin2hex(random_bytes(6));

    if (!mkdir($dir, 0700, true) && !is_dir($dir)) {
        throw new RuntimeException("failed to create temp dir: $dir");
    }

    return $dir;
}

function nghttp3_test_cleanup_dir(string $dir): void
{
    if (!is_dir($dir)) {
        return;
    }

    $items = scandir($dir);
    if ($items === false) {
        return;
    }

    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }

        $path = $dir . '/' . $item;
        if (is_dir($path)) {
            nghttp3_test_cleanup_dir($path);
            continue;
        }

        @unlink($path);
    }

    @rmdir($dir);
}

function nghttp3_test_generate_cert(string $dir): array
{
    $cert = $dir . '/localhost.crt';
    $key = $dir . '/localhost.key';
    $cmd = sprintf(
        'openssl req -x509 -newkey rsa:2048 -nodes -subj %s -addext %s -keyout %s -out %s -days 1 >/dev/null 2>&1',
        escapeshellarg('/CN=localhost'),
        escapeshellarg('subjectAltName=DNS:localhost'),
        escapeshellarg($key),
        escapeshellarg($cert)
    );

    exec($cmd, $output, $exitCode);
    if (!is_file($cert) || filesize($cert) === 0 || !is_file($key) || filesize($key) === 0) {
        throw new RuntimeException('failed to generate certificate');
    }

    return [$cert, $key];
}

function nghttp3_test_pick_udp_port(): int
{
    return random_int(20000, 50000);
}

function nghttp3_test_write_server_script(
    string $path,
    int $port,
    string $cert,
    string $key,
    string $body,
    string $mode,
    int $maxRequests
): void {
    $code = "<?php\n"
        . '$server = new Nghttp3\\Server(' . var_export($port, true) . ");\n"
        . '$server->setTls(' . var_export($cert, true) . ', ' . var_export($key, true) . ");\n"
        . '$server->setResponse(' . var_export($body, true) . ", 200, ['content-type' => 'text/plain']);\n"
        . "fwrite(STDERR, \"READY\\n\");\n";

    if ($mode === 'once') {
        $code .= "\$server->serveOnce();\n";
    } else {
        $code .= '$server->serve(' . var_export($maxRequests, true) . ");\n";
    }

    $code .= "fwrite(STDERR, \"DONE\\n\");\n";

    file_put_contents($path, $code);
}

function nghttp3_test_start_server(
    string $dir,
    int $port,
    string $cert,
    string $key,
    string $body,
    string $mode = 'once',
    int $maxRequests = 1
): array {
    $script = $dir . '/server.php';
    $command = sprintf(
        '%s -n -d extension=%s %s',
        escapeshellarg(PHP_BINARY),
        escapeshellarg(nghttp3_test_extension_path()),
        escapeshellarg($script)
    );

    nghttp3_test_write_server_script($script, $port, $cert, $key, $body, $mode, $maxRequests);

    $proc = proc_open(
        $command,
        [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ],
        $pipes,
        null,
        null
    );

    if (!is_resource($proc)) {
        throw new RuntimeException('failed to start server process');
    }

    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);

    return [$proc, $pipes];
}

function nghttp3_test_wait_for_server_ready($proc, $stderr, float $timeoutSeconds = 10.0): string
{
    $deadline = microtime(true) + $timeoutSeconds;
    $buffer = '';

    while (microtime(true) < $deadline) {
        $status = proc_get_status($proc);
        $chunk = stream_get_contents($stderr);
        if ($chunk !== false && $chunk !== '') {
            $buffer .= $chunk;
            if (strpos($buffer, "READY\n") !== false) {
                return $buffer;
            }
        }

        if (!$status['running']) {
            break;
        }

        usleep(100000);
    }

    throw new RuntimeException("server did not become ready: " . trim($buffer));
}

function nghttp3_test_finish_server(&$proc, array &$pipes, float $timeoutSeconds = 10.0): array
{
    $deadline = microtime(true) + $timeoutSeconds;
    $stdout = '';
    $stderr = '';

    while (microtime(true) < $deadline) {
        if (isset($pipes[1]) && is_resource($pipes[1])) {
            $chunk = stream_get_contents($pipes[1]);
            if ($chunk !== false && $chunk !== '') {
                $stdout .= $chunk;
            }
        }

        if (isset($pipes[2]) && is_resource($pipes[2])) {
            $chunk = stream_get_contents($pipes[2]);
            if ($chunk !== false && $chunk !== '') {
                $stderr .= $chunk;
            }
        }

        $status = proc_get_status($proc);
        if (!$status['running']) {
            break;
        }

        usleep(100000);
    }

    $status = proc_get_status($proc);
    if ($status['running']) {
        proc_terminate($proc);
        throw new RuntimeException('server did not exit before timeout');
    }

    foreach ($pipes as $pipe) {
        if (is_resource($pipe)) {
            fclose($pipe);
        }
    }

    $pipes = [];
    $exitCode = proc_close($proc);
    $proc = null;

    return [
        'stdout' => $stdout,
        'stderr' => $stderr,
        'exit' => $exitCode,
    ];
}

function nghttp3_test_terminate_server(&$proc, array &$pipes): void
{
    if (is_resource($proc)) {
        @proc_terminate($proc);
    }

    foreach ($pipes as $pipe) {
        if (is_resource($pipe)) {
            @fclose($pipe);
        }
    }

    $pipes = [];

    if (is_resource($proc)) {
        @proc_close($proc);
    }

    $proc = null;
}

function nghttp3_test_client_get_with_retry(
    string $url,
    int $timeoutMs = 10000,
    int $attempts = 30,
    int $delayMicroseconds = 100000
): array {
    $lastError = null;

    for ($attempt = 0; $attempt < $attempts; $attempt++) {
        try {
            $client = new Nghttp3\Client($timeoutMs);
            return $client->get($url);
        } catch (Throwable $e) {
            $lastError = $e;
            if (strpos($e->getMessage(), 'failed to connect UDP socket') === false) {
                throw $e;
            }
        }

        usleep($delayMicroseconds);
    }

    if ($lastError !== null) {
        throw $lastError;
    }

    throw new RuntimeException('request retry loop failed unexpectedly');
}
