<?php

$port = isset($argv[1]) ? (int) $argv[1] : 4433;
$cert = $argv[2] ?? __DIR__ . "/localhost.crt";
$key = $argv[3] ?? __DIR__ . "/localhost.key";

$server = new Nghttp3\Server($port);
$server->setTls($cert, $key);
$server->setResponse(
    json_encode([
        "message" => "hello from Nghttp3\\Server",
        "port" => $port,
    ], JSON_UNESCAPED_SLASHES) . "\n",
    200,
    [
        "content-type" => "application/json",
    ]
);

fwrite(STDERR, "Nghttp3\\Server listening on https://localhost:$port\n");
$server->serveOnce();
fwrite(STDERR, "Nghttp3\\Server served one request\n");
