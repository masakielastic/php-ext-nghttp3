<?php

$port = isset($argv[1]) ? (int) $argv[1] : 4433;
$cert = $argv[2] ?? __DIR__ . "/localhost.crt";
$key = $argv[3] ?? __DIR__ . "/localhost.key";
$maxRequests = isset($argv[4]) ? (int) $argv[4] : 0;

$server = new Nghttp3\Server($port);
$server->setTls($cert, $key);
$server->setResponse(
    json_encode([
        "message" => "hello from looping Nghttp3\\Server",
        "port" => $port,
        "maxRequests" => $maxRequests,
    ], JSON_UNESCAPED_SLASHES) . "\n",
    200,
    [
        "content-type" => "application/json",
    ]
);

fwrite(STDERR, "Nghttp3\\Server serving on https://localhost:$port\n");
$server->serve($maxRequests);
fwrite(STDERR, "Nghttp3\\Server serve() returned\n");
