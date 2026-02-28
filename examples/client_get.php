<?php

$url = $argv[1] ?? "https://localhost:4433/";
$timeoutMs = isset($argv[2]) ? (int) $argv[2] : 10000;

$client = new Nghttp3\Client($timeoutMs);
$result = $client->get($url);

var_dump($result["status"]);
var_dump($result["http_version"]);
var_dump($result["headers"]);
echo $result["body"];
