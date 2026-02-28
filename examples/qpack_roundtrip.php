<?php

declare(strict_types=1);

$qpack = new Nghttp3\Qpack();

$encoded = $qpack->encode([
    ['name' => ':method', 'value' => 'GET'],
    ['name' => ':scheme', 'value' => 'https'],
    ['name' => ':authority', 'value' => 'example.com'],
    ['name' => ':path', 'value' => '/'],
    ['name' => 'user-agent', 'value' => 'qpack-roundtrip/0.1'],
]);

$qpack->feedEncoder($encoded['encoder_stream']);

$decoded = $qpack->decode(0, $encoded['prefix'] . $encoded['header_block'], true);

var_dump($encoded);
var_dump($decoded);

$decoderStream = $qpack->flushDecoder();
if ($decoderStream !== '') {
    $qpack->feedDecoder($decoderStream);
}
