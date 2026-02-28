--TEST--
Nghttp3\Qpack roundtrip encode/decode
--SKIPIF--
<?php
if (!extension_loaded('nghttp3')) {
    echo 'skip nghttp3 extension is not loaded';
}
?>
--FILE--
<?php
$qpack = new Nghttp3\Qpack();

$encoded = $qpack->encode([
    ['name' => ':method', 'value' => 'GET'],
    ['name' => ':scheme', 'value' => 'https'],
    ['name' => ':authority', 'value' => 'example.com'],
    ['name' => ':path', 'value' => '/'],
    ['name' => 'user-agent', 'value' => 'qpack-roundtrip/0.1'],
]);

printf(
    "lens:%d,%d,%d\n",
    strlen($encoded['prefix']),
    strlen($encoded['header_block']),
    strlen($encoded['encoder_stream'])
);

$qpack->feedEncoder($encoded['encoder_stream']);

$prefixResult = $qpack->decode(0, $encoded['prefix'], false);
printf(
    "first:%d,%d,%d,%d\n",
    count($prefixResult['headers']),
    (int) $prefixResult['blocked'],
    (int) $prefixResult['final'],
    $prefixResult['consumed']
);

$headerResult = $qpack->decode(0, $encoded['header_block'], true);
printf(
    "second:%d,%d,%d,%d\n",
    count($headerResult['headers']),
    (int) $headerResult['blocked'],
    (int) $headerResult['final'],
    $headerResult['consumed']
);

foreach ($headerResult['headers'] as $header) {
    echo $header['name'], '=', $header['value'], "\n";
}

$decoderStream = $qpack->flushDecoder();
printf("decoder:%d\n", strlen($decoderStream));
$qpack->feedDecoder($decoderStream);
echo "fed\n";
?>
--EXPECT--
lens:2,30,30
first:0,0,0,2
second:5,0,1,30
:method=GET
:scheme=https
:authority=example.com
:path=/
user-agent=qpack-roundtrip/0.1
decoder:1
fed
