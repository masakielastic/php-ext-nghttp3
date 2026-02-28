--TEST--
Nghttp3\Qpack validation failures
--SKIPIF--
<?php
if (!extension_loaded('nghttp3')) {
    echo 'skip nghttp3 extension is not loaded';
}
?>
--FILE--
<?php
$qpack = new Nghttp3\Qpack();

foreach ([
    [['name' => '', 'value' => 'x']],
    [['value' => 'x']],
] as $case) {
    try {
        $qpack->encode($case);
    } catch (Throwable $e) {
        echo get_class($e), ':', $e->getMessage(), "\n";
    }
}

try {
    $qpack->decode(-1, '', false);
} catch (Throwable $e) {
    echo get_class($e), ':', $e->getMessage(), "\n";
}
?>
--EXPECT--
Exception:header name must not be empty
Exception:each header must contain name and value
ValueError:Nghttp3\Qpack::decode(): Argument #1 ($stream_id) must be greater than or equal to 0
