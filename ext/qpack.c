#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php_nghttp3.h"

#include <Zend/zend_exceptions.h>

#include <stdint.h>
#include <string.h>

#include <nghttp3/nghttp3.h>

#define PHP_NGHTTP3_QPACK_DEFAULT_TABLE_CAPACITY 4096

typedef struct _php_nghttp3_qpack_stream_ctx {
	int64_t stream_id;
	nghttp3_qpack_stream_context *ctx;
	struct _php_nghttp3_qpack_stream_ctx *next;
} php_nghttp3_qpack_stream_ctx;

typedef struct _php_nghttp3_qpack_object {
	nghttp3_qpack_encoder *encoder;
	nghttp3_qpack_decoder *decoder;
	php_nghttp3_qpack_stream_ctx *streams;
	zend_object std;
} php_nghttp3_qpack_object;

zend_class_entry *php_nghttp3_ce_qpack;
static zend_object_handlers php_nghttp3_qpack_object_handlers;

static inline php_nghttp3_qpack_object *php_nghttp3_qpack_object_from_obj(zend_object *obj)
{
	return (php_nghttp3_qpack_object *) ((char *) obj - XtOffsetOf(php_nghttp3_qpack_object, std));
}

#define Z_PHP_NGHTTP3_QPACK_OBJ_P(zv) php_nghttp3_qpack_object_from_obj(Z_OBJ_P((zv)))

static void php_nghttp3_qpack_throw_nghttp3_error(const char *context, int rv)
{
	zend_throw_exception_ex(
		zend_ce_exception,
		0,
		"%s failed: %s",
		context,
		nghttp3_strerror(rv)
	);
}

static void php_nghttp3_qpack_throw_message(const char *message)
{
	zend_throw_exception(zend_ce_exception, message, 0);
}

static void php_nghttp3_qpack_free_streams(php_nghttp3_qpack_object *intern)
{
	php_nghttp3_qpack_stream_ctx *current = intern->streams;

	while (current != NULL) {
		php_nghttp3_qpack_stream_ctx *next = current->next;

		if (current->ctx != NULL) {
			nghttp3_qpack_stream_context_del(current->ctx);
			current->ctx = NULL;
		}

		efree(current);
		current = next;
	}

	intern->streams = NULL;
}

static void php_nghttp3_qpack_reset_state(php_nghttp3_qpack_object *intern)
{
	php_nghttp3_qpack_free_streams(intern);

	if (intern->decoder != NULL) {
		nghttp3_qpack_decoder_del(intern->decoder);
		intern->decoder = NULL;
	}

	if (intern->encoder != NULL) {
		nghttp3_qpack_encoder_del(intern->encoder);
		intern->encoder = NULL;
	}
}

static int php_nghttp3_qpack_ensure_initialized(php_nghttp3_qpack_object *intern)
{
	if (intern->encoder == NULL || intern->decoder == NULL) {
		php_nghttp3_qpack_throw_message("QPACK instance is not initialized");
		return FAILURE;
	}

	return SUCCESS;
}

static php_nghttp3_qpack_stream_ctx *php_nghttp3_qpack_find_stream(
	php_nghttp3_qpack_object *intern,
	int64_t stream_id
)
{
	php_nghttp3_qpack_stream_ctx *current = intern->streams;

	while (current != NULL) {
		if (current->stream_id == stream_id) {
			return current;
		}

		current = current->next;
	}

	return NULL;
}

static nghttp3_qpack_stream_context *php_nghttp3_qpack_get_stream_context(
	php_nghttp3_qpack_object *intern,
	int64_t stream_id
)
{
	php_nghttp3_qpack_stream_ctx *entry = php_nghttp3_qpack_find_stream(intern, stream_id);

	if (entry != NULL) {
		return entry->ctx;
	}

	entry = ecalloc(1, sizeof(*entry));
	entry->stream_id = stream_id;

	if (nghttp3_qpack_stream_context_new(&entry->ctx, stream_id, nghttp3_mem_default()) != 0) {
		efree(entry);
		php_nghttp3_qpack_throw_message("nghttp3_qpack_stream_context_new failed");
		return NULL;
	}

	entry->next = intern->streams;
	intern->streams = entry;

	return entry->ctx;
}

static int php_nghttp3_qpack_append_decoded_header(zval *headers, const nghttp3_qpack_nv *nv)
{
	zval header;
	nghttp3_vec name_vec;
	nghttp3_vec value_vec;
	const char *name_ptr;
	const char *value_ptr;

	name_vec = nghttp3_rcbuf_get_buf(nv->name);
	value_vec = nghttp3_rcbuf_get_buf(nv->value);
	name_ptr = name_vec.base != NULL ? (const char *) name_vec.base : "";
	value_ptr = value_vec.base != NULL ? (const char *) value_vec.base : "";

	array_init(&header);
	add_assoc_stringl(&header, "name", name_ptr, name_vec.len);
	add_assoc_stringl(&header, "value", value_ptr, value_vec.len);
	add_next_index_zval(headers, &header);

	return SUCCESS;
}

static int php_nghttp3_qpack_parse_headers(
	zval *headers,
	nghttp3_nv **pnva,
	zend_string ***pnames,
	zend_string ***pvalues,
	size_t *pnvlen
)
{
	size_t nvlen;
	size_t i = 0;
	nghttp3_nv *nva;
	zend_string **names;
	zend_string **values;
	zval *header;

	nvlen = zend_hash_num_elements(Z_ARRVAL_P(headers));
	nva = safe_emalloc(nvlen == 0 ? 1 : nvlen, sizeof(*nva), 0);
	names = safe_emalloc(nvlen == 0 ? 1 : nvlen, sizeof(*names), 0);
	values = safe_emalloc(nvlen == 0 ? 1 : nvlen, sizeof(*values), 0);

	ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(headers), header) {
		zval *name_zv;
		zval *value_zv;

		if (Z_TYPE_P(header) != IS_ARRAY) {
			php_nghttp3_qpack_throw_message("headers must be a list of arrays with name and value");
			goto fail;
		}

		name_zv = zend_hash_str_find(Z_ARRVAL_P(header), "name", sizeof("name") - 1);
		value_zv = zend_hash_str_find(Z_ARRVAL_P(header), "value", sizeof("value") - 1);

		if (name_zv == NULL || value_zv == NULL) {
			php_nghttp3_qpack_throw_message("each header must contain name and value");
			goto fail;
		}

		names[i] = zval_get_string(name_zv);
		values[i] = zval_get_string(value_zv);

		if (ZSTR_LEN(names[i]) == 0) {
			zend_string_release(names[i]);
			zend_string_release(values[i]);
			php_nghttp3_qpack_throw_message("header name must not be empty");
			goto fail;
		}

		nva[i].name = (const uint8_t *) ZSTR_VAL(names[i]);
		nva[i].value = (const uint8_t *) ZSTR_VAL(values[i]);
		nva[i].namelen = ZSTR_LEN(names[i]);
		nva[i].valuelen = ZSTR_LEN(values[i]);
		nva[i].flags = NGHTTP3_NV_FLAG_NONE;
		i++;
	} ZEND_HASH_FOREACH_END();

	*pnva = nva;
	*pnames = names;
	*pvalues = values;
	*pnvlen = nvlen;

	return SUCCESS;

fail:
	while (i > 0) {
		i--;
		zend_string_release(names[i]);
		zend_string_release(values[i]);
	}

	efree(values);
	efree(names);
	efree(nva);

	return FAILURE;
}

static void php_nghttp3_qpack_free_parsed_headers(
	nghttp3_nv *nva,
	zend_string **names,
	zend_string **values,
	size_t nvlen
)
{
	size_t i;

	for (i = 0; i < nvlen; i++) {
		zend_string_release(names[i]);
		zend_string_release(values[i]);
	}

	efree(values);
	efree(names);
	efree(nva);
}

static zend_object *php_nghttp3_qpack_create_object(zend_class_entry *ce)
{
	php_nghttp3_qpack_object *intern = zend_object_alloc(sizeof(php_nghttp3_qpack_object), ce);

	intern->encoder = NULL;
	intern->decoder = NULL;
	intern->streams = NULL;

	zend_object_std_init(&intern->std, ce);
	object_properties_init(&intern->std, ce);
	intern->std.handlers = &php_nghttp3_qpack_object_handlers;

	return &intern->std;
}

static void php_nghttp3_qpack_free_object(zend_object *object)
{
	php_nghttp3_qpack_object *intern = php_nghttp3_qpack_object_from_obj(object);

	php_nghttp3_qpack_reset_state(intern);
	zend_object_std_dtor(&intern->std);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_nghttp3_qpack_construct, 0, 0, 0)
	ZEND_ARG_TYPE_INFO(0, hard_max_table_capacity, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, max_blocked_streams, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, encoder_max_table_capacity, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_nghttp3_qpack_encode, 0, 1, IS_ARRAY, 0)
	ZEND_ARG_ARRAY_INFO(0, headers, 0)
	ZEND_ARG_TYPE_INFO(0, stream_id, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_nghttp3_qpack_feed_encoder, 0, 1, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO(0, bytes, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_nghttp3_qpack_decode, 0, 2, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, stream_id, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, bytes, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, fin, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_nghttp3_qpack_flush_decoder, 0, 0, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_nghttp3_qpack_feed_decoder, 0, 1, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO(0, bytes, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_nghttp3_qpack_reset_stream, 0, 1, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO(0, stream_id, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Nghttp3_Qpack, __construct)
{
	php_nghttp3_qpack_object *intern = Z_PHP_NGHTTP3_QPACK_OBJ_P(ZEND_THIS);
	zend_long hard_max_table_capacity = PHP_NGHTTP3_QPACK_DEFAULT_TABLE_CAPACITY;
	zend_long max_blocked_streams = 0;
	zend_long encoder_max_table_capacity = PHP_NGHTTP3_QPACK_DEFAULT_TABLE_CAPACITY;
	int rv;

	ZEND_PARSE_PARAMETERS_START(0, 3)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(hard_max_table_capacity)
		Z_PARAM_LONG(max_blocked_streams)
		Z_PARAM_LONG(encoder_max_table_capacity)
	ZEND_PARSE_PARAMETERS_END();

	if (hard_max_table_capacity < 0) {
		zend_argument_value_error(1, "must be greater than or equal to 0");
		RETURN_THROWS();
	}

	if (max_blocked_streams < 0) {
		zend_argument_value_error(2, "must be greater than or equal to 0");
		RETURN_THROWS();
	}

	if (encoder_max_table_capacity < 0) {
		zend_argument_value_error(3, "must be greater than or equal to 0");
		RETURN_THROWS();
	}

	php_nghttp3_qpack_reset_state(intern);

	rv = nghttp3_qpack_encoder_new(
		&intern->encoder,
		(size_t) hard_max_table_capacity,
		nghttp3_mem_default()
	);
	if (rv != 0) {
		php_nghttp3_qpack_throw_nghttp3_error("nghttp3_qpack_encoder_new", rv);
		RETURN_THROWS();
	}

	rv = nghttp3_qpack_decoder_new(
		&intern->decoder,
		(size_t) hard_max_table_capacity,
		(size_t) max_blocked_streams,
		nghttp3_mem_default()
	);
	if (rv != 0) {
		php_nghttp3_qpack_throw_nghttp3_error("nghttp3_qpack_decoder_new", rv);
		php_nghttp3_qpack_reset_state(intern);
		RETURN_THROWS();
	}

	nghttp3_qpack_encoder_set_max_dtable_capacity(intern->encoder, (size_t) encoder_max_table_capacity);
	nghttp3_qpack_encoder_set_max_blocked_streams(intern->encoder, (size_t) max_blocked_streams);
}

PHP_METHOD(Nghttp3_Qpack, encode)
{
	php_nghttp3_qpack_object *intern = Z_PHP_NGHTTP3_QPACK_OBJ_P(ZEND_THIS);
	zval *headers;
	zend_long stream_id = 0;
	nghttp3_nv *nva = NULL;
	zend_string **names = NULL;
	zend_string **values = NULL;
	size_t nvlen = 0;
	nghttp3_buf pbuf;
	nghttp3_buf rbuf;
	nghttp3_buf ebuf;
	int rv;

	ZEND_PARSE_PARAMETERS_START(1, 2)
		Z_PARAM_ARRAY(headers)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(stream_id)
	ZEND_PARSE_PARAMETERS_END();

	if (stream_id < 0) {
		zend_argument_value_error(2, "must be greater than or equal to 0");
		RETURN_THROWS();
	}

	if (php_nghttp3_qpack_ensure_initialized(intern) != SUCCESS) {
		RETURN_THROWS();
	}

	if (php_nghttp3_qpack_parse_headers(headers, &nva, &names, &values, &nvlen) != SUCCESS) {
		RETURN_THROWS();
	}

	nghttp3_buf_init(&pbuf);
	nghttp3_buf_init(&rbuf);
	nghttp3_buf_init(&ebuf);

	rv = nghttp3_qpack_encoder_encode(
		intern->encoder,
		&pbuf,
		&rbuf,
		&ebuf,
		(int64_t) stream_id,
		nva,
		nvlen
	);
	if (rv != 0) {
		nghttp3_buf_free(&pbuf, nghttp3_mem_default());
		nghttp3_buf_free(&rbuf, nghttp3_mem_default());
		nghttp3_buf_free(&ebuf, nghttp3_mem_default());
		php_nghttp3_qpack_free_parsed_headers(nva, names, values, nvlen);
		php_nghttp3_qpack_throw_nghttp3_error("nghttp3_qpack_encoder_encode", rv);
		RETURN_THROWS();
	}

	array_init(return_value);
	add_assoc_stringl(
		return_value,
		"prefix",
		pbuf.begin != NULL ? (const char *) pbuf.begin : "",
		(size_t) (pbuf.last - pbuf.begin)
	);
	add_assoc_stringl(
		return_value,
		"header_block",
		rbuf.begin != NULL ? (const char *) rbuf.begin : "",
		(size_t) (rbuf.last - rbuf.begin)
	);
	add_assoc_stringl(
		return_value,
		"encoder_stream",
		ebuf.begin != NULL ? (const char *) ebuf.begin : "",
		(size_t) (ebuf.last - ebuf.begin)
	);

	nghttp3_buf_free(&pbuf, nghttp3_mem_default());
	nghttp3_buf_free(&rbuf, nghttp3_mem_default());
	nghttp3_buf_free(&ebuf, nghttp3_mem_default());
	php_nghttp3_qpack_free_parsed_headers(nva, names, values, nvlen);
}

PHP_METHOD(Nghttp3_Qpack, feedEncoder)
{
	php_nghttp3_qpack_object *intern = Z_PHP_NGHTTP3_QPACK_OBJ_P(ZEND_THIS);
	zend_string *bytes;
	nghttp3_ssize nread;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(bytes)
	ZEND_PARSE_PARAMETERS_END();

	if (php_nghttp3_qpack_ensure_initialized(intern) != SUCCESS) {
		RETURN_THROWS();
	}

	nread = nghttp3_qpack_decoder_read_encoder(
		intern->decoder,
		(const uint8_t *) ZSTR_VAL(bytes),
		ZSTR_LEN(bytes)
	);
	if (nread < 0) {
		php_nghttp3_qpack_throw_nghttp3_error("nghttp3_qpack_decoder_read_encoder", (int) nread);
		RETURN_THROWS();
	}

	if ((size_t) nread != ZSTR_LEN(bytes)) {
		php_nghttp3_qpack_throw_message("encoder stream input was only partially consumed");
		RETURN_THROWS();
	}
}

PHP_METHOD(Nghttp3_Qpack, decode)
{
	php_nghttp3_qpack_object *intern = Z_PHP_NGHTTP3_QPACK_OBJ_P(ZEND_THIS);
	zend_long stream_id;
	zend_string *bytes;
	zend_bool fin = 0;
	nghttp3_qpack_stream_context *sctx;
	const uint8_t *src;
	size_t remaining;
	zend_bool first_iteration = 1;
	zend_bool blocked = 0;
	zend_bool final = 0;
	size_t consumed = 0;
	zval headers_out;

	ZEND_PARSE_PARAMETERS_START(2, 3)
		Z_PARAM_LONG(stream_id)
		Z_PARAM_STR(bytes)
		Z_PARAM_OPTIONAL
		Z_PARAM_BOOL(fin)
	ZEND_PARSE_PARAMETERS_END();

	if (stream_id < 0) {
		zend_argument_value_error(1, "must be greater than or equal to 0");
		RETURN_THROWS();
	}

	if (php_nghttp3_qpack_ensure_initialized(intern) != SUCCESS) {
		RETURN_THROWS();
	}

	sctx = php_nghttp3_qpack_get_stream_context(intern, (int64_t) stream_id);
	if (sctx == NULL) {
		RETURN_THROWS();
	}

	array_init(&headers_out);
	src = (const uint8_t *) ZSTR_VAL(bytes);
	remaining = ZSTR_LEN(bytes);

	while (remaining > 0 || (first_iteration && fin)) {
		nghttp3_qpack_nv nv = {0};
		uint8_t flags = NGHTTP3_QPACK_DECODE_FLAG_NONE;
		nghttp3_ssize nread;

		first_iteration = 0;
		nread = nghttp3_qpack_decoder_read_request(
			intern->decoder,
			sctx,
			&nv,
			&flags,
			src,
			remaining,
			fin
		);
		if (nread < 0) {
			zval_ptr_dtor(&headers_out);
			php_nghttp3_qpack_throw_nghttp3_error("nghttp3_qpack_decoder_read_request", (int) nread);
			RETURN_THROWS();
		}

		src += (size_t) nread;
		remaining -= (size_t) nread;
		consumed += (size_t) nread;

		if (flags & NGHTTP3_QPACK_DECODE_FLAG_EMIT) {
			php_nghttp3_qpack_append_decoded_header(&headers_out, &nv);
			nghttp3_rcbuf_decref(nv.name);
			nghttp3_rcbuf_decref(nv.value);
		}

		if (flags & NGHTTP3_QPACK_DECODE_FLAG_BLOCKED) {
			blocked = 1;
			break;
		}

		if (flags & NGHTTP3_QPACK_DECODE_FLAG_FINAL) {
			final = 1;
			nghttp3_qpack_stream_context_reset(sctx);
			break;
		}

		if ((size_t) nread == 0) {
			if (remaining == 0) {
				break;
			}

			zval_ptr_dtor(&headers_out);
			php_nghttp3_qpack_throw_message("decoder made no progress");
			RETURN_THROWS();
		}
	}

	if (fin && !blocked && !final) {
		nghttp3_qpack_nv nv = {0};
		uint8_t flags = NGHTTP3_QPACK_DECODE_FLAG_NONE;
		nghttp3_ssize nread;

		nread = nghttp3_qpack_decoder_read_request(
			intern->decoder,
			sctx,
			&nv,
			&flags,
			src,
			0,
			1
		);
		if (nread < 0) {
			zval_ptr_dtor(&headers_out);
			php_nghttp3_qpack_throw_nghttp3_error("nghttp3_qpack_decoder_read_request", (int) nread);
			RETURN_THROWS();
		}

		if (flags & NGHTTP3_QPACK_DECODE_FLAG_EMIT) {
			php_nghttp3_qpack_append_decoded_header(&headers_out, &nv);
			nghttp3_rcbuf_decref(nv.name);
			nghttp3_rcbuf_decref(nv.value);
		}

		if (flags & NGHTTP3_QPACK_DECODE_FLAG_BLOCKED) {
			blocked = 1;
		}

		if (flags & NGHTTP3_QPACK_DECODE_FLAG_FINAL) {
			final = 1;
			nghttp3_qpack_stream_context_reset(sctx);
		}
	}

	array_init(return_value);
	add_assoc_zval(return_value, "headers", &headers_out);
	add_assoc_bool(return_value, "blocked", blocked);
	add_assoc_bool(return_value, "final", final);
	add_assoc_long(return_value, "consumed", (zend_long) consumed);
}

PHP_METHOD(Nghttp3_Qpack, flushDecoder)
{
	php_nghttp3_qpack_object *intern = Z_PHP_NGHTTP3_QPACK_OBJ_P(ZEND_THIS);
	size_t dlen;
	zend_string *result;
	nghttp3_buf dbuf;

	ZEND_PARSE_PARAMETERS_NONE();

	if (php_nghttp3_qpack_ensure_initialized(intern) != SUCCESS) {
		RETURN_THROWS();
	}

	dlen = nghttp3_qpack_decoder_get_decoder_streamlen(intern->decoder);
	if (dlen == 0) {
		RETURN_EMPTY_STRING();
	}

	result = zend_string_alloc(dlen, 0);
	dbuf.begin = (uint8_t *) ZSTR_VAL(result);
	dbuf.pos = dbuf.begin;
	dbuf.last = dbuf.begin;
	dbuf.end = dbuf.begin + dlen;

	nghttp3_qpack_decoder_write_decoder(intern->decoder, &dbuf);

	ZSTR_VAL(result)[dlen] = '\0';
	RETURN_NEW_STR(result);
}

PHP_METHOD(Nghttp3_Qpack, feedDecoder)
{
	php_nghttp3_qpack_object *intern = Z_PHP_NGHTTP3_QPACK_OBJ_P(ZEND_THIS);
	zend_string *bytes;
	nghttp3_ssize nread;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(bytes)
	ZEND_PARSE_PARAMETERS_END();

	if (php_nghttp3_qpack_ensure_initialized(intern) != SUCCESS) {
		RETURN_THROWS();
	}

	nread = nghttp3_qpack_encoder_read_decoder(
		intern->encoder,
		(const uint8_t *) ZSTR_VAL(bytes),
		ZSTR_LEN(bytes)
	);
	if (nread < 0) {
		php_nghttp3_qpack_throw_nghttp3_error("nghttp3_qpack_encoder_read_decoder", (int) nread);
		RETURN_THROWS();
	}

	if ((size_t) nread != ZSTR_LEN(bytes)) {
		php_nghttp3_qpack_throw_message("decoder stream input was only partially consumed");
		RETURN_THROWS();
	}
}

PHP_METHOD(Nghttp3_Qpack, resetStream)
{
	php_nghttp3_qpack_object *intern = Z_PHP_NGHTTP3_QPACK_OBJ_P(ZEND_THIS);
	zend_long stream_id;
	php_nghttp3_qpack_stream_ctx *entry;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_LONG(stream_id)
	ZEND_PARSE_PARAMETERS_END();

	if (stream_id < 0) {
		zend_argument_value_error(1, "must be greater than or equal to 0");
		RETURN_THROWS();
	}

	if (php_nghttp3_qpack_ensure_initialized(intern) != SUCCESS) {
		RETURN_THROWS();
	}

	entry = php_nghttp3_qpack_find_stream(intern, (int64_t) stream_id);
	if (entry != NULL && entry->ctx != NULL) {
		nghttp3_qpack_stream_context_reset(entry->ctx);
	}
}

static const zend_function_entry nghttp3_qpack_methods[] = {
	PHP_ME(Nghttp3_Qpack, __construct, arginfo_nghttp3_qpack_construct, ZEND_ACC_PUBLIC)
	PHP_ME(Nghttp3_Qpack, encode, arginfo_nghttp3_qpack_encode, ZEND_ACC_PUBLIC)
	PHP_ME(Nghttp3_Qpack, feedEncoder, arginfo_nghttp3_qpack_feed_encoder, ZEND_ACC_PUBLIC)
	PHP_ME(Nghttp3_Qpack, decode, arginfo_nghttp3_qpack_decode, ZEND_ACC_PUBLIC)
	PHP_ME(Nghttp3_Qpack, flushDecoder, arginfo_nghttp3_qpack_flush_decoder, ZEND_ACC_PUBLIC)
	PHP_ME(Nghttp3_Qpack, feedDecoder, arginfo_nghttp3_qpack_feed_decoder, ZEND_ACC_PUBLIC)
	PHP_ME(Nghttp3_Qpack, resetStream, arginfo_nghttp3_qpack_reset_stream, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

void php_nghttp3_register_qpack_class(void)
{
	zend_class_entry ce;

	INIT_NS_CLASS_ENTRY(ce, "Nghttp3", "Qpack", nghttp3_qpack_methods);
	php_nghttp3_ce_qpack = zend_register_internal_class(&ce);
	php_nghttp3_ce_qpack->create_object = php_nghttp3_qpack_create_object;
	php_nghttp3_ce_qpack->ce_flags |= ZEND_ACC_FINAL;

	memcpy(&php_nghttp3_qpack_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	php_nghttp3_qpack_object_handlers.offset = XtOffsetOf(php_nghttp3_qpack_object, std);
	php_nghttp3_qpack_object_handlers.free_obj = php_nghttp3_qpack_free_object;
}
