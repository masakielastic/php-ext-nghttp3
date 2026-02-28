#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php_nghttp3.h"

#include <Zend/zend_exceptions.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <nghttp3/nghttp3.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_ossl.h>

#define PHP_NGHTTP3_SERVER_DEFAULT_PORT 4433
#define PHP_NGHTTP3_SERVER_RXBUF_SIZE 65536
#define PHP_NGHTTP3_SERVER_TXBUF_SIZE 2048
#define PHP_NGHTTP3_SERVER_MAX_TX_PER_TICK 32
#define PHP_NGHTTP3_SERVER_MAX_ERROR_LEN 512

typedef struct _php_nghttp3_server_object {
	zend_long port;
	zend_string *cert_file;
	zend_string *key_file;
	zend_string *response_body;
	zend_long response_status;
	zval response_headers;
	zend_bool has_tls;
	zend_bool has_response;
	zend_object std;
} php_nghttp3_server_object;

typedef struct _php_nghttp3_server_stream_ctx {
	int64_t stream_id;
	int body_sent;
	int response_submitted;
	int response_pending;
	struct _php_nghttp3_server_stream_ctx *next;
} php_nghttp3_server_stream_ctx;

typedef struct _php_nghttp3_server_runtime {
	int fd;

	struct sockaddr_storage local_addr;
	socklen_t local_addrlen;
	struct sockaddr_storage peer_addr;
	socklen_t peer_addrlen;
	int has_peer;

	ngtcp2_path_storage path_storage;
	ngtcp2_conn *qconn;
	nghttp3_conn *h3conn;

	SSL_CTX *ssl_ctx;
	SSL *ssl;
	ngtcp2_crypto_ossl_ctx *ossl_ctx;
	ngtcp2_crypto_conn_ref conn_ref;

	uint8_t rxbuf[PHP_NGHTTP3_SERVER_RXBUF_SIZE];
	uint8_t txbuf[PHP_NGHTTP3_SERVER_TXBUF_SIZE];

	ngtcp2_tstamp last_ts;
	zend_bool handshake_completed;
	zend_bool h3_streams_bound;
	zend_bool done;
	zend_bool had_error;
	zend_bool connection_complete;
	zend_long request_limit;
	zend_long served_requests;

	php_nghttp3_server_stream_ctx *streams;
	php_nghttp3_server_object *server_object;
	char error_msg[PHP_NGHTTP3_SERVER_MAX_ERROR_LEN];
} php_nghttp3_server_runtime;

zend_class_entry *php_nghttp3_ce_server;
static zend_object_handlers php_nghttp3_server_object_handlers;

static inline php_nghttp3_server_object *php_nghttp3_server_object_from_obj(zend_object *obj)
{
	return (php_nghttp3_server_object *) ((char *) obj - XtOffsetOf(php_nghttp3_server_object, std));
}

#define Z_PHP_NGHTTP3_SERVER_OBJ_P(zv) php_nghttp3_server_object_from_obj(Z_OBJ_P((zv)))

static ngtcp2_tstamp php_nghttp3_server_timestamp_now_raw(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ngtcp2_tstamp) ts.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp) ts.tv_nsec;
}

static ngtcp2_tstamp php_nghttp3_server_timestamp_now(php_nghttp3_server_runtime *runtime)
{
	ngtcp2_tstamp ts = php_nghttp3_server_timestamp_now_raw();

	if (ts <= runtime->last_ts) {
		ts = runtime->last_ts + 1;
	}

	runtime->last_ts = ts;
	return ts;
}

static void php_nghttp3_server_runtime_errorf(php_nghttp3_server_runtime *runtime, const char *format, ...)
{
	va_list args;

	if (runtime->had_error) {
		return;
	}

	runtime->had_error = 1;

	va_start(args, format);
	vsnprintf(runtime->error_msg, sizeof(runtime->error_msg), format, args);
	va_end(args);
}

static void php_nghttp3_server_capture_openssl_error(php_nghttp3_server_runtime *runtime, const char *context)
{
	unsigned long err = ERR_get_error();

	if (err != 0) {
		char buf[256];

		ERR_error_string_n(err, buf, sizeof(buf));
		php_nghttp3_server_runtime_errorf(runtime, "%s: %s", context, buf);
		return;
	}

	php_nghttp3_server_runtime_errorf(runtime, "%s", context);
}

static int php_nghttp3_server_file_exists(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0;
}

static int php_nghttp3_server_sockaddr_eq(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family) {
		return 0;
	}

	if (a->ss_family == AF_INET) {
		const struct sockaddr_in *x = (const struct sockaddr_in *) a;
		const struct sockaddr_in *y = (const struct sockaddr_in *) b;

		return x->sin_port == y->sin_port && x->sin_addr.s_addr == y->sin_addr.s_addr;
	}

	if (a->ss_family == AF_INET6) {
		const struct sockaddr_in6 *x = (const struct sockaddr_in6 *) a;
		const struct sockaddr_in6 *y = (const struct sockaddr_in6 *) b;

		return x->sin6_port == y->sin6_port &&
			memcmp(&x->sin6_addr, &y->sin6_addr, sizeof(x->sin6_addr)) == 0;
	}

	return 0;
}

static php_nghttp3_server_stream_ctx *php_nghttp3_server_get_stream_ctx(php_nghttp3_server_runtime *runtime, int64_t stream_id, zend_bool create)
{
	php_nghttp3_server_stream_ctx *ctx;

	for (ctx = runtime->streams; ctx != NULL; ctx = ctx->next) {
		if (ctx->stream_id == stream_id) {
			return ctx;
		}
	}

	if (!create) {
		return NULL;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return NULL;
	}

	ctx->stream_id = stream_id;
	ctx->next = runtime->streams;
	runtime->streams = ctx;
	return ctx;
}

static void php_nghttp3_server_remove_stream_ctx(php_nghttp3_server_runtime *runtime, int64_t stream_id)
{
	php_nghttp3_server_stream_ctx **current = &runtime->streams;

	while (*current != NULL) {
		if ((*current)->stream_id == stream_id) {
			php_nghttp3_server_stream_ctx *to_delete = *current;

			*current = to_delete->next;
			free(to_delete);
			return;
		}

		current = &(*current)->next;
	}
}

static void php_nghttp3_server_free_streams(php_nghttp3_server_runtime *runtime)
{
	while (runtime->streams != NULL) {
		php_nghttp3_server_stream_ctx *next = runtime->streams->next;

		free(runtime->streams);
		runtime->streams = next;
	}
}

static zend_result php_nghttp3_server_validate_headers(zval *headers)
{
	HashTable *ht = Z_ARRVAL_P(headers);
	zval *entry;
	zend_string *key;
	zend_ulong index;

	ZEND_HASH_FOREACH_KEY_VAL(ht, index, key, entry) {
		(void) index;

		if (key != NULL) {
			if (Z_TYPE_P(entry) != IS_STRING) {
				zend_type_error("response header values must be string when using associative headers");
				return FAILURE;
			}
			continue;
		}

		if (Z_TYPE_P(entry) != IS_ARRAY) {
			zend_type_error("response headers must be an associative array or an array of arrays{name, value}");
			return FAILURE;
		}

		{
			zval *name = zend_hash_str_find(Z_ARRVAL_P(entry), "name", sizeof("name") - 1);
			zval *value = zend_hash_str_find(Z_ARRVAL_P(entry), "value", sizeof("value") - 1);

			if (name == NULL || value == NULL || Z_TYPE_P(name) != IS_STRING || Z_TYPE_P(value) != IS_STRING) {
				zend_type_error("each response header array must contain string 'name' and 'value'");
				return FAILURE;
			}
		}
	} ZEND_HASH_FOREACH_END();

	return SUCCESS;
}

static size_t php_nghttp3_server_count_headers(zval *headers)
{
	return zend_hash_num_elements(Z_ARRVAL_P(headers));
}

static zend_result php_nghttp3_server_fill_headers(nghttp3_nv *nva, size_t offset, zval *headers)
{
	HashTable *ht = Z_ARRVAL_P(headers);
	zval *entry;
	zend_string *key;
	zend_ulong index;
	size_t i = offset;

	ZEND_HASH_FOREACH_KEY_VAL(ht, index, key, entry) {
		(void) index;

		if (key != NULL) {
			nva[i].name = (uint8_t *) ZSTR_VAL(key);
			nva[i].namelen = ZSTR_LEN(key);
			nva[i].value = (uint8_t *) Z_STRVAL_P(entry);
			nva[i].valuelen = Z_STRLEN_P(entry);
			nva[i].flags = NGHTTP3_NV_FLAG_NONE;
			i++;
			continue;
		}

		{
			zval *name = zend_hash_str_find(Z_ARRVAL_P(entry), "name", sizeof("name") - 1);
			zval *value = zend_hash_str_find(Z_ARRVAL_P(entry), "value", sizeof("value") - 1);

			nva[i].name = (uint8_t *) Z_STRVAL_P(name);
			nva[i].namelen = Z_STRLEN_P(name);
			nva[i].value = (uint8_t *) Z_STRVAL_P(value);
			nva[i].valuelen = Z_STRLEN_P(value);
			nva[i].flags = NGHTTP3_NV_FLAG_NONE;
			i++;
		}
	} ZEND_HASH_FOREACH_END();

	return SUCCESS;
}

static ngtcp2_conn *php_nghttp3_server_get_conn(ngtcp2_crypto_conn_ref *ref)
{
	php_nghttp3_server_runtime *runtime = (php_nghttp3_server_runtime *) ref->user_data;

	return runtime->qconn;
}

static void php_nghttp3_server_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
	(void) rand_ctx;

	if (RAND_bytes(dest, (int) destlen) != 1) {
		memset(dest, 0, destlen);
	}
}

static int php_nghttp3_server_get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *user_data)
{
	(void) conn;
	(void) user_data;

	if (RAND_bytes(cid->data, (int) cidlen) != 1) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	cid->datalen = cidlen;

	if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static void php_nghttp3_server_extend_flow_control(php_nghttp3_server_runtime *runtime, int64_t stream_id, uint64_t amount)
{
	if (amount == 0) {
		return;
	}

	if (ngtcp2_conn_extend_max_stream_offset(runtime->qconn, stream_id, amount) != 0) {
		php_nghttp3_server_runtime_errorf(runtime, "ngtcp2_conn_extend_max_stream_offset failed");
		return;
	}

	ngtcp2_conn_extend_max_offset(runtime->qconn, amount);
}

static nghttp3_ssize php_nghttp3_server_read_resp_data_cb(nghttp3_conn *conn, int64_t stream_id, nghttp3_vec *vec, size_t veccnt, uint32_t *pflags, void *conn_user_data, void *stream_user_data)
{
	php_nghttp3_server_runtime *runtime = (php_nghttp3_server_runtime *) conn_user_data;
	php_nghttp3_server_stream_ctx *stream_ctx = (php_nghttp3_server_stream_ctx *) stream_user_data;
	zend_string *body = runtime->server_object->response_body;

	(void) conn;
	(void) stream_id;

	if (stream_ctx == NULL || veccnt == 0 || body == NULL || stream_ctx->body_sent) {
		*pflags = NGHTTP3_DATA_FLAG_EOF;
		return 0;
	}

	vec[0].base = (uint8_t *) ZSTR_VAL(body);
	vec[0].len = ZSTR_LEN(body);
	stream_ctx->body_sent = 1;
	*pflags = NGHTTP3_DATA_FLAG_EOF;
	return 1;
}

static int php_nghttp3_server_h3_recv_data_cb(nghttp3_conn *conn, int64_t stream_id, const uint8_t *data, size_t datalen, void *conn_user_data, void *stream_user_data)
{
	php_nghttp3_server_runtime *runtime = (php_nghttp3_server_runtime *) conn_user_data;

	(void) conn;
	(void) data;
	(void) stream_user_data;

	php_nghttp3_server_extend_flow_control(runtime, stream_id, (uint64_t) datalen);
	return runtime->had_error ? NGHTTP3_ERR_CALLBACK_FAILURE : 0;
}

static int php_nghttp3_server_h3_deferred_consume_cb(nghttp3_conn *conn, int64_t stream_id, size_t consumed, void *conn_user_data, void *stream_user_data)
{
	php_nghttp3_server_runtime *runtime = (php_nghttp3_server_runtime *) conn_user_data;

	(void) conn;
	(void) stream_user_data;

	php_nghttp3_server_extend_flow_control(runtime, stream_id, (uint64_t) consumed);
	return runtime->had_error ? NGHTTP3_ERR_CALLBACK_FAILURE : 0;
}

static int php_nghttp3_server_h3_recv_header_cb(nghttp3_conn *conn, int64_t stream_id, int32_t token, nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags, void *conn_user_data, void *stream_user_data)
{
	(void) conn;
	(void) stream_id;
	(void) token;
	(void) name;
	(void) value;
	(void) flags;
	(void) conn_user_data;
	(void) stream_user_data;

	return 0;
}

static int php_nghttp3_server_h3_stream_close_cb(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code, void *conn_user_data, void *stream_user_data)
{
	php_nghttp3_server_runtime *runtime = (php_nghttp3_server_runtime *) conn_user_data;
	php_nghttp3_server_stream_ctx *stream_ctx;

	(void) conn;
	(void) app_error_code;
	(void) stream_user_data;

	stream_ctx = php_nghttp3_server_get_stream_ctx(runtime, stream_id, 0);

	if (stream_ctx != NULL) {
		runtime->served_requests++;
		if (runtime->request_limit > 0 && runtime->served_requests >= runtime->request_limit) {
			runtime->done = 1;
		} else {
			runtime->connection_complete = 1;
		}
	}

	return 0;
}

static int php_nghttp3_server_h3_stop_sending_cb(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code, void *conn_user_data, void *stream_user_data)
{
	php_nghttp3_server_runtime *runtime = (php_nghttp3_server_runtime *) conn_user_data;

	(void) conn;
	(void) stream_user_data;

	if (ngtcp2_conn_shutdown_stream_read(runtime->qconn, 0, stream_id, app_error_code) < 0) {
		php_nghttp3_server_runtime_errorf(runtime, "ngtcp2_conn_shutdown_stream_read failed");
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int php_nghttp3_server_h3_reset_stream_cb(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code, void *conn_user_data, void *stream_user_data)
{
	php_nghttp3_server_runtime *runtime = (php_nghttp3_server_runtime *) conn_user_data;

	(void) conn;
	(void) stream_user_data;

	if (ngtcp2_conn_shutdown_stream_write(runtime->qconn, 0, stream_id, app_error_code) < 0) {
		php_nghttp3_server_runtime_errorf(runtime, "ngtcp2_conn_shutdown_stream_write failed");
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int php_nghttp3_server_h3_end_stream_cb(nghttp3_conn *conn, int64_t stream_id, void *conn_user_data, void *stream_user_data)
{
	php_nghttp3_server_runtime *runtime = (php_nghttp3_server_runtime *) conn_user_data;
	php_nghttp3_server_stream_ctx *stream_ctx;

	(void) conn;
	(void) stream_user_data;

	stream_ctx = php_nghttp3_server_get_stream_ctx(runtime, stream_id, 1);
	if (stream_ctx == NULL) {
		return NGHTTP3_ERR_NOMEM;
	}

	if (!stream_ctx->response_submitted && !stream_ctx->response_pending) {
		stream_ctx->response_pending = 1;
	}

	return 0;
}

static int php_nghttp3_server_q_recv_client_initial_cb(ngtcp2_conn *conn, const ngtcp2_cid *dcid, void *user_data)
{
	php_nghttp3_server_runtime *runtime = (php_nghttp3_server_runtime *) user_data;
	int rv = ngtcp2_crypto_recv_client_initial_cb(conn, dcid, user_data);

	if (rv != 0) {
		php_nghttp3_server_capture_openssl_error(runtime, "ngtcp2_crypto_recv_client_initial_cb failed");
	}

	return rv;
}

static int php_nghttp3_server_q_recv_crypto_data_cb(ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level, uint64_t offset, const uint8_t *data, size_t datalen, void *user_data)
{
	php_nghttp3_server_runtime *runtime = (php_nghttp3_server_runtime *) user_data;
	int rv = ngtcp2_crypto_recv_crypto_data_cb(conn, encryption_level, offset, data, datalen, user_data);

	if (rv != 0) {
		php_nghttp3_server_capture_openssl_error(runtime, "ngtcp2_crypto_recv_crypto_data_cb failed");
	}

	return rv;
}

static int php_nghttp3_server_q_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data)
{
	php_nghttp3_server_runtime *runtime = (php_nghttp3_server_runtime *) user_data;
	int fin = !!(flags & NGTCP2_STREAM_DATA_FLAG_FIN);
	nghttp3_ssize nconsumed;

	(void) conn;
	(void) offset;
	(void) stream_user_data;

	nconsumed = nghttp3_conn_read_stream(runtime->h3conn, stream_id, data, datalen, fin);
	if (nconsumed < 0) {
		php_nghttp3_server_runtime_errorf(runtime, "nghttp3_conn_read_stream failed: %s", nghttp3_strerror((int) nconsumed));
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	php_nghttp3_server_extend_flow_control(runtime, stream_id, (uint64_t) nconsumed);
	return runtime->had_error ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

static int php_nghttp3_server_q_acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t offset, uint64_t datalen, void *user_data, void *stream_user_data)
{
	php_nghttp3_server_runtime *runtime = (php_nghttp3_server_runtime *) user_data;

	(void) conn;
	(void) offset;
	(void) stream_user_data;

	if (nghttp3_conn_add_ack_offset(runtime->h3conn, stream_id, datalen) != 0) {
		php_nghttp3_server_runtime_errorf(runtime, "nghttp3_conn_add_ack_offset failed");
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int php_nghttp3_server_q_stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t app_error_code, void *user_data, void *stream_user_data)
{
	php_nghttp3_server_runtime *runtime = (php_nghttp3_server_runtime *) user_data;

	(void) conn;
	(void) flags;
	(void) stream_user_data;

	if (nghttp3_conn_close_stream(runtime->h3conn, stream_id, app_error_code) != 0) {
		php_nghttp3_server_runtime_errorf(runtime, "nghttp3_conn_close_stream failed");
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int php_nghttp3_server_q_handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
	php_nghttp3_server_runtime *runtime = (php_nghttp3_server_runtime *) user_data;

	(void) conn;
	runtime->handshake_completed = 1;
	return 0;
}

static int php_nghttp3_server_alpn_select_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
{
	unsigned int i = 0;

	(void) ssl;
	(void) arg;

	while (i < inlen) {
		unsigned int len = in[i];

		if (i + 1 + len > inlen) {
			break;
		}

		if (len == 2 && in[i + 1] == 'h' && in[i + 2] == '3') {
			*out = &in[i + 1];
			*outlen = 2;
			return SSL_TLSEXT_ERR_OK;
		}

		i += 1 + len;
	}

	return SSL_TLSEXT_ERR_NOACK;
}

static zend_result php_nghttp3_server_setup_ssl_ctx(php_nghttp3_server_runtime *runtime)
{
	php_nghttp3_server_object *intern = runtime->server_object;

	if (ngtcp2_crypto_ossl_init() != 0) {
		php_nghttp3_server_runtime_errorf(runtime, "ngtcp2_crypto_ossl_init failed");
		return FAILURE;
	}

	if (OPENSSL_init_ssl(0, NULL) != 1) {
		php_nghttp3_server_runtime_errorf(runtime, "OPENSSL_init_ssl failed");
		return FAILURE;
	}

	runtime->ssl_ctx = SSL_CTX_new(TLS_server_method());
	if (runtime->ssl_ctx == NULL) {
		php_nghttp3_server_capture_openssl_error(runtime, "SSL_CTX_new failed");
		return FAILURE;
	}

	SSL_CTX_set_min_proto_version(runtime->ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_clear_options(runtime->ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);
	SSL_CTX_set_alpn_select_cb(runtime->ssl_ctx, php_nghttp3_server_alpn_select_cb, NULL);

	if (SSL_CTX_use_certificate_file(runtime->ssl_ctx, ZSTR_VAL(intern->cert_file), SSL_FILETYPE_PEM) != 1) {
		php_nghttp3_server_capture_openssl_error(runtime, "SSL_CTX_use_certificate_file failed");
		return FAILURE;
	}

	if (SSL_CTX_use_PrivateKey_file(runtime->ssl_ctx, ZSTR_VAL(intern->key_file), SSL_FILETYPE_PEM) != 1) {
		php_nghttp3_server_capture_openssl_error(runtime, "SSL_CTX_use_PrivateKey_file failed");
		return FAILURE;
	}

	if (SSL_CTX_check_private_key(runtime->ssl_ctx) != 1) {
		php_nghttp3_server_runtime_errorf(runtime, "SSL_CTX_check_private_key failed");
		return FAILURE;
	}

	return SUCCESS;
}

static zend_result php_nghttp3_server_setup_socket(php_nghttp3_server_runtime *runtime)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *rp;
	char portbuf[6];
	int rv;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	snprintf(portbuf, sizeof(portbuf), "%ld", runtime->server_object->port);
	rv = getaddrinfo(NULL, portbuf, &hints, &res);
	if (rv != 0) {
		php_nghttp3_server_runtime_errorf(runtime, "getaddrinfo failed: %s", gai_strerror(rv));
		return FAILURE;
	}

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

		if (fd < 0) {
			continue;
		}

		{
			int on = 1;
			setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
		}

		if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
			runtime->fd = fd;
			break;
		}

		close(fd);
	}

	freeaddrinfo(res);

	if (runtime->fd < 0) {
		php_nghttp3_server_runtime_errorf(runtime, "failed to bind UDP socket");
		return FAILURE;
	}

	{
		int flags = fcntl(runtime->fd, F_GETFL, 0);

		if (flags < 0 || fcntl(runtime->fd, F_SETFL, flags | O_NONBLOCK) < 0) {
			php_nghttp3_server_runtime_errorf(runtime, "failed to set UDP socket non-blocking mode");
			return FAILURE;
		}
	}

	runtime->local_addrlen = sizeof(runtime->local_addr);
	if (getsockname(runtime->fd, (struct sockaddr *) &runtime->local_addr, &runtime->local_addrlen) != 0) {
		php_nghttp3_server_runtime_errorf(runtime, "getsockname failed");
		return FAILURE;
	}

	return SUCCESS;
}

static zend_result php_nghttp3_server_setup_h3(php_nghttp3_server_runtime *runtime)
{
	nghttp3_callbacks callbacks;
	nghttp3_settings settings;
	int rv;

	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.stream_close = php_nghttp3_server_h3_stream_close_cb;
	callbacks.recv_data = php_nghttp3_server_h3_recv_data_cb;
	callbacks.deferred_consume = php_nghttp3_server_h3_deferred_consume_cb;
	callbacks.recv_header = php_nghttp3_server_h3_recv_header_cb;
	callbacks.stop_sending = php_nghttp3_server_h3_stop_sending_cb;
	callbacks.reset_stream = php_nghttp3_server_h3_reset_stream_cb;
	callbacks.end_stream = php_nghttp3_server_h3_end_stream_cb;

	nghttp3_settings_default(&settings);

	rv = nghttp3_conn_server_new(&runtime->h3conn, &callbacks, &settings, NULL, runtime);
	if (rv != 0) {
		php_nghttp3_server_runtime_errorf(runtime, "nghttp3_conn_server_new failed: %s", nghttp3_strerror(rv));
		return FAILURE;
	}

	return SUCCESS;
}

static zend_result php_nghttp3_server_setup_tls_for_conn(php_nghttp3_server_runtime *runtime)
{
	runtime->ssl = SSL_new(runtime->ssl_ctx);
	if (runtime->ssl == NULL) {
		php_nghttp3_server_capture_openssl_error(runtime, "SSL_new failed");
		return FAILURE;
	}

	SSL_set_accept_state(runtime->ssl);

	runtime->conn_ref.get_conn = php_nghttp3_server_get_conn;
	runtime->conn_ref.user_data = runtime;
	SSL_set_app_data(runtime->ssl, &runtime->conn_ref);

	if (ngtcp2_crypto_ossl_configure_server_session(runtime->ssl) != 0) {
		php_nghttp3_server_runtime_errorf(runtime, "ngtcp2_crypto_ossl_configure_server_session failed");
		return FAILURE;
	}

	if (ngtcp2_crypto_ossl_ctx_new(&runtime->ossl_ctx, runtime->ssl) != 0) {
		php_nghttp3_server_runtime_errorf(runtime, "ngtcp2_crypto_ossl_ctx_new failed");
		return FAILURE;
	}

	ngtcp2_conn_set_tls_native_handle(runtime->qconn, runtime->ossl_ctx);
	return SUCCESS;
}

static zend_result php_nghttp3_server_create_conn(php_nghttp3_server_runtime *runtime, const uint8_t *pkt, size_t pktlen, const struct sockaddr_storage *peer, socklen_t peerlen)
{
	ngtcp2_pkt_hd hd;
	uint8_t scid_data[18];
	ngtcp2_cid scid;
	ngtcp2_callbacks callbacks;
	ngtcp2_settings settings;
	ngtcp2_transport_params params;
	int rv;

	if (ngtcp2_accept(&hd, pkt, pktlen) != 0) {
		return FAILURE;
	}

	if (RAND_bytes(scid_data, (int) sizeof(scid_data)) != 1) {
		php_nghttp3_server_runtime_errorf(runtime, "failed to generate QUIC server CID");
		return FAILURE;
	}

	ngtcp2_cid_init(&scid, scid_data, sizeof(scid_data));

	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.recv_client_initial = php_nghttp3_server_q_recv_client_initial_cb;
	callbacks.recv_crypto_data = php_nghttp3_server_q_recv_crypto_data_cb;
	callbacks.handshake_completed = php_nghttp3_server_q_handshake_completed_cb;
	callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
	callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
	callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
	callbacks.recv_stream_data = php_nghttp3_server_q_recv_stream_data_cb;
	callbacks.acked_stream_data_offset = php_nghttp3_server_q_acked_stream_data_offset_cb;
	callbacks.stream_close = php_nghttp3_server_q_stream_close_cb;
	callbacks.rand = php_nghttp3_server_rand_cb;
	callbacks.get_new_connection_id = php_nghttp3_server_get_new_connection_id_cb;
	callbacks.update_key = ngtcp2_crypto_update_key_cb;
	callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
	callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
	callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
	callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;

	ngtcp2_settings_default(&settings);
	settings.initial_ts = php_nghttp3_server_timestamp_now(runtime);

	ngtcp2_transport_params_default(&params);
	params.original_dcid = hd.dcid;
	params.original_dcid_present = 1;
	params.initial_max_data = 1024 * 1024;
	params.initial_max_stream_data_bidi_local = 256 * 1024;
	params.initial_max_stream_data_bidi_remote = 256 * 1024;
	params.initial_max_stream_data_uni = 256 * 1024;
	params.initial_max_streams_bidi = 100;
	params.initial_max_streams_uni = 10;

	ngtcp2_path_storage_init(
		&runtime->path_storage,
		(struct sockaddr *) &runtime->local_addr,
		runtime->local_addrlen,
		(const struct sockaddr *) peer,
		peerlen,
		NULL
	);

	rv = ngtcp2_conn_server_new(
		&runtime->qconn,
		&hd.scid,
		&scid,
		&runtime->path_storage.path,
		hd.version,
		&callbacks,
		&settings,
		&params,
		NULL,
		runtime
	);
	if (rv != 0) {
		php_nghttp3_server_runtime_errorf(runtime, "ngtcp2_conn_server_new failed: %s", ngtcp2_strerror(rv));
		return FAILURE;
	}

	if (php_nghttp3_server_setup_tls_for_conn(runtime) != SUCCESS) {
		return FAILURE;
	}

	if (php_nghttp3_server_setup_h3(runtime) != SUCCESS) {
		return FAILURE;
	}

	memcpy(&runtime->peer_addr, peer, peerlen);
	runtime->peer_addrlen = peerlen;
	runtime->has_peer = 1;

	return SUCCESS;
}

static zend_result php_nghttp3_server_bind_h3_unidirectional_streams(php_nghttp3_server_runtime *runtime)
{
	int rv;
	int64_t control_stream_id;
	int64_t qpack_encoder_stream_id;
	int64_t qpack_decoder_stream_id;

	if (runtime->h3_streams_bound) {
		return SUCCESS;
	}

	rv = ngtcp2_conn_open_uni_stream(runtime->qconn, &control_stream_id, NULL);
	if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
		return SUCCESS;
	}
	if (rv != 0) {
		php_nghttp3_server_runtime_errorf(runtime, "failed to open control stream: %s", ngtcp2_strerror(rv));
		return FAILURE;
	}

	rv = ngtcp2_conn_open_uni_stream(runtime->qconn, &qpack_encoder_stream_id, NULL);
	if (rv != 0) {
		php_nghttp3_server_runtime_errorf(runtime, "failed to open QPACK encoder stream: %s", ngtcp2_strerror(rv));
		return FAILURE;
	}

	rv = ngtcp2_conn_open_uni_stream(runtime->qconn, &qpack_decoder_stream_id, NULL);
	if (rv != 0) {
		php_nghttp3_server_runtime_errorf(runtime, "failed to open QPACK decoder stream: %s", ngtcp2_strerror(rv));
		return FAILURE;
	}

	rv = nghttp3_conn_bind_control_stream(runtime->h3conn, control_stream_id);
	if (rv != 0) {
		php_nghttp3_server_runtime_errorf(runtime, "nghttp3_conn_bind_control_stream failed: %s", nghttp3_strerror(rv));
		return FAILURE;
	}

	rv = nghttp3_conn_bind_qpack_streams(runtime->h3conn, qpack_encoder_stream_id, qpack_decoder_stream_id);
	if (rv != 0) {
		php_nghttp3_server_runtime_errorf(runtime, "nghttp3_conn_bind_qpack_streams failed: %s", nghttp3_strerror(rv));
		return FAILURE;
	}

	runtime->h3_streams_bound = 1;
	return SUCCESS;
}

static zend_result php_nghttp3_server_submit_pending_responses(php_nghttp3_server_runtime *runtime)
{
	php_nghttp3_server_stream_ctx *stream_ctx;
	php_nghttp3_server_object *intern = runtime->server_object;
	zend_string *status_string;
	nghttp3_data_reader data_reader = {php_nghttp3_server_read_resp_data_cb};
	size_t custom_header_count = php_nghttp3_server_count_headers(&intern->response_headers);
	size_t total_header_count = 1 + custom_header_count;
	nghttp3_nv *headers;

	headers = ecalloc(total_header_count, sizeof(*headers));
	status_string = zend_long_to_str(intern->response_status);

	headers[0].name = (uint8_t *) ":status";
	headers[0].namelen = sizeof(":status") - 1;
	headers[0].value = (uint8_t *) ZSTR_VAL(status_string);
	headers[0].valuelen = ZSTR_LEN(status_string);
	headers[0].flags = NGHTTP3_NV_FLAG_NONE;

	if (custom_header_count > 0) {
		php_nghttp3_server_fill_headers(headers, 1, &intern->response_headers);
	}

	for (stream_ctx = runtime->streams; stream_ctx != NULL; stream_ctx = stream_ctx->next) {
		int rv;

		if (!stream_ctx->response_pending || stream_ctx->response_submitted) {
			continue;
		}

		if (nghttp3_conn_set_stream_user_data(runtime->h3conn, stream_ctx->stream_id, stream_ctx) != 0) {
			zend_string_release(status_string);
			efree(headers);
			php_nghttp3_server_runtime_errorf(runtime, "nghttp3_conn_set_stream_user_data failed");
			return FAILURE;
		}

		rv = nghttp3_conn_submit_response(runtime->h3conn, stream_ctx->stream_id, headers, total_header_count, &data_reader);
		if (rv != 0) {
			zend_string_release(status_string);
			efree(headers);
			php_nghttp3_server_runtime_errorf(runtime, "nghttp3_conn_submit_response failed: %s", nghttp3_strerror(rv));
			return FAILURE;
		}

		stream_ctx->response_pending = 0;
		stream_ctx->response_submitted = 1;
	}

	zend_string_release(status_string);
	efree(headers);
	return SUCCESS;
}

static zend_result php_nghttp3_server_send_quic_packet(php_nghttp3_server_runtime *runtime, ngtcp2_ssize nwrite, ngtcp2_tstamp ts)
{
	ssize_t nwritten;

	if (nwrite <= 0) {
		return SUCCESS;
	}

	if (!runtime->has_peer) {
		php_nghttp3_server_runtime_errorf(runtime, "server has no peer address");
		return FAILURE;
	}

	nwritten = sendto(
		runtime->fd,
		runtime->txbuf,
		(size_t) nwrite,
		0,
		(struct sockaddr *) &runtime->peer_addr,
		runtime->peer_addrlen
	);
	if (nwritten < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			php_nghttp3_server_runtime_errorf(runtime, "UDP send would block");
			return FAILURE;
		}

		php_nghttp3_server_runtime_errorf(runtime, "sendto failed: %s", strerror(errno));
		return FAILURE;
	}

	if ((ngtcp2_ssize) nwritten != nwrite) {
		php_nghttp3_server_runtime_errorf(runtime, "short UDP send");
		return FAILURE;
	}

	ngtcp2_conn_update_pkt_tx_time(runtime->qconn, ts);
	return SUCCESS;
}

static zend_result php_nghttp3_server_flush_h3_to_quic(php_nghttp3_server_runtime *runtime)
{
	size_t sent = 0;

	while (sent < PHP_NGHTTP3_SERVER_MAX_TX_PER_TICK) {
		int64_t stream_id = -1;
		int fin = 0;
		nghttp3_vec h3vec[8];
		nghttp3_ssize veccnt;
		ngtcp2_vec quic_vec[8];
		nghttp3_ssize i;
		ngtcp2_tstamp ts;
		ngtcp2_ssize payload_len = -1;
		ngtcp2_ssize nwrite;

		veccnt = nghttp3_conn_writev_stream(runtime->h3conn, &stream_id, &fin, h3vec, sizeof(h3vec) / sizeof(h3vec[0]));
		if (veccnt < 0) {
			php_nghttp3_server_runtime_errorf(runtime, "nghttp3_conn_writev_stream failed: %s", nghttp3_strerror((int) veccnt));
			return FAILURE;
		}

		if (veccnt == 0 && stream_id == -1) {
			return SUCCESS;
		}

		for (i = 0; i < veccnt; i++) {
			quic_vec[i].base = h3vec[i].base;
			quic_vec[i].len = h3vec[i].len;
		}

		ts = php_nghttp3_server_timestamp_now(runtime);
		nwrite = ngtcp2_conn_writev_stream(
			runtime->qconn,
			&runtime->path_storage.path,
			NULL,
			runtime->txbuf,
			sizeof(runtime->txbuf),
			&payload_len,
			fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : NGTCP2_WRITE_STREAM_FLAG_NONE,
			stream_id,
			veccnt > 0 ? quic_vec : NULL,
			(size_t) veccnt,
			ts
		);
		if (nwrite < 0) {
			if (nwrite == NGTCP2_ERR_DRAINING || nwrite == NGTCP2_ERR_CLOSING) {
				runtime->connection_complete = 1;
				return SUCCESS;
			}

			if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED || nwrite == NGTCP2_ERR_STREAM_SHUT_WR || nwrite == NGTCP2_ERR_STREAM_NOT_FOUND) {
				return SUCCESS;
			}

			php_nghttp3_server_runtime_errorf(runtime, "ngtcp2_conn_writev_stream(H3) failed: %s", ngtcp2_strerror((int) nwrite));
			return FAILURE;
		}

		if (payload_len >= 0) {
			if (nghttp3_conn_add_write_offset(runtime->h3conn, stream_id, (size_t) payload_len) != 0) {
				php_nghttp3_server_runtime_errorf(runtime, "nghttp3_conn_add_write_offset failed");
				return FAILURE;
			}
		}

		if (php_nghttp3_server_send_quic_packet(runtime, nwrite, ts) != SUCCESS) {
			return FAILURE;
		}

		sent++;

		if (nwrite == 0) {
			return SUCCESS;
		}
	}

	return SUCCESS;
}

static zend_result php_nghttp3_server_flush_quic_control(php_nghttp3_server_runtime *runtime)
{
	size_t sent = 0;

	while (sent < PHP_NGHTTP3_SERVER_MAX_TX_PER_TICK) {
		ngtcp2_tstamp ts = php_nghttp3_server_timestamp_now(runtime);
		ngtcp2_ssize payload_len = -1;
		ngtcp2_ssize nwrite;

		nwrite = ngtcp2_conn_writev_stream(
			runtime->qconn,
			&runtime->path_storage.path,
			NULL,
			runtime->txbuf,
			sizeof(runtime->txbuf),
			&payload_len,
			NGTCP2_WRITE_STREAM_FLAG_NONE,
			-1,
			NULL,
			0,
			ts
		);
		if (nwrite < 0) {
			if (nwrite == NGTCP2_ERR_DRAINING || nwrite == NGTCP2_ERR_CLOSING) {
				runtime->connection_complete = 1;
				return SUCCESS;
			}

			php_nghttp3_server_runtime_errorf(runtime, "ngtcp2_conn_writev_stream(control) failed: %s", ngtcp2_strerror((int) nwrite));
			return FAILURE;
		}

		if (nwrite == 0) {
			return SUCCESS;
		}

		if (php_nghttp3_server_send_quic_packet(runtime, nwrite, ts) != SUCCESS) {
			return FAILURE;
		}

		sent++;
	}

	return SUCCESS;
}

static zend_result php_nghttp3_server_drive_tx(php_nghttp3_server_runtime *runtime)
{
	if (runtime->qconn == NULL) {
		return SUCCESS;
	}

	if (php_nghttp3_server_flush_h3_to_quic(runtime) != SUCCESS) {
		return FAILURE;
	}

	if (php_nghttp3_server_flush_quic_control(runtime) != SUCCESS) {
		return FAILURE;
	}

	return SUCCESS;
}

static int php_nghttp3_server_read_udp_once(php_nghttp3_server_runtime *runtime)
{
	struct sockaddr_storage peer;
	socklen_t peerlen = sizeof(peer);
	ssize_t nread;
	ngtcp2_tstamp ts;
	int rv;

	nread = recvfrom(runtime->fd, runtime->rxbuf, sizeof(runtime->rxbuf), 0, (struct sockaddr *) &peer, &peerlen);
	if (nread < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}

		php_nghttp3_server_runtime_errorf(runtime, "recvfrom failed: %s", strerror(errno));
		return -1;
	}

	if (runtime->qconn == NULL) {
		if (php_nghttp3_server_create_conn(runtime, runtime->rxbuf, (size_t) nread, &peer, peerlen) != SUCCESS) {
			if (!runtime->had_error) {
				return 1;
			}

			return -1;
		}
	} else if (!php_nghttp3_server_sockaddr_eq(&peer, &runtime->peer_addr)) {
		return 1;
	}

	ngtcp2_path_storage_init(
		&runtime->path_storage,
		(struct sockaddr *) &runtime->local_addr,
		runtime->local_addrlen,
		(struct sockaddr *) &peer,
		peerlen,
		NULL
	);

	ts = php_nghttp3_server_timestamp_now(runtime);
	rv = ngtcp2_conn_read_pkt(runtime->qconn, &runtime->path_storage.path, NULL, runtime->rxbuf, (size_t) nread, ts);
	if (rv != 0) {
		if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING) {
			runtime->connection_complete = 1;
			return 1;
		}

		php_nghttp3_server_runtime_errorf(runtime, "ngtcp2_conn_read_pkt failed: %s", ngtcp2_strerror(rv));
		return -1;
	}

	return 1;
}

static zend_result php_nghttp3_server_run_connection(php_nghttp3_server_runtime *runtime)
{
	struct pollfd pfd;

	pfd.fd = runtime->fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	while (!runtime->had_error && !runtime->done && !runtime->connection_complete) {
		ngtcp2_tstamp now = php_nghttp3_server_timestamp_now(runtime);
		int timeout_ms = 50;
		int poll_result;

		if (runtime->qconn != NULL) {
			ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(runtime->qconn);

			if (expiry <= now) {
				timeout_ms = 0;
			} else {
				uint64_t diff_ns = expiry - now;

				timeout_ms = (int) (diff_ns / NGTCP2_MILLISECONDS);
				if (timeout_ms > 50) {
					timeout_ms = 50;
				}
			}
		}

		poll_result = poll(&pfd, 1, timeout_ms);
		if (poll_result < 0) {
			if (errno == EINTR) {
				continue;
			}

			php_nghttp3_server_runtime_errorf(runtime, "poll failed: %s", strerror(errno));
			return FAILURE;
		}

		if (poll_result > 0 && (pfd.revents & POLLIN)) {
			for (;;) {
				int read_result = php_nghttp3_server_read_udp_once(runtime);

				if (read_result < 0) {
					return FAILURE;
				}
				if (read_result == 0) {
					break;
				}
			}
		}

		if (runtime->qconn != NULL) {
			now = php_nghttp3_server_timestamp_now(runtime);

			if (ngtcp2_conn_handle_expiry(runtime->qconn, now) != 0) {
				if (ngtcp2_conn_in_closing_period(runtime->qconn) || ngtcp2_conn_in_draining_period(runtime->qconn)) {
					runtime->connection_complete = 1;
					break;
				}

				php_nghttp3_server_runtime_errorf(runtime, "ngtcp2_conn_handle_expiry failed");
				return FAILURE;
			}

			if (runtime->handshake_completed) {
				if (php_nghttp3_server_bind_h3_unidirectional_streams(runtime) != SUCCESS) {
					return FAILURE;
				}

				if (runtime->h3_streams_bound && php_nghttp3_server_submit_pending_responses(runtime) != SUCCESS) {
					return FAILURE;
				}
			}

			if (php_nghttp3_server_drive_tx(runtime) != SUCCESS) {
				return FAILURE;
			}

			if (ngtcp2_conn_in_closing_period(runtime->qconn) || ngtcp2_conn_in_draining_period(runtime->qconn)) {
				runtime->connection_complete = 1;
				break;
			}
		}
	}

	return runtime->had_error ? FAILURE : SUCCESS;
}

static void php_nghttp3_server_runtime_reset_connection(php_nghttp3_server_runtime *runtime)
{
	if (runtime->h3conn != NULL) {
		nghttp3_conn_del(runtime->h3conn);
		runtime->h3conn = NULL;
	}

	if (runtime->qconn != NULL) {
		ngtcp2_conn_del(runtime->qconn);
		runtime->qconn = NULL;
	}

	if (runtime->ossl_ctx != NULL) {
		ngtcp2_crypto_ossl_ctx_del(runtime->ossl_ctx);
		runtime->ossl_ctx = NULL;
	}

	if (runtime->ssl != NULL) {
		SSL_set_app_data(runtime->ssl, NULL);
		SSL_free(runtime->ssl);
		runtime->ssl = NULL;
	}

	php_nghttp3_server_free_streams(runtime);

	runtime->has_peer = 0;
	runtime->peer_addrlen = 0;
	memset(&runtime->peer_addr, 0, sizeof(runtime->peer_addr));
	runtime->handshake_completed = 0;
	runtime->h3_streams_bound = 0;
	runtime->connection_complete = 0;
	runtime->last_ts = 0;
}

static void php_nghttp3_server_runtime_cleanup(php_nghttp3_server_runtime *runtime)
{
	php_nghttp3_server_runtime_reset_connection(runtime);

	if (runtime->ssl_ctx != NULL) {
		SSL_CTX_free(runtime->ssl_ctx);
		runtime->ssl_ctx = NULL;
	}

	if (runtime->fd >= 0) {
		close(runtime->fd);
		runtime->fd = -1;
	}
}

static zend_result php_nghttp3_server_validate_ready(php_nghttp3_server_object *intern)
{
	if (!intern->has_tls) {
		zend_throw_exception(zend_ce_exception, "TLS certificate and key must be configured before serving", 0);
		return FAILURE;
	}

	if (!intern->has_response) {
		zend_throw_exception(zend_ce_exception, "response must be configured before serving", 0);
		return FAILURE;
	}

	return SUCCESS;
}

static zend_result php_nghttp3_server_serve_impl(php_nghttp3_server_object *intern, zend_long max_requests)
{
	php_nghttp3_server_runtime runtime;

	if (max_requests < 0) {
		zend_argument_value_error(1, "must be greater than or equal to 0");
		return FAILURE;
	}

	memset(&runtime, 0, sizeof(runtime));
	runtime.fd = -1;
	runtime.server_object = intern;
	runtime.request_limit = max_requests;

	if (php_nghttp3_server_setup_socket(&runtime) != SUCCESS) {
		php_nghttp3_server_runtime_cleanup(&runtime);
		zend_throw_exception(zend_ce_exception, runtime.error_msg, 0);
		return FAILURE;
	}

	if (php_nghttp3_server_setup_ssl_ctx(&runtime) != SUCCESS) {
		php_nghttp3_server_runtime_cleanup(&runtime);
		zend_throw_exception(zend_ce_exception, runtime.error_msg, 0);
		return FAILURE;
	}

	while (!runtime.done) {
		if (php_nghttp3_server_run_connection(&runtime) != SUCCESS) {
			php_nghttp3_server_runtime_cleanup(&runtime);
			zend_throw_exception(zend_ce_exception, runtime.error_msg[0] != '\0' ? runtime.error_msg : "nghttp3 server failed", 0);
			return FAILURE;
		}

		if (runtime.request_limit > 0 && runtime.served_requests >= runtime.request_limit) {
			runtime.done = 1;
			break;
		}

		php_nghttp3_server_runtime_reset_connection(&runtime);
	}

	php_nghttp3_server_runtime_cleanup(&runtime);
	return SUCCESS;
}

static zend_object *php_nghttp3_server_create_object(zend_class_entry *ce)
{
	php_nghttp3_server_object *intern = zend_object_alloc(sizeof(php_nghttp3_server_object), ce);

	intern->port = PHP_NGHTTP3_SERVER_DEFAULT_PORT;
	intern->cert_file = NULL;
	intern->key_file = NULL;
	intern->response_body = NULL;
	intern->response_status = 200;
	intern->has_tls = 0;
	intern->has_response = 0;
	ZVAL_UNDEF(&intern->response_headers);
	array_init(&intern->response_headers);

	zend_object_std_init(&intern->std, ce);
	object_properties_init(&intern->std, ce);
	intern->std.handlers = &php_nghttp3_server_object_handlers;

	return &intern->std;
}

static void php_nghttp3_server_free_object(zend_object *object)
{
	php_nghttp3_server_object *intern = php_nghttp3_server_object_from_obj(object);

	if (intern->cert_file != NULL) {
		zend_string_release(intern->cert_file);
		intern->cert_file = NULL;
	}

	if (intern->key_file != NULL) {
		zend_string_release(intern->key_file);
		intern->key_file = NULL;
	}

	if (intern->response_body != NULL) {
		zend_string_release(intern->response_body);
		intern->response_body = NULL;
	}

	if (Z_TYPE(intern->response_headers) != IS_UNDEF) {
		zval_ptr_dtor(&intern->response_headers);
		ZVAL_UNDEF(&intern->response_headers);
	}

	zend_object_std_dtor(&intern->std);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_nghttp3_server_construct, 0, 0, 0)
	ZEND_ARG_TYPE_INFO(0, port, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_nghttp3_server_set_tls, 0, 2, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO(0, cert_file, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, key_file, IS_STRING, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_nghttp3_server_set_response, 0, 1, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO(0, body, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, status, IS_LONG, 0)
	ZEND_ARG_ARRAY_INFO(0, headers, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_nghttp3_server_serve_once, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_nghttp3_server_serve, 0, 0, IS_VOID, 0)
	ZEND_ARG_TYPE_INFO(0, max_requests, IS_LONG, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Nghttp3_Server, __construct)
{
	php_nghttp3_server_object *intern = Z_PHP_NGHTTP3_SERVER_OBJ_P(ZEND_THIS);
	zend_long port = PHP_NGHTTP3_SERVER_DEFAULT_PORT;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(port)
	ZEND_PARSE_PARAMETERS_END();

	if (port <= 0 || port > 65535) {
		zend_argument_value_error(1, "must be between 1 and 65535");
		RETURN_THROWS();
	}

	intern->port = port;
}

PHP_METHOD(Nghttp3_Server, setTls)
{
	php_nghttp3_server_object *intern = Z_PHP_NGHTTP3_SERVER_OBJ_P(ZEND_THIS);
	zend_string *cert_file;
	zend_string *key_file;

	ZEND_PARSE_PARAMETERS_START(2, 2)
		Z_PARAM_STR(cert_file)
		Z_PARAM_STR(key_file)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(cert_file) == 0) {
		zend_argument_value_error(1, "must not be empty");
		RETURN_THROWS();
	}

	if (ZSTR_LEN(key_file) == 0) {
		zend_argument_value_error(2, "must not be empty");
		RETURN_THROWS();
	}

	if (!php_nghttp3_server_file_exists(ZSTR_VAL(cert_file))) {
		zend_argument_value_error(1, "must point to an existing file");
		RETURN_THROWS();
	}

	if (!php_nghttp3_server_file_exists(ZSTR_VAL(key_file))) {
		zend_argument_value_error(2, "must point to an existing file");
		RETURN_THROWS();
	}

	if (intern->cert_file != NULL) {
		zend_string_release(intern->cert_file);
	}
	if (intern->key_file != NULL) {
		zend_string_release(intern->key_file);
	}

	intern->cert_file = zend_string_copy(cert_file);
	intern->key_file = zend_string_copy(key_file);
	intern->has_tls = 1;
}

PHP_METHOD(Nghttp3_Server, setResponse)
{
	php_nghttp3_server_object *intern = Z_PHP_NGHTTP3_SERVER_OBJ_P(ZEND_THIS);
	zend_string *body;
	zend_long status = 200;
	zval *headers = NULL;

	ZEND_PARSE_PARAMETERS_START(1, 3)
		Z_PARAM_STR(body)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(status)
		Z_PARAM_ARRAY(headers)
	ZEND_PARSE_PARAMETERS_END();

	if (status < 100 || status > 999) {
		zend_argument_value_error(2, "must be between 100 and 999");
		RETURN_THROWS();
	}

	if (headers != NULL && php_nghttp3_server_validate_headers(headers) != SUCCESS) {
		RETURN_THROWS();
	}

	if (intern->response_body != NULL) {
		zend_string_release(intern->response_body);
	}

	intern->response_body = zend_string_copy(body);
	intern->response_status = status;
	intern->has_response = 1;

	if (Z_TYPE(intern->response_headers) != IS_UNDEF) {
		zval_ptr_dtor(&intern->response_headers);
	}

	if (headers != NULL) {
		ZVAL_COPY(&intern->response_headers, headers);
	} else {
		array_init(&intern->response_headers);
	}
}

PHP_METHOD(Nghttp3_Server, serveOnce)
{
	php_nghttp3_server_object *intern = Z_PHP_NGHTTP3_SERVER_OBJ_P(ZEND_THIS);

	ZEND_PARSE_PARAMETERS_NONE();

	if (php_nghttp3_server_validate_ready(intern) != SUCCESS) {
		RETURN_THROWS();
	}

	if (php_nghttp3_server_serve_impl(intern, 1) != SUCCESS) {
		RETURN_THROWS();
	}
}

PHP_METHOD(Nghttp3_Server, serve)
{
	php_nghttp3_server_object *intern = Z_PHP_NGHTTP3_SERVER_OBJ_P(ZEND_THIS);
	zend_long max_requests = 0;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(max_requests)
	ZEND_PARSE_PARAMETERS_END();

	if (php_nghttp3_server_validate_ready(intern) != SUCCESS) {
		RETURN_THROWS();
	}

	if (php_nghttp3_server_serve_impl(intern, max_requests) != SUCCESS) {
		RETURN_THROWS();
	}
}

static const zend_function_entry nghttp3_server_methods[] = {
	PHP_ME(Nghttp3_Server, __construct, arginfo_nghttp3_server_construct, ZEND_ACC_PUBLIC)
	PHP_ME(Nghttp3_Server, setTls, arginfo_nghttp3_server_set_tls, ZEND_ACC_PUBLIC)
	PHP_ME(Nghttp3_Server, setResponse, arginfo_nghttp3_server_set_response, ZEND_ACC_PUBLIC)
	PHP_ME(Nghttp3_Server, serveOnce, arginfo_nghttp3_server_serve_once, ZEND_ACC_PUBLIC)
	PHP_ME(Nghttp3_Server, serve, arginfo_nghttp3_server_serve, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

void php_nghttp3_register_server_class(void)
{
	zend_class_entry ce;

	INIT_NS_CLASS_ENTRY(ce, "Nghttp3", "Server", nghttp3_server_methods);
	php_nghttp3_ce_server = zend_register_internal_class(&ce);
	php_nghttp3_ce_server->create_object = php_nghttp3_server_create_object;
	php_nghttp3_ce_server->ce_flags |= ZEND_ACC_FINAL;

	memcpy(&php_nghttp3_server_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	php_nghttp3_server_object_handlers.offset = XtOffsetOf(php_nghttp3_server_object, std);
	php_nghttp3_server_object_handlers.free_obj = php_nghttp3_server_free_object;
}
