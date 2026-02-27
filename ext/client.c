#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php_nghttp3.h"

#include <Zend/zend_exceptions.h>
#include <Zend/zend_smart_str.h>
#include <ext/standard/url.h>

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
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/socket.h>
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

#define NGHTTP3_RXBUF_SIZE 65536
#define NGHTTP3_TXBUF_SIZE 2048
#define NGHTTP3_MAX_ERROR_LEN 512
#define NGHTTP3_DEFAULT_TIMEOUT_MS 30000

typedef struct _php_nghttp3_client_object {
	zend_long timeout_ms;
	zend_object std;
} php_nghttp3_client_object;

typedef struct _php_nghttp3_client {
	int fd;

	struct sockaddr_storage local_addr;
	socklen_t local_addrlen;
	struct sockaddr_storage remote_addr;
	socklen_t remote_addrlen;
	ngtcp2_path_storage path_storage;

	ngtcp2_conn *qconn;
	nghttp3_conn *h3conn;

	SSL_CTX *ssl_ctx;
	SSL *ssl;
	ngtcp2_crypto_ossl_ctx *ossl_ctx;
	ngtcp2_crypto_conn_ref conn_ref;

	uint8_t rxbuf[NGHTTP3_RXBUF_SIZE];
	uint8_t txbuf[NGHTTP3_TXBUF_SIZE];

	zend_string *host;
	zend_string *authority;
	zend_string *request_path;
	uint16_t port;
	zend_long timeout_ms;

	zval response_headers;
	smart_str response_body;
	zend_bool has_status;
	zend_long status;

	zend_bool handshake_completed;
	zend_bool h3_streams_bound;
	zend_bool request_submitted;
	zend_bool response_complete;
	zend_bool had_error;

	int64_t req_stream_id;
	ngtcp2_tstamp last_ts;

	uint64_t tx_pkt_count;
	uint64_t rx_pkt_count;

	char error_msg[NGHTTP3_MAX_ERROR_LEN];
} php_nghttp3_client;

zend_class_entry *php_nghttp3_ce_client;
static zend_object_handlers php_nghttp3_client_object_handlers;

static inline php_nghttp3_client_object *php_nghttp3_client_object_from_obj(zend_object *obj)
{
	return (php_nghttp3_client_object *) ((char *) obj - XtOffsetOf(php_nghttp3_client_object, std));
}

#define Z_PHP_NGHTTP3_CLIENT_OBJ_P(zv) php_nghttp3_client_object_from_obj(Z_OBJ_P((zv)))

static ngtcp2_tstamp php_nghttp3_timestamp_now_raw(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (ngtcp2_tstamp) ts.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp) ts.tv_nsec;
}

static ngtcp2_tstamp php_nghttp3_timestamp_now(php_nghttp3_client *client)
{
	ngtcp2_tstamp ts = php_nghttp3_timestamp_now_raw();

	if (ts <= client->last_ts) {
		ts = client->last_ts + 1;
	}

	client->last_ts = ts;
	return ts;
}

static void php_nghttp3_errorf(php_nghttp3_client *client, const char *format, ...)
{
	va_list args;

	if (client->had_error) {
		return;
	}

	client->had_error = 1;

	va_start(args, format);
	vsnprintf(client->error_msg, sizeof(client->error_msg), format, args);
	va_end(args);
}

static void php_nghttp3_capture_openssl_error(php_nghttp3_client *client, const char *context)
{
	unsigned long err = ERR_get_error();

	if (err != 0) {
		char buf[256];

		ERR_error_string_n(err, buf, sizeof(buf));
		php_nghttp3_errorf(client, "%s: %s", context, buf);
		return;
	}

	php_nghttp3_errorf(client, "%s", context);
}

static int php_nghttp3_file_exists(const char *path)
{
	struct stat st;

	return stat(path, &st) == 0;
}

static void php_nghttp3_load_system_ca_bundle(php_nghttp3_client *client)
{
	static const char *bundle_candidates[] = {
		"/etc/ssl/certs/ca-certificates.crt",
		"/etc/pki/tls/certs/ca-bundle.crt"
	};
	size_t i;

	for (i = 0; i < sizeof(bundle_candidates) / sizeof(bundle_candidates[0]); i++) {
		if (!php_nghttp3_file_exists(bundle_candidates[i])) {
			continue;
		}

		if (SSL_CTX_load_verify_locations(client->ssl_ctx, bundle_candidates[i], NULL) == 1) {
			return;
		}
	}
}

static void php_nghttp3_reset_response(php_nghttp3_client *client)
{
	array_init(&client->response_headers);
	memset(&client->response_body, 0, sizeof(client->response_body));
	client->has_status = 0;
	client->status = 0;
}

static void php_nghttp3_release_request_parts(php_nghttp3_client *client)
{
	if (client->host != NULL) {
		zend_string_release(client->host);
		client->host = NULL;
	}

	if (client->authority != NULL) {
		zend_string_release(client->authority);
		client->authority = NULL;
	}

	if (client->request_path != NULL) {
		zend_string_release(client->request_path);
		client->request_path = NULL;
	}
}

static void php_nghttp3_cleanup(php_nghttp3_client *client)
{
	if (client->h3conn != NULL) {
		nghttp3_conn_del(client->h3conn);
		client->h3conn = NULL;
	}

	if (client->qconn != NULL) {
		ngtcp2_conn_del(client->qconn);
		client->qconn = NULL;
	}

	if (client->ossl_ctx != NULL) {
		ngtcp2_crypto_ossl_ctx_del(client->ossl_ctx);
		client->ossl_ctx = NULL;
	}

	if (client->ssl != NULL) {
		SSL_set_app_data(client->ssl, NULL);
		SSL_free(client->ssl);
		client->ssl = NULL;
	}

	if (client->ssl_ctx != NULL) {
		SSL_CTX_free(client->ssl_ctx);
		client->ssl_ctx = NULL;
	}

	if (client->fd >= 0) {
		close(client->fd);
		client->fd = -1;
	}

	if (Z_TYPE(client->response_headers) != IS_UNDEF) {
		zval_ptr_dtor(&client->response_headers);
		ZVAL_UNDEF(&client->response_headers);
	}

	smart_str_free(&client->response_body);
	php_nghttp3_release_request_parts(client);
}

static zend_result php_nghttp3_parse_url(php_nghttp3_client *client, zend_string *url)
{
	php_url *parts = php_url_parse_ex(ZSTR_VAL(url), ZSTR_LEN(url));

	if (parts == NULL) {
		php_nghttp3_errorf(client, "failed to parse URL");
		return FAILURE;
	}

	if (parts->scheme == NULL || strcasecmp(ZSTR_VAL(parts->scheme), "https") != 0) {
		php_url_free(parts);
		php_nghttp3_errorf(client, "only https URLs are supported");
		return FAILURE;
	}

	if (parts->host == NULL || ZSTR_LEN(parts->host) == 0) {
		php_url_free(parts);
		php_nghttp3_errorf(client, "URL must include a host");
		return FAILURE;
	}

	if (strchr(ZSTR_VAL(parts->host), ':') != NULL) {
		php_url_free(parts);
		php_nghttp3_errorf(client, "IPv6 hosts are not supported in this minimal client");
		return FAILURE;
	}

	client->port = parts->port > 0 ? (uint16_t) parts->port : 443;
	client->host = zend_string_copy(parts->host);

	if (parts->port > 0 && client->port != 443) {
		client->authority = strpprintf(0, "%s:%u", ZSTR_VAL(parts->host), client->port);
	} else {
		client->authority = zend_string_copy(client->host);
	}

	if (parts->path != NULL && parts->query != NULL) {
		client->request_path = strpprintf(0, "%s?%s", ZSTR_VAL(parts->path), ZSTR_VAL(parts->query));
	} else if (parts->path != NULL) {
		client->request_path = zend_string_copy(parts->path);
	} else if (parts->query != NULL) {
		client->request_path = strpprintf(0, "/?%s", ZSTR_VAL(parts->query));
	} else {
		client->request_path = zend_string_init("/", sizeof("/") - 1, 0);
	}

	php_url_free(parts);
	return SUCCESS;
}

static ngtcp2_conn *php_nghttp3_get_conn(ngtcp2_crypto_conn_ref *ref)
{
	php_nghttp3_client *client = (php_nghttp3_client *) ref->user_data;

	return client->qconn;
}

static void php_nghttp3_rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
	(void) rand_ctx;

	if (RAND_bytes(dest, (int) destlen) != 1) {
		memset(dest, 0, destlen);
	}
}

static int php_nghttp3_get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *user_data)
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

static int php_nghttp3_q_client_initial_cb(ngtcp2_conn *conn, void *user_data)
{
	php_nghttp3_client *client = (php_nghttp3_client *) user_data;
	int rv = ngtcp2_crypto_client_initial_cb(conn, user_data);

	if (rv != 0) {
		php_nghttp3_capture_openssl_error(client, "ngtcp2_crypto_client_initial_cb failed");
	}

	return rv;
}

static int php_nghttp3_q_recv_crypto_data_cb(ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level, uint64_t offset, const uint8_t *data, size_t datalen, void *user_data)
{
	php_nghttp3_client *client = (php_nghttp3_client *) user_data;
	int rv = ngtcp2_crypto_recv_crypto_data_cb(conn, encryption_level, offset, data, datalen, user_data);

	if (rv != 0) {
		php_nghttp3_capture_openssl_error(client, "ngtcp2_crypto_recv_crypto_data_cb failed");
	}

	return rv;
}

static void php_nghttp3_extend_flow_control(php_nghttp3_client *client, int64_t stream_id, uint64_t consumed)
{
	if (consumed == 0) {
		return;
	}

	if (ngtcp2_conn_extend_max_stream_offset(client->qconn, stream_id, consumed) != 0) {
		php_nghttp3_errorf(client, "ngtcp2_conn_extend_max_stream_offset failed");
		return;
	}

	ngtcp2_conn_extend_max_offset(client->qconn, consumed);
}

static int php_nghttp3_h3_recv_data_cb(nghttp3_conn *conn, int64_t stream_id, const uint8_t *data, size_t datalen, void *conn_user_data, void *stream_user_data)
{
	php_nghttp3_client *client = (php_nghttp3_client *) conn_user_data;

	(void) conn;
	(void) stream_user_data;

	if (datalen > 0) {
		smart_str_appendl(&client->response_body, (const char *) data, datalen);
	}

	php_nghttp3_extend_flow_control(client, stream_id, (uint64_t) datalen);
	return client->had_error ? NGHTTP3_ERR_CALLBACK_FAILURE : 0;
}

static int php_nghttp3_h3_deferred_consume_cb(nghttp3_conn *conn, int64_t stream_id, size_t consumed, void *conn_user_data, void *stream_user_data)
{
	php_nghttp3_client *client = (php_nghttp3_client *) conn_user_data;

	(void) conn;
	(void) stream_user_data;

	php_nghttp3_extend_flow_control(client, stream_id, (uint64_t) consumed);
	return client->had_error ? NGHTTP3_ERR_CALLBACK_FAILURE : 0;
}

static int php_nghttp3_h3_recv_header_cb(nghttp3_conn *conn, int64_t stream_id, int32_t token, nghttp3_rcbuf *name, nghttp3_rcbuf *value, uint8_t flags, void *conn_user_data, void *stream_user_data)
{
	php_nghttp3_client *client = (php_nghttp3_client *) conn_user_data;
	nghttp3_vec header_name = nghttp3_rcbuf_get_buf(name);
	nghttp3_vec header_value = nghttp3_rcbuf_get_buf(value);

	(void) conn;
	(void) stream_id;
	(void) token;
	(void) flags;
	(void) stream_user_data;

	if (header_name.len == sizeof(":status") - 1 && memcmp(header_name.base, ":status", sizeof(":status") - 1) == 0) {
		zend_long parsed = 0;

		if (is_numeric_string((const char *) header_value.base, header_value.len, &parsed, NULL, 0) == IS_LONG) {
			client->status = parsed;
			client->has_status = 1;
		}

		return 0;
	}

	{
		zval header;
		zval name_zv;
		zval value_zv;

		array_init(&header);
		ZVAL_STRINGL(&name_zv, (const char *) header_name.base, header_name.len);
		ZVAL_STRINGL(&value_zv, (const char *) header_value.base, header_value.len);
		zend_hash_str_update(Z_ARRVAL(header), "name", sizeof("name") - 1, &name_zv);
		zend_hash_str_update(Z_ARRVAL(header), "value", sizeof("value") - 1, &value_zv);
		add_next_index_zval(&client->response_headers, &header);
	}

	return 0;
}

static int php_nghttp3_h3_end_stream_cb(nghttp3_conn *conn, int64_t stream_id, void *conn_user_data, void *stream_user_data)
{
	php_nghttp3_client *client = (php_nghttp3_client *) conn_user_data;

	(void) conn;
	(void) stream_user_data;

	if (stream_id == client->req_stream_id) {
		client->response_complete = 1;
	}

	return 0;
}

static int php_nghttp3_h3_stream_close_cb(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code, void *conn_user_data, void *stream_user_data)
{
	php_nghttp3_client *client = (php_nghttp3_client *) conn_user_data;

	(void) conn;
	(void) stream_user_data;

	if (stream_id == client->req_stream_id && app_error_code != 0 && !client->response_complete) {
		php_nghttp3_errorf(client, "HTTP/3 stream closed with application error %" PRIu64, app_error_code);
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int php_nghttp3_h3_stop_sending_cb(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code, void *conn_user_data, void *stream_user_data)
{
	php_nghttp3_client *client = (php_nghttp3_client *) conn_user_data;

	(void) conn;
	(void) stream_user_data;

	if (ngtcp2_conn_shutdown_stream_read(client->qconn, 0, stream_id, app_error_code) < 0) {
		php_nghttp3_errorf(client, "ngtcp2_conn_shutdown_stream_read failed");
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int php_nghttp3_h3_reset_stream_cb(nghttp3_conn *conn, int64_t stream_id, uint64_t app_error_code, void *conn_user_data, void *stream_user_data)
{
	php_nghttp3_client *client = (php_nghttp3_client *) conn_user_data;

	(void) conn;
	(void) stream_user_data;

	if (ngtcp2_conn_shutdown_stream_write(client->qconn, 0, stream_id, app_error_code) < 0) {
		php_nghttp3_errorf(client, "ngtcp2_conn_shutdown_stream_write failed");
		return NGHTTP3_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int php_nghttp3_q_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset, const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data)
{
	php_nghttp3_client *client = (php_nghttp3_client *) user_data;
	int fin = !!(flags & NGTCP2_STREAM_DATA_FLAG_FIN);
	nghttp3_ssize nconsumed;

	(void) conn;
	(void) offset;
	(void) stream_user_data;

	nconsumed = nghttp3_conn_read_stream(client->h3conn, stream_id, data, datalen, fin);
	if (nconsumed < 0) {
		php_nghttp3_errorf(client, "nghttp3_conn_read_stream failed: %s", nghttp3_strerror((int) nconsumed));
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	php_nghttp3_extend_flow_control(client, stream_id, (uint64_t) nconsumed);
	return client->had_error ? NGTCP2_ERR_CALLBACK_FAILURE : 0;
}

static int php_nghttp3_q_acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id, uint64_t offset, uint64_t datalen, void *user_data, void *stream_user_data)
{
	php_nghttp3_client *client = (php_nghttp3_client *) user_data;

	(void) conn;
	(void) offset;
	(void) stream_user_data;

	if (nghttp3_conn_add_ack_offset(client->h3conn, stream_id, datalen) != 0) {
		php_nghttp3_errorf(client, "nghttp3_conn_add_ack_offset failed");
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int php_nghttp3_q_stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t app_error_code, void *user_data, void *stream_user_data)
{
	php_nghttp3_client *client = (php_nghttp3_client *) user_data;

	(void) conn;
	(void) flags;
	(void) stream_user_data;

	if (nghttp3_conn_close_stream(client->h3conn, stream_id, app_error_code) != 0) {
		php_nghttp3_errorf(client, "nghttp3_conn_close_stream failed");
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int php_nghttp3_q_handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
	php_nghttp3_client *client = (php_nghttp3_client *) user_data;

	(void) conn;
	client->handshake_completed = 1;
	return 0;
}

static zend_result php_nghttp3_socket_connect(php_nghttp3_client *client)
{
	struct addrinfo hints;
	struct addrinfo *res = NULL;
	struct addrinfo *rp;
	char portbuf[6];
	int rv;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	snprintf(portbuf, sizeof(portbuf), "%u", client->port);
	rv = getaddrinfo(ZSTR_VAL(client->host), portbuf, &hints, &res);
	if (rv != 0) {
		php_nghttp3_errorf(client, "getaddrinfo failed: %s", gai_strerror(rv));
		return FAILURE;
	}

	for (rp = res; rp != NULL; rp = rp->ai_next) {
		int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

		if (fd < 0) {
			continue;
		}

		if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) {
			client->fd = fd;
			memcpy(&client->remote_addr, rp->ai_addr, (size_t) rp->ai_addrlen);
			client->remote_addrlen = (socklen_t) rp->ai_addrlen;
			break;
		}

		close(fd);
	}

	freeaddrinfo(res);

	if (client->fd < 0) {
		php_nghttp3_errorf(client, "failed to connect UDP socket");
		return FAILURE;
	}

	{
		int flags = fcntl(client->fd, F_GETFL, 0);

		if (flags < 0 || fcntl(client->fd, F_SETFL, flags | O_NONBLOCK) < 0) {
			php_nghttp3_errorf(client, "failed to set UDP socket non-blocking mode");
			return FAILURE;
		}
	}

	client->local_addrlen = sizeof(client->local_addr);
	if (getsockname(client->fd, (struct sockaddr *) &client->local_addr, &client->local_addrlen) != 0) {
		php_nghttp3_errorf(client, "getsockname failed");
		return FAILURE;
	}

	ngtcp2_path_storage_init(
		&client->path_storage,
		(struct sockaddr *) &client->local_addr,
		client->local_addrlen,
		(struct sockaddr *) &client->remote_addr,
		client->remote_addrlen,
		NULL
	);

	return SUCCESS;
}

static zend_result php_nghttp3_setup_tls(php_nghttp3_client *client)
{
	static const uint8_t alpn[] = {2, 'h', '3'};

	if (ngtcp2_crypto_ossl_init() != 0) {
		php_nghttp3_errorf(client, "ngtcp2_crypto_ossl_init failed");
		return FAILURE;
	}

	if (OPENSSL_init_ssl(0, NULL) != 1) {
		php_nghttp3_errorf(client, "OPENSSL_init_ssl failed");
		return FAILURE;
	}

	client->ssl_ctx = SSL_CTX_new(TLS_client_method());
	if (client->ssl_ctx == NULL) {
		php_nghttp3_capture_openssl_error(client, "SSL_CTX_new failed");
		return FAILURE;
	}

	(void) SSL_CTX_set_default_verify_paths(client->ssl_ctx);
	php_nghttp3_load_system_ca_bundle(client);

	SSL_CTX_set_verify(client->ssl_ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_min_proto_version(client->ssl_ctx, TLS1_3_VERSION);
	SSL_CTX_clear_options(client->ssl_ctx, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);

	client->ssl = SSL_new(client->ssl_ctx);
	if (client->ssl == NULL) {
		php_nghttp3_capture_openssl_error(client, "SSL_new failed");
		return FAILURE;
	}

	SSL_set_connect_state(client->ssl);

	if (SSL_set_tlsext_host_name(client->ssl, ZSTR_VAL(client->host)) != 1) {
		php_nghttp3_capture_openssl_error(client, "SSL_set_tlsext_host_name failed");
		return FAILURE;
	}

	if (SSL_set1_host(client->ssl, ZSTR_VAL(client->host)) != 1) {
		php_nghttp3_capture_openssl_error(client, "SSL_set1_host failed");
		return FAILURE;
	}

	if (SSL_set_alpn_protos(client->ssl, alpn, sizeof(alpn)) != 0) {
		php_nghttp3_errorf(client, "SSL_set_alpn_protos failed");
		return FAILURE;
	}

	client->conn_ref.get_conn = php_nghttp3_get_conn;
	client->conn_ref.user_data = client;
	SSL_set_app_data(client->ssl, &client->conn_ref);

	if (ngtcp2_crypto_ossl_configure_client_session(client->ssl) != 0) {
		php_nghttp3_errorf(client, "ngtcp2_crypto_ossl_configure_client_session failed");
		return FAILURE;
	}

	if (ngtcp2_crypto_ossl_ctx_new(&client->ossl_ctx, client->ssl) != 0) {
		php_nghttp3_errorf(client, "ngtcp2_crypto_ossl_ctx_new failed");
		return FAILURE;
	}

	return SUCCESS;
}

static zend_result php_nghttp3_setup_http3(php_nghttp3_client *client)
{
	nghttp3_callbacks callbacks;
	nghttp3_settings settings;
	int rv;

	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.stream_close = php_nghttp3_h3_stream_close_cb;
	callbacks.recv_data = php_nghttp3_h3_recv_data_cb;
	callbacks.deferred_consume = php_nghttp3_h3_deferred_consume_cb;
	callbacks.recv_header = php_nghttp3_h3_recv_header_cb;
	callbacks.stop_sending = php_nghttp3_h3_stop_sending_cb;
	callbacks.reset_stream = php_nghttp3_h3_reset_stream_cb;
	callbacks.end_stream = php_nghttp3_h3_end_stream_cb;

	nghttp3_settings_default(&settings);

	rv = nghttp3_conn_client_new(&client->h3conn, &callbacks, &settings, NULL, client);
	if (rv != 0) {
		php_nghttp3_errorf(client, "nghttp3_conn_client_new failed: %s", nghttp3_strerror(rv));
		return FAILURE;
	}

	return SUCCESS;
}

static zend_result php_nghttp3_setup_quic(php_nghttp3_client *client)
{
	ngtcp2_callbacks callbacks;
	ngtcp2_settings settings;
	ngtcp2_transport_params params;
	uint8_t dcid_data[18];
	uint8_t scid_data[18];
	ngtcp2_cid dcid;
	ngtcp2_cid scid;
	int rv;

	if (RAND_bytes(dcid_data, (int) sizeof(dcid_data)) != 1 || RAND_bytes(scid_data, (int) sizeof(scid_data)) != 1) {
		php_nghttp3_errorf(client, "failed to create QUIC connection IDs");
		return FAILURE;
	}

	ngtcp2_cid_init(&dcid, dcid_data, sizeof(dcid_data));
	ngtcp2_cid_init(&scid, scid_data, sizeof(scid_data));

	memset(&callbacks, 0, sizeof(callbacks));
	callbacks.client_initial = php_nghttp3_q_client_initial_cb;
	callbacks.recv_crypto_data = php_nghttp3_q_recv_crypto_data_cb;
	callbacks.handshake_completed = php_nghttp3_q_handshake_completed_cb;
	callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
	callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
	callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
	callbacks.recv_stream_data = php_nghttp3_q_recv_stream_data_cb;
	callbacks.acked_stream_data_offset = php_nghttp3_q_acked_stream_data_offset_cb;
	callbacks.stream_close = php_nghttp3_q_stream_close_cb;
	callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
	callbacks.rand = php_nghttp3_rand_cb;
	callbacks.get_new_connection_id = php_nghttp3_get_new_connection_id_cb;
	callbacks.update_key = ngtcp2_crypto_update_key_cb;
	callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
	callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
	callbacks.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb;
	callbacks.version_negotiation = ngtcp2_crypto_version_negotiation_cb;

	ngtcp2_settings_default(&settings);
	settings.initial_ts = php_nghttp3_timestamp_now(client);

	ngtcp2_transport_params_default(&params);
	params.initial_max_data = 1024 * 1024;
	params.initial_max_stream_data_bidi_local = 512 * 1024;
	params.initial_max_stream_data_bidi_remote = 256 * 1024;
	params.initial_max_stream_data_uni = 256 * 1024;
	params.initial_max_streams_bidi = 16;
	params.initial_max_streams_uni = 16;

	rv = ngtcp2_conn_client_new(
		&client->qconn,
		&dcid,
		&scid,
		&client->path_storage.path,
		NGTCP2_PROTO_VER_V1,
		&callbacks,
		&settings,
		&params,
		NULL,
		client
	);
	if (rv != 0) {
		php_nghttp3_errorf(client, "ngtcp2_conn_client_new failed: %s", ngtcp2_strerror(rv));
		return FAILURE;
	}

	ngtcp2_conn_set_tls_native_handle(client->qconn, client->ossl_ctx);
	return SUCCESS;
}

static zend_result php_nghttp3_bind_h3_unidirectional_streams(php_nghttp3_client *client)
{
	int rv;
	int64_t control_stream_id;
	int64_t qpack_encoder_stream_id;
	int64_t qpack_decoder_stream_id;

	if (client->h3_streams_bound) {
		return SUCCESS;
	}

	rv = ngtcp2_conn_open_uni_stream(client->qconn, &control_stream_id, NULL);
	if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
		return SUCCESS;
	}
	if (rv != 0) {
		php_nghttp3_errorf(client, "failed to open control stream: %s", ngtcp2_strerror(rv));
		return FAILURE;
	}

	rv = ngtcp2_conn_open_uni_stream(client->qconn, &qpack_encoder_stream_id, NULL);
	if (rv != 0) {
		php_nghttp3_errorf(client, "failed to open QPACK encoder stream: %s", ngtcp2_strerror(rv));
		return FAILURE;
	}

	rv = ngtcp2_conn_open_uni_stream(client->qconn, &qpack_decoder_stream_id, NULL);
	if (rv != 0) {
		php_nghttp3_errorf(client, "failed to open QPACK decoder stream: %s", ngtcp2_strerror(rv));
		return FAILURE;
	}

	rv = nghttp3_conn_bind_control_stream(client->h3conn, control_stream_id);
	if (rv != 0) {
		php_nghttp3_errorf(client, "nghttp3_conn_bind_control_stream failed: %s", nghttp3_strerror(rv));
		return FAILURE;
	}

	rv = nghttp3_conn_bind_qpack_streams(client->h3conn, qpack_encoder_stream_id, qpack_decoder_stream_id);
	if (rv != 0) {
		php_nghttp3_errorf(client, "nghttp3_conn_bind_qpack_streams failed: %s", nghttp3_strerror(rv));
		return FAILURE;
	}

	client->h3_streams_bound = 1;
	return SUCCESS;
}

static zend_result php_nghttp3_submit_request(php_nghttp3_client *client)
{
	int rv;
	int64_t stream_id;
	static const uint8_t method[] = "GET";
	static const uint8_t scheme[] = "https";
	static const uint8_t user_agent[] = "php-ext-nghttp3/0.1.0";
	nghttp3_nv headers[] = {
		{(uint8_t *) ":method", (uint8_t *) method, sizeof(":method") - 1, sizeof(method) - 1, NGHTTP3_NV_FLAG_NONE},
		{(uint8_t *) ":scheme", (uint8_t *) scheme, sizeof(":scheme") - 1, sizeof(scheme) - 1, NGHTTP3_NV_FLAG_NONE},
		{(uint8_t *) ":authority", (uint8_t *) ZSTR_VAL(client->authority), sizeof(":authority") - 1, ZSTR_LEN(client->authority), NGHTTP3_NV_FLAG_NONE},
		{(uint8_t *) ":path", (uint8_t *) ZSTR_VAL(client->request_path), sizeof(":path") - 1, ZSTR_LEN(client->request_path), NGHTTP3_NV_FLAG_NONE},
		{(uint8_t *) "user-agent", (uint8_t *) user_agent, sizeof("user-agent") - 1, sizeof(user_agent) - 1, NGHTTP3_NV_FLAG_NONE}
	};

	if (client->request_submitted) {
		return SUCCESS;
	}

	rv = ngtcp2_conn_open_bidi_stream(client->qconn, &stream_id, NULL);
	if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
		return SUCCESS;
	}
	if (rv != 0) {
		php_nghttp3_errorf(client, "ngtcp2_conn_open_bidi_stream failed: %s", ngtcp2_strerror(rv));
		return FAILURE;
	}

	rv = nghttp3_conn_submit_request(client->h3conn, stream_id, headers, sizeof(headers) / sizeof(headers[0]), NULL, NULL);
	if (rv != 0) {
		php_nghttp3_errorf(client, "nghttp3_conn_submit_request failed: %s", nghttp3_strerror(rv));
		return FAILURE;
	}

	client->req_stream_id = stream_id;
	client->request_submitted = 1;
	return SUCCESS;
}

static zend_result php_nghttp3_send_quic_packet(php_nghttp3_client *client, ngtcp2_ssize nwrite, ngtcp2_tstamp ts)
{
	ssize_t nwritten;

	if (nwrite <= 0) {
		return SUCCESS;
	}

	nwritten = send(client->fd, client->txbuf, (size_t) nwrite, 0);
	if (nwritten < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			php_nghttp3_errorf(client, "UDP send would block");
			return FAILURE;
		}

		php_nghttp3_errorf(client, "send failed: %s", strerror(errno));
		return FAILURE;
	}

	if ((ngtcp2_ssize) nwritten != nwrite) {
		php_nghttp3_errorf(client, "short UDP send");
		return FAILURE;
	}

	client->tx_pkt_count++;
	ngtcp2_conn_update_pkt_tx_time(client->qconn, ts);
	return SUCCESS;
}

static zend_result php_nghttp3_flush_h3_to_quic(php_nghttp3_client *client)
{
	size_t sent_packets = 0;

	for (;;) {
		int64_t stream_id = -1;
		int fin = 0;
		nghttp3_vec h3vec[8];
		nghttp3_ssize veccnt;
		ngtcp2_vec quic_vec[8];
		ngtcp2_tstamp ts;
		ngtcp2_ssize payload_len = -1;
		ngtcp2_ssize nwrite;
		nghttp3_ssize i;

		if (sent_packets >= 32) {
			return SUCCESS;
		}

		veccnt = nghttp3_conn_writev_stream(client->h3conn, &stream_id, &fin, h3vec, sizeof(h3vec) / sizeof(h3vec[0]));
		if (veccnt < 0) {
			php_nghttp3_errorf(client, "nghttp3_conn_writev_stream failed: %s", nghttp3_strerror((int) veccnt));
			return FAILURE;
		}

		if (veccnt == 0 && stream_id == -1) {
			return SUCCESS;
		}

		for (i = 0; i < veccnt; i++) {
			quic_vec[i].base = h3vec[i].base;
			quic_vec[i].len = h3vec[i].len;
		}

		ts = php_nghttp3_timestamp_now(client);
		nwrite = ngtcp2_conn_writev_stream(
			client->qconn,
			&client->path_storage.path,
			NULL,
			client->txbuf,
			sizeof(client->txbuf),
			&payload_len,
			fin ? NGTCP2_WRITE_STREAM_FLAG_FIN : NGTCP2_WRITE_STREAM_FLAG_NONE,
			stream_id,
			veccnt > 0 ? quic_vec : NULL,
			(size_t) veccnt,
			ts
		);
		if (nwrite < 0) {
			if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED || nwrite == NGTCP2_ERR_STREAM_SHUT_WR || nwrite == NGTCP2_ERR_STREAM_NOT_FOUND) {
				return SUCCESS;
			}

			php_nghttp3_errorf(client, "ngtcp2_conn_writev_stream failed: %s", ngtcp2_strerror((int) nwrite));
			return FAILURE;
		}

		if (payload_len >= 0) {
			if (nghttp3_conn_add_write_offset(client->h3conn, stream_id, (size_t) payload_len) != 0) {
				php_nghttp3_errorf(client, "nghttp3_conn_add_write_offset failed");
				return FAILURE;
			}
		}

		if (php_nghttp3_send_quic_packet(client, nwrite, ts) != SUCCESS) {
			return FAILURE;
		}

		sent_packets++;

		if (nwrite == 0) {
			return SUCCESS;
		}
	}
}

static zend_result php_nghttp3_flush_quic_control(php_nghttp3_client *client)
{
	size_t sent_packets = 0;

	for (;;) {
		ngtcp2_tstamp ts;
		ngtcp2_ssize payload_len = -1;
		ngtcp2_ssize nwrite;

		if (sent_packets >= 32) {
			return SUCCESS;
		}

		ts = php_nghttp3_timestamp_now(client);
		nwrite = ngtcp2_conn_writev_stream(
			client->qconn,
			&client->path_storage.path,
			NULL,
			client->txbuf,
			sizeof(client->txbuf),
			&payload_len,
			NGTCP2_WRITE_STREAM_FLAG_NONE,
			-1,
			NULL,
			0,
			ts
		);
		if (nwrite < 0) {
			php_nghttp3_errorf(client, "ngtcp2_conn_writev_stream(control) failed: %s", ngtcp2_strerror((int) nwrite));
			return FAILURE;
		}

		if (nwrite == 0) {
			return SUCCESS;
		}

		if (php_nghttp3_send_quic_packet(client, nwrite, ts) != SUCCESS) {
			return FAILURE;
		}

		sent_packets++;
	}
}

static zend_result php_nghttp3_drive_tx(php_nghttp3_client *client)
{
	if (php_nghttp3_flush_h3_to_quic(client) != SUCCESS) {
		return FAILURE;
	}

	if (php_nghttp3_flush_quic_control(client) != SUCCESS) {
		return FAILURE;
	}

	return SUCCESS;
}

static int php_nghttp3_read_udp_once(php_nghttp3_client *client)
{
	ssize_t nread = recv(client->fd, client->rxbuf, sizeof(client->rxbuf), 0);
	ngtcp2_tstamp ts;
	int rv;

	if (nread < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return 0;
		}

		php_nghttp3_errorf(client, "recv failed: %s", strerror(errno));
		return -1;
	}

	ts = php_nghttp3_timestamp_now(client);
	client->rx_pkt_count++;
	rv = ngtcp2_conn_read_pkt(client->qconn, &client->path_storage.path, NULL, client->rxbuf, (size_t) nread, ts);
	if (rv != 0) {
		php_nghttp3_errorf(client, "ngtcp2_conn_read_pkt failed: %s", ngtcp2_strerror(rv));
		return -1;
	}

	return 1;
}

static zend_result php_nghttp3_run(php_nghttp3_client *client)
{
	struct pollfd pfd;
	ngtcp2_tstamp started_ts = php_nghttp3_timestamp_now(client);

	pfd.fd = client->fd;
	pfd.events = POLLIN;
	pfd.revents = 0;

	if (php_nghttp3_drive_tx(client) != SUCCESS) {
		return FAILURE;
	}

	while (!client->had_error && !client->response_complete) {
		ngtcp2_tstamp now = php_nghttp3_timestamp_now(client);
		ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(client->qconn);
		int timeout_ms = 50;
		int poll_result;

		if (expiry <= now) {
			timeout_ms = 0;
		} else {
			uint64_t diff_ns = expiry - now;

			timeout_ms = (int) (diff_ns / NGTCP2_MILLISECONDS);
			if (timeout_ms > 50) {
				timeout_ms = 50;
			}
		}

		poll_result = poll(&pfd, 1, timeout_ms);
		if (poll_result < 0) {
			if (errno == EINTR) {
				continue;
			}

			php_nghttp3_errorf(client, "poll failed: %s", strerror(errno));
			return FAILURE;
		}

		if (poll_result > 0 && (pfd.revents & POLLIN)) {
			for (;;) {
				int read_result = php_nghttp3_read_udp_once(client);

				if (read_result < 0) {
					return FAILURE;
				}
				if (read_result == 0) {
					break;
				}
			}
		}

		now = php_nghttp3_timestamp_now(client);
		if (ngtcp2_conn_handle_expiry(client->qconn, now) != 0) {
			php_nghttp3_errorf(client, "ngtcp2_conn_handle_expiry failed");
			return FAILURE;
		}

		if (ngtcp2_conn_in_closing_period(client->qconn) || ngtcp2_conn_in_draining_period(client->qconn)) {
			php_nghttp3_errorf(client, "QUIC connection entered closing or draining state");
			return FAILURE;
		}

		if (client->handshake_completed) {
			if (php_nghttp3_bind_h3_unidirectional_streams(client) != SUCCESS) {
				return FAILURE;
			}

			if (client->h3_streams_bound && php_nghttp3_submit_request(client) != SUCCESS) {
				return FAILURE;
			}
		}

		if (php_nghttp3_drive_tx(client) != SUCCESS) {
			return FAILURE;
		}

		if (php_nghttp3_timestamp_now(client) - started_ts > (ngtcp2_tstamp) client->timeout_ms * NGTCP2_MILLISECONDS) {
			php_nghttp3_errorf(client, "timed out waiting for the HTTP/3 response");
			return FAILURE;
		}
	}

	return client->had_error ? FAILURE : SUCCESS;
}

static zend_result php_nghttp3_execute_request(zval *return_value, zend_string *url, zend_long timeout_ms)
{
	php_nghttp3_client client;
	zend_result rv;

	memset(&client, 0, sizeof(client));
	client.fd = -1;
	client.req_stream_id = -1;
	client.timeout_ms = timeout_ms;
	ZVAL_UNDEF(&client.response_headers);
	memset(&client.response_body, 0, sizeof(client.response_body));

	php_nghttp3_reset_response(&client);

	if (php_nghttp3_parse_url(&client, url) != SUCCESS) {
		php_nghttp3_cleanup(&client);
		return FAILURE;
	}

	rv = php_nghttp3_socket_connect(&client);
	if (rv == SUCCESS) {
		rv = php_nghttp3_setup_tls(&client);
	}
	if (rv == SUCCESS) {
		rv = php_nghttp3_setup_http3(&client);
	}
	if (rv == SUCCESS) {
		rv = php_nghttp3_setup_quic(&client);
	}
	if (rv == SUCCESS) {
		rv = php_nghttp3_run(&client);
	}

	if (rv != SUCCESS) {
		zend_throw_exception(zend_ce_exception, client.error_msg[0] != '\0' ? client.error_msg : "nghttp3 request failed", 0);
		php_nghttp3_cleanup(&client);
		return FAILURE;
	}

	array_init(return_value);
	if (client.has_status) {
		add_assoc_long(return_value, "status", client.status);
	} else {
		add_assoc_null(return_value, "status");
	}
	add_assoc_long(return_value, "http_version", 3);
	add_assoc_zval(return_value, "headers", &client.response_headers);
	ZVAL_UNDEF(&client.response_headers);

	smart_str_0(&client.response_body);
	if (client.response_body.s != NULL) {
		add_assoc_str(return_value, "body", client.response_body.s);
		client.response_body.s = NULL;
	} else {
		add_assoc_string(return_value, "body", "");
	}

	php_nghttp3_cleanup(&client);
	return SUCCESS;
}

static zend_object *php_nghttp3_client_create_object(zend_class_entry *ce)
{
	php_nghttp3_client_object *intern = zend_object_alloc(sizeof(php_nghttp3_client_object), ce);

	intern->timeout_ms = NGHTTP3_DEFAULT_TIMEOUT_MS;

	zend_object_std_init(&intern->std, ce);
	object_properties_init(&intern->std, ce);
	intern->std.handlers = &php_nghttp3_client_object_handlers;

	return &intern->std;
}

static void php_nghttp3_client_free_object(zend_object *object)
{
	php_nghttp3_client_object *intern = php_nghttp3_client_object_from_obj(object);

	zend_object_std_dtor(&intern->std);
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_nghttp3_client_construct, 0, 0, 0)
	ZEND_ARG_TYPE_INFO(0, timeout_ms, IS_LONG, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_nghttp3_client_get, 0, 1, IS_ARRAY, 0)
	ZEND_ARG_TYPE_INFO(0, url, IS_STRING, 0)
ZEND_END_ARG_INFO()

PHP_METHOD(Nghttp3_Client, __construct)
{
	php_nghttp3_client_object *intern = Z_PHP_NGHTTP3_CLIENT_OBJ_P(ZEND_THIS);
	zend_long timeout_ms = NGHTTP3_DEFAULT_TIMEOUT_MS;

	ZEND_PARSE_PARAMETERS_START(0, 1)
		Z_PARAM_OPTIONAL
		Z_PARAM_LONG(timeout_ms)
	ZEND_PARSE_PARAMETERS_END();

	if (timeout_ms <= 0) {
		zend_argument_value_error(1, "must be greater than 0");
		RETURN_THROWS();
	}

	intern->timeout_ms = timeout_ms;
}

PHP_METHOD(Nghttp3_Client, get)
{
	php_nghttp3_client_object *intern = Z_PHP_NGHTTP3_CLIENT_OBJ_P(ZEND_THIS);
	zend_string *url;

	ZEND_PARSE_PARAMETERS_START(1, 1)
		Z_PARAM_STR(url)
	ZEND_PARSE_PARAMETERS_END();

	if (ZSTR_LEN(url) == 0) {
		zend_argument_value_error(1, "must not be empty");
		RETURN_THROWS();
	}

	if (php_nghttp3_execute_request(return_value, url, intern->timeout_ms) != SUCCESS) {
		RETURN_THROWS();
	}
}

static const zend_function_entry nghttp3_client_methods[] = {
	PHP_ME(Nghttp3_Client, __construct, arginfo_nghttp3_client_construct, ZEND_ACC_PUBLIC)
	PHP_ME(Nghttp3_Client, get, arginfo_nghttp3_client_get, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

void php_nghttp3_register_client_class(void)
{
	zend_class_entry ce;

	INIT_NS_CLASS_ENTRY(ce, "Nghttp3", "Client", nghttp3_client_methods);
	php_nghttp3_ce_client = zend_register_internal_class(&ce);
	php_nghttp3_ce_client->create_object = php_nghttp3_client_create_object;
	php_nghttp3_ce_client->ce_flags |= ZEND_ACC_FINAL;

	memcpy(&php_nghttp3_client_object_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	php_nghttp3_client_object_handlers.offset = XtOffsetOf(php_nghttp3_client_object, std);
	php_nghttp3_client_object_handlers.free_obj = php_nghttp3_client_free_object;
}
