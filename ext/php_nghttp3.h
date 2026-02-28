#ifndef PHP_NGHTTP3_H
#define PHP_NGHTTP3_H

#include <php.h>

extern zend_module_entry nghttp3_module_entry;
extern zend_class_entry *php_nghttp3_ce_client;
extern zend_class_entry *php_nghttp3_ce_qpack;
extern zend_class_entry *php_nghttp3_ce_server;

#define phpext_nghttp3_ptr &nghttp3_module_entry

void php_nghttp3_register_client_class(void);
void php_nghttp3_register_qpack_class(void);
void php_nghttp3_register_server_class(void);

#endif
