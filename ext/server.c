#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php_nghttp3.h"

zend_class_entry *php_nghttp3_ce_server;

static const zend_function_entry nghttp3_server_methods[] = {
	PHP_FE_END
};

void php_nghttp3_register_server_class(void)
{
	zend_class_entry ce;

	INIT_NS_CLASS_ENTRY(ce, "Nghttp3", "Server", nghttp3_server_methods);
	php_nghttp3_ce_server = zend_register_internal_class(&ce);
	php_nghttp3_ce_server->ce_flags |= ZEND_ACC_FINAL;
}
