#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "php_nghttp3.h"

#include <ext/standard/info.h>

PHP_MINIT_FUNCTION(nghttp3)
{
	php_nghttp3_register_client_class();
	php_nghttp3_register_qpack_class();
	php_nghttp3_register_server_class();
	return SUCCESS;
}

PHP_MINFO_FUNCTION(nghttp3)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "nghttp3 support", "enabled");
	php_info_print_table_end();
}

zend_module_entry nghttp3_module_entry = {
	STANDARD_MODULE_HEADER,
	"nghttp3",
	NULL,
	PHP_MINIT(nghttp3),
	NULL,
	NULL,
	NULL,
	PHP_MINFO(nghttp3),
	"0.1.0",
	STANDARD_MODULE_PROPERTIES
};

#if defined(COMPILE_DL_NGHTTP3) || defined(COMPILE_DL_EXT) || defined(ZEND_COMPILE_DL_NGHTTP3) || defined(ZEND_COMPILE_DL_EXT)
# ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
# endif
ZEND_GET_MODULE(nghttp3)
#endif
