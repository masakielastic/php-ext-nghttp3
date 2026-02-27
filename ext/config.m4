PHP_ARG_ENABLE([nghttp3],
  [whether to enable nghttp3 extension],
  [AS_HELP_STRING([--enable-nghttp3], [Enable nghttp3 extension])],
  [yes])

if test "$PHP_NGHTTP3" != "no"; then
  PKG_PROG_PKG_CONFIG
  PKG_CHECK_MODULES([NGHTTP3_DEPS], [libngtcp2 libngtcp2_crypto_ossl libnghttp3 openssl])

  PHP_EVAL_INCLINE([$NGHTTP3_DEPS_CFLAGS])
  PHP_EVAL_LIBLINE([$NGHTTP3_DEPS_LIBS], [NGHTTP3_SHARED_LIBADD])

  PHP_NEW_EXTENSION([nghttp3], [nghttp3.c client.c server.c], [$ext_shared])
  PHP_SUBST([NGHTTP3_SHARED_LIBADD])
fi
