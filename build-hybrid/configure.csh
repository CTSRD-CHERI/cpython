#!/bin/csh

# === CHERI hybrid (aapcs) environment ===
setenv CFLAGS "-mabi=aapcs"
setenv CPPFLAGS "-I/usr/local64/include -I/usr/include"
setenv PKG_CONFIG "/usr/local64/bin/pkg-config"
setenv LDFLAGS "-mabi=aapcs -L/usr/local64/lib -lmd"

# === Configure CPython for hybrid build ===
../configure \
		--with-pydebug \
		--build=aarch64-unknown-freebsd \
		--with-assertions \
		--prefix=/home/qianhuiwang/cpython/build-hybrid

