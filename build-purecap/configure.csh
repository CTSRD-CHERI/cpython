#!/bin/csh

# === CHERI purecap environment ===
setenv CFLAGS "-mabi=purecap"
setenv CPPFLAGS "-I/usr/local/include -I/usr/include"
setenv PKG_CONFIG "/usr/local/bin/pkg-config"
setenv PKG_CONFIG_PATH "/usr/local/lib/pkgconfig" # libffi built from source
setenv LDFLAGS "-mabi=purecap -L/usr/local/lib -L/usr/lib -lmd -lcheri_caprevoke"

# === Configure CPython for purecap build ===
../configure \
		--with-pydebug \
		--build=aarch64-unknown-freebsd \
		--with-assertions \
		--prefix=/home/qianhuiwang/cpython/build-purecap
