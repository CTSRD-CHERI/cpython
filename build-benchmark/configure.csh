#!/bin/csh

# === CHERI purecap-benchmark environment ===
setenv CFLAGS "-mabi=purecap-benchmark"
setenv CPPFLAGS "-I/usr/local64cb/include -I/usr/include"
setenv PKG_CONFIG "/usr/local64cb/bin/pkg-config"
setenv PKG_CONFIG_PATH "/usr/local64cb/lib/pkgconfig"  # libffi built from source
setenv LDFLAGS "-mabi=purecap-benchmark -L/usr/local64cb/lib -lmd"

# === Configure CPython with debugging, assertions, and install prefix ===
../configure \
		--with-pydebug \
		--build=aarch64-unknown-freebsd \
		--with-assertions \
		--prefix=/home/qianhuiwang/cpython/build-benchmark

