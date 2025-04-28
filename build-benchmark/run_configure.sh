#!/bin/sh
env $(grep -v '^#' .env | xargs) ../configure \
	--with-pydebug \
	--build=aarch64-unknown-freebsd \
	--with-assertions \
	--prefix=/home/qianhuiwang/cpython/build-benchmark


