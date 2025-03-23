#! /bin/sh

SANFLAG= --with-address-sanitizer
#  --with-address-sanitizer
#                          enable AddressSanitizer memory error detector,
#                          'asan' (default is no)
#  --with-memory-sanitizer enable MemorySanitizer allocation error detector,
#                          'msan' (default is no)
#  --with-undefined-behavior-sanitizer
#                          enable UndefinedBehaviorSanitizer undefined
#                          behaviour detector, 'ubsan' (default is no)

./configure --with-pydebug --build=aarch64-unknown-freebsd --with-assertions --without-pymalloc

gmake
