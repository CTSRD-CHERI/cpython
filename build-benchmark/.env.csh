
# .env.csh
setenv CFLAGS "-mabi=purecap-benchmark"
setenv CPPFLAGS "-I/usr/local64cb/include -I/usr/include"
setenv PKG_CONFIG "/usr/local64cb/bin/pkg-config"
setenv PKG_CONFIG_PATH "/usr/local64cb/lib/pkgconfig"
setenv LDFLAGS "-mabi=purecap-benchmark -L/usr/local64cb/lib -lmd"

