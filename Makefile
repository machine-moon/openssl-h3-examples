-include config.mk

OSSL_CFLAGS  = -I$(OPENSSL)/include
OSSL_LDFLAGS = -L$(OPENSSL)/lib64 -Wl,-rpath,$(OPENSSL)/lib64
NH3_CFLAGS   = -I$(NGHTTP3)/include
NH3_LDFLAGS  = -L$(NGHTTP3)/lib -Wl,-rpath,$(NGHTTP3)/lib

.PHONY: all mod_h3 certs clean

all: quic_client_test biomemexample server mod_h3

quic_client_test: quic_client_test.c
	cc -g quic_client_test.c -o $@ $(OSSL_CFLAGS) $(NH3_CFLAGS) $(OSSL_LDFLAGS) $(NH3_LDFLAGS) -lssl -lcrypto -lnghttp3 -lapr-1

quic_server_test: quic_server_test.c
	cc -g quic_server_test.c -o $@ $(OSSL_CFLAGS) $(NH3_CFLAGS) $(OSSL_LDFLAGS) $(NH3_LDFLAGS) -lssl -lcrypto -lnghttp3

quic-client-block: quic-client-block.c
	cc quic-client-block.c -o $@ $(OSSL_CFLAGS) $(OSSL_LDFLAGS) -lssl -lcrypto

biomemexample: biomemexample.c
	cc biomemexample.c -o $@ $(OSSL_CFLAGS) $(OSSL_LDFLAGS) -lssl -lcrypto

server: server.c
	cc -g server.c -o $@ $(OSSL_CFLAGS) $(NH3_CFLAGS) $(OSSL_LDFLAGS) $(NH3_LDFLAGS) -lssl -lcrypto -lnghttp3

mod_h3: httpd/mod_h3.c httpd/ossl-nghttp3.c
	cd httpd && ./configure --with-apxs=$(APACHE)/bin/apxs --with-openssl=$(OPENSSL) --with-nghttp3=$(NGHTTP3) && touch .deps && $(MAKE)

certs: pubcert.pem

pubcert.pem:
	LD_LIBRARY_PATH=$(OPENSSL)/lib64 OPENSSL_CONF=/dev/null \
	$(OPENSSL)/bin/openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
	-keyout privkey.pem -out pubcert.pem -days 365 -nodes -subj '/CN=localhost'

clean:
	rm -f quic_client_test quic_server_test quic-client-block biomemexample server
	rm -f pubcert.pem privkey.pem
	cd httpd && rm -f *.o *.lo *.slo *.so .deps Makefile config.status config.log && rm -rf .libs autom4te.cache
