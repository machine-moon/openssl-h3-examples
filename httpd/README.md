# Quick hack to get openssl+nghttp3 working with httpd.

## To build use openssl, nghttp3 and httpd from their mster/trunk repositories, install them in $USER/

```bash
bash buildconf
./configure --with-apxs=$USER/APACHE/bin/apxs --with-openssl=$USER/OPENSSL --with-nghttp3=$USER/NGHTTP3
make clean
make
cp ./mod_h3.so $USER/APACHE/modules
```

## How the prototype works
0. The h3 data is received and sent using openssl QUIC api.
1. Create a thread per child to open/process the UDP socket
2. Use a "fake" httpd connection (conn_rec) linked to the nghttp3_conn the conn_rec is created when an SSL_POLL_EVENT_IC is received
3. Use a request_rec that is created at the time the first header is received in the on_recv_header h3 call back.
4. Use a bunch of hooks/filters in mod_h3 allow to process the request.
5. The httpd logic takes care of freeing the request pool
6. Once the http3_conn is finished the conn_rec and the corresponding pools are freed. 

## Testing with google-chrome
```bash
google-chrome --user-data-dir=/tmp/quic_dev --ignore-certificate-errors --origin-to-force-quic-on=localhost:4433 https://localhost:4433
```

## httpd.conf for testing
```
Define MOD_H3
<IfDefine MOD_H3>

# define the alt-svc for browser
Listen 4433 https
EnableMMAP Off
<VirtualHost *:4433>
ServerName localhost:4433

Protocols http/1.1
ProtocolsHonorOrder on
SSLEngine on
SSLCertificateFile "/home/jfclere/CERTS/localhost/localhost.crt"
SSLCertificateKeyFile "/home/jfclere/CERTS/localhost/localhost.key"
Header set alt-svc "h3=\":4433\"; ma=60; h3=\":4433\"; persist=1"
Header set Referrer-Policy same-origin

</VirtualHost>

LoadModule http3_module modules/mod_h3.so
</IfDefine>
# END IfDefine MOD_H3
```
