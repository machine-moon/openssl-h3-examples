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
