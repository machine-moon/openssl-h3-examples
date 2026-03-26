#!/bin/sh
make quic_server_test
./quic_server_test 127.0.0.1 4433 pubcert.pem privkey.pem
