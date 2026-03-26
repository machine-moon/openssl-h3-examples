#!/bin/sh
make server
./server 4433 pubcert.pem privkey.pem
