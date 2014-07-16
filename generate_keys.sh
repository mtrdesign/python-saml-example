#!/bin/sh

# generate private key
openssl genrsa -out jam-private.pem 2048

# export public X509 certificate
openssl req -new -x509 -key jam-private.pem -out jam-public.cer -days 3650
