#!/bin/sh

set -x

export OPENSSL_MODULES=/home/ubuntu/md5_mb_prov.git/build/src

# default provider
openssl speed -config openssl-default.cnf md5
# md5_mb provider
openssl speed -config openssl-md5mb.cnf md5

# "loadbalance" provider (lbprov) with default provider as backend
openssl speed -config openssl-lbprov-default.cnf -propquery "provider=loadbalance" md5
# "loadbalance" provider (lbprov) with default and md5_mb provider as backend
openssl speed -config openssl-lbprov-md5mb-default.cnf -propquery "provider=loadbalance" md5

