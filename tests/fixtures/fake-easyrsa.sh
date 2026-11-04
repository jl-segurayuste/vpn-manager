#!/bin/bash
# easy-rsa mínimo para pruebas (openssl ca): build-client-full, revoke, gen-crl, renew
set -euo pipefail
[ "${1:-}" = "--batch" ] && shift
cmd=$1; name=${2:-}
issue() { openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj "/CN=$1" -keyout pki/private/$1.key -out pki/reqs/$1.req 2>/dev/null
          openssl ca -batch -config openssl.cnf -extensions ${2:-client} -in pki/reqs/$1.req -out pki/issued/$1.crt 2>/dev/null; }
case $cmd in
  build-client-full) issue "$name" client ;;
  build-server-full) issue "$name" server ;;
  revoke) openssl ca -batch -config openssl.cnf -revoke pki/issued/$name.crt 2>/dev/null ;;
  gen-crl) openssl ca -batch -config openssl.cnf -gencrl -out pki/crl.pem 2>/dev/null ;;
  renew) openssl ca -batch -config openssl.cnf -revoke pki/issued/$name.crt -crl_reason superseded 2>/dev/null; issue "$name" client ;;
esac
