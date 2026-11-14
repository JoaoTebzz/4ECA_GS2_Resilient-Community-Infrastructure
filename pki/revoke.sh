#!/usr/bin/env bash
# Revoga o certificado de um dispositivo e publica a nova CRL.
# Uso: ./revoke.sh <nome_do_dispositivo> [pasta_pki]
set -euo pipefail
N="$1"; OUT="${2:-$(dirname "$0")/out}"
cd "$OUT"
openssl ca -config ca/openssl.cnf -revoke devices/$N.crt 2>/dev/null
openssl ca -config ca/openssl.cnf -gencrl -out ca/crl.pem 2>/dev/null
echo "revogado: $N"
