#!/usr/bin/env bash
# Cria a CA do projeto e um certificado por dispositivo (X.509, EC P-256).
# Uso: ./make_pki.sh [pasta_saida]
# As chaves privadas ficam so na pasta de saida (NAO vao pro git, veja .gitignore).
set -euo pipefail
OUT="${1:-$(dirname "$0")/out}"
rm -rf "$OUT"; mkdir -p "$OUT"/{ca,devices,newcerts}
cd "$OUT"
: > ca/index.txt; echo 1000 > ca/serial; echo 1000 > ca/crlnumber

cat > ca/openssl.cnf <<'EOF'
[ ca ]
default_ca = CA_default
[ CA_default ]
dir = .
database = ca/index.txt
serial = ca/serial
crlnumber = ca/crlnumber
new_certs_dir = newcerts
certificate = ca/ca.crt
private_key = ca/ca.key
default_md = sha256
default_days = 365
default_crl_days = 30
policy = policy_any
unique_subject = no
copy_extensions = none
[ policy_any ]
commonName = supplied
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = x
[ v3_ca ]
basicConstraints = critical,CA:true,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[ v3_server ]
basicConstraints = CA:false
keyUsage = digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:edge.vilaaurora.example,DNS:localhost,IP:127.0.0.1
[ v3_client ]
basicConstraints = CA:false
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

# CA
openssl ecparam -name prime256v1 -genkey -noout -out ca/ca.key
openssl req -new -x509 -key ca/ca.key -sha256 -days 1825 -subj "/CN=Vila Aurora CA (lab)" \
  -config ca/openssl.cnf -extensions v3_ca -out ca/ca.crt

issue() { # nome tipo(server|client)
  local n="$1" t="$2"
  openssl ecparam -name prime256v1 -genkey -noout -out devices/$n.key
  openssl req -new -key devices/$n.key -subj "/CN=$n" -out devices/$n.csr
  openssl ca -batch -config ca/openssl.cnf -extensions v3_$t -in devices/$n.csr \
     -out devices/$n.crt -notext -days 365 2>/dev/null
}
issue edge-server server
for d in sensor-ubs-temp01 sensor-escola-nivel01 sensor-abrigo-alag01 fechadura-centro01 rele-bomba-escola01; do
  issue "$d" client
done
# um certificado "falso" de outra CA, para testar rejeicao
openssl ecparam -name prime256v1 -genkey -noout -out devices/rogue.key
openssl req -x509 -new -key devices/rogue.key -subj "/CN=sensor-ubs-temp01" -days 30 -out devices/rogue.crt

gen_crl() { openssl ca -config ca/openssl.cnf -gencrl -out ca/crl.pem 2>/dev/null; }
gen_crl
echo "PKI pronta em $OUT"
