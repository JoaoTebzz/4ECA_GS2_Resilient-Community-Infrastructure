#!/usr/bin/env bash
# Gera a chave DKIM (privada fica so local, ignorada pelo Git) e escreve a zona DNS do dominio ficticio.
set -euo pipefail
cd "$(dirname "$0")"
openssl genrsa -out dkim_private.key 2048 2>/dev/null
openssl rsa -in dkim_private.key -pubout -out dkim_public.pem 2>/dev/null
PUB=$(grep -v '^-' dkim_public.pem | tr -d '\n')
cat > vilaaurora.example.zone <<ZONE
; Zona do dominio ficticio do projeto (".example" e reservado e nunca resolve na internet)
\$ORIGIN vilaaurora.example.
\$TTL 3600
@               IN MX 10 mail.vilaaurora.example.
mail            IN A  203.0.113.25
@               IN TXT "v=spf1 ip4:203.0.113.25 -all"
va2026._domainkey IN TXT "v=DKIM1; k=rsa; p=${PUB}"
_dmarc          IN TXT "v=DMARC1; p=quarantine; pct=100; adkim=s; aspf=s; rua=mailto:dmarc@vilaaurora.example"
ZONE
echo "chave e zona gerados"
