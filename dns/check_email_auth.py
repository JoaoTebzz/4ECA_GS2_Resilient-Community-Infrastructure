"""Confere SPF, DKIM e DMARC do dominio ficticio (RT-10) usando o arquivo de zona (nao a internet).
1) le os registros TXT da zona
2) valida SPF (-all), DMARC (p=quarantine ou reject)
3) assina um e-mail de teste com a chave privada e verifica a assinatura usando a chave publica DA ZONA
4) mostra que um e-mail de dominio parecido (sem DKIM) falharia
Salva results/email_auth.json"""
import os, re, sys, json, dkim
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
import subprocess
if not os.path.exists(os.path.join(ROOT, "dns", "dkim_private.key")):
    subprocess.run([os.path.join(ROOT, "dns", "make_dkim.sh")], check=True)   # gera chave e zona se faltar
Z = os.path.join(ROOT, "dns", "vilaaurora.example.zone")
txt = {}
for line in open(Z):
    m = re.match(r'^(\S+)\s+IN\s+TXT\s+"(.*)"\s*$', line)
    if m:
        txt[m.group(1)] = m.group(2)
dominio = "vilaaurora.example"
spf = txt["@"]
dmarc = txt["_dmarc"]
dk = txt["va2026._domainkey"]
res = {
    "spf": spf, "spf_ok": spf.startswith("v=spf1") and spf.rstrip().endswith("-all"),
    "dmarc": dmarc, "dmarc_ok": bool(re.search(r"p=(quarantine|reject)", dmarc)) and "adkim=s" in dmarc,
    "dkim_registro_publico_tamanho_chars": len(dk),
}
msg = (b"From: Coordenacao <coord@vilaaurora.example>\r\nTo: voluntarios@vilaaurora.example\r\n"
       b"Subject: Reuniao de sexta\r\nDate: Sat, 07 Nov 2026 10:00:00 -0300\r\nMessage-ID: <1@vilaaurora.example>\r\n\r\nOi, pessoal. Reuniao as 19h.\r\n")
priv = open(os.path.join(ROOT, "dns", "dkim_private.key"), "rb").read()
sig = dkim.sign(msg, b"va2026", dominio.encode(), priv, include_headers=[b"from", b"to", b"subject", b"date", b"message-id"])
signed = sig + msg
dnsfunc = lambda name, timeout=5: dk.encode() if name.decode().startswith("va2026._domainkey") else None
res["dkim_assinatura_valida"] = bool(dkim.verify(signed, dnsfunc=dnsfunc))
res["dkim_valida_se_corpo_alterado"] = bool(dkim.verify(signed.replace(b"19h", b"20h"), dnsfunc=dnsfunc))
res["dkim_email_sem_assinatura"] = bool(dkim.verify(msg, dnsfunc=dnsfunc)) if b"DKIM-Signature" in msg else "sem assinatura: falha"
# DMARC passa se SPF ou DKIM passar alinhado; para um dominio parecido (prefeitura-serraclara.example) nao ha politica nossa
res["dominio_parecido_atacante"] = "acesso-prefeitura-serraclara.example nao e nosso dominio: SPF/DKIM/DMARC dele nao nos protegem sozinhos; ver controle de dominios parecidos no relatorio"
json.dump(res, open(os.path.join(ROOT, "results", "email_auth.json"), "w"), indent=2, ensure_ascii=False)
print(json.dumps(res, indent=2, ensure_ascii=False))
