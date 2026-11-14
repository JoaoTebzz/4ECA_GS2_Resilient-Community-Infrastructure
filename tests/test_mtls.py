"""Teste de mTLS e revogacao (E3 / RT-04, RT-05). Salva results/mtls.json."""
import os, sys, json, subprocess, tempfile, time
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "edge"))
sys.path.insert(0, os.path.join(ROOT, "panel"))
tmp = tempfile.mkdtemp()
os.environ["VA_LOGS"] = os.path.join(tmp, "logs")
pki = os.path.join(tmp, "pki")
subprocess.run([os.path.join(ROOT, "pki", "make_pki.sh"), pki], check=True, capture_output=True)
import mtls_gateway as g

gw = g.Gateway(pki).start()
D = f"{pki}/devices"
res = {}
res["1_certificado_valido"] = g.client_try(gw.port, pki, f"{D}/sensor-ubs-temp01.crt", f"{D}/sensor-ubs-temp01.key")
res["2_sem_certificado"] = g.client_try(gw.port, pki)
res["3_cert_de_outra_CA_mesmo_nome"] = g.client_try(gw.port, pki, f"{D}/rogue.crt", f"{D}/rogue.key")
res["4_cert_de_um_dispositivo_com_chave_de_outro"] = "nao testado (par cert/chave precisa casar)"
try:
    res["4_cert_de_um_dispositivo_com_chave_de_outro"] = g.client_try(gw.port, pki, f"{D}/sensor-ubs-temp01.crt", f"{D}/rele-bomba-escola01.key")
except Exception as e:
    res["4_cert_de_um_dispositivo_com_chave_de_outro"] = "rejeitado no cliente (chave nao casa): " + type(e).__name__

# revogacao: tempo entre revogar e o portao recusar
res["5_antes_de_revogar_rele"] = g.client_try(gw.port, pki, f"{D}/rele-bomba-escola01.crt", f"{D}/rele-bomba-escola01.key")
t0 = time.time()
subprocess.run([os.path.join(ROOT, "pki", "revoke.sh"), "rele-bomba-escola01", pki], check=True, capture_output=True)
gw.reload_crl()
res["6_depois_de_revogar_rele"] = g.client_try(gw.port, pki, f"{D}/rele-bomba-escola01.crt", f"{D}/rele-bomba-escola01.key")
res["6_tempo_revogar_e_publicar_s"] = round(time.time() - t0, 2)
res["7_outro_dispositivo_continua_ok"] = g.client_try(gw.port, pki, f"{D}/sensor-ubs-temp01.crt", f"{D}/sensor-ubs-temp01.key")

# versao do TLS negociada e cifra
import ssl, socket
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname = False
ctx.load_verify_locations(f"{pki}/ca/ca.crt"); ctx.load_cert_chain(f"{D}/sensor-ubs-temp01.crt", f"{D}/sensor-ubs-temp01.key")
with socket.create_connection(("127.0.0.1", gw.port)) as r, ctx.wrap_socket(r, server_hostname="localhost") as s:
    res["tls_versao"], res["tls_cifra"] = s.version(), s.cipher()[0]
    s.sendall(b"x"); s.recv(10)
gw.stop()
res["log_mqtt_linhas"] = sum(1 for _ in open(os.path.join(tmp, "logs", "mqtt.log")))
os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
json.dump(res, open(os.path.join(ROOT, "results", "mtls.json"), "w"), indent=2, ensure_ascii=False)
print(json.dumps(res, indent=2, ensure_ascii=False))
