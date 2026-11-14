"""Mede MTTD e MTTR em tempo real no laboratorio (RT-22) e valida as 4 regras (RT-13) e o SOAR (RT-15).
Eventos reais: requisicao SQLi no painel legado, conexao TLS com cert falso/revogado no portao mTLS.
Eventos sinteticos (nao temos VPN aqui): linha de log de login VPN e comando de atuador.
Salva results/detect.json."""
import os, sys, json, tempfile, threading, time, statistics, subprocess
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
for d in ("panel", "edge", "siem", "soar"):
    sys.path.insert(0, os.path.join(ROOT, d))
tmp = tempfile.mkdtemp()
os.environ["VA_LOGS"] = os.path.join(tmp, "logs")
os.environ["VA_STATE"] = os.path.join(tmp, "state")
os.environ["VA_DB_VULN"] = os.path.join(tmp, "v.db")
pki = os.path.join(tmp, "pki")
os.environ["VA_PKI"] = pki
subprocess.run([os.path.join(ROOT, "pki", "make_pki.sh"), pki], check=True, capture_output=True)
import common as c
os.makedirs(os.environ["VA_LOGS"], exist_ok=True)
c.make_db(os.environ["VA_DB_VULN"], legacy=True)
import app_vulnerable as V, mtls_gateway as g, detect, soar

alert_times = {}
def cb(a, rec):
    t_alert = time.time()
    soar.on_alert(a, rec)
    t_done = time.time()
    alert_times.setdefault(a["rule"], []).append((rec["_t"], t_alert, t_done))

cfg = dict(detect.CFG, vpn_horario_ok=[0, 24])   # janela de horario testada a parte (testes unitarios abaixo)
det = detect.Detector(os.environ["VA_LOGS"], on_alert=lambda a, r: cb(a, r), cfg=cfg)
# guardamos o instante real do evento dentro do registro para medir
orig = det.process
def proc(rec):
    rec["_t"] = detect.parse_ts(rec["ts"]).timestamp()
    orig(rec)
det.process = proc
stop = {"v": False}
th = threading.Thread(target=det.follow, kwargs={"interval": 0.5, "stop": lambda: stop["v"]}, daemon=True)
th.start()

gw = g.Gateway(pki).start()
D = f"{pki}/devices"
cv = V.app.test_client()
N = 10
for i in range(N):
    # A: login vpn anomalo (sintetico)
    c.log_event("vpn", event="auth_success", user="coord1", src="203.0.113.77", method="password", mfa="none")
    # B: SQLi real
    cv.get("/historico", query_string={"q": "zzz' UNION SELECT id,email,phone,kind FROM users --"}, environ_overrides={"REMOTE_ADDR": "203.0.113.77"})
    # C: cert falso real
    g.client_try(gw.port, pki, f"{D}/rogue.crt", f"{D}/rogue.key")
    # D: atuador com origem fora do perfil (sintetico)
    c.log_event("actuator", cmd="schedule", pump="bomba_escola", start=0, end=24, via="db_sync")
    time.sleep(1.2)
# um evento normal para medir falso positivo das regras
c.log_event("vpn", event="auth_success", user="tec1", src="198.51.100.10", method="cert+totp", mfa="totp")
time.sleep(2)
stop["v"] = True; th.join(2); gw.stop()

# a hora fixa 02h so vale para D; para a regra A o horario real do relogio pode ou nao cair fora da janela, nao importa (ja ha motivo sem MFA)
res = {"alertas_por_regra": {}, "mttd_s": {}, "mttr_automatico_s": {}}
for rule, lst in alert_times.items():
    res["alertas_por_regra"][rule] = len(lst)
    mttd = [t_alert - t_ev for t_ev, t_alert, _ in lst]
    mttr = [t_done - t_alert for _, t_alert, t_done in lst]
    res["mttd_s"][rule] = {"media": round(statistics.mean(mttd), 3), "max": round(max(mttd), 3)}
    res["mttr_automatico_s"][rule] = {"media": round(statistics.mean(mttr), 3), "max": round(max(mttr), 3)}
allm = [t_alert - t_ev for l in alert_times.values() for t_ev, t_alert, _ in l]
allr = [t_done - t_alert for l in alert_times.values() for _, t_alert, t_done in l]
res["mttd_geral_s"] = round(statistics.mean(allm), 3)
res["mttr_automatico_geral_s"] = round(statistics.mean(allr), 3)
res["eventos_maliciosos_injetados"] = N * 4
res["alertas_gerados"] = sum(len(l) for l in alert_times.values())
res["eventos_normais_injetados"] = 1
res["falsos_positivos_nos_eventos_normais"] = len([a for a in det.alerts if a.get("user") == "tec1" or a.get("via") == "painel"])
# regras de horario (testes unitarios com relogio fixo)
def alerta(rec):
    d2 = detect.Detector(os.environ["VA_LOGS"], on_alert=None); n0 = len(d2.alerts); d2.alert = lambda *a, **k: d2.alerts.append(1); d2.process(rec); return len(d2.alerts) > n0
res["regras_de_horario"] = {
 "vpn_03h_com_mfa_ip_ok": alerta({"ts": "2026-10-17T03:00:00.000Z", "source": "vpn", "event": "auth_success", "user": "tec1", "src": "198.51.100.10", "mfa": "totp"}),
 "vpn_10h_com_mfa_ip_ok": alerta({"ts": "2026-10-17T10:00:00.000Z", "source": "vpn", "event": "auth_success", "user": "tec1", "src": "198.51.100.10", "mfa": "totp"}),
 "atuador_02h_via_painel": alerta({"ts": "2026-10-17T02:00:00.000Z", "source": "actuator", "cmd": "schedule", "via": "painel"}),
 "atuador_10h_via_painel": alerta({"ts": "2026-10-17T10:00:00.000Z", "source": "actuator", "cmd": "schedule", "via": "painel"}),
}
S = os.environ["VA_STATE"]
rd = lambda n: open(os.path.join(S, n)).read().split("\n")[:-1] if os.path.exists(os.path.join(S, n)) else []
res["efeitos_soar"] = {"ips_bloqueados": sorted(set(rd("blocklist.txt"))), "sessoes_vpn_derrubadas": len(rd("vpn_revoked_sessions.txt")),
                       "dispositivos_isolados": len(rd("isolated_devices.txt")), "modo_seguro_acionado": len(rd("safe_mode.txt"))}
pend = os.listdir(os.path.join(S, "approvals", "pending"))
res["alto_impacto"] = {"pedidos_pendentes": len(pend), "executados_sem_humano": len(rd("high_impact_executed.txt"))}
# aprovar um pedido como humano e conferir que so entao executa
if pend:
    rid = pend[0].replace(".json", "")
    soar.approve(rid, "coord1")
res["alto_impacto"]["executados_apos_aprovacao"] = len(rd("high_impact_executed.txt"))
try:
    soar.run_action("desligar_bomba")
    res["alto_impacto"]["chamada_direta_bloqueada"] = False
except PermissionError:
    res["alto_impacto"]["chamada_direta_bloqueada"] = True
json.dump(res, open(os.path.join(ROOT, "results", "detect.json"), "w"), indent=2, ensure_ascii=False)
print(json.dumps(res, indent=2, ensure_ascii=False))
