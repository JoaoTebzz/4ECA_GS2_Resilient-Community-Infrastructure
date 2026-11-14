"""Repete o incidente INC-VA-0712 diante das regras novas (RT-13) e do SOAR (RT-15).
Pergunta: com o projeto novo, em que momento o ataque teria sido barrado? Salva results/replay.json
Uso: python3 lab/replay_detection.py [pasta_logs_do_incidente]"""
import os, sys, json, datetime
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
for d in ("panel", "siem"):
    sys.path.insert(0, os.path.join(ROOT, d))
LOGS = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "lab_out", "INC-VA-0712", "cofre"))
import tempfile
os.environ["VA_LOGS"] = tempfile.mkdtemp()
import common as c, detect
SKEW = {"vpn": 192}
ev = []
for fn in os.listdir(LOGS):
    if fn.endswith(".log"):
        for line in open(os.path.join(LOGS, fn)):
            r = json.loads(line)
            t = detect.parse_ts(r["ts"]) - datetime.timedelta(seconds=SKEW.get(fn[:-4], 0))
            ev.append((t, r))
ev.sort(key=lambda x: x[0])
d = detect.Detector(LOGS)
primeiro, bloqueio_em = {}, None
d.alert = lambda rule, rec, desc, **kw: primeiro.setdefault(rule, []).append(c.iso() and desc and rec["ts"])
tempos = {}
def alert(rule, rec, desc, **kw):
    t = detect.parse_ts(rec["ts"]) - datetime.timedelta(seconds=SKEW.get(rec["source"], 0))
    tempos.setdefault(rule, []).append(t)
d.alert = alert
for t, r in ev:
    d.process(r)
res = {"regras_que_disparariam": {k: {"alertas": len(v), "primeiro_alerta_utc": min(v).strftime("%H:%M:%S")} for k, v in tempos.items()}}
t_bloq = min(min(v) for k, v in tempos.items() if k in ("A_VPN_LOGIN_ANOMALO", "B_SQL_INJECTION"))
res["bloqueio_automatico_do_ip_em"] = t_bloq.strftime("%H:%M:%S")
sqli = [t for t, r in ev if r["source"] == "web" and r.get("path") == "/historico"]
res["requisicoes_sqli_do_atacante"] = len(sqli)
res["requisicoes_que_seriam_barradas"] = sum(1 for t in sqli if t > t_bloq)
res["mudanca_da_bomba_seria_evitada"] = True if [t for t, r in ev if r["source"] == "actuator"][0] > t_bloq else False
res["nota"] = "Estimativa por repeticao dos logs: assume o SOAR reagindo no instante do evento (no teste ao vivo o atraso medio foi menor que 1 s)."
json.dump(res, open(os.path.join(ROOT, "results", "replay.json"), "w"), indent=2, ensure_ascii=False)
print(json.dumps(res, indent=2, ensure_ascii=False))
