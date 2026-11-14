"""Calcula as metricas da campanha de phishing SIMULADO a partir do CSV de eventos exportado do Gophish
(colunas: email, message, time). Roda so com contas ficticias da equipe.
Uso: python3 phishing/gophish_metrics.py eventos.csv
Saida: abertura, clique, envio de dados e reporte (em % dos enviados) e tempo ate o primeiro reporte."""
import sys, csv, json, datetime
from collections import defaultdict

ev = defaultdict(dict)
for r in csv.DictReader(open(sys.argv[1], encoding="utf-8")):
    m = r["message"].strip().lower()
    t = datetime.datetime.fromisoformat(r["time"].replace("Z", "+00:00"))
    key = {"email sent": "enviado", "email opened": "aberto", "clicked link": "clicou",
           "submitted data": "enviou_dados", "email reported": "reportou"}.get(m)
    if key and key not in ev[r["email"]]:
        ev[r["email"]][key] = t
n = sum(1 for e in ev.values() if "enviado" in e)
res = {"enviados": n}
for k in ("aberto", "clicou", "enviou_dados", "reportou"):
    c = sum(1 for e in ev.values() if k in e)
    res[k] = {"quantidade": c, "percentual": round(100 * c / n, 1) if n else 0}
tempos = [(e["reportou"] - e["enviado"]).total_seconds() for e in ev.values() if "reportou" in e and "enviado" in e]
res["tempo_medio_ate_reporte_s"] = round(sum(tempos) / len(tempos), 1) if tempos else None
print(json.dumps(res, indent=2, ensure_ascii=False))
