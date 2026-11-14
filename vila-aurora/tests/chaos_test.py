"""Teste de caos (E3 / RT-23 e RT-22): derruba o WAN por 30 min e mede continuidade e reconciliacao.
Por padrao usa relogio VIRTUAL (roda em segundos). Para o teste de verdade em tempo real:
    python3 tests/chaos_test.py --real          (leva ~37 min)
Salva results/chaos.json."""
import os, sys, json, time, random, resource, tracemalloc
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, os.path.join(ROOT, "edge"))
sys.path.insert(0, os.path.join(ROOT, "panel"))
from edge_node import EdgeNode, Cloud

REAL = "--real" in sys.argv
DUR_TOTAL, WAN_INI, WAN_FIM = 37 * 60, 3 * 60, 33 * 60   # 3 min normal, 30 min sem WAN, 4 min depois
FALHA_CAMARA = 13 * 60                                   # a camara fria "quebra" no minuto 13 (dentro da queda)
rnd = random.Random(7)

state = {"t": 0.0}
clock = (lambda: time.time()) if REAL else (lambda: state["t"])
t_start = clock()
wan_up = lambda: not (WAN_INI <= (clock() - t_start) < WAN_FIM)
cloud = Cloud()
edge = EdgeNode("UBS", cloud, wan_up, clock)

# linha de base: sistema antigo, que dependia da nuvem para gerar alerta
legacy_alerts, legacy_hot, legacy_pending = [], 0, []

produced = 0
tracemalloc.start()
cpu0 = time.process_time()
wall0 = time.time()
sync_times = []
t_back = None
last_offline_alarm = None

for sec in range(DUR_TOTAL):
    if REAL:
        time.sleep(1.0)
    else:
        state["t"] = float(sec)
    rel = clock() - t_start
    camara_ruim = rel >= FALHA_CAMARA
    temp = 4.5 + rnd.gauss(0, 0.3) + (6.0 if camara_ruim else 0)
    nivel = 60 + 25 * ((sec % 1200) / 1200 - 0.5) + rnd.gauss(0, 0.5)
    power = 800 + rnd.gauss(0, 30)
    for dev, met, val in (("sensor-ubs-temp01", "temp_camara_fria", temp),
                          ("sensor-escola-nivel01", "nivel_reservatorio", nivel),
                          ("medidor-energia01", "potencia_w", power),
                          ("sensor-abrigo-alag01", "alagamento", 0.0)):
        edge.ingest(dev, met, val)
        produced += 1
        # sistema legado: so alerta se a nuvem estiver acessivel
        if met == "temp_camara_fria":
            legacy_hot = legacy_hot + 1 if val > 8.0 else 0
            if legacy_hot >= 3 and wan_up() and not legacy_alerts:
                legacy_alerts.append(rel)
    # tenta sincronizar a cada 10 s; apos a volta do WAN, simula 20% de acks perdidos nos primeiros lotes
    if sec % 10 == 0 and wan_up():
        t0 = time.perf_counter()
        edge.sync(ack_loss=0.2 if (rel >= WAN_FIM and rel < WAN_FIM + 60) else 0.0, rnd=rnd)
        dt = time.perf_counter() - t0
        if rel >= WAN_FIM and t_back is None and dt > 0:
            t_back = rel
        if rel >= WAN_FIM:
            sync_times.append((rel, dt, edge.pending()))

edge.sync()          # sincronizacao final
cur, peak = tracemalloc.get_traced_memory()
cpu = time.process_time() - cpu0
wall = time.time() - wall0

alarmes = [(a[0] - t_start, a[1]) for a in edge.local_actions if a[1].startswith("ALARME_LOCAL_CAMARA")]
res = {
    "modo": "tempo real" if REAL else "relogio virtual (acelerado)",
    "duracao_total_min": DUR_TOTAL / 60,
    "wan_fora_min": (WAN_FIM - WAN_INI) / 60,
    "leituras_produzidas": produced,
    "leituras_unicas_na_nuvem": len(cloud.seen),
    "perda_na_reconciliacao": produced - len(cloud.seen),
    "perda_percentual": round(100 * (produced - len(cloud.seen)) / produced, 4),
    "repetidos_descartados_pela_nuvem": cloud.duplicates,
    "pendentes_no_buffer_no_fim": edge.pending(),
    "camara_fria_falha_no_minuto": FALHA_CAMARA / 60,
    "alarme_local_no_minuto": round(alarmes[0][0] / 60, 2) if alarmes else None,
    "atraso_do_alarme_local_s": round(alarmes[0][0] - FALHA_CAMARA, 1) if alarmes else None,
    "alarme_no_sistema_legado": "so apos o WAN voltar (minuto %.1f)" % (legacy_alerts[0] / 60) if legacy_alerts else "nunca durante a queda",
    "operacao_autonoma_min": (WAN_FIM - WAN_INI) / 60,
    "acoes_locais_durante_queda": sum(1 for a in edge.local_actions if WAN_INI <= a[0] - t_start < WAN_FIM),
    "sms_na_fila_para_enviar_quando_der": len(edge.queued_sms),
    "tempo_para_esvaziar_buffer_s_cpu": round(max([s[1] for s in sync_times] + [0]), 4),
    "cpu_segundos_processo": round(cpu, 2),
    "memoria_pico_python_kb": round(peak / 1024, 1),
    "ram_max_processo_mb": round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024, 1),
    "tempo_real_do_teste_s": round(wall, 1),
}
os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
out = "chaos_real.json" if REAL else "chaos.json"
json.dump(res, open(os.path.join(ROOT, "results", out), "w"), indent=2, ensure_ascii=False)
print(json.dumps(res, indent=2, ensure_ascii=False))
