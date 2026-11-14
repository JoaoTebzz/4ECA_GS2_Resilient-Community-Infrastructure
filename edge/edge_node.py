"""No de borda de um espaco comunitario.
- recebe leituras dos sensores (MQTT local no real; aqui por chamada de funcao)
- aplica regras LOCAIS (alarme da camara fria, limite da bomba) sem depender da nuvem
- guarda tudo num buffer SQLite (store-and-forward)
- quando o link volta, envia em lotes; a nuvem ignora repetidos (chave device+seq)
"""
import sqlite3, json, time, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "panel"))
import common as c

TEMP_MAX = 8.0          # camara fria de vacinas: acima disso e problema (faixa segura 2 a 8 C)
TEMP_LEITURAS = 3       # leituras seguidas fora da faixa para disparar
NIVEL_MIN, NIVEL_MAX = 20.0, 90.0


class Cloud:
    """Nuvem simulada: guarda leituras unicas e conta repetidas."""
    def __init__(self):
        self.seen = {}
        self.duplicates = 0
        self.alerts_received = []

    def receive(self, batch):
        acked = []
        for r in batch:
            k = (r["device"], r["seq"])
            if k in self.seen:
                self.duplicates += 1
            else:
                self.seen[k] = r
            acked.append(r["id"])
        return acked


class EdgeNode:
    def __init__(self, space, cloud, link_up, clock, path=":memory:", batch=500):
        self.space, self.cloud, self.link_up, self.clock, self.batch = space, cloud, link_up, clock, batch
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS buf(id INTEGER PRIMARY KEY AUTOINCREMENT, device TEXT, seq INTEGER,"
                        " ts REAL, metric TEXT, value REAL, sent INTEGER DEFAULT 0)")
        self.seq = {}
        self.hot = 0
        self.alarm_since = None
        self.pump_on = False
        self.local_actions = []   # (t, acao)
        self.queued_sms = []

    # ---- entrada de leituras ----
    def ingest(self, device, metric, value):
        self.seq[device] = self.seq.get(device, 0) + 1
        t = self.clock()
        self.db.execute("INSERT INTO buf(device,seq,ts,metric,value) VALUES(?,?,?,?,?)",
                        (device, self.seq[device], t, metric, value))
        self.rules(device, metric, value, t)

    # ---- regras locais (nao dependem da nuvem) ----
    def rules(self, device, metric, value, t):
        if metric == "temp_camara_fria":
            self.hot = self.hot + 1 if value > TEMP_MAX else 0
            if self.hot >= TEMP_LEITURAS and self.alarm_since is None:
                self.alarm_since = t
                self.local_actions.append((t, "ALARME_LOCAL_CAMARA_FRIA"))
                self.queued_sms.append((t, "Camara fria da UBS acima de 8 C"))
            if value <= TEMP_MAX and self.alarm_since is not None:
                self.local_actions.append((t, "ALARME_LOCAL_ENCERRADO"))
                self.alarm_since = None
        elif metric == "nivel_reservatorio":
            if value < NIVEL_MIN and not self.pump_on:
                self.pump_on = True
                self.local_actions.append((t, "BOMBA_LIGAR_NIVEL_BAIXO"))
            elif value > NIVEL_MAX and self.pump_on:
                self.pump_on = False
                self.local_actions.append((t, "BOMBA_DESLIGAR_NIVEL_ALTO"))

    # ---- sincronizacao ----
    def pending(self):
        return self.db.execute("SELECT COUNT(*) FROM buf WHERE sent=0").fetchone()[0]

    def sync(self, max_batches=None, ack_loss=0.0, rnd=None):
        """Tenta enviar. ack_loss simula o ack se perdendo (o lote chega, mas o no nao sabe)."""
        if not self.link_up():
            return 0
        sent_total, n = 0, 0
        while True:
            rows = self.db.execute("SELECT id,device,seq,ts,metric,value FROM buf WHERE sent=0 ORDER BY id LIMIT ?",
                                   (self.batch,)).fetchall()
            if not rows:
                break
            batch = [dict(id=r[0], device=r[1], seq=r[2], ts=r[3], metric=r[4], value=r[5]) for r in rows]
            acked = self.cloud.receive(batch)
            if rnd is not None and rnd.random() < ack_loss:
                acked = []        # ack perdido: o no vai reenviar, a nuvem descarta o repetido
            if acked:
                self.db.executemany("UPDATE buf SET sent=1 WHERE id=?", [(i,) for i in acked])
                sent_total += len(acked)
            n += 1
            if max_batches and n >= max_batches:
                break
            if not acked:
                break
        self.db.commit()
        return sent_total
