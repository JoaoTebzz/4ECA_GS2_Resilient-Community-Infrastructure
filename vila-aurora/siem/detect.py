"""Motor de deteccao simples (stand-in do Wazuh para o laboratorio). Le os logs JSON em logs/
e aplica as 4 regras do RT-13:
  A  login VPN anomalo (sem MFA, IP fora da lista ou fora do horario)
  B  padrao de SQL Injection nas requisicoes web
  C  dispositivo sem certificado valido (handshake falhou ou CN desconhecido)
  D  comando de atuador fora do horario ou do perfil
Cada alerta vai para logs/alerts.log e chama o SOAR (callback)."""
import os, re, json, sys, time, datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "panel"))
import common as c

CFG = {
    "vpn_ips_permitidos": ["198.51.100.10", "198.51.100.11"],   # IPs conhecidos de tecnicos (fictícios)
    "vpn_horario_ok": [6, 22],                                   # horas UTC (laboratorio)
    "dispositivos_validos": ["sensor-ubs-temp01", "sensor-escola-nivel01", "sensor-abrigo-alag01",
                             "fechadura-centro01", "rele-bomba-escola01"],
    "atuador_horario_ok": [6, 20],
    "atuador_origens_ok": ["painel", "regra_local"],
}
SQLI = re.compile(r"(union(\s|\+|%20)+select|('|%27)\s*(or|and)\s|\bor\b\s*1\s*=\s*1|--|%2d%2d|;|sqlite_master|information_schema"
                  r"|sleep\s*\(|benchmark\s*\(|%27)", re.I)


def parse_ts(s):
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc)


class Detector:
    def __init__(self, logdir, on_alert=None, cfg=None):
        self.logdir, self.on_alert, self.cfg = logdir, on_alert, cfg or CFG
        self.pos = {}
        self.alerts = []

    def alert(self, rule, rec, desc, **extra):
        a = {"ts": c.iso(), "rule": rule, "descricao": desc, "evento_ts": rec["ts"], "fonte": rec["source"], **extra}
        self.alerts.append(a)
        c.log_event("alerts", **{k: v for k, v in a.items() if k != "ts"})
        if self.on_alert:
            try:
                self.on_alert(a, rec)
            except Exception as e:      # o detector nao pode morrer por erro na resposta
                c.log_event("soar", erro=repr(e), regra=rule)

    # ---- regras ----
    def rule_a(self, r):
        if r.get("source") != "vpn" or r.get("event") != "auth_success":
            return
        h = parse_ts(r["ts"]).hour
        lo, hi = self.cfg["vpn_horario_ok"]
        motivos = []
        if r.get("mfa") in (None, "none", False):
            motivos.append("sem MFA")
        if r.get("src") not in self.cfg["vpn_ips_permitidos"]:
            motivos.append("IP fora da lista")
        if not (lo <= h < hi):
            motivos.append("fora do horario")
        if motivos:
            self.alert("A_VPN_LOGIN_ANOMALO", r, "Login VPN anomalo: " + ", ".join(motivos), user=r.get("user"), src=r.get("src"))

    def rule_b(self, r):
        if r.get("source") != "web" or "query" not in r:
            return
        if SQLI.search(r.get("query", "")):
            self.alert("B_SQL_INJECTION", r, "Padrao de SQL Injection na requisicao", src=r.get("src"), path=r.get("path"))

    def rule_c(self, r):
        if r.get("source") != "mqtt" or r.get("event") != "tls_handshake":
            return
        if r.get("result") == "fail" or r.get("cn") not in self.cfg["dispositivos_validos"]:
            self.alert("C_DISPOSITIVO_SEM_CERT_VALIDO", r, "Dispositivo sem certificado valido", src=r.get("src"), cn=r.get("cn"))

    def rule_d(self, r):
        if r.get("source") != "actuator" or r.get("cmd") is None:
            return
        h = parse_ts(r["ts"]).hour
        lo, hi = self.cfg["atuador_horario_ok"]
        motivos = []
        if not (lo <= h < hi):
            motivos.append("fora do horario")
        if r.get("via") not in self.cfg["atuador_origens_ok"]:
            motivos.append("origem fora do perfil (" + str(r.get("via")) + ")")
        if motivos:
            self.alert("D_ATUADOR_FORA_DO_PERFIL", r, "Comando de atuador suspeito: " + ", ".join(motivos), pump=r.get("pump"), via=r.get("via"))

    def process(self, rec):
        for f in (self.rule_a, self.rule_b, self.rule_c, self.rule_d):
            f(rec)

    # ---- leitura incremental dos arquivos ----
    def scan(self):
        n = 0
        for fn in sorted(os.listdir(self.logdir)):
            if not fn.endswith(".log") or fn in ("alerts.log", "soar.log"):
                continue
            p = os.path.join(self.logdir, fn)
            with open(p, "r", encoding="utf-8") as f:
                f.seek(self.pos.get(fn, 0))
                for line in f:
                    if not line.endswith("\n"):
                        break
                    try:
                        self.process(json.loads(line))
                        n += 1
                    except json.JSONDecodeError:
                        pass
                self.pos[fn] = f.tell()
        return n

    def follow(self, interval=0.5, stop=lambda: False):
        while not stop():
            self.scan()
            time.sleep(interval)
