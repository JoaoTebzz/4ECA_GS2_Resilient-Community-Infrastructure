"""Teste de SQL Injection antes e depois (E3 / RT-08).
Roda os mesmos ataques contra o painel legado e o corrigido e salva results/sqli.json.
Ambiente isolado, dados sinteticos."""
import os, sys, json, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "panel"))
tmp = tempfile.mkdtemp()
os.environ["VA_LOGS"] = os.path.join(tmp, "logs")
os.environ["VA_DB_VULN"] = os.path.join(tmp, "v.db")
os.environ["VA_DB_FIX"] = os.path.join(tmp, "f.db")
import common as c
c.make_db(os.environ["VA_DB_VULN"], legacy=True)
c.make_db(os.environ["VA_DB_FIX"], legacy=False)
import app_vulnerable as V
import app_fixed as F

ATAQUES = {
    "booleano": "x%' OR 1=1 --",
    "union_usuarios": "zzz' UNION SELECT id, email, phone, kind FROM users --",
    "union_operadores": "zzz' UNION SELECT username, pw_hash, role, totp_secret FROM operators --",
    "erro_revela_sql": "'",
    "empilhada_altera_bomba": "x%'; UPDATE schedule SET enabled=0 WHERE pump='bomba_escola'; --",
}
res = {"legado": {}, "corrigido": {}}

# legado: entra so com senha
cv = V.app.test_client()
cv.post("/login", data={"usuario": "op1", "senha": "Horta2026"})
for nome, p in ATAQUES.items():
    r = cv.get("/historico", query_string={"q": p}, environ_overrides={"REMOTE_ADDR": "203.0.113.77"})
    j = r.get_json(silent=True) or {}
    res["legado"][nome] = {"status": r.status_code, "linhas": len(j.get("rows", [])), "vazou_erro": "consulta" in j,
                          "amostra": (j.get("rows") or [None])[0] if j.get("rows") else j.get("erro")}
import sqlite3
res["legado"]["bomba_escola_enabled_depois"] = sqlite3.connect(os.environ["VA_DB_VULN"]).execute(
    "SELECT enabled FROM schedule WHERE pump='bomba_escola'").fetchone()[0]

# corrigido: login com MFA correto
cf = F.app.test_client()
sec = sqlite3.connect(os.environ["VA_DB_FIX"]).execute("SELECT totp_secret FROM operators WHERE username='op1'").fetchone()[0]
rl = cf.post("/login", data={"usuario": "op1", "senha": "Horta2026", "codigo": c.totp(sec)})
res["corrigido"]["login_com_mfa"] = rl.status_code
bad = F.app.test_client().post("/login", data={"usuario": "op1", "senha": "Horta2026", "codigo": "000000"})
res["corrigido"]["login_sem_mfa_correto"] = bad.status_code
for nome, p in ATAQUES.items():
    r = cf.get("/historico", query_string={"q": p}, environ_overrides={"REMOTE_ADDR": "203.0.113.77"})
    j = r.get_json(silent=True) or {}
    res["corrigido"][nome] = {"status": r.status_code, "linhas": len(j.get("rows", [])), "vazou_erro": "consulta" in j,
                             "resposta": j.get("erro")}
res["corrigido"]["bomba_escola_enabled_depois"] = sqlite3.connect(os.environ["VA_DB_FIX"]).execute(
    "SELECT enabled FROM schedule WHERE pump='bomba_escola'").fetchone()[0]

# camada de aplicacao SEM o filtro WAF, para provar que a parametrizacao sozinha ja resolve a causa raiz
F.WAF = __import__("re").compile(r"(?!x)x")
cf2 = F.app.test_client()
cf2.post("/login", data={"usuario": "op1", "senha": "Horta2026", "codigo": c.totp(sec)})
res["corrigido_sem_waf"] = {}
for nome, p in ATAQUES.items():
    r = cf2.get("/historico", query_string={"q": p})
    res["corrigido_sem_waf"][nome] = {"status": r.status_code, "linhas": len((r.get_json(silent=True) or {}).get("rows", []))}

# so a parametrizacao: desliga WAF e validacao para provar que a causa raiz foi resolvida
F.PERMITIDO = __import__("re").compile(r"^.*$", __import__("re").S)
cf3 = F.app.test_client()
cf3.post("/login", data={"usuario": "op1", "senha": "Horta2026", "codigo": c.totp(sec)})
res["so_parametrizacao"] = {}
for nome, p in ATAQUES.items():
    r = cf3.get("/historico", query_string={"q": p})
    j = r.get_json(silent=True) or {}
    res["so_parametrizacao"][nome] = {"status": r.status_code, "linhas": len(j.get("rows", [])), "vazou_erro": "consulta" in j}
res["so_parametrizacao"]["bomba_escola_enabled_depois"] = sqlite3.connect(os.environ["VA_DB_FIX"]).execute(
    "SELECT enabled FROM schedule WHERE pump='bomba_escola'").fetchone()[0]
F.PERMITIDO = __import__("re").compile(r"^[A-Za-zÀ-ÿ .'-]{0,40}$")

# funcao normal continua funcionando
r = cf2.get("/historico", query_string={"q": "Ana"})
res["corrigido"]["busca_normal_Ana"] = {"status": r.status_code, "linhas": len(r.get_json()["rows"])}
r = cf2.get("/historico", query_string={"q": "O'Neil"})
res["corrigido"]["busca_com_apostrofo_legitimo"] = {"status": r.status_code}

os.makedirs(os.path.join(os.path.dirname(__file__), "..", "results"), exist_ok=True)
out = os.path.join(os.path.dirname(__file__), "..", "results", "sqli.json")
json.dump(res, open(out, "w"), indent=2, ensure_ascii=False)
print(json.dumps(res, indent=2, ensure_ascii=False))
