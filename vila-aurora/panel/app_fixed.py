"""PAINEL CORRIGIDO. Mesmas funcoes do legado, com os controles do RT-08 e RT-09:
 - consultas parametrizadas
 - validacao de entrada no servidor (lista de caracteres permitidos + tamanho)
 - conexao SOMENTE LEITURA para buscas (privilegio minimo)
 - erro generico com codigo de ocorrencia (detalhe fica so no log)
 - senha com scrypt + sal, MFA (TOTP) e perfis (RBAC)
 - camada extra: filtro tipo WAF (defesa em profundidade) e cabecalhos de seguranca
 - privacidade: nomes aparecem mascarados para o perfil auditor e o log usa pseudonimo
"""
import os, re, sqlite3, uuid, hmac, hashlib, secrets
from functools import wraps
from flask import Flask, request, session, jsonify, abort, make_response
import common as c

DB = os.environ.get("VA_DB_FIX", os.path.join(c.BASE, "vila_fix.db"))
PSEUDO_KEY = os.environ.get("VA_PSEUDO_KEY") or secrets.token_hex(16)   # sem valor fixo no codigo
PSEUDO_KEY = PSEUDO_KEY.encode()
app = Flask(__name__)
app.secret_key = os.environ.get("VA_SECRET") or secrets.token_hex(16)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

PERMITIDO = re.compile(r"^[A-Za-zÀ-ÿ .'-]{0,40}$")
WAF = re.compile(r"(union\s+select|--|;|/\*|\bor\b\s+['\d]|sqlite_master|information_schema|sleep\s*\()", re.I)
PERMISSOES = {
    "operador": {"ver_historico"},
    "tecnico": {"ver_historico", "alterar_bomba"},
    "coordenacao": {"ver_historico", "alterar_bomba", "gerir_usuarios"},
    "auditor": {"ver_historico_mascarado"},
}


def ro():
    return sqlite3.connect(f"file:{DB}?mode=ro", uri=True)


def rw():
    return sqlite3.connect(DB)


def pseudo(txt):
    return hmac.new(PSEUDO_KEY, txt.encode(), hashlib.sha256).hexdigest()[:10]


def precisa(perm):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if "user" not in session:
                abort(401)
            if perm not in PERMISSOES.get(session["role"], set()) and not (
                    perm == "ver_historico" and "ver_historico_mascarado" in PERMISSOES.get(session["role"], set())):
                c.log_event("web", app="corrigido", event="acesso_negado", user=pseudo(session["user"]), perm=perm)
                abort(403)
            return f(*a, **k)
        return w
    return deco


@app.before_request
def _log_e_waf():
    c.log_event("web", app="corrigido", src=request.remote_addr, method=request.method,
                path=request.path, query=request.query_string.decode(errors="replace"))
    texto = request.query_string.decode(errors="replace")
    if WAF.search(texto):
        c.log_event("web", app="corrigido", event="waf_bloqueio", src=request.remote_addr, query=texto)
        abort(403)


@app.after_request
def _cab(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.errorhandler(Exception)
def _erro(e):
    code = getattr(e, "code", 500)
    if code == 500 or not isinstance(code, int):
        oc = uuid.uuid4().hex[:8]
        c.log_event("web", app="corrigido", event="erro_interno", ocorrencia=oc, detalhe=repr(e))
        return jsonify(erro="Algo deu errado. Informe o codigo da ocorrencia.", ocorrencia=oc), 500
    return jsonify(erro="Pedido nao permitido." if code == 403 else "Acesso nao autorizado." if code == 401 else "Pedido invalido."), code


@app.route("/login", methods=["POST"])
def login():
    u, p, otp = request.form.get("usuario", ""), request.form.get("senha", ""), request.form.get("codigo", "")
    row = ro().execute("SELECT pw_hash, salt, role, totp_secret FROM operators WHERE username=?", (u,)).fetchone()
    ok = False
    if row:
        h = c.hash_scrypt(p, bytes.fromhex(row[1]))
        ok = hmac.compare_digest(h, row[0]) and c.totp_ok(row[3], otp)
    if ok:
        session["user"], session["role"] = u, row[2]
        c.log_event("web", app="corrigido", event="login_ok", user=pseudo(u), src=request.remote_addr, mfa=True)
        return jsonify(ok=True)
    c.log_event("web", app="corrigido", event="login_fail", user=pseudo(u), src=request.remote_addr)
    return jsonify(ok=False, erro="Usuario, senha ou codigo incorretos."), 401


@app.route("/historico")
@precisa("ver_historico")
def historico():
    q = request.args.get("q", "")
    if not PERMITIDO.match(q):
        return jsonify(erro="Use so letras, espaco, ponto e hifen (ate 40)."), 400
    rows = ro().execute(
        "SELECT a.ts, u.name, a.space, a.result FROM access_log a JOIN users u ON u.id=a.user_id "
        "WHERE u.name LIKE ? ORDER BY a.ts DESC LIMIT 50", (f"%{q}%",)).fetchall()
    if session["role"] == "auditor":
        rows = [(t, n.split()[0][0] + "***", s, r) for t, n, s, r in rows]
    return jsonify(rows=rows)


@app.route("/bomba", methods=["POST"])
@precisa("alterar_bomba")
def bomba():
    pump = request.form.get("bomba", "")
    try:
        ini, fim = int(request.form["inicio"]), int(request.form["fim"])
    except Exception:
        abort(400)
    if pump not in ("bomba_escola", "bomba_abrigo") or not (0 <= ini < fim <= 24):
        abort(400)
    db = rw()
    db.execute("UPDATE schedule SET start_h=?, end_h=? WHERE pump=?", (ini, fim, pump))
    db.commit()
    c.log_event("actuator", cmd="schedule", pump=pump, start=ini, end=fim, by=pseudo(session["user"]), via="painel")
    return jsonify(ok=True)


@app.route("/")
def inicio():
    html = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><title>Rede Vila Aurora</title>
<style>body{font:18px/1.5 sans-serif;color:#111;background:#fff;max-width:40rem;margin:1rem auto;padding:0 1rem}
a.pular{position:absolute;left:-999px}a.pular:focus{left:0;background:#ff0;color:#000}
label{display:block;margin-top:.8rem}input,button{font-size:1rem;padding:.5rem;min-height:44px}
button{background:#0b4f8a;color:#fff;border:0;border-radius:4px}:focus{outline:3px solid #0b4f8a;outline-offset:2px}</style></head>
<body><a class="pular" href="#conteudo">Pular para o conteudo</a><header><h1>Rede Vila Aurora</h1></header>
<main id="conteudo"><h2>Entrar</h2><form method="post" action="/login">
<label for="u">Usuario</label><input id="u" name="usuario" autocomplete="username">
<label for="s">Senha</label><input id="s" name="senha" type="password" autocomplete="current-password">
<label for="o">Codigo do aplicativo (6 numeros)</label><input id="o" name="codigo" inputmode="numeric" autocomplete="one-time-code">
<p><button type="submit">Entrar</button></p></form></main></body></html>"""
    return make_response(html)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5002)
