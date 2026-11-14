"""PAINEL LEGADO (VULNERAVEL). Reproduz o painel do incidente INC-VA-0712.
NAO usar fora do laboratorio. Falhas de proposito:
 - consulta montada com texto (SQL Injection) no historico de acessos
 - login so com senha (sem MFA), hash sem sal
 - mensagem de erro mostra a consulta
 - o app usa um usuario de banco com poder total
"""
import os, sqlite3
from flask import Flask, request, session, jsonify, redirect
import common as c

DB = os.environ.get("VA_DB_VULN", os.path.join(c.BASE, "vila_vuln.db"))
app = Flask(__name__)
app.secret_key = os.environ.get("VA_SECRET") or __import__("secrets").token_hex(8)


def conn():
    return sqlite3.connect(DB)


def run_multi(db, sql):
    """Imita drivers com multi-statement ligado (ex.: MySQL allowMultiQueries): roda varias
    instrucoes separadas por ';' e devolve as linhas da ultima. Isso permite consulta empilhada."""
    rows = []
    for part in sql.split(";"):
        if part.strip():
            rows = db.execute(part).fetchall()
    return rows


@app.before_request
def _log():
    c.log_event("web", app="legado", src=request.remote_addr, method=request.method,
                path=request.path, query=request.query_string.decode(errors="replace"))


@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("usuario", "")
    p = request.form.get("senha", "")
    row = conn().execute("SELECT role FROM operators WHERE username=? AND pw_hash=?", (u, c.hash_legacy(p))).fetchone()
    if row:
        session["user"], session["role"] = u, row[0]
        c.log_event("web", app="legado", event="login_ok", user=u, src=request.remote_addr, mfa=False)
        return jsonify(ok=True)
    c.log_event("web", app="legado", event="login_fail", user=u, src=request.remote_addr)
    return jsonify(ok=False), 401


@app.route("/historico")
def historico():
    q = request.args.get("q", "")
    db = conn()
    sql = None
    try:
        # auditoria da busca (o "escape" ingenuo era comum em codigo legado)
        db.execute("INSERT INTO search_audit(ts, term) VALUES(?,?)", (c.iso(), q.replace("'", "''")))
        db.commit()
        # FALHA 1: SELECT montado com texto
        sql = ("SELECT a.ts, u.name, a.space, a.result FROM access_log a "
               f"JOIN users u ON u.id = a.user_id WHERE u.name LIKE '%{q}%' ORDER BY a.ts DESC LIMIT 50")
        rows = run_multi(db, sql)
        db.commit()
        return jsonify(rows=rows)
    except Exception as e:
        # FALHA 2: devolve detalhes do erro e a consulta
        return jsonify(erro=str(e), consulta=sql), 500
    finally:
        db.close()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)
