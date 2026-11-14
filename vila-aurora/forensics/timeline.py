"""Linha do tempo consolidada (RT-14). Junta todos os logs do cofre, corrige o relogio das fontes
que estavam desajustadas (ajuste da cadeia de custodia) e marca cada evento com a tecnica MITRE ATT&CK.
Uso: python3 forensics/timeline.py <cofre> <saida.csv>"""
import os, sys, json, csv, re, datetime, hashlib

ATTACK = {
    "phishing_entregue": ("T1566.002", "Phishing: Spearphishing Link", "Acesso inicial"),
    "phishing_clique": ("T1566.002", "Phishing: Spearphishing Link", "Acesso inicial"),
    "phishing_credencial": ("T1056.003", "Input Capture: Web Portal Capture (pagina falsa)", "Credential Access"),
    "vpn_login": ("T1133", "External Remote Services (VPN legada sem MFA)", "Acesso inicial / Persistencia"),
    "contas_validas": ("T1078", "Valid Accounts (conta roubada)", "Defense Evasion / Acesso inicial"),
    "sqli_sonda": ("T1190", "Exploit Public-Facing Application (SQL Injection)", "Acesso inicial"),
    "sqli_dump": ("T1213", "Data from Information Repositories", "Collection"),
    "sqli_altera": ("T1565.001", "Data Manipulation: Stored Data Manipulation", "Impact"),
    "bomba": ("T0836", "ICS: Modify Parameter (agenda da bomba)", "Impact (ICS)"),
    "nivel_baixo": ("T0826", "ICS: Loss of Availability (reservatorio vazio)", "Impact (ICS)"),
    "wan": ("-", "Falha de infraestrutura (nao e tecnica do atacante)", "Contexto"),
    "camara": ("T0826", "ICS: Loss of Availability (alerta nao saiu, camara fora da faixa)", "Impact (ICS)"),
}


def pts(s):
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=datetime.timezone.utc)


def classify(r):
    s = r["source"]
    q = r.get("query", "") or ""
    if s == "mail" and r.get("event") == "delivered":
        return "phishing_entregue", "E-mail falso entregue a coord1 (SPF fail, sem DKIM, sem DMARC)"
    if s == "proxy" and r.get("event") == "http_get":
        return "phishing_clique", "Estacao da coordenadora abriu a pagina falsa"
    if s == "proxy" and r.get("event") == "http_post":
        return "phishing_credencial", "Formulario enviado para a pagina falsa (credenciais)"
    if s == "vpn" and r.get("event") == "auth_success":
        return "vpn_login", f"Login na VPN com senha, sem MFA, vindo de {r.get('src')} (usuario {r.get('user')})"
    if s == "web" and r.get("event") == "login_ok":
        return "contas_validas", f"Login no painel legado como {r.get('user')} vindo de {r.get('src')}"
    if s == "web" and r.get("path") == "/historico":
        if re.search(r"update(\+|%20|\s)", q, re.I):
            return "sqli_altera", "SQL Injection empilhada alterando a agenda da bomba"
        if re.search(r"union(\+|%20|\s)+select", q, re.I):
            alvo = "operadores (senhas)" if "operators" in q else "usuarios (dados pessoais)"
            return "sqli_dump", f"SQL Injection UNION extraindo tabela de {alvo}"
        if re.search(r"('|%27|--|%2d)", q):
            return "sqli_sonda", "Sondagem de SQL Injection no campo de busca"
    if s == "actuator" and r.get("cmd") == "schedule":
        return "bomba", f"Borda aplicou agenda {r.get('start')}h a {r.get('end')}h na {r.get('pump')} (origem {r.get('via')})"
    if s == "edge" and r.get("event") == "wan_down":
        return "wan", "Fibra caiu; alertas da UBS dependiam da nuvem"
    return None, None


def main(vault, out):
    ajustes = {}
    for row in csv.DictReader(open(os.path.join(vault, "cadeia_de_custodia.csv"), encoding="utf-8")):
        ajustes[row["arquivo"].replace(".log", "")] = int(row["ajuste_relogio_s"] or 0)
    ev, nivel_zero, camara = [], False, False
    for fn in sorted(os.listdir(vault)):
        if not fn.endswith(".log"):
            continue
        src = fn[:-4]
        for line in open(os.path.join(vault, fn), encoding="utf-8"):
            r = json.loads(line)
            r["ts_original"] = r["ts"]
            t = pts(r["ts"]) - datetime.timedelta(seconds=ajustes.get(src, 0))
            r["ts_corrigido"] = t
            if r["source"] == "telemetry":
                if r["metric"] == "nivel_reservatorio" and r["value"] <= 10 and not nivel_zero:
                    nivel_zero = True
                    ev.append((t, r, "nivel_baixo", f"Reservatorio da escola chegou a {r['value']}%"))
                if r["metric"] == "temp_camara_fria" and r["value"] > 8.0 and not camara:
                    camara = True
                    ev.append((t, r, "camara", f"Camara fria da UBS passou de 8 C ({r['value']} C) e ninguem foi avisado"))
                continue
            k, d = classify(r)
            if k:
                ev.append((t, r, k, d))
    ev.sort(key=lambda x: x[0])
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["n", "hora_utc_corrigida", "hora_no_log", "fonte", "evento", "tecnica_attack", "nome_tecnica", "tatica"])
        for i, (t, r, k, d) in enumerate(ev, 1):
            tid, nome, tat = ATTACK[k]
            w.writerow([i, t.strftime("%Y-%m-%dT%H:%M:%SZ"), r["ts_original"], r["source"], d, tid, nome, tat])
    h = hashlib.sha256(open(out, "rb").read()).hexdigest()
    print(f"{len(ev)} eventos na linha do tempo. SHA-256 da linha do tempo: {h}")
    return ev, h


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
