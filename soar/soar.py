"""Respostas automatizadas (RT-15). Duas classes de acao:
  BAIXO RISCO  -> roda sozinha (isolar dispositivo, revogar cert, derrubar sessao VPN, bloquear IP, modo seguro)
  ALTO IMPACTO -> so cria um pedido de aprovacao; um humano precisa aprovar (desligar bomba, liberar portas)
Tudo grava em logs/soar.log. Em producao os "efeitos" abaixo viram chamadas ao firewall/WireGuard/CA."""
import os, sys, json, uuid, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "panel"))
import common as c

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
STATE = os.environ.get("VA_STATE", os.path.join(ROOT, "state"))
PKI = os.environ.get("VA_PKI", os.path.join(ROOT, "pki", "out"))


def _append(name, line):
    os.makedirs(STATE, exist_ok=True)
    with open(os.path.join(STATE, name), "a") as f:
        f.write(line + "\n")


# ---------- baixo risco ----------
def block_ip(src=None, **_):
    _append("blocklist.txt", str(src))      # real: nft add element inet filter blocklist { ip }


def kill_vpn_session(user=None, src=None, **_):
    _append("vpn_revoked_sessions.txt", f"{user}|{src}")   # real: wg set wg0 peer <key> remove


def isolate_device(cn=None, src=None, **_):
    _append("isolated_devices.txt", f"{cn}|{src}")         # real: mover para VLAN/segmento de quarentena


def revoke_cert(cn=None, **_):
    if cn and os.path.exists(os.path.join(PKI, "devices", f"{cn}.crt")):
        subprocess.run([os.path.join(ROOT, "pki", "revoke.sh"), cn, PKI], check=True, capture_output=True)
    else:
        _append("revoke_skipped.txt", str(cn))


def safe_mode(pump=None, **_):
    # modo seguro = o no de borda ignora agendamento remoto e usa so as regras locais de nivel
    _append("safe_mode.txt", str(pump))


BAIXO = {"block_ip": block_ip, "kill_vpn_session": kill_vpn_session, "isolate_device": isolate_device,
         "revoke_cert": revoke_cert, "safe_mode": safe_mode}
ALTO = {"desligar_bomba", "liberar_todas_as_portas", "desativar_vpn_do_site"}

PLAYBOOK = {
    "A_VPN_LOGIN_ANOMALO": [("kill_vpn_session", ["user", "src"]), ("block_ip", ["src"])],
    "B_SQL_INJECTION": [("block_ip", ["src"])],
    "C_DISPOSITIVO_SEM_CERT_VALIDO": [("isolate_device", ["cn", "src"]), ("revoke_cert", ["cn"])],
    "D_ATUADOR_FORA_DO_PERFIL": [("safe_mode", ["pump"])],
}
# regras que, alem do automatico, pedem decisao humana sobre acao de alto impacto
PEDIDO_HUMANO = {"D_ATUADOR_FORA_DO_PERFIL": ("desligar_bomba", "Bomba com agenda alterada fora do perfil. Desligar a bomba?")}


def pend_dir():
    d = os.path.join(STATE, "approvals", "pending")
    os.makedirs(d, exist_ok=True)
    return d


def run_action(name, **kw):
    if name in ALTO:
        raise PermissionError(f"{name} e de alto impacto: precisa de aprovacao humana")
    BAIXO[name](**kw)
    c.log_event("soar", acao=name, risco="baixo", modo="automatico", args=kw)


def request_approval(action, reason, alert):
    rid = uuid.uuid4().hex[:8]
    json.dump({"id": rid, "acao": action, "motivo": reason, "alerta": alert["rule"], "criado": c.iso()},
              open(os.path.join(pend_dir(), rid + ".json"), "w"))
    c.log_event("soar", acao=action, risco="alto", modo="aguardando_aprovacao", id=rid)
    return rid


def approve(rid, by, decision="aprovar"):
    p = os.path.join(pend_dir(), rid + ".json")
    req = json.load(open(p))
    os.remove(p)
    if decision == "aprovar":
        _append("high_impact_executed.txt", f"{req['acao']}|{by}")   # real: comando MQTT ao rele, assinado
    c.log_event("soar", acao=req["acao"], risco="alto", modo="humano", decisao=decision, por=by, id=rid)
    return req


def on_alert(alert, rec):
    """Ligar no detector: Detector(logdir, on_alert=soar.on_alert)"""
    for name, fields in PLAYBOOK.get(alert["rule"], []):
        kw = {k: alert.get(k, rec.get(k)) for k in fields}
        run_action(name, **kw)
    if alert["rule"] in PEDIDO_HUMANO:
        act, why = PEDIDO_HUMANO[alert["rule"]]
        request_approval(act, why, alert)


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "approve":
        print(approve(sys.argv[2], sys.argv[3]))
    elif len(sys.argv) >= 2 and sys.argv[1] == "list":
        for f in os.listdir(pend_dir()):
            print(open(os.path.join(pend_dir(), f)).read())
