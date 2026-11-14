"""Portao mTLS do no de borda (stand-in do Mosquitto no laboratorio).
Exige certificado de cliente emitido pela CA do projeto, confere a CRL (revogados) e
grava um log por tentativa em logs/mqtt.log (usado pela regra de deteccao C do SIEM).
Em producao quem faz isso e o Mosquitto (veja infra/mosquitto.conf)."""
import ssl, socket, threading, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "panel"))
import common as c


def server_context(pki):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(f"{pki}/devices/edge-server.crt", f"{pki}/devices/edge-server.key")
    ctx.load_verify_locations(f"{pki}/ca/ca.crt")
    ctx.load_verify_locations(f"{pki}/ca/crl.pem")
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    return ctx


class Gateway:
    def __init__(self, pki, host="127.0.0.1", port=0):
        self.pki = pki
        self.ctx = server_context(pki)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.running = True
        self.t = threading.Thread(target=self.loop, daemon=True)

    def start(self):
        self.t.start()
        return self

    def reload_crl(self):
        self.ctx = server_context(self.pki)

    def loop(self):
        self.sock.settimeout(0.2)
        while self.running:
            try:
                raw, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.handle, args=(raw, addr), daemon=True).start()

    def handle(self, raw, addr):
        try:
            s = self.ctx.wrap_socket(raw, server_side=True)
            cn = None
            for rdn in s.getpeercert()["subject"]:
                for k, v in rdn:
                    if k == "commonName":
                        cn = v
            data = s.recv(1024)
            s.sendall(b"ACK:" + data)
            c.log_event("mqtt", event="tls_handshake", result="ok", cn=cn, src=addr[0], tls=s.version())
            s.close()
        except ssl.SSLError as e:
            c.log_event("mqtt", event="tls_handshake", result="fail", cn=None, src=addr[0], reason=str(e)[:80])
            raw.close()
        except OSError:
            raw.close()

    def stop(self):
        self.running = False
        self.sock.close()


def client_try(port, pki, cert=None, key=None, ca=True):
    """Tenta conectar. Devolve 'aceito' ou 'rejeitado: motivo'."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.load_verify_locations(f"{pki}/ca/ca.crt")
    if cert:
        ctx.load_cert_chain(cert, key)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=3) as r:
            with ctx.wrap_socket(r, server_hostname="localhost") as s:
                s.sendall(b"ping")
                resp = s.recv(100)  # no TLS 1.3 o erro de certificado aparece aqui
                return "aceito" if resp.startswith(b"ACK") else "rejeitado: sem resposta"
    except (ssl.SSLError, ConnectionError, OSError) as e:
        return "rejeitado: " + type(e).__name__
