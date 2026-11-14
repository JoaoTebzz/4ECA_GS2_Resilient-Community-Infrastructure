"""Funcoes comuns do painel: banco sintetico, logs em JSON, TOTP e hash de senha.
Todos os dados sao FICTICIOS (LGPD)."""
import os, json, hmac, hashlib, base64, struct, time, random, sqlite3, datetime, threading

BASE = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.environ.get("VA_LOGS", os.path.join(BASE, "..", "logs"))
_lock = threading.Lock()

# relogio trocavel: no laboratorio de reproducao do incidente usamos um relogio virtual
CLOCK = None


def now():
    if CLOCK is not None:
        return CLOCK()
    return datetime.datetime.now(datetime.timezone.utc)


def iso(dt=None):
    dt = dt or now()
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def log_event(source, **fields):
    os.makedirs(LOG_DIR, exist_ok=True)
    rec = {"ts": iso(), "source": source}
    rec.update(fields)
    with _lock:
        with open(os.path.join(LOG_DIR, f"{source}.log"), "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return rec


# ---------- senhas ----------
def hash_legacy(pw):
    # ERRADO de proposito (versao vulneravel): sha256 sem sal
    return hashlib.sha256(pw.encode()).hexdigest()


def hash_scrypt(pw, salt):
    return hashlib.scrypt(pw.encode(), salt=salt, n=2**14, r=8, p=1).hex()


# ---------- TOTP (RFC 6238) ----------
def totp(secret_b32, t=None, step=30, digits=6):
    key = base64.b32decode(secret_b32)
    counter = int((t if t is not None else time.time()) // step)
    h = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    code = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_ok(secret_b32, code, window=1):
    t = time.time()
    return any(hmac.compare_digest(totp(secret_b32, t + d * 30), code) for d in range(-window, window + 1))


# ---------- banco sintetico ----------
NOMES = ["Ana Souza", "Bruno Lima", "Carla Dias", "Diego Alves", "Elisa Rocha", "Fabio Nunes",
         "Gabi Torres", "Heitor Pinto", "Iara Campos", "Joao Melo", "Karen Silva", "Lucas Prado",
         "Marta Gomes", "Nando Reis", "Olivia Cruz", "Paulo Neri", "Quiteria Lopes", "Rafa Mota",
         "Sara Viana", "Tiago Assis", "Ursula Pena", "Vitor Braga", "Wanda Leal", "Xavier Dutra", "Yara Costa"]
ESPACOS = ["Centro Comunitario", "Escola Municipal", "UBS", "Horta e Cozinha", "Abrigo"]


def make_db(path, legacy):
    if os.path.exists(path):
        os.remove(path)
    rnd = random.Random(2026)
    db = sqlite3.connect(path)
    db.executescript("""
    CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, email TEXT, phone TEXT, kind TEXT);
    CREATE TABLE access_log(id INTEGER PRIMARY KEY, ts TEXT, user_id INTEGER, space TEXT, result TEXT);
    CREATE TABLE operators(username TEXT PRIMARY KEY, pw_hash TEXT, salt TEXT, role TEXT, totp_secret TEXT);
    CREATE TABLE schedule(pump TEXT PRIMARY KEY, start_h INTEGER, end_h INTEGER, enabled INTEGER);
    CREATE TABLE search_audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, term TEXT);
    """)
    for i, n in enumerate(NOMES, 1):
        first = n.split()[0].lower()
        db.execute("INSERT INTO users VALUES(?,?,?,?,?)",
                   (i, n, f"{first}{i}@exemplo.invalid", f"+55 11 5550-{1000 + i}",
                    rnd.choice(["voluntario", "morador", "tecnico", "saude"])))
    for i in range(1, 301):
        d = datetime.datetime(2026, 10, 1) + datetime.timedelta(minutes=rnd.randint(0, 60 * 24 * 14))
        db.execute("INSERT INTO access_log VALUES(?,?,?,?,?)",
                   (i, d.strftime("%Y-%m-%dT%H:%M:%SZ"), rnd.randint(1, len(NOMES)),
                    rnd.choice(ESPACOS), rnd.choice(["ok", "ok", "ok", "negado"])))
    ops = [("coord1", "Vila123", "coordenacao"), ("tec1", "Bomba2026", "tecnico"),
           ("op1", "Horta2026", "operador"), ("aud1", "Auditoria2026", "auditor")]
    for u, pw, role in ops:
        secret = base64.b32encode(hashlib.sha256(("seed" + u).encode()).digest()[:10]).decode()
        if legacy:
            db.execute("INSERT INTO operators VALUES(?,?,?,?,?)", (u, hash_legacy(pw), "", role, secret))
        else:
            salt = hashlib.sha256(("salt" + u).encode()).digest()[:16]
            db.execute("INSERT INTO operators VALUES(?,?,?,?,?)", (u, hash_scrypt(pw, salt), salt.hex(), role, secret))
    db.execute("INSERT INTO schedule VALUES('bomba_escola',6,20,1)")
    db.execute("INSERT INTO schedule VALUES('bomba_abrigo',0,24,1)")
    db.commit()
    db.close()
    return path
