"""Aquisicao de evidencias com SHA-256 e cadeia de custodia (RT-14).
  collect : copia os logs para o cofre de evidencias (somente leitura), calcula SHA-256 NA HORA da coleta e
            grava uma linha na cadeia de custodia (quem, quando, onde, como).
  verify  : recalcula os hashes e compara com a cadeia. Qualquer mudanca aparece.
Uso:
  python3 forensics/collect.py collect <pasta_logs> <cofre> --por "Nome do integrante" [--clock-offset vpn=192]
  python3 forensics/collect.py verify <cofre>"""
import os, sys, csv, hashlib, shutil, argparse, datetime, stat, platform, json


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def collect(src, vault, por, offsets):
    os.makedirs(vault, exist_ok=True)
    custody = os.path.join(vault, "cadeia_de_custodia.csv")
    novo = not os.path.exists(custody)
    i = 0 if novo else sum(1 for _ in open(custody, encoding="utf-8")) - 1
    with open(custody, "a", newline="", encoding="utf-8") as cf:
        w = csv.writer(cf)
        if novo:
            w.writerow(["item", "arquivo", "origem", "sha256", "bytes", "coletado_por", "data_hora_utc", "local", "metodo", "ajuste_relogio_s"])
        for fn in sorted(os.listdir(src)):
            p = os.path.join(src, fn)
            if not os.path.isfile(p):
                continue
            i += 1
            h_origem = sha256(p)                 # hash na origem, no momento da coleta
            dst = os.path.join(vault, fn)
            shutil.copy2(p, dst)
            h_copia = sha256(dst)
            assert h_origem == h_copia, "copia diferente da origem!"
            os.chmod(dst, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
            key = fn.replace(".log", "")
            w.writerow([f"E{i:02d}", fn, os.path.abspath(p), h_copia, os.path.getsize(dst), por,
                        datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        platform.node(), "cp -p + sha256 (python hashlib) na origem e na copia", offsets.get(key, 0)])
    # manifesto no formato do sha256sum
    with open(os.path.join(vault, "SHA256SUMS"), "w") as m:
        for fn in sorted(os.listdir(vault)):
            if fn not in ("SHA256SUMS", "cadeia_de_custodia.csv") and os.path.isfile(os.path.join(vault, fn)):
                m.write(f"{sha256(os.path.join(vault, fn))}  {fn}\n")
    print("coletado em", vault)


def verify(vault):
    ok, bad = 0, []
    for row in csv.DictReader(open(os.path.join(vault, "cadeia_de_custodia.csv"), encoding="utf-8")):
        p = os.path.join(vault, row["arquivo"])
        if os.path.exists(p) and sha256(p) == row["sha256"]:
            ok += 1
        else:
            bad.append(row["arquivo"])
    print(json.dumps({"integros": ok, "alterados_ou_ausentes": bad}))
    return ok, bad


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["collect", "verify"])
    ap.add_argument("src_or_vault")
    ap.add_argument("vault", nargs="?")
    ap.add_argument("--por", default="integrante")
    ap.add_argument("--clock-offset", action="append", default=[])
    a = ap.parse_args()
    if a.cmd == "collect":
        collect(a.src_or_vault, a.vault, a.por, {k: int(v) for k, v in (x.split("=") for x in a.clock_offset)})
    else:
        verify(a.src_or_vault)
