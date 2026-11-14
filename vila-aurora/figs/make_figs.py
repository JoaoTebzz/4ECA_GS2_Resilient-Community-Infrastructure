import json, csv, os, datetime
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
AZ, VD, LJ, CZ, VM = "#1f4e79", "#2e7d32", "#c77700", "#555555", "#b3261e"

def box(ax, x, y, w, h, txt, fc, ec, fs=9, bold=False, tc="black"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08", fc=fc, ec=ec, lw=1.4))
    ax.text(x + w / 2, y + h / 2, txt, ha="center", va="center", fontsize=fs, fontweight="bold" if bold else "normal", color=tc)

# ---------- 1. arquitetura ----------
fig, ax = plt.subplots(figsize=(10, 7.2)); ax.set_xlim(0, 10); ax.set_ylim(0, 7.2); ax.axis("off")
camadas = [(5.9, "SUPERVISAO", "#e8f0fa", AZ), (4.2, "NUVEM / SERVICOS", "#eaf5ea", VD), (2.2, "BORDA (um no por espaco)", "#fff3e0", LJ), (0.2, "CAMPO", "#f2f2f2", CZ)]
alt = {5.9: 1.1, 4.2: 1.4, 2.2: 1.7, 0.2: 1.5}
for y, nome, fc, ec in camadas:
    ax.add_patch(FancyBboxPatch((0.1, y), 9.8, alt[y], boxstyle="round,pad=0.02,rounding_size=0.1", fc=fc, ec=ec, lw=1.6))
    ax.text(0.25, y + alt[y] - 0.2, nome, fontsize=10, fontweight="bold", color=ec, va="top")
box(ax, 1.8, 6.05, 2.4, 0.55, "Painel web (HTTPS + MFA)", "white", AZ, 8.5)
box(ax, 4.4, 6.05, 2.4, 0.55, "Alertas por e-mail e mensagem", "white", AZ, 8.5)
box(ax, 7.0, 6.05, 2.6, 0.55, "Console do SOC\n(aprovacao humana)", "white", AZ, 8.5)
box(ax, 0.4, 4.35, 1.8, 0.65, "SIEM (Wazuh)\nlogs + regras", "white", VD, 8.5)
box(ax, 2.35, 4.35, 1.8, 0.65, "SOAR (scripts)\nbaixo risco auto", "white", VD, 8.5)
box(ax, 4.3, 4.35, 1.8, 0.65, "Banco + painel\n(consultas seguras)", "white", VD, 8.5)
box(ax, 6.25, 4.35, 1.6, 0.65, "IA: Isolation\nForest", "white", VD, 8.5)
box(ax, 8.0, 4.35, 1.8, 0.65, "CA do projeto\n(PKI) + CRL", "white", VD, 8.5)
spaces = ["Centro", "Escola", "UBS", "Horta", "Abrigo"]
for i, s in enumerate(spaces):
    x = 0.4 + i * 1.9
    box(ax, x, 2.35, 1.7, 1.05, f"No de borda\n{s}\nMQTT local + regras\nbuffer + logs + 4G", "white", LJ, 7.6)
campo = ["Fechadura\nRFID/QR", "Nivel / cloro\nturbidez", "Camara fria\n(temperatura)", "Energia\n(medidor)", "Rele da\nbomba", "Alagamento\numidade"]
for i, s in enumerate(campo):
    box(ax, 0.35 + i * 1.6, 0.3, 1.45, 0.8, s, "white", CZ, 8)
def arr(x1, y1, x2, y2, txt="", col="black", dx=0.12):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="<->", mutation_scale=12, lw=1.5, color=col))
    if txt:
        ax.text((x1 + x2) / 2 + dx, (y1 + y2) / 2, txt, fontsize=7.8, color=col, va="center", bbox=dict(fc="white", ec="none", pad=1.5))
arr(5.0, 5.1, 5.0, 6.0, "HTTPS (so pela VPN)", AZ)
arr(5.0, 3.5, 5.0, 4.3, "VPN WireGuard + mTLS (4G ou fibra)", VD)
arr(5.0, 1.25, 5.0, 2.3, "MQTT com mTLS (certificado por dispositivo)", CZ)
ax.text(0.2, 7.05, "Rede Comunitaria Vila Aurora: arquitetura em camadas", fontsize=12, fontweight="bold")
plt.savefig(os.path.join(ROOT, "figs", "arquitetura.png"), dpi=170, bbox_inches="tight"); plt.close()

# ---------- 2. segmentacao ----------
fig, ax = plt.subplots(figsize=(10, 4.8)); ax.set_xlim(0, 10); ax.set_ylim(0, 4.8); ax.axis("off")
box(ax, 0.2, 3.3, 2.8, 1.2, "IoT  10.20.10.0/24\nsensores, fechaduras, rele\nso fala MQTT 8883 com a borda", "#fff3e0", LJ, 8.5)
box(ax, 3.6, 3.3, 2.8, 1.2, "Operadores  10.20.20.0/24\npainel local (443)\nsem acesso direto ao IoT", "#e8f0fa", AZ, 8.5)
box(ax, 7.0, 3.3, 2.8, 1.2, "Administracao  10.20.30.0/24\nbastiao, SIEM agente, SSH\nso com VPN + MFA", "#fdecea", VM, 8.5)
box(ax, 3.2, 1.55, 3.6, 0.9, "No de borda: firewall nftables\npolitica padrao DROP", "#eeeeee", "black", 9, True)
box(ax, 3.2, 0.1, 3.6, 0.8, "WireGuard wg0  10.50.0.0/24\n(unica porta aberta: UDP 51820)", "#eaf5ea", VD, 8.5)
for x in (1.6, 5.0, 8.4):
    ax.add_patch(FancyArrowPatch((x, 3.3), (5.0 if x != 5.0 else 5.0, 2.45), arrowstyle="->", mutation_scale=12, lw=1.2, color="black"))
ax.add_patch(FancyArrowPatch((5.0, 1.55), (5.0, 0.9), arrowstyle="<->", mutation_scale=12, lw=1.5, color=VD))
ax.text(8.0, 0.5, "Nuvem: SIEM, banco, IA, CA", fontsize=9, color=VD); ax.add_patch(FancyArrowPatch((6.8, 0.5), (7.95, 0.5), arrowstyle="->", mutation_scale=12, color=VD))
ax.text(0.2, 4.7, "Segmentacao de rede de cada espaco", fontsize=12, fontweight="bold")
plt.savefig(os.path.join(ROOT, "figs", "segmentacao.png"), dpi=170, bbox_inches="tight"); plt.close()

# ---------- 3. linha do tempo do incidente ----------
tel = [json.loads(l) for l in open(os.path.join(ROOT, "evidencias", "INC-VA-0712", "cofre", "telemetry.log"))]
def tt(s): return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%fZ")
lv = [(tt(r["ts"]), r["value"]) for r in tel if r["metric"] == "nivel_reservatorio"]
tp = [(tt(r["ts"]), r["value"]) for r in tel if r["metric"] == "temp_camara_fria"]
fig, (a1, a2) = plt.subplots(2, 1, figsize=(10, 6), sharex=True)
a1.plot([x for x, _ in lv], [y for _, y in lv], color=AZ); a1.set_ylabel("Nivel da escola (%)"); a1.grid(alpha=.3)
a2.plot([x for x, _ in tp], [y for _, y in tp], color=VM); a2.axhline(8, color="black", ls="--", lw=1); a2.set_ylabel("Camara fria da UBS (C)"); a2.grid(alpha=.3)
a2.text(tp[2][0], 8.1, "limite seguro: 8 C", fontsize=8)
marcas = [("02:11 VPN", datetime.datetime(2026, 10, 17, 2, 11, 10)), ("02:16 muda a bomba", datetime.datetime(2026, 10, 17, 2, 16, 30)),
          ("04:05 fibra cai", datetime.datetime(2026, 10, 17, 4, 5)), ("08:50 alguem percebe", datetime.datetime(2026, 10, 17, 8, 50))]
for i, (n, t) in enumerate(marcas):
    for a in (a1, a2):
        a.axvline(t, color="gray", ls=":", lw=1)
    a1.text(t, 95 - i * 9, " " + n, fontsize=8, rotation=0)
a1.set_ylim(0, 100)
import matplotlib.dates as md
a2.xaxis.set_major_formatter(md.DateFormatter("%H:%M")); a2.set_xlabel("Hora (UTC, 17/10/2026)")
fig.suptitle("Reproducao do INC-VA-0712: impacto na agua e na camara fria", fontsize=11, fontweight="bold")
plt.tight_layout(); plt.savefig(os.path.join(ROOT, "figs", "linha_do_tempo.png"), dpi=170); plt.close()
print("ok")
