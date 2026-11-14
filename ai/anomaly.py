"""IA defensiva (RT-16): Isolation Forest sobre telemetria sintetica.
Gera 14 dias de leituras (a cada 5 min), treina com os 10 primeiros (so normal) e testa nos 4 ultimos,
onde injetamos anomalias rotuladas. Calcula precisao, revocacao e falsos positivos.
Salva results/ai.json"""
import os, json
import numpy as np, pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
rng = np.random.default_rng(42)
N = 14 * 24 * 12
t = np.arange(N)
hora = (t % 288) / 12.0

# normal: camara fria ~4.5C (sobe um pouco no horario de movimento), nivel enche/esvazia, energia segue o dia
temp = 4.5 + 0.4 * np.sin(2 * np.pi * hora / 24) + rng.normal(0, 0.25, N)
nivel = 60 + 15 * np.sin(2 * np.pi * (hora - 3) / 24) + rng.normal(0, 1.5, N)
power = 600 + 400 * np.clip(np.sin(2 * np.pi * (hora - 6) / 24), 0, None) + rng.normal(0, 40, N)
bomba = ((hora >= 6) & (hora < 20) & (nivel < 55)).astype(float)
label = np.zeros(N, int)
KIND = {}

def inject(start, length, kind):
    s, e = start, start + length
    label[s:e] = 1
    KIND[s] = kind
    if kind == "porta_aberta":     # temperatura sobe devagar
        temp[s:e] += np.linspace(0.5, 4.5, length)
    elif kind == "bomba_madrugada":   # bomba ligada de madrugada e nivel caindo (igual ao INC-VA-0712)
        bomba[s:e] = 1; nivel[s:e] -= np.linspace(5, 40, length)
    elif kind == "pico_energia":
        power[s:e] += rng.normal(900, 80, length)
    elif kind == "sensor_travado":    # leitura congelada
        temp[s:e] = temp[s];

base = 10 * 288
for dia, kind, dur in [(10, "porta_aberta", 20), (10, "bomba_madrugada", 36), (11, "pico_energia", 6),
                       (11, "sensor_travado", 24), (12, "porta_aberta", 30), (12, "bomba_madrugada", 30),
                       (13, "pico_energia", 8), (13, "bomba_madrugada", 40)]:
    off = {"bomba_madrugada": 2 * 12, "porta_aberta": 14 * 12, "pico_energia": 11 * 12, "sensor_travado": 16 * 12}[kind]
    if dia == 12 and kind == "bomba_madrugada":
        off = 3 * 12
    if dia == 13 and kind == "bomba_madrugada":
        off = 1 * 12 + 6
    if dia == 12 and kind == "porta_aberta":
        off = 9 * 12
    if dia == 13 and kind == "pico_energia":
        off = 20 * 12
    inject(dia * 288 + off, dur, kind)

df = pd.DataFrame({"temp": temp, "nivel": nivel, "power": power, "bomba": bomba,
                   "h_sin": np.sin(2 * np.pi * hora / 24), "h_cos": np.cos(2 * np.pi * hora / 24)})
df["d_temp"] = df["temp"].diff().fillna(0)
df["d_nivel"] = df["nivel"].diff().fillna(0)
df["temp_std6"] = df["temp"].rolling(6, min_periods=1).std().fillna(0)
X = df.values
tr, te = slice(0, base), slice(base, N)

res = {"amostras_treino": base, "amostras_teste": N - base, "amostras_anomalas_no_teste": int(label[te].sum())}
for cont in (0.01, 0.02, 0.05):
    m = IsolationForest(n_estimators=200, contamination=cont, random_state=1).fit(X[tr])
    pred = (m.predict(X[te]) == -1).astype(int)
    y = label[te]
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    res[f"contamination_{cont}"] = {"precisao": round(precision_score(y, pred), 3), "revocacao": round(recall_score(y, pred), 3),
                                    "f1": round(f1_score(y, pred), 3), "falsos_positivos": int(fp), "falsos_negativos": int(fn),
                                    "taxa_falso_positivo_%": round(100 * fp / (fp + tn), 2), "alarmes_por_dia": round((tp + fp) / 4, 1)}

# comparacao com a regra simples (limite fixo de temperatura 8 C)
y = label[te]
regra = (df["temp"].values[te] > 8.0).astype(int)
res["baseline_limite_fixo_8C"] = {"precisao": round(precision_score(y, regra, zero_division=0), 3),
                                  "revocacao": round(recall_score(y, regra, zero_division=0), 3)}
# janelas anomalas (cada evento injetado) e quantas o modelo percebeu
idx = np.where(label == 1)[0]
janelas, ini = [], idx[0]
for a_, b_ in zip(idx[:-1], idx[1:]):
    if b_ != a_ + 1:
        janelas.append((ini, a_)); ini = b_
janelas.append((ini, idx[-1]))
res["janelas_anomalas"] = len(janelas)
for cont in (0.01, 0.02, 0.05):
    m = IsolationForest(n_estimators=200, contamination=cont, random_state=1).fit(X[tr])
    pred = (m.predict(X[te]) == -1).astype(int)
    det, perdidas = 0, []
    for a_, b_ in janelas:
        if pred[a_ - base:b_ - base + 1].any():
            det += 1
        else:
            perdidas.append(KIND[a_])
    res[f"contamination_{cont}"]["janelas_detectadas"] = det
    res[f"contamination_{cont}"]["tipos_nao_detectados"] = perdidas
os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
json.dump(res, open(os.path.join(ROOT, "results", "ai.json"), "w"), indent=2, ensure_ascii=False)
print(json.dumps(res, indent=2, ensure_ascii=False))
