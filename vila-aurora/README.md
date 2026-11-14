# Rede Comunitária Vila Aurora (GS2026.2, E2)

Protótipo do desafio Resilient Community Infrastructure. **Tudo aqui é de laboratório, com dados sintéticos.**
Nunca aponte as ferramentas para sistemas de terceiros (Lei 12.737/2012).

## Requisitos
Python 3.11+, OpenSSL, Node 18+ (só para gerar os relatórios). `pip install -r requirements.txt`.
Docker é opcional (só para os arquivos de `infra/`).

## Passo a passo (cada passo gera um arquivo em `results/`)
```bash
python3 tests/test_sqli.py              # SQL Injection antes e depois
python3 tests/test_mtls.py              # CA, mTLS, revogação (cria a PKI em pasta temporária)
python3 tests/chaos_test.py             # WAN fora por 30 min (relógio virtual, roda em segundos)
python3 tests/chaos_test.py --real      # o mesmo em tempo real (cerca de 37 min)
python3 tests/live_detect_response.py   # regras A a D, SOAR, MTTD e MTTR
python3 ai/anomaly.py                   # Isolation Forest
python3 dns/check_email_auth.py         # SPF, DKIM e DMARC pela zona DNS
python3 lab/run_incident.py             # reproduz o INC-VA-0712 em lab_out/
python3 forensics/collect.py collect lab_out/INC-VA-0712/logs lab_out/INC-VA-0712/cofre --por "João Tebaldi" --clock-offset vpn=192
python3 forensics/collect.py verify lab_out/INC-VA-0712/cofre
python3 forensics/timeline.py lab_out/INC-VA-0712/cofre lab_out/INC-VA-0712/linha_do_tempo.csv
python3 lab/replay_detection.py
```
Rodar os painéis: `cd panel && python3 app_vulnerable.py` (porta 5001, só laboratório) ou `app_fixed.py` (porta 5002).
Para criar os bancos use `common.make_db(caminho, legacy=True/False)`.

## Pastas
`panel/` painel legado e corrigido · `edge/` nó de borda e portão mTLS · `pki/` CA e revogação · `siem/` detector e regras Wazuh ·
`soar/` respostas · `ai/` anomalias · `forensics/` coleta e linha do tempo · `lab/` reprodução do incidente ·
`dns/` zona e checagem de e-mail · `phishing/` plano e métricas · `infra/` Mosquitto, WireGuard, nftables, compose · `evidencias/` cofre do incidente.

## O que NÃO foi testado
WireGuard, nftables, Mosquitto, Docker Compose, Wazuh real e campanha do Gophish. (O teste de caos em tempo real foi feito: `results/chaos_real.json`.)
Os arquivos existem, mas faltam evidências de execução. Os logs de VPN, e-mail, proxy, atuador e telemetria do incidente são gerados por script.

## Segredos
Chaves privadas não vão para o Git (veja `.gitignore`). `dns/dkim_private.key` e `pki/out/` são gerados localmente.
**Antes de publicar, apague `dns/dkim_private.key` e gere outra.**

## Sobre senhas e chaves que aparecem no código
- As senhas de operador em `panel/common.py` (ex.: `Vila123`) são **fictícias**, do banco sintético do laboratório.
- Chaves de sessão e de pseudônimo vêm de variável de ambiente (`.env.example`) ou são aleatórias a cada execução.
- A chave DKIM e a PKI são **geradas localmente** (`dns/make_dkim.sh`, `pki/make_pki.sh`) e nunca vão para o Git.

