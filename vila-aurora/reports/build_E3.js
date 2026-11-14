const path = require("path");
const L = require("./lib");
const { P, H1, H2, B, N, SP, BR, CODE, TABLE, cover, build, R, ROOT } = L;
const RT = R("chaos_real"), sq = R("sqli"), mt = R("mtls"), em = R("email_auth"), det = R("detect"), ch = R("chaos"), ai = R("ai"), rp = R("replay");

const c = [];
c.push(...cover("Relatório de Testes de Segurança", "Provas de que os controles funcionam (e dos limites do que testamos)", "E3 · Relatório de Testes de Segurança"));
c.push(BR());

c.push(H1("1. Resumo e ambiente de teste"));
c.push(P("Neste relatório mostramos o que foi testado, como foi testado e o que deu certo ou errado. Todos os testes rodaram no ambiente isolado do grupo, com dados sintéticos (nomes e e-mails inventados, domínio `.example`). Nenhum sistema de terceiros foi testado."));
c.push(TABLE(["Teste", "Resultado em uma frase", "Seção"], [
  ["SQL Injection antes e depois", "No painel antigo, 4 de 5 ataques deram certo (vazou dados e a bomba foi desligada). No corrigido, 0 de 5", "2"],
  ["mTLS e revogação", "Só certificado válido entra. Revogado é recusado em " + mt["6_tempo_revogar_e_publicar_s"] + " s", "3"],
  ["VPN e segmentação", "Configuração escrita, **não executada** no laboratório", "4"],
  ["SPF, DKIM e DMARC", "Registros corretos e assinatura DKIM verificada (e quebrada quando o corpo muda)", "5"],
  ["Phishing simulado", "Plano e script prontos, **campanha ainda não executada**", "6"],
  ["Prompt injection", "Não se aplica, o projeto não tem LLM", "7"],
  ["Detecção e resposta", det.eventos_maliciosos_injetados + " de " + det.eventos_maliciosos_injetados + " eventos detectados, MTTD médio " + det.mttd_geral_s + " s", "8"],
  ["Teste de caos (WAN fora por 30 min)", "0 leituras perdidas, alarme local em " + RT.atraso_do_alarme_local_s + " s (tempo real, 37 min)", "9"],
  ["IA (Isolation Forest)", "Detectou " + ai["contamination_0.05"].janelas_detectadas + " de " + ai.janelas_anomalas + " eventos, com falsos positivos medidos", "10"],
], [3000, 5900, 738]));
c.push(SP());
c.push(P("**Como reproduzir:** os scripts estão na pasta `tests/` do repositório. Exemplo: `python3 tests/test_sqli.py` salva o resultado em `results/sqli.json`. Todos os números abaixo vêm desses arquivos."));

// ---------- 2 ----------
c.push(H1("2. SQL Injection antes e depois"));
c.push(H2("2.1 O que testamos"));
c.push(P("Usamos o campo de busca do histórico de acessos (`/historico?q=`). Rodamos os mesmos cinco ataques contra o painel legado (`app_vulnerable.py`) e contra o corrigido (`app_fixed.py`). Os ataques foram escritos à mão, no mesmo estilo do incidente. Não usamos o sqlmap neste relatório."));
c.push(TABLE(["Ataque", "Texto enviado na busca", "Objetivo"], [
  ["booleano", "`x%' OR 1=1 --`", "Fazer a condição ser sempre verdadeira e listar tudo"],
  ["union_usuarios", "`zzz' UNION SELECT id,email,phone,kind FROM users --`", "Roubar e-mail e telefone dos usuários"],
  ["union_operadores", "`zzz' UNION SELECT username,pw_hash,role,totp_secret FROM operators --`", "Roubar hash de senha e segredo do MFA"],
  ["erro_revela_sql", "`'`", "Provocar erro que mostre a consulta"],
  ["empilhada_altera_bomba", "`x%'; UPDATE schedule SET enabled=0 WHERE pump='bomba_escola'; --`", "Desligar a bomba da escola"],
], [1900, 4700, 3038]));
c.push(SP());
c.push(H2("2.2 Resultado no painel legado (antes)"));
const lg = sq.legado;
c.push(TABLE(["Ataque", "Status", "Linhas devolvidas", "Efeito"], [
  ["booleano", String(lg.booleano.status), String(lg.booleano.linhas), "Devolveu o histórico inteiro (300 registros)"],
  ["union_usuarios", String(lg.union_usuarios.status), String(lg.union_usuarios.linhas), "Vazou os 25 usuários com e-mail e telefone"],
  ["union_operadores", String(lg.union_operadores.status), String(lg.union_operadores.linhas), "Vazou os 4 operadores, com hash e segredo do MFA"],
  ["erro_revela_sql", String(lg.erro_revela_sql.status), "0", "O erro mostrou a consulta montada"],
  ["empilhada_altera_bomba", String(lg.empilhada_altera_bomba.status), "0", "A bomba da escola foi **desligada** (enabled passou de 1 para " + lg.bomba_escola_enabled_depois + ")"],
], [2300, 900, 1700, 4738]));
c.push(SP());
c.push(P("**Resumo:** 4 de 5 ataques deram certo (o do erro só vazou informação). O painel antigo guardava o hash de senha com SHA-256 sem sal, então o hash roubado ainda seria fácil de quebrar. Um detalhe que tivemos que ajustar: o ataque empilhado só funciona se o driver aceitar várias instruções de uma vez. Reproduzimos isso no laboratório com uma função `run_multi` que imita drivers com esse recurso ligado. O sqlite3 do Python, sozinho, recusa isso."));
c.push(H2("2.3 Resultado no painel corrigido (depois)"));
const cr = sq.corrigido;
c.push(TABLE(["Ataque", "Status", "Linhas", "Quem barrou"], [
  ["booleano", String(cr.booleano.status), "0", "Filtro WAF (padrão `--`)"],
  ["union_usuarios", String(cr.union_usuarios.status), "0", "Filtro WAF (`union select`)"],
  ["union_operadores", String(cr.union_operadores.status), "0", "Filtro WAF"],
  ["erro_revela_sql", String(cr.erro_revela_sql.status), "0", "Passou pelo WAF, mas a validação e a consulta parametrizada tratam o `'` como texto. Sem erro e sem vazamento"],
  ["empilhada_altera_bomba", String(cr.empilhada_altera_bomba.status), "0", "Filtro WAF (`;`). Bomba continua ligada (enabled = " + cr.bomba_escola_enabled_depois + ")"],
], [2300, 900, 900, 5538]));
c.push(SP());
c.push(P("Antes disso, conferimos que o login do corrigido exige o código MFA: com senha certa e código certo, status " + cr.login_com_mfa + ". Com senha certa e código errado, status " + cr.login_sem_mfa_correto + "."));
c.push(H2("2.4 Reteste: a causa raiz foi mesmo corrigida?"));
c.push(P("Um filtro sozinho é fraco, então desligamos as camadas extras para ver o que sobra. Fizemos duas rodadas:"));
c.push(B("**Sem o WAF:** a validação de entrada (só letras, espaço, ponto e hífen) barrou 4 dos 5 ataques com status 400. O ataque com só uma aspa passou pela validação do apóstrofo (ele é permitido de propósito, para nomes como O'Neil) e foi tratado como texto."));
c.push(B("**Sem o WAF e sem a validação (só a parametrização):** os 5 ataques voltaram status 200 com **0 linhas**, sem erro e sem alterar a bomba (enabled = " + sq.so_parametrizacao.bomba_escola_enabled_depois + "). Ou seja, a consulta parametrizada sozinha já resolve o problema. O resto é defesa em profundidade."));
c.push(P("Também testamos o uso normal: buscar \"Ana\" devolveu " + cr.busca_normal_Ana.linhas + " linhas, e buscar \"O'Neil\" funcionou (status " + cr.busca_com_apostrofo_legitimo.status + "). A correção não quebrou a função."));
c.push(H2("2.5 Resumo das defesas"));
c.push(TABLE(["Camada", "O que faz", "Provada no teste?"], [
  ["Parametrização", "Separa o código SQL do dado do usuário", "Sim (2.4)"],
  ["Validação no servidor", "Aceita só caracteres esperados, até 40", "Sim (2.4)"],
  ["Menor privilégio", "Busca usa conexão somente leitura do SQLite (`mode=ro`)", "Parcial. Não testamos papéis de PostgreSQL"],
  ["Erro genérico", "Mostra um código de ocorrência, não a consulta", "Sim (2.3)"],
  ["WAF simples", "Barra padrões conhecidos", "Sim (2.3). É contornável, serve só de camada extra"],
], [2300, 4300, 3038]));
c.push(SP());

// ---------- 3 ----------
c.push(H1("3. mTLS, certificados por dispositivo e revogação"));
c.push(P("Criamos uma CA do projeto com OpenSSL (`pki/make_pki.sh`, curva P-256) e um certificado para cada dispositivo. O portão `edge/mtls_gateway.py` exige certificado de cliente e confere a lista de revogação (CRL). **Atenção:** esse portão em Python é um substituto do Mosquitto, que não rodamos aqui. A configuração do Mosquitto está em `infra/mosquitto.conf`, mas não foi testada."));
c.push(TABLE(["#", "Situação testada", "Resultado esperado", "Resultado obtido"], [
  ["1", "Certificado válido do sensor da UBS", "Aceito", mt["1_certificado_valido"]],
  ["2", "Sem certificado", "Recusado", mt["2_sem_certificado"]],
  ["3", "Certificado de outra CA com o mesmo nome do sensor", "Recusado", mt["3_cert_de_outra_CA_mesmo_nome"]],
  ["4", "Certificado de um dispositivo com a chave de outro", "Recusado", "Recusado no próprio cliente, a chave não casa com o certificado"],
  ["5", "Relé da bomba, antes de revogar", "Aceito", mt["5_antes_de_revogar_rele"]],
  ["6", "Relé da bomba, depois de revogar", "Recusado", mt["6_depois_de_revogar_rele"]],
  ["7", "Outro sensor, depois da revogação do relé", "Continua aceito", mt["7_outro_dispositivo_continua_ok"]],
], [500, 4000, 2000, 3138]));
c.push(SP());
c.push(P("O tempo para revogar e publicar a nova CRL foi de " + mt["6_tempo_revogar_e_publicar_s"] + " s. Nesse teste, o portão recarregou a CRL logo depois (`reload_crl`). No Mosquitto de verdade, é preciso recarregar a configuração ou esperar o broker reler o arquivo, e isso pode levar mais tempo. [[Medir no Mosquitto real]]"));
c.push(P("A conexão negociou **" + mt.tls_versao + "** com a cifra **" + mt.tls_cifra + "**. O portão aceita no mínimo TLS 1.2. Cada tentativa gera uma linha no log (`mqtt.log`), que a regra C do SIEM usa."));

// ---------- 4 ----------
c.push(H1("4. VPN e segmentação"));
c.push(P("**Estado honesto:** escrevemos os arquivos `infra/wg-edge.conf.template` (WireGuard) e `infra/nftables.conf` (firewall com política padrão DROP e segmentos IoT, operadores e administração). **Não executamos nenhum dos dois**, então não temos evidência de funcionamento. O que existe é a configuração revisada pelo grupo."));
c.push(P("Para fechar este item, o grupo deve rodar o ambiente e anexar estas provas:"));
c.push(N("`wg show` mostrando o handshake entre o nó e a nuvem. [[colar saída]]"));
c.push(N("`nmap` de fora para o IP do nó, no nosso laboratório, mostrando só a porta UDP 51820. [[colar saída]]"));
c.push(N("Teste de ping e de conexão do segmento IoT para operadores e administração, que deve falhar. [[colar saída]]"));
c.push(N("Conferir que não há porta administrativa (SSH, painel, banco) aberta para fora. [[colar saída]]"));
c.push(P("Um ponto de projeto: o WireGuard autentica a máquina, não a pessoa. Por isso o acesso humano passa por um bastião com MFA dentro da VPN. Isso ainda não foi montado."));

// ---------- 5 ----------
c.push(H1("5. SPF, DKIM e DMARC"));
c.push(P("Criamos a zona DNS do domínio fictício `vilaaurora.example` (`dns/vilaaurora.example.zone`) e um script (`dns/check_email_auth.py`) que lê os registros da própria zona e testa. Não usamos a internet, porque o sufixo `.example` não existe nela."));
c.push(TABLE(["Controle", "Registro", "Resultado"], [
  ["SPF", "`" + em.spf + "`", em.spf_ok ? "Correto: só o nosso servidor pode enviar e o resto é recusado (`-all`)" : "Falhou"],
  ["DMARC", "`p=quarantine; pct=100; adkim=s; aspf=s`", em.dmarc_ok ? "Correto: quarentena e alinhamento estrito" : "Falhou"],
  ["DKIM, mensagem assinada", "Seletor `va2026`, RSA 2048", em.dkim_assinatura_valida ? "Assinatura válida" : "Falhou"],
  ["DKIM, corpo alterado depois de assinar", "Mudamos \"19h\" para \"20h\"", em.dkim_valida_se_corpo_alterado ? "Passou (ruim)" : "Assinatura inválida, como esperado"],
  ["DKIM, mensagem sem assinatura", "Mensagem original sem cabeçalho", "Sem assinatura, falha"],
], [2300, 3800, 3538]));
c.push(SP());
c.push(P("**Limite importante:** no incidente, o e-mail falso veio de `prefeitura-serraclara.example`, um domínio parecido, e não do nosso. SPF, DKIM e DMARC protegem **o nosso domínio** de ser falsificado. Eles não impedem alguém de registrar um domínio parecido. Por isso usamos também o aviso \"EXTERNO\", o monitoramento de domínios parecidos e a regra de nunca entrar por link de e-mail (E1, seção 9)."));

// ---------- 6 ----------
c.push(H1("6. Campanha de phishing simulado e voz clonada"));
c.push(P("**Estado honesto:** a campanha com o Gophish **ainda não foi executada**. O que está pronto:"));
c.push(B("`phishing/campanha_plano.md`: passo a passo com 10 contas fictícias criadas pela equipe, dois modelos de e-mail (um fácil de notar e um parecido com o do incidente) e duas rodadas, antes e depois do treinamento. A página falsa **não guarda a senha digitada**."));
c.push(B("`phishing/gophish_metrics.py`: lê o CSV exportado do Gophish e calcula abertura, clique, envio de dados, reporte e tempo até o primeiro reporte. Testamos o formato com 2 linhas de exemplo, mas não com uma campanha real."));
c.push(P("Quando a campanha rodar, os resultados entram nesta tabela:"));
c.push(TABLE(["Métrica", "Antes do treinamento", "Depois do treinamento"], [
  ["E-mails enviados", "[[preencher]]", "[[preencher]]"],
  ["Abriram", "[[%]]", "[[%]]"],
  ["Clicaram no link", "[[%]]", "[[%]]"],
  ["Enviaram dados", "[[%]]", "[[%]]"],
  ["Reportaram", "[[%]]", "[[%]]"],
  ["Tempo até o primeiro reporte", "[[s]]", "[[s]]"],
], [3600, 3000, 3038]));
c.push(SP());
c.push(P("**Voz clonada:** não clonamos a voz de ninguém. A regra do desafio exige consentimento escrito e aviso de conteúdo sintético. Mostramos só o **controle**: palavra-código e verificação fora de banda (ligar de volta para um número já conhecido). Está descrito no E1, seção 9."));

// ---------- 7 ----------
c.push(H1("7. Prompt injection"));
c.push(P("O projeto **não usa LLM**, então não há o que testar aqui. A decisão e as regras para o caso de alguém adicionar um estão no E1, seção 12.2. Se o grupo quiser testar de qualquer forma, o caminho é rodar o `garak` contra um modelo local (por exemplo Ollama), em ambiente isolado. [[Remover esta nota se não for fazer]]"));

// ---------- 8 ----------
c.push(H1("8. Detecção e resposta automática"));
c.push(P("Rodamos o detector (`siem/detect.py`) lendo os logs em tempo real, ligado ao SOAR (`soar/soar.py`). Repetimos 10 vezes um conjunto de 4 eventos maliciosos, um por regra:"));
c.push(B("**Regra A:** linha de log de login na VPN sem MFA (**sintética**, não temos VPN)."));
c.push(B("**Regra B:** SQL Injection **de verdade** contra o painel legado."));
c.push(B("**Regra C:** conexão **de verdade** com certificado falso no portão mTLS."));
c.push(B("**Regra D:** comando de atuador com origem fora do perfil (**sintético**)."));
c.push(P("Resultado: " + det.eventos_maliciosos_injetados + " eventos maliciosos injetados e " + det.alertas_gerados + " alertas gerados. Todos foram detectados. Com o evento normal (login da técnica com MFA e IP conhecido) houve **" + det.falsos_positivos_nos_eventos_normais + " falsos positivos**."));
c.push(TABLE(["Regra", "Alertas", "MTTD médio (s)", "MTTD máximo (s)"], [
  ["A, VPN anômala", String(det.alertas_por_regra.A_VPN_LOGIN_ANOMALO), String(det.mttd_s.A_VPN_LOGIN_ANOMALO.media), String(det.mttd_s.A_VPN_LOGIN_ANOMALO.max)],
  ["B, SQL Injection", String(det.alertas_por_regra.B_SQL_INJECTION), String(det.mttd_s.B_SQL_INJECTION.media), String(det.mttd_s.B_SQL_INJECTION.max)],
  ["C, dispositivo sem certificado", String(det.alertas_por_regra.C_DISPOSITIVO_SEM_CERT_VALIDO), String(det.mttd_s.C_DISPOSITIVO_SEM_CERT_VALIDO.media), String(det.mttd_s.C_DISPOSITIVO_SEM_CERT_VALIDO.max)],
  ["D, atuador fora do perfil", String(det.alertas_por_regra.D_ATUADOR_FORA_DO_PERFIL), String(det.mttd_s.D_ATUADOR_FORA_DO_PERFIL.media), String(det.mttd_s.D_ATUADOR_FORA_DO_PERFIL.max)],
], [3800, 1600, 2100, 2138]));
c.push(SP());
c.push(P("O MTTD fica perto de 0,25 s porque o detector lê os arquivos a cada 0,5 s (em média metade disso). **Isso mede o nosso laboratório e não vale como promessa para a produção.** O MTTR automático ficou abaixo de 0,01 s, mas só mede o tempo entre o alerta e a ação gravada, não o efeito real no firewall."));
c.push(H2("8.1 Janelas de horário"));
c.push(TABLE(["Caso", "Alerta?"], [
  ["Login VPN às 03h UTC, com MFA e IP conhecido", det.regras_de_horario.vpn_03h_com_mfa_ip_ok ? "Sim (fora do horário)" : "Não"],
  ["Login VPN às 10h UTC, com MFA e IP conhecido", det.regras_de_horario.vpn_10h_com_mfa_ip_ok ? "Sim" : "Não (normal)"],
  ["Comando de atuador às 02h UTC pelo painel", det.regras_de_horario.atuador_02h_via_painel ? "Sim (fora do horário)" : "Não"],
  ["Comando de atuador às 10h UTC pelo painel", det.regras_de_horario.atuador_10h_via_painel ? "Sim" : "Não (normal)"],
], [6600, 3038]));
c.push(SP());
c.push(H2("8.2 O SOAR separa baixo risco de alto impacto"));
const ef = det.efeitos_soar, ai2 = det.alto_impacto;
c.push(B("**Baixo risco (automático):** IP bloqueado (" + ef.ips_bloqueados.join(", ") + "), " + ef.sessoes_vpn_derrubadas + " sessões VPN encerradas, " + ef.dispositivos_isolados + " dispositivos isolados, modo seguro acionado " + ef.modo_seguro_acionado + " vezes. Aqui os \"efeitos\" são arquivos de estado (`blocklist.txt` etc.). No ambiente real viram comandos do nftables e do WireGuard, que não testamos."));
c.push(B("**Alto impacto (humano):** a regra D criou " + ai2.pedidos_pendentes + " pedidos para desligar a bomba, e **" + ai2.executados_sem_humano + " foram executados sozinhos**. Depois que uma pessoa aprovou um pedido pelo comando `approve`, passou a haver " + ai2.executados_apos_aprovacao + " execução. Chamar a ação direto levanta erro (`chamada_direta_bloqueada = " + (ai2.chamada_direta_bloqueada ? "verdadeiro" : "falso") + "`)."));
c.push(H2("8.3 E se isso valesse no dia do incidente?"));
c.push(P("Repetimos os logs do INC-VA-0712 diante das regras novas (`lab/replay_detection.py`). A regra A teria disparado às **" + rp.regras_que_disparariam.A_VPN_LOGIN_ANOMALO.primeiro_alerta_utc + " UTC**, já no login na VPN sem MFA, e o IP do atacante seria bloqueado nesse instante. As " + rp.requisicoes_sqli_do_atacante + " requisições de SQL Injection (a partir das 02:12) e a mudança da bomba (02:20) viriam depois do bloqueio. Já a regra B sozinha teria disparado às " + rp.regras_que_disparariam.B_SQL_INJECTION.primeiro_alerta_utc + ", e a D às " + rp.regras_que_disparariam.D_ATUADOR_FORA_DO_PERFIL.primeiro_alerta_utc + "."));
c.push(P("É uma estimativa, não um fato: ela supõe que o SOAR reage no mesmo instante do evento (no teste ao vivo foi menos de 1 s) e que o bloqueio de IP funciona de verdade no firewall."));

// ---------- 9 ----------
c.push(H1("9. Teste de caos: WAN fora por 30 minutos"));
c.push(P("Rodamos duas vezes, uma acelerada (relógio virtual) e outra em tempo real. Montamos a linha do tempo de 37 minutos: 3 minutos normais, 30 minutos sem WAN e 4 minutos de volta. Quatro sensores mandavam uma leitura por segundo cada. No minuto 13, durante a queda, a câmara fria \"quebrou\" (subiu uns 6 °C). Na volta da rede, simulamos 20% dos acks perdidos no primeiro minuto."));
c.push(TABLE(["Indicador", "Resultado"], [
  ["Leituras produzidas", String(ch.leituras_produzidas)],
  ["Leituras únicas na nuvem", String(ch.leituras_unicas_na_nuvem)],
  ["Perda na reconciliação", ch.perda_na_reconciliacao + " (" + ch.perda_percentual + "%)"],
  ["Repetidos descartados pela nuvem", String(ch.repetidos_descartados_pela_nuvem)],
  ["Pendentes no buffer no fim", String(ch.pendentes_no_buffer_no_fim)],
  ["Alarme local da câmara fria", "No minuto " + ch.alarme_local_no_minuto + ", " + ch.atraso_do_alarme_local_s + " s depois da falha"],
  ["Sistema antigo (depende da nuvem)", ch.alarme_no_sistema_legado],
  ["SMS na fila para sair quando houver 4G ou WAN", String(ch.sms_na_fila_para_enviar_quando_der)],
  ["Maior tempo de uma sincronização", ch.tempo_para_esvaziar_buffer_s_cpu + " s"],
  ["CPU do processo e RAM máxima", ch.cpu_segundos_processo + " s e " + ch.ram_max_processo_mb + " MB (VM de 2 vCPU, não é Raspberry Pi)"],
], [4600, 5038]));
c.push(SP());
c.push(H2("9.1 Análise crítica"));
c.push(B("**O que mostra:** com a regra local, a falha da câmara fria foi percebida em 2 segundos, mesmo sem internet. No sistema antigo, o alerta só sairia **20 minutos depois** da falha (minuto 33), quando a WAN voltou. Essa é a lição do incidente."));
c.push(B("**Tempo real:** repetimos o teste em tempo real (37 min de relógio, " + RT.tempo_real_do_teste_s + " s). Resultado igual: " + RT.leituras_produzidas + " produzidas, " + RT.leituras_unicas_na_nuvem + " na nuvem, perda " + RT.perda_na_reconciliacao + ", " + RT.repetidos_descartados_pela_nuvem + " repetidos descartados, alarme local em " + RT.atraso_do_alarme_local_s + " s, CPU de " + RT.cpu_segundos_processo + " s e RAM máxima de " + RT.ram_max_processo_mb + " MB. Arquivo: `results/chaos_real.json`. A tabela acima vem da corrida acelerada."));
c.push(B("**Limite 2:** a \"nuvem\" é uma classe Python e a WAN é uma variável. Não derrubamos uma interface de rede de verdade. O 4G também não foi simulado: o SMS ficou na fila."));
c.push(B("**Limite 3:** o buffer foi SQLite em memória. Não testamos queda de energia do nó (o que acontece com o buffer se desligar na tomada)."));
c.push(B("**Limite 4:** o dado perdido, na prática, também depende do tamanho do buffer. Em 30 minutos foram 7.200 leituras. Para quedas de dias, é preciso calcular o disco e decidir o que descartar."));

// ---------- 10 ----------
c.push(H1("10. IA defensiva: Isolation Forest"));
c.push(P("Geramos 14 dias de telemetria sintética (uma leitura a cada 5 minutos), treinamos com os 10 primeiros dias só com comportamento normal e testamos nos 4 últimos, com 8 eventos anômalos marcados: porta da câmara aberta, bomba ligada de madrugada com nível caindo (como no incidente), pico de energia e sensor travado. Testamos três valores do parâmetro `contamination`."));
const a1 = ai["contamination_0.01"], a2 = ai["contamination_0.02"], a5 = ai["contamination_0.05"];
c.push(TABLE(["Parâmetro", "Precisão", "Revocação", "F1", "Falsos positivos", "Taxa de FP", "Alarmes por dia", "Eventos detectados"], [
  ["0,01", String(a1.precisao), String(a1.revocacao), String(a1.f1), String(a1.falsos_positivos), a1["taxa_falso_positivo_%"] + "%", String(a1.alarmes_por_dia), a1.janelas_detectadas + " de " + ai.janelas_anomalas],
  ["0,02", String(a2.precisao), String(a2.revocacao), String(a2.f1), String(a2.falsos_positivos), a2["taxa_falso_positivo_%"] + "%", String(a2.alarmes_por_dia), a2.janelas_detectadas + " de " + ai.janelas_anomalas],
  ["0,05", String(a5.precisao), String(a5.revocacao), String(a5.f1), String(a5.falsos_positivos), a5["taxa_falso_positivo_%"] + "%", String(a5.alarmes_por_dia), a5.janelas_detectadas + " de " + ai.janelas_anomalas],
], [1100, 1050, 1100, 800, 1200, 1100, 1300, 1988], { size: 16 }));
c.push(SP());
c.push(B("**Comparação:** uma regra fixa (temperatura acima de 8 °C) tem precisão " + ai.baseline_limite_fixo_8C.precisao + " e revocação de só " + ai.baseline_limite_fixo_8C.revocacao + ". Ela acerta o que pega, mas deixa passar quase tudo."));
c.push(B("**Trade-off:** subir a sensibilidade pega mais eventos, mas aumenta os alarmes. Com 0,05 são cerca de " + a5.alarmes_por_dia + " alarmes por dia. Isso é muito para voluntários. Por isso a IA **só avisa** e não age sozinha."));
c.push(B("**O que não foi detectado:** o pico de energia curto (6 a 8 amostras) escapou na maioria das configurações. Os eventos mais longos foram pegos."));
c.push(B("**Limite grande:** os dados são sintéticos e as anomalias foram escritas por nós. Os números são **otimistas** e não valem como desempenho no mundo real."));

// ---------- 11 ----------
c.push(H1("11. O que ficou pendente"));
c.push(TABLE(["Item", "O que falta"], [
  ["VPN e segmentação", "Rodar WireGuard e nftables e anexar `wg show` e `nmap`"],
  ["Mosquitto real", "Subir o `docker compose` e repetir o teste de mTLS e a revogação"],
  ["Wazuh", "Carregar as regras XML e testar os alertas"],
  ["Phishing", "Rodar a campanha com o Gophish nas duas rodadas e preencher a tabela da seção 6"],
    ["Acessibilidade", "Rodar Lighthouse ou axe no painel"],
  ["Prompt injection", "Não se aplica enquanto não houver LLM"],
], [3000, 6638]));
c.push(SP());
c.push(P("Uso de IA: veja a seção 18 do E1. [[Repetir ou ajustar aqui o que o grupo decidir]]"));

build("GS2026.2 E3 Relatório de Testes", c, path.join(ROOT, "reports", "GS2026.2_TURMA_GXX_E3.docx"));
