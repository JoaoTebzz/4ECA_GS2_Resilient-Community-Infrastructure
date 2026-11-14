const path = require("path");
const L = require("./lib");
const { P, H1, H2, H3, B, N, SP, BR, CODE, TABLE, IMG, cover, build, R, brl, ROOT } = L;
const RT = R("chaos_real"), chaos = R("chaos"), ai = R("ai"), det = R("detect"), mtls = R("mtls");

const c = [];
c.push(...cover("Documento de Arquitetura", "Infraestrutura segura e resiliente para a Rede Vila Aurora", "E1 · Documento de Arquitetura"));
c.push(BR());

// ---------------- 1 ----------------
c.push(H1("1. Resumo"));
c.push(P("A Rede Vila Aurora tem cinco espaços (Centro Comunitário, Escola, UBS, Horta e Cozinha, Abrigo) que dependem de energia, água, acesso e sensores ambientais. No incidente INC-VA-0712 um e-mail falso, uma VPN só com senha e um painel com SQL Injection deixaram o atacante mexer na bomba da escola. Para piorar, a fibra caiu e a câmara fria das vacinas ficou sem alerta."));
c.push(P("Nosso projeto troca a ideia de \"tudo depende da nuvem\" por uma arquitetura em quatro camadas (campo, borda, nuvem e supervisão), em que **cada espaço tem um nó de borda que continua funcionando sozinho** quando a internet cai. Cada dispositivo tem o próprio certificado, a ligação entre borda e nuvem usa WireGuard, a rede é dividida em segmentos, o painel foi refeito sem SQL Injection e os logs vão para um SIEM com relógio sincronizado."));
c.push(P("Fizemos um protótipo e testamos o que foi possível testar. Os números principais estão na seção 15. Em resumo, no teste de caos o nó de borda ficou 30 minutos sem WAN, disparou o alarme da câmara fria em " + chaos.atraso_do_alarme_local_s + " segundos, e na volta da rede não perdeu nenhuma leitura (" + chaos.leituras_produzidas + " de " + chaos.leituras_unicas_na_nuvem + " chegaram). As quatro regras de detecção pegaram os " + det.eventos_maliciosos_injetados + " eventos maliciosos que injetamos, com tempo médio de detecção de " + det.mttd_geral_s + " s."));
c.push(P("Este documento também diz o que **não** testamos de verdade e por quê (seção 17). Preferimos ser honestos sobre os limites."));

// ---------------- 2 ----------------
c.push(H1("2. O que deu errado no INC-VA-0712 e qual controle responde"));
c.push(P("Começamos pelo modelo de ameaças, como o professor sugeriu. Relemos o incidente e listamos cada falha. Cada linha da tabela abaixo aponta o controle da nossa arquitetura que fecha aquela porta."));
c.push(TABLE(["#", "Falha no incidente", "Controle no projeto", "Seção"], [
  ["F1", "E-mail e áudio falsos, bem escritos, gerados com IA", "SPF, DKIM e DMARC no nosso domínio, aviso de domínio parecido, treinamento, palavra-código e verificação por outro canal", "9"],
  ["F2", "VPN antiga só com senha, sem MFA", "WireGuard com chave por nó e acesso de pessoas por bastião com MFA (TOTP)", "7"],
  ["F3", "Painel com SQL Injection no histórico de acessos", "Consulta parametrizada, validação, banco só leitura, erro genérico, filtro extra (WAF)", "8"],
  ["F4", "Painel e VPN sem separação de rede", "Segmentos IoT, operadores e administração com política padrão DROP", "7"],
  ["F5", "Atacante mudou a agenda da bomba e ninguém percebeu", "Regra D do SIEM, modo seguro automático e aprovação humana para desligar bomba", "10"],
  ["F6", "Fibra caiu e a câmara fria ficou sem alerta", "Regra local no nó de borda, buffer e sincronização depois", "5"],
  ["F7", "Logs espalhados, relógios errados, parte sobrescrita", "NTP em tudo, coleta central, retenção definida, hash na coleta", "10"],
  ["F8", "Dados de voluntários e moradores vazaram", "Minimização, pseudonimização, perfil auditor com nomes mascarados, RIPD", "13"],
], [500, 3000, 5200, 938]));
c.push(SP());

// ---------------- 3 ----------------
c.push(H1("3. Arquitetura em camadas"));
c.push(...IMG("arquitetura.png", 560, 404, "Figura 1. Camadas da Rede Vila Aurora"));
c.push(TABLE(["Camada", "O que faz", "Componentes"], [
  ["Campo", "Mede e age sobre equipamentos", "Sensores de nível, cloro, turbidez, temperatura, alagamento, medidor de energia, fechaduras RFID/QR, relé da bomba (ESP32 ou simulados em contêiner)"],
  ["Borda", "Opera sozinha em cada espaço, aplica regras locais, guarda e reenvia dados", "Raspberry Pi por espaço com Mosquitto (mTLS), regras de controle, buffer SQLite, agente de logs, roteador 4G"],
  ["Nuvem", "Reúne histórico, SIEM, IA, banco e CA", "VM com Wazuh, painel e banco, serviço de IA, CA do projeto e lista de revogação"],
  ["Supervisão", "Mostra, avisa e deixa o humano decidir", "Painel web acessível, alertas por e-mail e mensagem, console do SOC com fila de aprovação"],
], [1400, 3200, 5038]));
c.push(SP());
c.push(H2("3.1 Fluxo de dados"));
c.push(N("O sensor lê o valor e publica no broker MQTT do nó de borda do seu espaço, usando mTLS (certificado do dispositivo)."));
c.push(N("O nó de borda grava a leitura no buffer local, confere as regras locais (por exemplo, câmara fria acima de 8 °C por 3 leituras seguidas) e aciona o alarme local se precisar."));
c.push(N("Se a WAN está de pé, o nó envia lotes para a nuvem pela VPN WireGuard. Cada leitura tem uma chave única (dispositivo + número de sequência), então repetição não vira dado duplicado."));
c.push(N("Os logs do broker, da VPN, do painel e do sistema vão para o SIEM. O SIEM aplica as regras e chama o SOAR."));
c.push(N("O SOAR faz sozinho as ações de baixo risco. Ações de alto impacto viram um pedido que um humano aprova no console."));
c.push(N("O painel mostra o estado para os voluntários. Operadores entram com senha e MFA, e cada perfil vê só o que precisa."));
c.push(H2("3.2 Decisões e trade-offs"));
c.push(TABLE(["Decisão", "Por que", "O que perdemos"], [
  ["Um nó de borda por espaço (e não um servidor central)", "Se a fibra ou um nó cair, os outros quatro espaços seguem", "Cinco equipamentos para manter em vez de um"],
  ["MQTT local com mTLS", "Padrão leve para IoT, e o certificado dá identidade por dispositivo", "Precisa de uma CA e de rotina de renovação"],
  ["WireGuard em vez de IPsec", "Configuração curta, cifras modernas fixas, fácil para voluntários técnicos manterem", "Não tem MFA nativo, por isso a MFA fica no bastião"],
  ["Wazuh como SIEM", "Open source, tem agente, regras e resposta ativa", "Pede VM com mais memória (usamos 4 vCPU e 8 GB na estimativa)"],
  ["SQLite no protótipo, PostgreSQL em produção", "SQLite roda em qualquer máquina de aluno", "O teste de privilégio mínimo no protótipo é por conexão somente leitura, não por papel do banco"],
  ["Sem LLM no sistema", "Menos superfície de ataque (seção 12)", "Sem assistente em linguagem natural para o operador"],
], [2900, 3700, 3038]));
c.push(SP());

// ---------------- 4 ----------------
c.push(H1("4. Modularidade"));
c.push(P("Cada parte pode ser trocada sem mexer nas outras, porque conversam por contratos simples:"));
c.push(B("**Campo ↔ borda:** tópicos MQTT no formato `va/<dispositivo>/telemetria` e `va/<dispositivo>/comando`. Trocar um sensor real por um simulado não muda nada na borda."));
c.push(B("**Borda ↔ nuvem:** lotes de leituras com chave (dispositivo, seq). Qualquer nuvem que aceite esse lote serve."));
c.push(B("**Detecção ↔ resposta:** o detector só gera um alerta com a regra e os campos. O SOAR tem um playbook por regra. Dá para trocar o `siem/detect.py` pelo Wazuh sem mudar o SOAR (as regras do Wazuh estão em `siem/wazuh_local_rules.xml`)."));
c.push(B("**Painel ↔ banco:** o painel só usa consultas parametrizadas e uma conexão de leitura separada da de escrita."));

// ---------------- 5 ----------------
c.push(H1("5. Operação local quando a internet cai (RT-01, RT-02)"));
c.push(P("O nó de borda foi pensado para não precisar da nuvem em nada que seja crítico para a vida ou a saúde:"));
c.push(TABLE(["Função", "Onde roda", "Depende da nuvem?"], [
  ["Alarme da câmara fria (acima de 8 °C por 3 leituras)", "Nó de borda da UBS", "Não"],
  ["Ligar a bomba com nível abaixo de 20% e desligar acima de 90%", "Nó de borda de cada espaço", "Não"],
  ["Abrir fechadura com crachá válido (lista local de crachás)", "Nó de borda", "Não (lista sincronizada quando há rede)"],
  ["Sirene e aviso local de alagamento no abrigo", "Nó de borda do abrigo", "Não"],
  ["Envio de SMS e e-mail de alerta", "Nó de borda (fila) e 4G", "Usa 4G, e fica na fila se tudo estiver fora"],
  ["Histórico, painel central, SIEM, IA", "Nuvem", "Sim (fica atrasado, mas nada se perde)"],
], [4200, 2800, 2638]));
c.push(SP());
c.push(P("**Store-and-forward.** Toda leitura entra no buffer com um número de sequência por dispositivo. Quando a WAN volta, o nó envia em lotes de 500. A nuvem ignora o que já recebeu. Se a confirmação (ack) se perde, o nó reenvia e a nuvem descarta o repetido. No teste simulamos 20% de acks perdidos no primeiro minuto depois da volta da rede, e a nuvem descartou " + chaos.repetidos_descartados_pela_nuvem + " repetidos sem perder nenhuma leitura."));
c.push(P("**Reconciliação.** A conta é simples: leituras produzidas menos leituras únicas na nuvem. No teste foi " + chaos.perda_na_reconciliacao + " (" + chaos.perda_percentual + "%)."));

// ---------------- 6 ----------------
c.push(H1("6. Redundância proporcional (RT-03)"));
c.push(P("O orçamento é pequeno e a manutenção é de voluntários. Então não montamos cluster em várias regiões. Escolhemos redundância onde uma falha machuca mais:"));
c.push(TABLE(["Item", "Tem redundância?", "Como ou por que não"], [
  ["Link de internet", "Sim", "Fibra comunitária + roteador 4G em cada nó. Se os dois caírem, entra o modo degradado (seção 5)"],
  ["Energia do nó de borda", "Parcial", "Mini no-break de 12 V por nó. Cobre algumas horas. O gerador do abrigo já existe e não faz parte do nosso escopo"],
  ["Dados de telemetria", "Sim", "Buffer local no nó + cópia na nuvem + backup diário do banco"],
  ["Alarme da câmara fria", "Sim", "Alarme local sonoro, luz e SMS pela fila do 4G"],
  ["Nó de borda", "Não", "Um nó por espaço. Se um quebrar, o espaço perde automação, mas as regras mínimas de segurança (bomba manual, alarme sonoro por sensor com bateria) ficam. Comprar um nó reserva para o grupo de cinco é a alternativa mais barata (já está na estimativa de reposição)"],
  ["Nuvem (VM do SIEM e painel)", "Não", "Uma VM só, com snapshot e backup. Se cair, a operação local continua e o SIEM volta a processar o buffer quando voltar"],
  ["CA do projeto", "Não", "Chave raiz guardada offline, com cópia em local separado. Só é usada para emitir ou revogar"],
  ["Fechaduras", "Não", "Se faltar energia e rede, valem chaves físicas guardadas pela coordenação"],
], [2300, 1500, 5838]));
c.push(SP());
c.push(P("**Modo degradado documentado:** sem WAN, sem 4G e sem nuvem, cada espaço funciona com as regras locais, alarme sonoro e anotação em papel. Quando a rede volta, a sincronização cuida do resto."));

// ---------------- 7 ----------------
c.push(H1("7. Identidade, VPN e segmentação (RT-04 a RT-07)"));
c.push(H2("7.1 Identidade por dispositivo e mTLS"));
c.push(B("A CA do projeto (EC P-256) emite um certificado X.509 **por dispositivo**, com o nome do dispositivo no CN. Não existe segredo compartilhado entre dispositivos."));
c.push(B("O Mosquitto exige certificado de cliente (`require_certificate true`), usa o CN como usuário (`use_identity_as_username true`) e confere a lista de revogação."));
c.push(B("A ACL dá a cada dispositivo permissão só no próprio tópico. Um sensor de temperatura não consegue mandar comando para o relé."));
c.push(B("Certificado vale 365 dias. A renovação é feita com 30 dias de folga (ver plano de manutenção)."));
c.push(B("**Revogação:** `pki/revoke.sh <dispositivo>` revoga o certificado e publica a nova CRL. No teste, o dispositivo revogado passou a ser recusado logo depois (" + mtls["6_tempo_revogar_e_publicar_s"] + " s para revogar e publicar) e os outros continuaram aceitos."));
c.push(B("**Rotação de credenciais:** certificados de dispositivo em 12 meses, chaves WireGuard em 12 meses, senhas de operador por troca sob demanda e MFA obrigatória."));
c.push(H2("7.2 VPN"));
c.push(P("A ligação borda e nuvem usa **WireGuard** (ChaCha20-Poly1305, Curve25519), com chave por nó e chave pré-compartilhada por par. A única porta aberta para a internet em cada nó é UDP 51820. Nenhuma porta administrativa (SSH, painel, banco, MQTT) fica exposta."));
c.push(P("O WireGuard autentica a **máquina**, não a pessoa. Por isso o acesso administrativo de pessoas passa por um **bastião (ZTNA simples)** dentro da VPN, com login individual e TOTP. A VPN antiga só com senha foi desativada."));
c.push(H2("7.3 Segmentação"));
c.push(...IMG("segmentacao.png", 520, 250, "Figura 2. Segmentos de rede em cada espaço"));
c.push(P("Regras principais do `infra/nftables.conf` (política padrão DROP):"));
c.push(B("IoT só fala MQTT 8883 com o nó de borda. IoT nunca inicia conexão para operadores nem administração."));
c.push(B("Operadores acessam o painel local (443) e não conversam direto com o IoT. Comando para atuador passa sempre pela borda."));
c.push(B("Administração (SSH) só vem do segmento de administração ou da VPN."));
c.push(B("Existe uma `blocklist` que o SOAR alimenta para bloquear IP atacante."));

// ---------------- 8 ----------------
c.push(H1("8. Segurança do painel (RT-08, RT-09)"));
c.push(P("Mantivemos duas versões: `panel/app_vulnerable.py` (o painel do incidente, só para o laboratório) e `panel/app_fixed.py` (o corrigido). O que mudou:"));
c.push(TABLE(["Problema no legado", "Correção"], [
  ["SQL montado com texto (`LIKE '%…%'`)", "Consulta parametrizada (`LIKE ?`) em todos os pontos"],
  ["Sem validação do que o usuário digita", "Lista de caracteres permitidos (letras, espaço, ponto, hífen, apóstrofo) e limite de 40 caracteres, validados no servidor"],
  ["Banco com poder total", "Buscas usam uma conexão somente leitura. Só a rota da bomba usa conexão de escrita. Em produção: papéis separados no PostgreSQL (leitura, escrita restrita), sem DDL"],
  ["Erro mostrava a consulta", "Resposta genérica com código da ocorrência. O detalhe fica só no log"],
  ["Login só com senha, hash SHA-256 sem sal", "scrypt com sal e MFA TOTP (RFC 6238)"],
  ["Todo mundo via tudo", "RBAC com quatro perfis: operador, técnico, coordenação e auditor. O auditor vê nomes mascarados"],
  ["Sem camada extra", "Filtro tipo WAF (defesa em profundidade) e cabeçalhos de segurança (CSP, nosniff, no-store). Em produção usaríamos ModSecurity na frente"],
], [3800, 5838]));
c.push(SP());
c.push(P("O filtro WAF do protótipo é uma lista de padrões simples e pode ser contornado. Ele é só uma camada extra. A **causa raiz** foi corrigida na parametrização, e provamos isso desligando o filtro e a validação e repetindo os ataques (relatório E3)."));

// ---------------- 9 ----------------
c.push(H1("9. Phishing, voz clonada e fator humano (RT-10, RT-11, RT-18)"));
c.push(H2("9.1 Controles técnicos"));
c.push(B("Domínio fictício do projeto: `vilaaurora.example` (o sufixo .example é reservado e nunca resolve na internet)."));
c.push(B("**SPF** com `-all` e só o IP do nosso servidor de e-mail. **DKIM** com chave RSA de 2048 bits (seletor `va2026`). **DMARC** com `p=quarantine`, alinhamento estrito e relatório para uma caixa nossa."));
c.push(B("No incidente o e-mail veio de um **domínio parecido** (`prefeitura-serraclara.example`). SPF, DKIM e DMARC protegem o **nosso** domínio contra falsificação, mas não impedem alguém de registrar um domínio parecido. Para isso usamos: aviso automático em e-mails de fora (\"EXTERNO\"), lista de domínios parecidos monitorada, e regra de que **pedido de acesso nunca vale por link**: sempre se entra digitando o endereço do painel ou usando o favorito."));
c.push(B("MFA no painel e no bastião reduz o estrago se uma senha vazar."));
c.push(H2("9.2 Ameaças com IA presentes no cenário (RT-18)"));
c.push(TABLE(["Ameaça", "Por que é perigosa", "Controle"], [
  ["E-mail sem erros e personalizado, feito por IA", "O sinal clássico (erro de português) sumiu", "Não confiar no texto. Conferir o remetente e o domínio. Pedido de acesso só pelo favorito. Botão de reportar"],
  ["Áudio de WhatsApp com a voz clonada do secretário", "A pessoa reconhece a voz e se sente segura", "**Verificação fora de banda:** ligar de volta para um número já conhecido. **Palavra-código** combinada com a prefeitura para pedidos urgentes. Voz sozinha nunca autoriza nada"],
  ["Urgência (\"obrigatório\", \"hoje\")", "Faz a pessoa pular a conferência", "Regra: pedido urgente é motivo para **desconfiar mais**. Dois minutos de conferência valem a pena"],
  ["Credencial digitada em página falsa", "Dá acesso direto", "MFA, bloqueio de login anômalo (regra A) e VPN sem senha reaproveitável"],
], [2900, 2700, 4038]));
c.push(SP());
c.push(H2("9.3 Conscientização para voluntários"));
c.push(P("A maioria dos voluntários não é técnica. O treinamento tem 30 minutos, em linguagem simples, e fala de três hábitos: (1) não clicar em link de pedido de acesso, (2) ligar de volta antes de obedecer a um áudio ou pedido urgente, (3) apertar o botão de reportar na dúvida. Entregamos um cartão de bolso com a palavra-código e o telefone de conferência. A campanha simulada (Gophish, só com contas fictícias da equipe) mede abertura, clique, envio de dados e reporte antes e depois do treinamento (ver E3)."));

// ---------------- 10 ----------------
c.push(H1("10. Logs, detecção, resposta e forense (RT-12 a RT-15)"));
c.push(H2("10.1 Coleta central"));
c.push(B("Fontes: dispositivos e broker (`mqtt`), VPN, painel (`web`), banco, sistema operacional e atuadores. Todas em JSON com hora UTC em milissegundos."));
c.push(B("**NTP em tudo** (chrony apontando para dois servidores) e alerta se um relógio se afastar mais de 1 s. A lição do incidente: a VPN antiga estava adiantada 3 min 12 s na nossa reprodução e isso quase estragou a linha do tempo."));
c.push(B("**Retenção:** 90 dias no SIEM (busca rápida) e 12 meses em arquivo compactado, com SHA-256 registrado. Logs com dados pessoais são pseudonimizados (seção 13)."));
c.push(B("O Wazuh tem as regras em `siem/wazuh_local_rules.xml`. No laboratório usamos `siem/detect.py` com a mesma lógica, para poder medir MTTD e MTTR."));
c.push(H2("10.2 As quatro regras (RT-13)"));
c.push(TABLE(["Regra", "O que detecta", "Condição"], [
  ["A", "Login VPN anômalo", "Login com sucesso sem MFA, ou IP fora da lista, ou fora do horário (06h às 22h UTC no laboratório)"],
  ["B", "Padrão de SQL Injection", "Consulta com `UNION SELECT`, aspas seguidas de OR/AND, `--`, `;`, `sqlite_master`, `sleep(` etc."],
  ["C", "Dispositivo sem certificado válido", "Handshake TLS falhou ou CN fora da lista de dispositivos"],
  ["D", "Comando de atuador fora do perfil", "Comando de agenda fora de 06h às 20h UTC ou com origem diferente de `painel` ou `regra_local`"],
], [900, 2800, 5938]));
c.push(SP());
c.push(H2("10.3 Respostas automáticas e aprovação humana (RT-15)"));
c.push(P("Separamos as ações por risco, como o professor recomendou. Se errar, uma ação de baixo risco só incomoda. Uma de alto impacto pode machucar alguém (desligar a bomba durante uma enchente, por exemplo)."));
c.push(TABLE(["Ação", "Risco", "Como roda"], [
  ["Bloquear IP", "Baixo", "Automática (entra na `blocklist` do nftables)"],
  ["Encerrar sessão VPN", "Baixo", "Automática"],
  ["Isolar dispositivo", "Baixo", "Automática (vai para segmento de quarentena)"],
  ["Revogar certificado", "Baixo", "Automática (revoga e publica nova CRL)"],
  ["Colocar atuador em modo seguro", "Baixo", "Automática. Modo seguro = o nó ignora a agenda remota e usa só as regras locais de nível"],
  ["Desligar a bomba", "**Alto**", "Só com aprovação humana no console"],
  ["Liberar todas as portas (fechaduras)", "**Alto**", "Só com aprovação humana"],
  ["Desativar a VPN de um site", "**Alto**", "Só com aprovação humana"],
], [3600, 1300, 4738]));
c.push(SP());
c.push(P("No código, o SOAR (`soar/soar.py`) levanta um erro se alguém tentar rodar uma ação de alto impacto direto. O único caminho é `request_approval` seguido de `approve`, que registra quem aprovou."));
c.push(H2("10.4 Forense"));
c.push(P("O processo está no laudo (E4): copiar com hash SHA-256 na origem e na cópia, registrar na cadeia de custódia (quem, quando, onde, como), guardar em modo somente leitura, corrigir os relógios e montar a linha do tempo com mapeamento MITRE ATT&CK. A verificação (`forensics/collect.py verify`) recalcula os hashes e acusa qualquer mudança."));

// ---------------- 11 ----------------
c.push(H1("11. Modelo de ameaças (STRIDE) com rastreabilidade"));
c.push(TABLE(["Ameaça (STRIDE)", "Exemplo no projeto", "Controle", "Teste/Evidência"], [
  ["S: Falsificação", "Sensor falso mandando leituras", "Certificado por dispositivo, mTLS, ACL por tópico", "E3 seção 3"],
  ["S: Falsificação", "E-mail e voz falsos do secretário", "SPF/DKIM/DMARC, palavra-código, verificação fora de banda", "E3 seções 5 e 6"],
  ["T: Adulteração", "Agenda da bomba alterada por SQLi", "Parametrização, regra D, modo seguro, aprovação humana", "E3 seções 2 e 8"],
  ["T: Adulteração", "Log alterado depois do ataque", "Cofre somente leitura, SHA-256, cadeia de custódia", "E4 seção 5"],
  ["R: Repúdio", "Operador nega que mexeu na bomba", "Log do atuador com `by` pseudonimizado e MFA individual", "E3 seção 8"],
  ["I: Vazamento", "Tabela de usuários extraída", "Consulta parametrizada, perfil auditor mascarado, minimização", "E3 seção 2"],
  ["D: Negação de serviço", "Fibra cai e câmara fria fica sem alerta", "Regras locais, buffer, 4G", "E3 seção 9"],
  ["E: Elevação de privilégio", "Voluntário vira administrador", "RBAC, MFA, menor privilégio no banco, segmentação", "E3 seção 2"],
], [1800, 2600, 3300, 1938]));
c.push(SP());

// ---------------- 12 ----------------
c.push(H1("12. IA e cibersegurança (RT-16, RT-17)"));
c.push(H2("12.1 Uso defensivo: Isolation Forest"));
c.push(P("Usamos Isolation Forest (scikit-learn) sobre a telemetria (temperatura da câmara, nível, energia, bomba, hora do dia e variações). Treinamos só com dados normais e testamos em dados com anomalias marcadas. A bomba ligada de madrugada com o nível caindo imita o INC-VA-0712. Os números estão no relatório E3. Como a regra fixa de 8 °C só pega temperatura alta, ela pega bem pouco do que o modelo pega."));
c.push(P("Resultado resumido (contamination 0,05): detectou " + ai["contamination_0.05"].janelas_detectadas + " das " + ai.janelas_anomalas + " janelas anômalas, com precisão de " + ai["contamination_0.05"].precisao + " e revocação de " + ai["contamination_0.05"].revocacao + " por amostra. A taxa de falso positivo foi " + ai["contamination_0.05"]["taxa_falso_positivo_%"] + "%. É um **apoio** à decisão humana, não um gatilho automático."));
c.push(H2("12.2 Por que não usamos LLM"));
c.push(P("O RT-17 só vale se houver LLM, e **decidimos não colocar um**. Motivos: o ganho para voluntários seria pequeno perto do risco, e um LLM abre novas portas (prompt injection direto e indireto por e-mail ou documento, vazamento de dados). Se o grupo vier a adicionar um assistente ou triagem de e-mail, as regras de projeto já ficam definidas:"));
c.push(B("O LLM **nunca** aciona atuador. Ele só sugere texto. Nenhuma ação passa por ele."));
c.push(B("Entradas externas (e-mail, anexo) são tratadas como dados, nunca como instrução, e entram em um campo separado do prompt."));
c.push(B("Sem acesso a banco de usuários nem a segredos. Saída filtrada para não repetir dados pessoais."));
c.push(B("Riscos mapeados: OWASP Top 10 para LLM (prompt injection, divulgação de informação sensível, agência excessiva) e MITRE ATLAS (injeção de prompt, extração de dados). Testar com ferramentas como o `garak` antes de afirmar que está protegido."));

// ---------------- 13 ----------------
c.push(H1("13. Privacidade desde a concepção (LGPD) e RIPD simplificado (RT-19)"));
c.push(P("Todos os dados do protótipo são **sintéticos**. A tabela abaixo é o RIPD simplificado do sistema real que o projeto desenha."));
c.push(TABLE(["Item", "Descrição"], [
  ["Dados tratados", "Nome, e-mail e telefone de voluntários e moradores, registro de entradas (data, espaço, resultado), nome de usuário de operadores. Não tratamos dado de saúde de pacientes: a UBS guarda isso em outros sistemas, fora deste escopo. A temperatura da câmara é dado de equipamento"],
  ["Finalidade", "Controlar acesso aos espaços, proteger equipamentos e investigar incidentes"],
  ["Base legal", "Legítimo interesse da associação para segurança dos espaços (art. 7º, IX). Para o uso do abrigo pela Defesa Civil, execução de política pública (art. 7º, III). [[Confirmar com o jurídico da associação]]"],
  ["Minimização", "Só os campos necessários. O log de acesso guarda um código no lugar do nome. Câmeras e biometria não fazem parte do projeto"],
  ["Pseudonimização", "Nos logs e no SIEM o usuário aparece como `HMAC-SHA256(chave, usuario)` (10 primeiros caracteres). A chave fica separada do SIEM. O auditor vê nomes mascarados (A***)"],
  ["Retenção", "Registro de acesso: 6 meses. Cadastro de voluntário: enquanto estiver ativo + 6 meses. Logs de segurança: 90 dias no SIEM + 12 meses em arquivo (com pseudônimo)"],
  ["Riscos", "Vazamento da tabela de usuários; reidentificação pelo pseudônimo se a chave vazar; acesso indevido pelo perfil errado; retenção além do necessário"],
  ["Mitigações", "Parametrização e menor privilégio; chave do pseudônimo separada; RBAC e MFA; rotina de exclusão automática; backup cifrado; direitos do titular atendidos pela coordenação"],
  ["Direitos do titular", "Pedido de acesso, correção e exclusão pela coordenação em até 15 dias. Encarregado: [[nome do encarregado]]"],
  ["Incidente", "Plano de resposta com aviso à ANPD e aos titulares quando houver risco relevante, conforme a LGPD"],
], [2200, 7438]));
c.push(SP());

// ---------------- 14 ----------------
c.push(H1("14. Custos, manutenção e acessibilidade (RT-20, RT-21)"));
c.push(H2("14.1 Estimativa de custos para 12 meses"));
const impl = [
  ["Nó de borda (Raspberry Pi 5 4 GB, fonte, caixa)", 5, 850],
  ["SSD ou cartão industrial 128 GB", 5, 200],
  ["Mini no-break 12 V para o nó", 5, 350],
  ["Roteador 4G com chip", 5, 450],
  ["Switch gerenciável com VLAN", 5, 300],
  ["Sensores e módulos ESP32 (6 por espaço)", 30, 90],
  ["Cabos, caixas e material de instalação", 1, 1500],
];
let tImpl = 0;
const rowsImpl = impl.map(([n, q, v]) => { tImpl += q * v; return [n, String(q), brl(v), brl(q * v)]; });
rowsImpl.push(["**Subtotal implantação**", "", "", "**" + brl(tImpl) + "**"]);
const hardware = 5 * 850 + 5 * 200 + 5 * 350 + 5 * 450 + 5 * 300 + 30 * 90;
const op = [
  ["Plano de dados 4G (5 chips × 12 meses)", 60, 40],
  ["VM em nuvem (4 vCPU, 8 GB) para SIEM e painel", 12, 350],
  ["Backup em armazenamento de objetos", 12, 30],
  ["Domínio e DNS", 1, 100],
  ["Reposição de peças (10% do hardware)", 1, Math.round(hardware * 0.1)],
  ["Treinamento (material impresso e cartões)", 1, 300],
];
let tOp = 0;
const rowsOp = op.map(([n, q, v]) => { tOp += q * v; return [n, String(q), brl(v), brl(q * v)]; });
rowsOp.push(["**Subtotal operação (12 meses)**", "", "", "**" + brl(tOp) + "**"]);
c.push(TABLE(["Implantação", "Qtd", "Unitário", "Total"], rowsImpl, [5200, 800, 1700, 1938]));
c.push(SP());
c.push(TABLE(["Operação em 12 meses", "Qtd", "Unitário", "Total"], rowsOp, [5200, 800, 1700, 1938]));
c.push(SP());
c.push(P("**Total estimado: " + brl(tImpl + tOp) + "** no primeiro ano. Os preços são estimativas de mercado (pesquisa de lojas e provedores) e precisam de orçamento formal. [[Atualizar com as cotações que o grupo conseguir]]. Todo o software é open source (Mosquitto, WireGuard, Wazuh, PostgreSQL, Gophish), sem custo de licença. Não contamos as horas dos voluntários. Fechaduras e gerador já existem e ficaram de fora."));
c.push(H2("14.2 Plano de manutenção"));
c.push(TABLE(["Tarefa", "Frequência", "Responsável"], [
  ["Atualizar sistema e pacotes dos nós de borda", "Mensal", "Técnico"],
  ["Atualizar firmware dos ESP32 com OTA assinado", "A cada 3 meses", "Técnico"],
  ["Renovar certificados dos dispositivos (validade 365 dias)", "Anual, com 30 dias de folga", "Técnico, com aprovação da coordenação"],
  ["Gerar CRL nova", "A cada 30 dias e sempre que revogar", "Técnico"],
  ["Rodar a CA offline (renovar CA em 5 anos)", "Quando preciso", "Coordenação guarda a chave"],
  ["Backup do banco (diário) e imagem do nó (semanal)", "Diário e semanal", "Técnico"],
  ["Teste de restauração do backup", "Trimestral", "Técnico e auditor"],
  ["Conferir NTP e saúde dos nós", "Semanal (alerta automático)", "Técnico"],
  ["Rever perfis e acessos (RBAC)", "Trimestral", "Coordenação e auditor"],
  ["Treinamento e campanha de phishing simulado", "Semestral", "Coordenação"],
  ["Teste de caos (derrubar a WAN por 30 minutos)", "Semestral", "Técnico"],
  ["Rotação de chaves WireGuard", "Anual", "Técnico"],
  ["Trocar baterias do no-break", "A cada 2 anos", "Técnico"],
], [4700, 2500, 2438]));
c.push(SP());
c.push(H2("14.3 Acessibilidade do painel"));
c.push(P("Referência: WCAG 2.1 nível AA. O que a página de entrada (`panel/app_fixed.py`, rota `/`) já faz:"));
c.push(B("Idioma declarado (`lang=\"pt-BR\"`), link \"Pular para o conteúdo\", e cada campo com `label` ligado ao `input`."));
c.push(B("Contraste medido: texto #111 sobre branco, **18,9:1**; botão branco sobre #0b4f8a, **8,4:1**; contorno de foco #0b4f8a, **8,4:1** (o mínimo do AA é 4,5:1 para texto e 3:1 para componentes). Na primeira versão o contorno era laranja e dava só 2,1:1, então trocamos."));
c.push(B("Tudo funciona só com teclado, com foco bem visível (contorno de 3 px). Alvos de toque com no mínimo 44 px de altura. Fonte de 18 px."));
c.push(B("Mensagens de erro em português simples, sem código (\"Usuário, senha ou código incorretos\")."));
c.push(P("Ainda falta rodar uma ferramenta automática (Lighthouse ou axe) e testar com leitor de tela e com dois voluntários reais. [[Registrar o resultado do Lighthouse ou axe aqui]]"));

// ---------------- 15 ----------------
c.push(H1("15. Métricas medidas no laboratório (RT-22, RT-23)"));
c.push(TABLE(["Indicador", "Resultado", "Como foi medido"], [
  ["Disponibilidade da operação local (nó de borda)", "100% (2220 de 2220 s processados)", "Teste de caos de 37 min (30 min sem WAN), repetido em tempo real"],
  ["Disponibilidade do link com a nuvem no teste", "18,9% (7 de 37 min)", "É o que o teste de caos impôs de propósito"],
  ["Tempo de operação autônoma sem internet", chaos.operacao_autonoma_min + " min", "Teste de caos"],
  ["Perda de dados na reconciliação", chaos.perda_na_reconciliacao + " leituras (" + chaos.perda_percentual + "%)", "Produzidas menos únicas na nuvem"],
  ["Alarme local da câmara fria", chaos.atraso_do_alarme_local_s + " s depois da falha", "Regra local da borda. O sistema antigo só alertaria depois da WAN voltar"],
  ["MTTD (detecção)", det.mttd_geral_s + " s em média, máximo 0,5 s", "Detector lendo logs a cada 0,5 s, 10 repetições × 4 regras"],
  ["MTTR automático (alerta até ação de baixo risco)", "menos de 0,01 s", "Do alerta até a ação gravada pelo SOAR"],
  ["Tempo de esvaziar o buffer na volta da WAN", chaos.tempo_para_esvaziar_buffer_s_cpu + " s (maior lote)", "Teste de caos"],
  ["CPU e memória do processo da borda", chaos.cpu_segundos_processo + " s de CPU na corrida inteira, RAM máx. " + chaos.ram_max_processo_mb + " MB", "Medido em VM de 2 vCPU. **Não** é um Raspberry Pi"],
  ["Banda", "cerca de 1,2 MB para 8880 leituras (130 bytes por leitura em JSON)", "Calculada, não medida na rede"],
  ["Energia do nó", "[[medir com wattímetro no Raspberry Pi]]", "Não medido"],
], [3200, 3200, 3238]));
c.push(SP());
c.push(P("**Teste em tempo real feito:** além da corrida acelerada, rodamos o mesmo teste em tempo real (37 min de relógio, " + RT.tempo_real_do_teste_s + " s). Resultado: " + RT.leituras_produzidas + " leituras produzidas, " + RT.leituras_unicas_na_nuvem + " na nuvem (perda " + RT.perda_na_reconciliacao + "), " + RT.repetidos_descartados_pela_nuvem + " repetidos descartados e alarme local " + RT.atraso_do_alarme_local_s + " s depois da falha. O arquivo é `results/chaos_real.json`. Os números da tabela acima vêm da corrida acelerada e batem com a de tempo real."));

// ---------------- 16 ----------------
c.push(H1("16. Cronograma e responsabilidades do grupo"));
c.push(P("[[Preencher quem do grupo ficou com cada parte: arquitetura, borda e PKI, painel e SQLi, SIEM e SOAR, forense, IA, phishing, documentação e vídeo]]. Todos precisam saber explicar qualquer parte do projeto."));

// ---------------- 17 ----------------
c.push(H1("17. Limitações (o que não fizemos ou não testamos)"));
c.push(B("**WireGuard, nftables, Mosquitto e Docker Compose:** escrevemos as configurações (pasta `infra/`), mas não rodamos no ambiente de desenvolvimento. No laboratório, o teste de mTLS e revogação usou um portão TLS em Python (`edge/mtls_gateway.py`) no lugar do Mosquitto. O grupo precisa subir os serviços reais e anexar as evidências."));
c.push(B("**Wazuh:** as regras XML não foram carregadas em um Wazuh real. A lógica foi testada no `siem/detect.py`."));
c.push(B("**Logs de VPN, e-mail, proxy, atuador e telemetria do incidente** foram gerados por script. Só o painel legado e o banco rodaram de verdade."));
c.push(B("**Phishing simulado:** o plano e o script de métricas estão prontos, mas os números da campanha dependem de rodar o Gophish. Campo marcado em amarelo no E3."));
c.push(B("**CPU e energia do Raspberry Pi e hardware real (ESP32):** pendentes. O teste de caos em tempo real foi feito, mas em uma VM e com a WAN simulada por variável, não por interface de rede derrubada."));
c.push(B("**LLM:** não usamos (decisão da seção 12.2)."));
c.push(B("**Captura de memória (Volatility):** não feita."));
c.push(B("O filtro WAF do protótipo é simples e contornável. Em produção usaríamos ModSecurity com regras OWASP CRS."));
c.push(B("A CSP do painel permite estilo embutido (`unsafe-inline`) só por causa do CSS da página de entrada. O ideal é mover o CSS para arquivo estático."));

// ---------------- 18 ----------------
c.push(H1("18. Uso de IA"));
c.push(P("Usamos o assistente **Claude (Anthropic)** como apoio para: escrever e organizar o código do protótipo e dos scripts de teste, gerar as figuras e redigir os relatórios a partir dos resultados dos testes. Os resultados citados nos relatórios saíram da execução dos scripts do repositório. A equipe revisou o conteúdo, sabe explicar cada parte e responde por tudo o que está entregue. [[Confirmar e ajustar este parágrafo com o que o grupo realmente fez]]"));

// ---------------- 19 ----------------
c.push(H1("19. Referências"));
c.push(B("OWASP Top 10 para aplicações LLM e OWASP SQL Injection Prevention Cheat Sheet."));
c.push(B("MITRE ATT&CK (Enterprise e ICS) e MITRE ATLAS."));
c.push(B("RFC 6238 (TOTP), RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC)."));
c.push(B("WireGuard: documentação oficial do protocolo."));
c.push(B("Lei 13.709/2018 (LGPD), Lei 12.737/2012 e art. 154-A do Código Penal."));
c.push(B("WCAG 2.1, W3C."));

build("GS2026.2 E1 Documento de Arquitetura", c, path.join(ROOT, "reports", "GS2026.2_TURMA_GXX_E1.docx"));
