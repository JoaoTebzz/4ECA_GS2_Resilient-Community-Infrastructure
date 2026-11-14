const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const L = require("./lib");
const { P, H1, H2, B, N, SP, BR, CODE, TABLE, IMG, cover, build, R, ROOT } = L;
const rp = R("replay");

const EV = path.join(ROOT, "evidencias", "INC-VA-0712");
function csv(file) {
  const lines = fs.readFileSync(file, "utf8").trim().split("\n");
  const parse = (l) => { const out = []; let cur = "", q = false; for (const ch of l) { if (ch === '"') q = !q; else if (ch === "," && !q) { out.push(cur); cur = ""; } else cur += ch; } out.push(cur); return out; };
  const head = parse(lines[0]);
  return lines.slice(1).map((l) => Object.fromEntries(parse(l).map((v, i) => [head[i], v])));
}
const cust = csv(path.join(EV, "cofre", "cadeia_de_custodia.csv"));
const tl = csv(path.join(EV, "linha_do_tempo.csv"));
const tlHash = crypto.createHash("sha256").update(fs.readFileSync(path.join(EV, "linha_do_tempo.csv"))).digest("hex");
const desc = { "actuator.log": "Comandos aplicados nos atuadores (agenda da bomba)", "edge.log": "Eventos dos nós de borda (queda da WAN, percepção humana)", "mail.log": "Gateway de e-mail (entrega, SPF, DKIM, DMARC)", "proxy.log": "Proxy web da estação da coordenadora", "telemetry.log": "Telemetria de nível da escola e temperatura da UBS", "vpn.log": "Autenticação da VPN legada", "web.log": "Requisições e logins do painel legado" };
const nlinhas = (f) => fs.readFileSync(path.join(EV, "cofre", f), "utf8").trim().split("\n").length;

const c = [];
c.push(...cover("Laudo Forense do INC-VA-0712", "Quem entrou, como, o que fez e o que ficou sem proteção", "E4 · Laudo Forense do INC-VA-0712"));
c.push(BR());

c.push(H1("1. Resumo"));
c.push(P("Em 17 de outubro de 2026, entre 02:11 e 08:50 (UTC), alguém usou uma senha roubada de uma coordenadora para entrar na VPN antiga, explorou uma falha de SQL Injection no painel, mexeu na agenda da bomba da escola e deixou o reservatório secar. Depois, a fibra caiu e a câmara fria da UBS passou do limite sem nenhum alerta. Uma voluntária só percebeu às 08:50."));
c.push(P("A cadeia do ataque, de acordo com a nossa reprodução, é: **e-mail falso (phishing) → senha roubada → VPN sem MFA → login no painel → SQL Injection (dados e senhas vazados) → agenda da bomba alterada → reservatório vazio → câmara fria sem alerta**. As causas de fundo foram quatro: falta de MFA, painel com SQL Injection, rede sem separação e alertas que dependiam da nuvem."));
c.push(P("**Aviso importante sobre este laudo:** não tínhamos as máquinas reais do incidente. Reproduzimos o cenário em laboratório, com dados sintéticos. O painel legado e o banco rodaram de verdade, e os logs de VPN, e-mail, proxy, atuador e telemetria foram **gerados por script** a partir da descrição do cenário. Então as evidências abaixo são da reprodução. O método (hash, custódia, correção de relógio, linha do tempo) é o mesmo que usaríamos num caso real, mas as conclusões valem para o cenário reproduzido, e não para uma investigação em campo."));

c.push(H1("2. Escopo"));
c.push(TABLE(["Item", "Descrição"], [
  ["Incidente", "INC-VA-0712, Rede Comunitária Vila Aurora"],
  ["Período analisado", "16/10/2026 21:30 até 17/10/2026 09:00 (UTC)"],
  ["Sistemas", "E-mail, proxy, VPN legada, painel web e banco, nós de borda (escola e UBS), telemetria"],
  ["Perguntas do laudo", "1) Como o atacante entrou? 2) O que acessou e alterou? 3) Qual foi o impacto? 4) Por que ninguém foi avisado? 5) Como evitar?"],
  ["Fora do escopo", "Captura de memória (Volatility), análise de disco de estações, identificação do autor. Não temos esses dados"],
  ["Ambiente", "Laboratório isolado do grupo, sem acesso à internet, dados sintéticos"],
], [2400, 7238]));
c.push(SP());

c.push(H1("3. Método"));
c.push(N("Reproduzimos o cenário com `lab/run_incident.py`. Rodá-lo duas vezes dá os **mesmos hashes** (conferimos), então qualquer pessoa chega nas mesmas evidências."));
c.push(N("Coletamos os logs com `forensics/collect.py collect`: calcula o SHA-256 do arquivo na origem, copia, calcula o SHA-256 da cópia, confere que são iguais, marca a cópia como somente leitura e registra tudo na cadeia de custódia."));
c.push(N("Verificamos a integridade com `forensics/collect.py verify`, que recalcula os hashes e compara com a cadeia."));
c.push(N("Montamos a linha do tempo com `forensics/timeline.py`, que junta todos os logs, **corrige o relógio** das fontes que estavam erradas e classifica cada evento com a técnica do MITRE ATT&CK."));
c.push(N("Repetimos o ataque diante das regras novas do SIEM para saber onde teria sido barrado (`lab/replay_detection.py`)."));

c.push(H1("4. Evidências com hash"));
c.push(P("Tabela da cadeia de custódia (arquivo `evidencias/INC-VA-0712/cofre/cadeia_de_custodia.csv`). O hash é SHA-256, calculado na hora da coleta."));
const evRows = cust.map((r) => [r.item, r.arquivo, desc[r.arquivo] || "", String(nlinhas(r.arquivo)), r.sha256.slice(0, 16) + "…"]);
c.push(TABLE(["Item", "Arquivo", "O que é", "Linhas", "SHA-256 (início)"], evRows, [700, 1600, 3900, 800, 2638], { size: 17 }));
c.push(SP());
c.push(P("Os hashes completos estão no arquivo `SHA256SUMS` e abaixo:"));
c.push(...CODE(cust.map((r) => r.sha256 + "  " + r.arquivo)));
c.push(SP());
c.push(P("**Hash da linha do tempo** (`linha_do_tempo.csv`): `" + tlHash + "`"));
c.push(P("**Teste de adulteração:** copiamos o cofre, acrescentamos uma linha no `web.log` e rodamos o `verify`. Resultado: 6 arquivos íntegros e `web.log` apontado como alterado. Ou seja, o hash pega qualquer mudança."));

c.push(H1("5. Cadeia de custódia"));
c.push(TABLE(["Campo", "Valor"], [
  ["Coletado por", cust[0].coletado_por + " [[trocar pelo nome do integrante que coletou]]"],
  ["Data e hora da coleta (UTC)", cust[0].data_hora_utc],
  ["Local", "Máquina virtual do laboratório do grupo"],
  ["Método", "Cópia com `cp -p`, SHA-256 na origem e na cópia (hashlib do Python), conferência de igualdade"],
  ["Armazenamento", "Pasta `cofre/` com permissão somente leitura (modo 444). A cópia de trabalho é separada"],
  ["Ajuste de relógio registrado", "vpn.log: **+192 s** (a VPN estava adiantada 3 min 12 s). Demais fontes: 0"],
  ["Transferências", "Nenhuma até aqui. Cada nova transferência deve ganhar uma linha (quem entregou, quem recebeu, quando)"],
], [3000, 6638]));
c.push(SP());
c.push(P("Limite: a cadeia de custódia aqui é um arquivo CSV, e quem tem acesso à máquina poderia editá-lo. Num caso real, o hash deveria ser guardado também em um lugar separado (impresso, e-mail para a coordenação ou carimbo de tempo)."));

c.push(H1("6. Sincronização de relógios"));
c.push(P("Esse foi o ponto que mais quase deu errado. O log da VPN estava com o relógio **192 segundos adiantado**. Sem corrigir, o login na VPN apareceria às 02:14:22, **depois** do login no painel (02:12:03) e de duas sondagens de SQL Injection. Parece que o atacante entrou no painel antes de entrar na VPN, o que não faz sentido. Com o ajuste de 192 s, o login na VPN vai para **02:11:10**, que é a ordem lógica."));
c.push(TABLE(["Fonte", "Hora no log", "Ajuste", "Hora corrigida (UTC)"], [
  ["VPN, login com senha", "02:14:22", "−192 s", "02:11:10"],
  ["Painel, login", "02:12:03", "0", "02:12:03"],
], [3000, 2200, 1800, 2638]));
c.push(SP());
c.push(P("Como o ajuste foi descoberto: o desvio é conhecido pelo cenário. Num caso real, o jeito é achar um evento que apareça em duas fontes (por exemplo, a conexão na VPN e o primeiro acesso do mesmo IP no painel) e medir a diferença. Todos os nossos sistemas novos usam NTP (E1, seção 10)."));

c.push(H1("7. Linha do tempo"));
c.push(P("Horário em UTC, já corrigido. A coluna ATT&CK mostra a técnica."));
c.push(TABLE(["#", "Hora (UTC)", "Fonte", "O que aconteceu", "ATT&CK"], tl.map((r) => [r.n, r.hora_utc_corrigida.slice(5, 19).replace("T", " "), r.fonte, r.evento, r.tecnica_attack]), [450, 1500, 1000, 5688, 1000], { size: 16 }));
c.push(SP());
c.push(...IMG("linha_do_tempo.png", 560, 336, "Figura 1. Nível da escola e temperatura da UBS durante o incidente (reprodução)"));
c.push(P("Pontos que a linha do tempo mostra:"));
c.push(B("O ataque inteiro (do login na VPN à mudança da bomba) levou **9 minutos** (02:11 às 02:20). Foi rápido e feito de madrugada."));
c.push(B("Entre a mudança da bomba (02:20) e o reservatório chegar a 9% (05:45) passaram **3 h 25 min**. Houve tempo de sobra para alguém reagir, se houvesse alerta."));
c.push(B("A fibra caiu às 04:05, quase duas horas depois do ataque. **A queda da fibra não foi causada pelo atacante**, segundo o que temos. Ela só tirou os alertas do ar. Dizemos isso com cuidado: não temos evidência para afirmar coincidência ou não."));
c.push(B("A câmara fria passou de 8 °C às 07:20, e alguém só percebeu às 08:50. **1 h 30 min** acima do limite sem aviso."));

c.push(H1("8. Análise: o que cada evento prova"));
c.push(H2("8.1 Acesso inicial: phishing"));
c.push(P("O gateway de e-mail registrou a entrega às 21:32 de uma mensagem para `coord1`, com **SPF em fail, sem DKIM e sem DMARC**, com assunto \"Atualização obrigatória do acesso ao painel\" e link para `acesso-prefeitura-serraclara.example`, um domínio parecido com o da prefeitura. Às 21:38 a estação da coordenadora abriu a página e às 21:39 enviou um formulário de 212 bytes para ela. Nossa leitura: a senha foi digitada na página falsa. **Não temos o conteúdo do formulário**, então isso é uma conclusão por indício."));
c.push(H2("8.2 VPN sem MFA e conta válida"));
c.push(P("Às 02:11:10 (hora corrigida) o usuário `coord1` entrou na VPN com **senha e sem MFA**, vindo de 203.0.113.77, um IP que não era dos técnicos. Dois minutos depois, o mesmo IP fez login no painel com a mesma conta. Não há como saber só pelos logs se foi a pessoa ou o atacante, mas o IP, o horário (madrugada) e o fato de a senha ter sido enviada ao site falso apontam para o atacante."));
c.push(H2("8.3 SQL Injection e o que vazou"));
c.push(P("O `web.log` mostra 5 requisições ao `/historico` do mesmo IP, em cerca de 4 minutos, com progressão de sondagem para extração:"));
c.push(TABLE(["Hora", "Busca enviada", "Resultado na reprodução"], [
  ["02:12:40", "`Matheus' `", "Erro 500 (sondagem, mostrou a consulta)"],
  ["02:13:02", "`x%' OR 1=1 --`", "200 com 300 linhas (todo o histórico de acessos)"],
  ["02:14:15", "`… UNION SELECT id,email,phone,kind FROM users --`", "200 com 25 linhas (todos os usuários)"],
  ["02:15:09", "`… UNION SELECT username,pw_hash,role,totp_secret FROM operators --`", "200 com 4 linhas (operadores, hashes e segredo do MFA)"],
  ["02:16:30", "`x%'; UPDATE schedule SET start_h=0, end_h=24 WHERE pump='bomba_escola'; --`", "200 (agenda da bomba alterada para 0h às 24h)"],
], [1100, 5200, 3338]));
c.push(SP());
c.push(P("**Dados expostos (no cenário):** nome, e-mail e telefone de 25 pessoas (sintéticas na reprodução), e os hashes de senha e os segredos de MFA dos 4 operadores. Hash de senha SHA-256 sem sal é fácil de quebrar, e o segredo de MFA vazado permite gerar os códigos. **Recomendação imediata, num caso real:** trocar todas as senhas e refazer o MFA dos 4 operadores, e avisar os titulares e a ANPD, conforme a LGPD."));
c.push(P("O que não sabemos: se o atacante realmente baixou o resultado de cada consulta. O log mostra que a requisição foi feita e que a aplicação respondeu 200 com dados, o que é indício forte de extração, mas não uma prova do que foi copiado."));
c.push(H2("8.4 Impacto físico"));
c.push(P("Às 02:20 o nó de borda da escola aplicou o novo agendamento (bomba ligada de 0h a 24h, `via = db_sync`, origem fora do perfil). Pela telemetria da reprodução, o nível do reservatório começou a cair e passou de 72% para menos de 10% em cerca de 3 h 25 min. Na nossa reprodução o nível ficou em torno de 2%."));
c.push(P("**Atenção para não exagerar:** a telemetria é uma simulação que escrevemos. A taxa de queda (1,5 ponto por 5 minutos) foi escolhida por nós. No caso real, a causa da queda precisaria ser confirmada com o dado do sensor e a conferência física da bomba (por exemplo, se ela não estava em manutenção)."));
c.push(P("A câmara fria da UBS começou a subir após as 04:05 (fibra fora) e cruzou 8 °C às 07:20. Nós **não** conseguimos ligar essa subida ao ataque, porque a causa pode ter sido falha do equipamento. O que o laudo afirma é: **o alerta não saiu porque dependia da nuvem**, e isso é verificável (no teste de caos, o sistema antigo só alertou depois da volta da WAN)."));

c.push(H1("9. Mapeamento MITRE ATT&CK"));
c.push(TABLE(["Tática", "Técnica", "Evidência no laudo"], [
  ["Acesso inicial", "T1566.002 Phishing: link", "mail.log (21:32), proxy.log (21:38)"],
  ["Acesso às credenciais", "T1056.003 Captura por portal web (página falsa)", "proxy.log, POST às 21:39 (indício)"],
  ["Acesso inicial / persistência", "T1133 Serviços remotos externos (VPN sem MFA)", "vpn.log, 02:11:10 corrigido"],
  ["Acesso inicial", "T1078 Contas válidas", "web.log, login `coord1` às 02:12:03"],
  ["Acesso inicial", "T1190 Exploração de aplicação pública (SQL Injection)", "web.log, 02:12:40, 02:13:02, 02:16:30"],
  ["Coleta", "T1213 Dados de repositórios de informação", "web.log, 02:14:15 e 02:15:09"],
  ["Impacto", "T1565.001 Manipulação de dados armazenados", "web.log 02:16:30 (UPDATE no agendamento)"],
  ["Impacto (ICS)", "T0836 Modificar parâmetro", "actuator.log, 02:20:00"],
  ["Impacto (ICS)", "T0826 Perda de disponibilidade", "telemetry.log, nível ≤ 10% às 05:45 e câmara fria > 8 °C às 07:20"],
], [2300, 4000, 3338]));
c.push(SP());
c.push(P("Observação: a queda da fibra (04:05) aparece na linha do tempo como contexto e não recebeu técnica, porque não temos evidência de que foi ação do atacante."));

c.push(H1("10. Causas e como cada uma teria mudado o resultado"));
c.push(TABLE(["Causa de fundo", "O que fizemos no projeto novo", "Evidência"], [
  ["VPN com senha, sem MFA", "WireGuard por chave de máquina e acesso humano por bastião com MFA. Regra A do SIEM", "Regra A dispara no login (02:11:10) e bloqueia o IP (E3, seção 8)"],
  ["SQL Injection no painel", "Consulta parametrizada, validação, só leitura, erro genérico, WAF", "5 de 5 ataques barrados (E3, seção 2)"],
  ["Rede sem separação", "Segmentos IoT, operadores e administração, política DROP", "Configuração escrita, ainda **não testada** (E3, seção 4)"],
  ["Alterar a bomba sem ninguém ver", "Regra D, modo seguro automático e aprovação humana para desligar", "Pedidos criados e nenhum executado sem humano (E3, seção 8)"],
  ["Alerta dependia da nuvem", "Regras locais no nó de borda e buffer", "Alarme em 2 s sem WAN (E3, seção 9)"],
  ["Logs e relógios ruins", "NTP, coleta central e hash na coleta", "Este laudo"],
], [2600, 4200, 2838]));
c.push(SP());
c.push(P("Se as regras novas estivessem no ar, a nossa reprodução indica que o IP do atacante seria bloqueado às **" + rp.bloqueio_automatico_do_ip_em + "**, antes das " + rp.requisicoes_sqli_do_atacante + " requisições de SQL Injection e antes da mudança da bomba. **É uma estimativa** feita repetindo os logs, e supõe que o bloqueio de IP funcione de verdade no firewall (não testamos isso)."));

c.push(H1("11. Conclusões"));
c.push(N("O ataque seguiu a cadeia phishing, senha, VPN sem MFA, SQL Injection e alteração da bomba. Os logs da reprodução sustentam cada passo, e os pontos que são só indício estão marcados no texto.", "num2"));
c.push(N("Foram expostos dados pessoais e os hashes de senha e segredos de MFA de 4 operadores. A senha e o MFA precisam ser trocados.", "num2"));
c.push(N("O impacto na água da escola é consequência direta da mudança da agenda. O impacto na câmara fria não pode ser atribuído ao atacante, mas a falta de alerta é falha de projeto.", "num2"));
c.push(N("Ninguém foi avisado por 6 h 30 min (02:20 às 08:50), apesar de o ataque ter feito barulho nos logs. Faltava coleta central e detecção.", "num2"));
c.push(N("A linha do tempo só fica coerente depois de corrigir o relógio da VPN em 192 s. Sem isso, a ordem dos eventos engana.", "num2"));

c.push(H1("12. Recomendações"));
c.push(TABLE(["Prioridade", "Ação", "Prazo sugerido"], [
  ["Imediata", "Trocar senhas e refazer o MFA dos 4 operadores. Desativar a VPN antiga. Avisar titulares e ANPD", "Hoje"],
  ["Imediata", "Corrigir o SQL Injection (parametrização) e tirar a exposição do painel antigo", "Até 48 h"],
  ["Curto prazo", "Ligar MFA em tudo, subir WireGuard e bastião, publicar SPF, DKIM e DMARC", "2 semanas"],
  ["Curto prazo", "Regras locais de alarme em cada nó de borda, com buffer", "2 semanas"],
  ["Médio prazo", "SIEM com regras A a D, SOAR com aprovação humana, NTP em tudo", "1 mês"],
  ["Médio prazo", "Treinamento dos voluntários, palavra-código e botão de reportar. Campanha de phishing simulado", "1 mês"],
  ["Contínuo", "Teste de caos semestral, revisão de acessos trimestral, teste de restauração de backup", "Calendário de manutenção"],
], [1700, 6000, 1938]));
c.push(SP());

c.push(H1("13. Limitações do laudo"));
c.push(B("As evidências vêm de **reprodução em laboratório** com dados sintéticos. Logs de VPN, e-mail, proxy, atuador e telemetria foram gerados por script."));
c.push(B("Não tivemos captura de memória, imagem de disco nem tráfego de rede (PCAP). O pacote do formulário enviado ao site falso (212 bytes) não pode ser lido."));
c.push(B("Não identificamos o autor. O IP 203.0.113.77 é de documentação e serve só como exemplo."));
c.push(B("A cadeia de custódia é um CSV, sem carimbo de tempo externo."));
c.push(B("Não usamos FTK Imager, Autopsy, Volatility nem plaso. A linha do tempo foi feita com script próprio. [[Se o grupo usar o plaso, anexar o resultado]]"));
c.push(B("O laudo não afirma a causa da subida da câmara fria. Só afirma que o alerta não saiu."));

c.push(H1("14. Anexos (no repositório)"));
c.push(B("`evidencias/INC-VA-0712/cofre/`: logs, `SHA256SUMS` e `cadeia_de_custodia.csv`."));
c.push(B("`evidencias/INC-VA-0712/linha_do_tempo.csv`."));
c.push(B("`forensics/collect.py`, `forensics/timeline.py`, `lab/run_incident.py`, `lab/replay_detection.py`."));
c.push(P("Uso de IA: ver a seção 18 do E1. [[Ajustar com o que o grupo decidir]]"));

build("GS2026.2 E4 Laudo Forense", c, path.join(ROOT, "reports", "GS2026.2_TURMA_GXX_E4.docx"));
