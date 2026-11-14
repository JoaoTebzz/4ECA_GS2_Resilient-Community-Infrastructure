# Plano da campanha de phishing simulado (RT-11)

Regras: so contas FICTICIAS criadas pela equipe. Nenhuma credencial real e coletada. Nenhuma pessoa real recebe e-mail.
Ambiente: Gophish na maquina de laboratorio, sem acesso a internet, SMTP de teste (MailHog ou o proprio servidor fake).

## Passo a passo
1. Criar 10 contas ficticias (ex.: voluntario01@vilaaurora.example ... voluntario10@vilaaurora.example) no servidor de teste.
2. No Gophish: Sending Profile (SMTP de teste), Users & Groups (as 10 contas), Email Template, Landing Page.
3. Template 1 (facil de notar): e-mail generico, com erros de portugues e remetente estranho.
4. Template 2 (parecido com o ataque do INC-VA-0712): texto bem escrito e personalizado, falando de "atualizacao obrigatoria do acesso ao painel", link para pagina falsa do laboratorio. Marcar claramente no rodape do laboratorio: "SIMULACAO DA EQUIPE".
5. Landing page: formulario que NAO guarda a senha digitada (desligar "Capture Passwords"; no Gophish, deixar so "Capture Submitted Data" sem senha).
6. Disparar template 1 para 5 contas e template 2 para 5 contas. Cada conta tem um "voluntario" da equipe que age de forma natural (abre, clica, reporta ou ignora). Registrar no diario qual regra de comportamento cada um seguiu.
7. Exportar os eventos (Results > Export CSV) e rodar `python3 phishing/gophish_metrics.py eventos.csv`.
8. Rodar a campanha 2 vezes: antes e depois do treinamento (palavra-codigo, verificacao fora de banda, botao de reportar). Comparar.

## Metricas que vao para o relatorio E3
abertura, clique, envio de dados, reporte, tempo ate o primeiro reporte, antes e depois do treinamento.

## Voz clonada
Nao clonar voz de ninguem sem consentimento escrito. Se for demonstrar, usar so voz de integrante que assinou autorizacao,
com o aviso "AUDIO SINTETICO" no inicio. Caso contrario, so descrever o ataque e mostrar o controle (palavra-codigo).
