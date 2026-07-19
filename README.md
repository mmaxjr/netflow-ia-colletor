# NetFlow AI Collector

Coletor de NetFlow v5 que usa uma IA gratuita (Groq / Llama 3.3) para
detectar anomalias de tráfego de rede e avisar no Telegram — com status
periódico ("está tudo bem") e alerta imediato quando algo suspeito aparece.

Repositório: https://github.com/mmaxjr/netflow-ia-colletor

## Arquivos

| Arquivo | O que é |
|---|---|
| `netflow_ai_monitor.py` | O coletor + analisador. Roda para sempre, escutando NetFlow e chamando a IA periodicamente. O `setup_netflow_debian.sh` instala esse conteúdo no servidor como `/opt/netflow-ai/monitor.py`. |
| `setup_netflow_debian.sh` | Script que configura um servidor Debian do zero: instala o exportador (`softflowd`), o Python, e sobe o monitor como serviço systemd. |
| `netflow_reports.log` | Gerado em tempo de execução (no servidor, em `/opt/netflow-ai/`) — histórico de todos os relatórios e análises da IA. |

## Como funciona (visão geral)

```
 roteador/switch/servidor          este servidor (Debian)
 ┌──────────────────┐   NetFlow v5   ┌──────────────────────────────┐
 │  interface eth0   │ ─── UDP 2055 ─▶│ softflowd  →  netflow_ai_monitor.py │
 │  (softflowd lê    │                │  (coleta)     (agrega + IA)  │
 │   o tráfego real) │                └───────────────┬──────────────┘
 └──────────────────┘                                 │
                                                        ▼
                                              Telegram (status/alerta)
```

1. **`softflowd`** olha o tráfego de uma interface de rede (ex: `eth0`) e
   gera pacotes NetFlow v5, exportando via UDP para `127.0.0.1:2055`.
2. **`netflow_ai_monitor.py`** escuta essa porta, decodifica os pacotes e acumula os
   flows (quem falou com quem, quantos bytes, qual porta/protocolo).
3. A cada **60 segundos** (`REPORT_INTERVAL`), ele agrega tudo que chegou
   nesse intervalo num resumo compacto (não manda o tráfego bruto pra IA,
   só números agregados).
4. Esse resumo vai pro **Groq** (modelo `llama-3.3-70b-versatile`, gratuito),
   que responde em JSON com um resumo geral e uma lista de anomalias
   (descrição, severidade, ação recomendada).
5. Se alguma anomalia for `media` ou `alta`, o script manda **na hora** uma
   mensagem explicando no Telegram.
6. A cada **10 ciclos** (10 minutos, por padrão), o script manda um
   **status periódico** no Telegram mesmo se não houver nada de errado —
   assim você sabe que o monitor está vivo e coletando, não só quando dá
   problema.

## Explicando o código (`netflow_ai_monitor.py`)

- `parse_netflow_v5(packet)` — decodifica o pacote binário do NetFlow v5.
  O pacote tem um cabeçalho de 24 bytes (quantos registros vêm ali) seguido
  de registros de 48 bytes cada, um por flow, com IP origem/destino, portas,
  protocolo, bytes e pacotes transferidos.

- `collector_loop()` — roda numa thread separada, para sempre. Fica escutando
  a porta UDP 2055 e, a cada pacote recebido, decodifica e guarda os flows
  num buffer compartilhado (`flow_buffer`).

- `summarize_flows(flows)` — pega todos os flows acumulados no intervalo e
  calcula: total de bytes/pacotes, top 10 hosts que mais transmitiram
  bytes, portas de destino mais usadas, protocolos, e hosts que falaram
  com um número anormalmente alto de destinos distintos (indício de
  varredura/scan).

- `analyze_with_ai(summary)` — manda esse resumo pro Groq com um prompt
  pedindo uma resposta em JSON estruturado (resumo + lista de anomalias
  com severidade e ação recomendada).

- `send_telegram_message(text)` — chama a API do Telegram
  (`api.telegram.org/bot<TOKEN>/sendMessage`) para mandar a mensagem pro
  chat configurado.

- `save_report(summary, analysis)` — grava cada ciclo (dados agregados +
  resposta da IA) em `netflow_reports.log`, pra você ter histórico e
  poder auditar depois.

- `report_loop()` — o loop principal de análise: espera `REPORT_INTERVAL`
  segundos, processa o que acumulou, dispara alerta imediato se achar algo
  grave, e a cada `HEARTBEAT_EVERY` ciclos manda o status periódico.

- `main()` — sobe a thread de coleta e entra no loop de relatório. É o que
  o systemd chama.

### Variáveis de configuração (topo do arquivo)

| Variável | Padrão | O que ajusta |
|---|---|---|
| `LISTEN_PORT` | `2055` | Porta UDP onde o NetFlow é recebido |
| `REPORT_INTERVAL` | `60` (segundos) | Frequência de análise/chamada à IA |
| `HEARTBEAT_EVERY` | `10` (ciclos) | A cada quantos ciclos manda status "tudo ok" |
| `GROQ_MODEL` | `llama-3.3-70b-versatile` | Modelo usado na Groq |

Aumentar `REPORT_INTERVAL` (ex: para 300) reduz o número de chamadas à IA
por dia — útil se você estiver perto do limite gratuito da Groq.

## Configurando o Telegram

O script manda os alertas para um **bot do Telegram** que você cria em 2 minutos.

1. **Criar o bot** — no Telegram, procure por `@BotFather`, mande `/newbot`,
   escolha um nome e um username (precisa terminar em `bot`, ex:
   `netflow_alerts_bot`). O BotFather devolve um token parecido com:

   ```
   123456789:AAFExemplo-DeTokenAqui123456
   ```

   Esse é o seu `TELEGRAM_BOT_TOKEN`.

2. **Descobrir o `chat_id`** — mande qualquer mensagem para o seu bot recém
   criado (procure o username dele e clique em "Start"). Depois, no
   navegador ou via `curl`, acesse:

   ```bash
   curl "https://api.telegram.org/bot<SEU_TOKEN>/getUpdates"
   ```

   Na resposta JSON, procure por `"chat":{"id": ...}` — esse número é o
   `TELEGRAM_CHAT_ID`. Se quiser mandar pra um grupo em vez de conversa
   individual, adicione o bot ao grupo e o `chat_id` aparece do mesmo jeito
   (geralmente como um número negativo).

3. **Testar rapidamente** (opcional, antes de rodar o monitor):

   ```bash
   curl -X POST "https://api.telegram.org/bot<SEU_TOKEN>/sendMessage" \
        -d chat_id=<SEU_CHAT_ID> \
        -d text="teste do bot"
   ```

   Se a mensagem chegar no seu Telegram, as credenciais estão certas.

## Instalando no Debian (automatizado)

Com o token e o chat_id em mãos, e a `GROQ_API_KEY` (grátis em
[console.groq.com/keys](https://console.groq.com/keys)):

```bash
git clone https://github.com/mmaxjr/netflow-ia-colletor.git
cd netflow-ia-colletor
chmod +x setup_netflow_debian.sh
sudo ./setup_netflow_debian.sh eth0 <GROQ_API_KEY> <TELEGRAM_BOT_TOKEN> <TELEGRAM_CHAT_ID>
```

O script:

1. Instala `softflowd`, Python e venv via `apt`
2. Configura o `softflowd` para exportar NetFlow v5 da interface informada
   (`eth0` no exemplo) para `127.0.0.1:2055`, como serviço systemd
3. Cria um virtualenv em `/opt/netflow-ai/venv` e instala `groq` + `requests`
4. Grava o conteúdo de `netflow_ai_monitor.py` em `/opt/netflow-ai/monitor.py`
5. Salva as credenciais em `/opt/netflow-ai/.env` (permissão `600`)
6. Cria e sobe o serviço `netflow-ai.service` (`Restart=on-failure`,
   habilitado no boot)
7. Libera a porta UDP 2055 no `ufw`, se estiver ativo

## Testando sem hardware de rede real

Se você não tem um roteador que exporte NetFlow, simule tráfego com o
[`nflow-generator`](https://github.com/nerdalert/nflow-generator) apontando
para `127.0.0.1:2055` — o `netflow_ai_monitor.py` processa normalmente e você já
recebe os status/alertas no Telegram.

## Acompanhando depois de rodando

```bash
systemctl status softflowd netflow-ai   # os dois serviços devem estar "active"
journalctl -u netflow-ai -f             # logs em tempo real
cat /opt/netflow-ai/netflow_reports.log # histórico de relatórios/análises da IA
```

## Status do projeto

Projeto de estudo, em construção. Ainda tem bastante coisa pra melhorar:

- Pré-filtro local antes de chamar a IA (hoje ele chama a cada ciclo,
  mesmo sem indício de anomalia)
- Testar outros provedores de IA além da Groq, pra comparar qualidade de
  detecção e latência (Groq foi escolhido pela facilidade de uso e por
  ter API gratuita, não necessariamente por ser o melhor pra esse caso)
- Suporte a NetFlow v9 / IPFIX (hoje só decodifica v5)
- Persistir os relatórios em algo além de um `.log` local (ex: SQLite)

PRs e sugestões são bem-vindos.

## Aviso de segurança

O script salva `GROQ_API_KEY`, `TELEGRAM_BOT_TOKEN` e `TELEGRAM_CHAT_ID`
em `/opt/netflow-ai/.env` com permissão `600` (só root lê). Ainda assim,
nunca comite esse arquivo nem essas chaves no repositório Git.
