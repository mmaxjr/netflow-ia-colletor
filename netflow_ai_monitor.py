"""
Coletor de NetFlow v5 + análise de anomalias por IA (Groq, gratuito)
+ relatório periódico + alerta no Slack.

Requisitos:
    pip install groq requests

Como testar sem hardware de rede de verdade:
    - Use o `nfcapd`/`softflowd` num roteador/Linux box apontando pra essa
      máquina na porta 2055, OU
    - Gere tráfego de teste com `nflow-generator` (github.com/nerdalert/nflow-generator)
      apontando pra 127.0.0.1:2055

Groq API key gratuita em: https://console.groq.com/keys
    export GROQ_API_KEY="sua_chave"
"""

import json
import os
import socket
import struct
import threading
import time
from collections import Counter, defaultdict

import requests
from groq import Groq

# --- Config -------------------------------------------------------------
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 2055          # porta padrão do NetFlow v5
REPORT_INTERVAL = 60        # segundos entre análises da IA
GROQ_MODEL = "llama-3.3-70b-versatile"   # modelo gratuito na Groq
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")
REPORT_LOG_FILE = "netflow_reports.log"

groq_client = Groq(api_key=os.environ["GROQ_API_KEY"])

# buffer compartilhado entre a thread de captura e a de análise
lock = threading.Lock()
flow_buffer = []

PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}


# --- Parser NetFlow v5 ----------------------------------------------------
def ip_to_str(raw):
    return socket.inet_ntoa(raw)


def parse_netflow_v5(packet):
    header = struct.unpack("!HHIIIIBBH", packet[:24])
    count = header[1]

    flows = []
    offset = 24
    record_fmt = "!4s4s4sHHIIIIHHBBBBHHBBH"
    record_size = struct.calcsize(record_fmt)  # 48 bytes

    for _ in range(count):
        chunk = packet[offset: offset + record_size]
        if len(chunk) < record_size:
            break
        fields = struct.unpack(record_fmt, chunk)
        flows.append(
            {
                "src": ip_to_str(fields[0]),
                "dst": ip_to_str(fields[1]),
                "packets": fields[6],
                "bytes": fields[7],
                "srcport": fields[10],
                "dstport": fields[11],
                "proto": PROTO_MAP.get(fields[14], str(fields[14])),
            }
        )
        offset += record_size

    return flows


# --- Thread de captura ------------------------------------------------------
def collector_loop():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP, LISTEN_PORT))
    print(f"[collector] ouvindo NetFlow v5 em {LISTEN_IP}:{LISTEN_PORT}")

    while True:
        packet, _addr = sock.recvfrom(65535)
        try:
            flows = parse_netflow_v5(packet)
        except struct.error:
            continue
        with lock:
            flow_buffer.extend(flows)


# --- Agregação para dar contexto compacto à IA -------------------------------
def summarize_flows(flows):
    total_bytes = sum(f["bytes"] for f in flows)
    total_packets = sum(f["packets"] for f in flows)

    bytes_by_src = defaultdict(int)
    dst_ports = Counter()
    protocols = Counter()
    unique_dst_by_src = defaultdict(set)

    for f in flows:
        bytes_by_src[f["src"]] += f["bytes"]
        dst_ports[f["dstport"]] += 1
        protocols[f["proto"]] += 1
        unique_dst_by_src[f["src"]].add(f["dst"])

    top_talkers = sorted(bytes_by_src.items(), key=lambda x: -x[1])[:10]
    top_ports = dst_ports.most_common(10)
    # hosts falando com muitos IPs diferentes = candidato a varredura/scan
    scan_candidates = sorted(
        ((src, len(dsts)) for src, dsts in unique_dst_by_src.items()),
        key=lambda x: -x[1],
    )[:10]

    return {
        "total_flows": len(flows),
        "total_bytes": total_bytes,
        "total_packets": total_packets,
        "top_talkers": top_talkers,
        "top_dst_ports": top_ports,
        "protocols": protocols.most_common(),
        "scan_candidates": scan_candidates,
    }


# --- Chamada à IA (Groq) -----------------------------------------------------
def analyze_with_ai(summary):
    prompt = f"""Você é um analista de segurança de rede. Analise o resumo de
tráfego NetFlow dos últimos {REPORT_INTERVAL} segundos e responda em JSON puro,
sem markdown, com este formato:

{{
  "resumo": "1-2 frases sobre o estado geral do tráfego",
  "anomalias": [
    {{"descricao": "...", "severidade": "baixa|media|alta", "acao_recomendada": "..."}}
  ]
}}

Considere como possível anomalia: hosts com volume de bytes muito acima dos
demais, hosts falando com um número anormalmente alto de destinos distintos
(possível varredura/scan), portas de destino incomuns concentradas em poucos
hosts, ou protocolos fora do padrão esperado (ex: muito ICMP).
Se não houver nada suspeito, retorne "anomalias": [].

Dados:
{json.dumps(summary, indent=2, ensure_ascii=False)}
"""

    completion = groq_client.chat.completions.create(
        model=GROQ_MODEL,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        response_format={"type": "json_object"},
    )
    return json.loads(completion.choices[0].message.content)


# --- Alerta / relatório -------------------------------------------------------
def send_slack_alert(text):
    if not SLACK_WEBHOOK_URL:
        return
    requests.post(SLACK_WEBHOOK_URL, json={"text": text})


def save_report(summary, analysis):
    with open(REPORT_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n=== Relatório {time.strftime('%Y-%m-%d %H:%M:%S')} ===\n")
        f.write(json.dumps({"summary": summary, "analysis": analysis}, ensure_ascii=False, indent=2))
        f.write("\n")


def report_loop():
    while True:
        time.sleep(REPORT_INTERVAL)

        with lock:
            flows, flow_buffer[:] = flow_buffer[:], []

        if not flows:
            print("[report] nenhum flow recebido nesse intervalo")
            continue

        summary = summarize_flows(flows)
        analysis = analyze_with_ai(summary)
        save_report(summary, analysis)

        print(f"[report] {summary['total_flows']} flows | {analysis['resumo']}")

        for anomalia in analysis.get("anomalias", []):
            texto = (
                f"🚨 [{anomalia['severidade'].upper()}] {anomalia['descricao']}\n"
                f"Ação recomendada: {anomalia['acao_recomendada']}"
            )
            print(texto)
            if anomalia["severidade"] in ("media", "alta"):
                send_slack_alert(texto)


def main():
    threading.Thread(target=collector_loop, daemon=True).start()
    report_loop()


if __name__ == "__main__":
    main()
