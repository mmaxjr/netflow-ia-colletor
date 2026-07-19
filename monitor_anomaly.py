"""
Monitor de CPU/memória com detecção de anomalia (z-score) e alerta
gerado por IA (resumo em linguagem natural) via Slack webhook.

Requisitos: pip install psutil requests anthropic
"""

import time
import statistics
from collections import deque

import psutil
import requests
import anthropic

SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/XXX/YYY/ZZZ"
WINDOW_SIZE = 30          # amostras usadas para calcular média/desvio
Z_SCORE_THRESHOLD = 3.0   # quantos desvios padrão define anomalia
CHECK_INTERVAL = 5        # segundos entre coletas

client = anthropic.Anthropic()  # usa ANTHROPIC_API_KEY do ambiente

history = {
    "cpu": deque(maxlen=WINDOW_SIZE),
    "mem": deque(maxlen=WINDOW_SIZE),
}


def z_score(value, series):
    if len(series) < WINDOW_SIZE:
        return 0.0
    mean = statistics.mean(series)
    stdev = statistics.pstdev(series) or 1e-9
    return (value - mean) / stdev


def explain_anomaly(metric, value, z):
    """Pede pra IA transformar o número em explicação legível pro time."""
    prompt = (
        f"Métrica '{metric}' está em {value:.1f}%, "
        f"z-score={z:.2f} (limite={Z_SCORE_THRESHOLD}). "
        "Escreva um alerta curto (2 frases) para um canal de ops, "
        "em português, explicando a gravidade e uma ação recomendada."
    )
    msg = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=150,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text


def send_alert(text):
    requests.post(SLACK_WEBHOOK_URL, json={"text": f"🚨 {text}"})


def check(metric, value):
    series = history[metric]
    z = z_score(value, series)
    series.append(value)

    if abs(z) >= Z_SCORE_THRESHOLD:
        alert_text = explain_anomaly(metric, value, z)
        send_alert(alert_text)
        print(f"[ALERTA] {metric}={value:.1f}% (z={z:.2f}) -> {alert_text}")
    else:
        print(f"[ok] {metric}={value:.1f}% (z={z:.2f})")


def main():
    while True:
        check("cpu", psutil.cpu_percent(interval=1))
        check("mem", psutil.virtual_memory().percent)
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
