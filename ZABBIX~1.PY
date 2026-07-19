"""
Monitor Zabbix -> detecção de anomalia (z-score) -> alerta explicado por IA
-> anotação automática no Grafana.

Requisitos: pip install requests anthropic

Fluxo:
1. Puxa o histórico recente de um item do Zabbix via API (JSON-RPC).
2. Calcula z-score do valor mais recente contra a janela histórica.
3. Se for anomalia, pede pra IA (Claude) traduzir em linguagem de ops.
4. Cria uma anotação no Grafana (aparece marcada no dashboard)
   e manda o alerta pro Slack.
"""

import statistics
import time

import requests
import anthropic

# --- Config ---------------------------------------------------------------
ZABBIX_URL = "http://zabbix.exemplo.com/api_jsonrpc.php"
ZABBIX_TOKEN = "SEU_API_TOKEN"          # Zabbix 6.4+ suporta API token direto
ZABBIX_ITEM_ID = "12345"                # itemid do item que quer monitorar

GRAFANA_URL = "http://grafana.exemplo.com"
GRAFANA_API_KEY = "SEU_GRAFANA_API_KEY"
GRAFANA_DASHBOARD_UID = "abc123"

SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/XXX/YYY/ZZZ"

Z_SCORE_THRESHOLD = 3.0
HISTORY_LIMIT = 60       # nº de pontos usados pra calcular média/desvio
CHECK_INTERVAL = 60      # segundos entre verificações

client = anthropic.Anthropic()  # usa ANTHROPIC_API_KEY do ambiente


# --- Zabbix -----------------------------------------------------------------
def zabbix_call(method, params):
    resp = requests.post(
        ZABBIX_URL,
        json={
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1,
        },
        headers={
            "Content-Type": "application/json-rpc",
            "Authorization": f"Bearer {ZABBIX_TOKEN}",
        },
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["result"]


def get_item_history(item_id, limit=HISTORY_LIMIT):
    """history=0 => float; troque pra 3 se o item for inteiro (uptime, contadores etc)."""
    result = zabbix_call(
        "history.get",
        {
            "itemids": item_id,
            "history": 0,
            "sortfield": "clock",
            "sortorder": "DESC",
            "limit": limit,
        },
    )
    values = [float(r["value"]) for r in result]
    values.reverse()  # ordem cronológica
    return values


def get_item_meta(item_id):
    result = zabbix_call(
        "item.get",
        {"itemids": item_id, "output": ["name", "key_", "hostid"]},
    )
    return result[0] if result else {}


# --- Detecção de anomalia ---------------------------------------------------
def z_score(value, series):
    if len(series) < 5:
        return 0.0
    mean = statistics.mean(series)
    stdev = statistics.pstdev(series) or 1e-9
    return (value - mean) / stdev


# --- IA para explicar --------------------------------------------------------
def explain_anomaly(item_name, value, z):
    prompt = (
        f"O item de monitoramento '{item_name}' registrou o valor {value:.2f}, "
        f"com z-score={z:.2f} (limite normal={Z_SCORE_THRESHOLD}). "
        "Escreva um alerta curto (2-3 frases), em português, para o time de "
        "infra, explicando a gravidade provável e uma ação recomendada."
    )
    msg = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=150,
        messages=[{"role": "user", "content": prompt}],
    )
    return msg.content[0].text


# --- Grafana annotation ------------------------------------------------------
def create_grafana_annotation(text, tags=None):
    requests.post(
        f"{GRAFANA_URL}/api/annotations",
        json={
            "dashboardUID": GRAFANA_DASHBOARD_UID,
            "time": int(time.time() * 1000),
            "tags": tags or ["anomalia", "ia"],
            "text": text,
        },
        headers={"Authorization": f"Bearer {GRAFANA_API_KEY}"},
        timeout=10,
    )


# --- Slack -------------------------------------------------------------------
def send_slack_alert(text):
    requests.post(SLACK_WEBHOOK_URL, json={"text": f"🚨 {text}"})


# --- Loop principal ------------------------------------------------------------
def main():
    meta = get_item_meta(ZABBIX_ITEM_ID)
    item_name = meta.get("name", f"item {ZABBIX_ITEM_ID}")

    while True:
        history = get_item_history(ZABBIX_ITEM_ID)
        if not history:
            time.sleep(CHECK_INTERVAL)
            continue

        current = history[-1]
        baseline = history[:-1]
        z = z_score(current, baseline)

        if abs(z) >= Z_SCORE_THRESHOLD:
            alert_text = explain_anomaly(item_name, current, z)
            create_grafana_annotation(alert_text)
            send_slack_alert(alert_text)
            print(f"[ALERTA] {item_name}={current:.2f} (z={z:.2f}) -> {alert_text}")
        else:
            print(f"[ok] {item_name}={current:.2f} (z={z:.2f})")

        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
