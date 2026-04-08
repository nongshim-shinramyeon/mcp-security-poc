import os

import requests

URL = os.getenv("PROXY_URL", "http://proxy/rpc")


def build_headers():
    return {
        "X-Agent-ID": os.getenv("AGENT_ID", "agent-01"),
        "X-Device-ID": os.getenv("DEVICE_ID", "device-01"),
        "X-API-Key": os.getenv("API_KEY", "demo-api-key"),
    }


def send_invalid_request(method="invalid_method"):
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": {},
        "id": 1,
    }

    response = requests.post(URL, json=payload, headers=build_headers(), timeout=5)
    print("Status:", response.status_code)
    print("Response:", response.json())


if __name__ == "__main__":
    send_invalid_request()

