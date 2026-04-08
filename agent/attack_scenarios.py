import os
from itertools import count

import requests

URL = os.getenv("PROXY_URL", "http://proxy/rpc")
BASE_HEADERS = {
    "X-Agent-ID": os.getenv("AGENT_ID", "agent-01"),
    "X-Device-ID": os.getenv("DEVICE_ID", "device-01"),
    "X-API-Key": os.getenv("API_KEY", "demo-api-key"),
}
ID_SEQUENCE = count(1)


def send_case(name, payload, headers=None):
    merged_headers = dict(BASE_HEADERS)
    if headers:
        merged_headers.update(headers)

    response = requests.post(URL, json=payload, headers=merged_headers, timeout=5)
    try:
        body = response.json()
    except ValueError:
        body = response.text

    print(f"[{name}] status={response.status_code}")
    print(body)
    print("-" * 60)


def next_payload(method, params=None, request_id=None):
    return {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
        "id": request_id if request_id is not None else next(ID_SEQUENCE),
    }


if __name__ == "__main__":
    send_case("valid_request", next_payload("ping"))
    send_case("invalid_method", next_payload("invalid_method"))
    send_case("sensitive_param", next_payload("get_data", {"token": "demo-secret"}))
    send_case("missing_api_key", next_payload("ping"), {"X-API-Key": ""})
    send_case("unknown_device", next_payload("ping"), {"X-Device-ID": "rogue-device"})

    reused_id = 999
    for idx in range(4):
        send_case(f"reused_request_id_{idx + 1}", next_payload("ping", request_id=reused_id))
