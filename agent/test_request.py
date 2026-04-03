import requests

URL = "http://proxy/rpc"

def send_request(method="get_data", params=None):
    if params is None:
        params = {}

    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1
    }

    response = requests.post(URL, json=payload)
    print("Status:", response.status_code)
    print("Response:", response.json())

if __name__ == "__main__":
    send_request()