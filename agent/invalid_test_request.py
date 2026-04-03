import requests

URL = "http://proxy/rpc"

def send_invalid_request(method="invalid_method"):
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": {},
        "id": 1
    }

    response = requests.post(URL, json=payload)
    print("Status:", response.status_code)
    print("Response:", response.json())

if __name__ == "__main__":
    send_invalid_request()