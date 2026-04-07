import requests

URL = "http://proxy/rpc"

def send_valid_request(method="get_data"):
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
    send_valid_request()