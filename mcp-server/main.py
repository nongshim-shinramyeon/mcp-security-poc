from fastapi import FastAPI, Request
import logging

app = FastAPI()
logging.basicConfig(filename="/logs/mcp.log", level=logging.INFO)

@app.post("/rpc")
async def rpc_handler(request: Request):
    data = await request.json()

    logging.info(f"Request: {data}")

    method = data.get("method")

    if method == "get_data":
        result = {"message": "Here is your data"}
    else:
        result = {"error": "Unknown method"}

    return {
        "jsonrpc": "2.0",
        "result": result,
        "id": data.get("id")
    }