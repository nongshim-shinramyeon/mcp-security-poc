import requests

OLLAMA_URL = "http://host.docker.internal:11434/api/generate"
MCP_URL = "http://proxy/rpc"

def ask_llm(user_input):
    response = requests.post(
        OLLAMA_URL,
        json={
            "model": "llama3",
            "prompt": f"""
You are an AI agent that is calling an MCP server.

Convert the user's request into a JSON-RPC call.
There is a method called "get_data", with no parameters.

Return ONLY valid JSON.
Do NOT include explanations.
Do NOT include markdown.
Do NOT include text before or after.

Format:
{{
  "method": "...",
  "params": {{}}
}}

User request:
{user_input}
""",
            "stream": False
        }
    )
    return response.json()["response"]

def call_mcp(rpc_json):
    return requests.post(MCP_URL, json={
        "jsonrpc": "2.0",
        "method": rpc_json["method"],
        "params": rpc_json.get("params", {}),
        "id": 1
    })

user_input = "Get some data"

llm_output = ask_llm(user_input)

print("LLM Output:", llm_output)

import json
rpc = json.loads(llm_output)

response = call_mcp(rpc)

print("MCP Response:", response.json())