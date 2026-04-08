# Zero Trust MCP Proxy for LLM Integration

## Background 
LMM agents are beginning to be granted access to internal systems via MCP, which is difficult to monitor with traditional security tools, because it uses JSON-RPC.

There are two main problems. 
- Lack of **traffic visibility** in MCP communication
- No **central control point** for LLM-driven actions

This project implements a **Zero Trust–based security layer** in front of the MCP server using reverse proxy architecture, achieving full traffic visibility
Then, we implement rules to properly **detect**, **validate**, and **block** insecure requests for MCP traffic.

## 1. Current Architecture

Agent(User) -> Reverse Proxy (Nginx) -> MCP Server

---

## 2. Identity & Access Control (Zero Trust)

We enforce **strict request-level identity verification** at the proxy layer.

### Implemented Controls
- Required headers:
  - `X-Agent-ID`
  - `X-Device-ID`
  - `X-API-Key`
- Requests are validated against an allowlist of trusted agents/devices
- Unauthorized or missing headers → **request denied**

### Outcome
- Only **verified agents** can access MCP

---

## 3. Structured JSON Logging (Traffic Visibility)

Proxy logs are transformed into **structured JSON format** for analysis.

### Logged Fields
- Timestamp
- Source IP
- Rule Hit (e.g., auth failure, rate limit)
- Request JSON

### Example Log
```
2026-04-08 04:23:37,487 WARNING [RULE_HIT] RULE_4_METHOD_ALLOWLIST | ip=172.19.0.4 | detail=unknown method: invalid_method | payload={'jsonrpc': '2.0', 'method': 'invalid_method', 'params': {}, 'id': 2}
```

### Outcome
- Enables **MCP traffic observability**
- Supports downstream analysis

---

## 4. Rule Implementation & Testing 

We implemented rules to catch common insecure or malicious requests.

- JSON RPC Version Check
- Missing Required Fields
- Valid Method, Param Type / Length
- Method, Param Valid Characters
- Allow-listed Method
- Black-listed Keywords
- Rate Limit

We also implemented a combinational rule that utilizes many different conditions to identify anomalous behavior
<img width="293" height="117" alt="image" src="https://github.com/user-attachments/assets/ad5b4e89-5a9f-465b-b781-4ca91e66dbd2" />

We created test scripts to simulate both **legitimate and malicious traffic**.

### Covered Test Scenarios
Allowed
- Normal request  

Denied
- Unauthorized method  
- Sensitive parameter injection  
- Rate limit exceeded  
- Request ID reuse (replay attempt)  
- Missing authentication headers

<img width="660" height="268" alt="image" src="https://github.com/user-attachments/assets/c51ec90d-83fd-4c78-ab85-ef91a692cc58" />

### Outcome
- Demonstrates **detection and blocking capability**

---

## 5. Configuration Drift Detection

We implemented a simple **integrity monitoring mechanism**.

### Mechanism
- Store baseline file hashes
<img width="631" height="341" alt="image" src="https://github.com/user-attachments/assets/6e30cc57-1497-4331-9e48-9011db3f0b5b" />

- Compare on runtime or scheduled check  
- Trigger warning on mismatch  

### Outcome
- Detects **configuration changes**
<img width="714" height="496" alt="image" src="https://github.com/user-attachments/assets/2ab7d000-913c-4e8e-8a82-87cc8afa9931" />

---
## Project Notes

Planning to schedule a Mentor meeting during 4/13 - 4/15 to recalibrate and refocus on future direction.

---

## Work to do

- Integrate LLM (Llama3) to Agent Server
- LLM Focused Rulebase - [OWASP TOP 10 for LLM](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

- Automating Drift Check on Run
- SBOM-Based Security Check
