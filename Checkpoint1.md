# 🔐 Zero Trust MCP Proxy – Security Enhancements

This project implements a **Zero Trust–based security layer** in front of the MCP server using a reverse proxy architecture. The goal is to provide **authentication, observability, and threat detection capabilities** for MCP traffic.

---

## 1. Identity & Access Control (Zero Trust)

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
- Demonstrates **Zero Trust user/device validation**

---

## 2. TLS Termination at Proxy

The proxy (Nginx) is configured as a **TLS termination point**.

### Implemented Controls
- HTTPS enabled (`listen 443 ssl`)
- Self-signed certificate applied (for PoC)
- All incoming traffic encrypted before reaching backend

### Logging at TLS Boundary
- Requests are logged at the TLS termination layer

### Outcome
- Visibility into **encrypted traffic at entry point**
- Demonstrates **TLS termination observability**

---

## 3. Structured JSON Logging (Traffic Visibility)

Proxy logs are transformed into **structured JSON format** for analysis.

### Logged Fields
- Timestamp
- Source IP
- `X-Agent-ID`
- HTTP Method
- Status Code
- Upstream Latency
- Rule Hit (e.g., auth failure, rate limit)

### Example Log
```json
{
  "timestamp": "...",
  "source_ip": "...",
  "agent_id": "...",
  "method": "POST",
  "status": 403,
  "latency_ms": 12,
  "rule": "missing_api_key"
}
```

### Outcome
- Enables **MCP traffic observability**
- Supports downstream analysis (**SIEM / monitoring**)

---

## 4. Attack & False Positive Scenarios

We created test scripts to simulate both **legitimate and malicious traffic**.

### Scenarios Covered
- ✅ Normal request  
- ❌ Unauthorized method  
- ❌ Sensitive parameter injection  
- ❌ Rate limit exceeded  
- ❌ Request ID reuse (replay attempt)  
- ❌ Missing authentication headers  

### Outcome
- Demonstrates **detection and blocking capability**
- Validates security rules under realistic conditions

---

## 5. Configuration Drift Detection

We implemented a simple **integrity monitoring mechanism**.

### Monitored Files
- `docker-compose.yml`
- `proxy/nginx.conf`
- `mcp-server/main.py`

### Mechanism
- Store baseline file hashes  
- Compare on runtime or scheduled check  
- Trigger warning on mismatch  

### Outcome
- Detects **unauthorized configuration changes**
- Demonstrates **Drift detection capability**

---

## Summary of Security Guarantees

| Capability | Description |
|----------|------------|
| Identity Verification | Header-based agent/device authentication |
| Zero Trust Enforcement | Deny-by-default access policy |
| TLS Security | HTTPS termination at proxy |
| Observability | Structured JSON logs for all traffic |
| Threat Detection | Attack scenario simulation & blocking |
| Integrity Monitoring | Config drift detection via hashing |