# MCP Security Proxy with Zero Trust Architecture

## Overview
This project implements a **Zero Trust security layer** in front of an MCP (Model Context Protocol) server.  
It focuses on **authentication, traffic validation, observability, and attack detection** for JSON-RPC-based communication.

The system is designed to simulate real-world security threats and demonstrate how they can be detected and mitigated in a production-like environment.

---

## Architecture
Client → Nginx (TLS Termination & Proxy) → FastAPI MCP Server

- **Nginx**: TLS termination, request filtering, logging
- **FastAPI**: JSON-RPC handling and rule validation
- **Docker Compose**: Service orchestration

---

## Key Features

### 1. Zero Trust Authentication & Identification
- Enforced custom headers:
  - `X-Agent-ID`
  - `X-Device-ID`
  - `X-API-Key`
- Only authorized agents/devices can access the MCP server
- Implemented at proxy and application layers

**Goal:** Demonstrate Zero Trust-based user/device verification

---

### 2. TLS Termination & Secure Communication
- Nginx configured as HTTPS endpoint
- Self-signed certificate applied
- All incoming traffic is encrypted before reaching backend

**Goal:** Secure entry point and enable traffic inspection at TLS boundary

---

### 3. Structured Observability (JSON Logging)
- All requests logged in structured JSON format:
  - timestamp
  - source IP
  - agent ID
  - method
  - status
  - upstream latency
  - rule hit (true/false)

**Goal:** Provide full visibility into MCP traffic

---

### 4. Attack Simulation & Detection
Implemented test scenarios to validate detection logic:

- Normal request
- Unauthorized method
- Sensitive parameter injection
- Rate limit exceeded
- Request ID reuse (replay attack)
- Missing authentication headers

**Goal:** Demonstrate detection and blocking mechanisms

---

### 5. Configuration Drift Detection
- Stored baseline hashes for:
  - `docker-compose.yml`
  - `proxy/nginx.conf`
  - `mcp-server/main.py`
- Compared runtime files with baseline
- Triggered warning on mismatch

**Goal:** Detect unauthorized configuration changes (Drift)

---

## Tech Stack
- Python (FastAPI)
- Nginx
- Docker / Docker Compose
- JSON-RPC 2.0

---

## My Contribution
- Designed Zero Trust authentication mechanism
- Implemented request validation rules for JSON-RPC traffic
- Built attack simulation scripts for security testing
- Configured TLS termination and structured logging in Nginx
- Implemented configuration drift detection logic

---

## How to Run

```bash
docker compose up --build

The proxy server will start at:

```
https://localhost:8080
```

## Example Request (JSON-RPC)

```json
{
  "jsonrpc": "2.0",
  "method": "get_data",
  "params": { "id": 1 },
  "id": 1
}
```

## Required Headers

```
X-Agent-ID: test-agent
X-Device-ID: device-001
X-API-Key: secret-key
```

## Test Scenarios

Run provided scripts to simulate normal and malicious traffic:

```bash
python agent/test_request.py
python agent/attack_scenarios.py
```

## Expected Behavior

- Valid requests → forwarded to MCP server  
- Invalid headers → blocked  
- Malicious patterns → detected and logged  
- Drift detected → warning triggered





