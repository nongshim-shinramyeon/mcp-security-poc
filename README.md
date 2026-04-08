### Initial Run
Build and start containers
> docker compose up --build

Run Agent (if not auto-running)
> docker compose run agent

Check logs docker compose up --build
> docker logs <proxy-container> 

### Zero Trust Demo
The proxy now validates `X-Agent-ID`, `X-Device-ID`, and `X-API-Key` before forwarding `/rpc` traffic.

Default demo values:
- `AGENT_ID=agent-01`
- `DEVICE_ID=device-01`
- `API_KEY=demo-api-key`

Run a valid request from the agent container:
> docker compose run --rm agent python test_request.py

Run attack and detection scenarios:
> docker compose run --rm agent python attack_scenarios.py

Check structured proxy logs:
> docker compose logs proxy

### Drift Detection
Create the initial drift baseline:
> python scripts/drift_check.py baseline

Check for configuration drift and save a report:
> python scripts/drift_check.py check

The baseline is stored in `security-baseline/drift_baseline.json` and reports are written to `artifacts/drift/`.

### SBOM Generation
Build the images first:
> docker compose build

Generate SBOM files for all services:
> python scripts/generate_sbom.py

Generate SBOM for a single service:
> python scripts/generate_sbom.py --service mcp-server

SBOM files are written to `artifacts/sbom/`.
