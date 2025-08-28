# Deployment strategy writer

DEPLOYMENT_MD = """# Project Guardian 2.0 — Deployment Strategy (Real‑time PII Defense)

## Goals
- Stop PII at the **perimeter**, before it reaches logs, traces, and data lakes.
- **Low latency** (<10 ms typical per JSON payload) and **linear scalability**.
- **Defense in depth:** ingress gateway + sidecar log filter + async backstop.

## Recommended Placement
1. **L7 API Gateway plugin (primary):** Envoy WASM or NGINX Lua filter streams
   request/response bodies to a **local sidecar** over a Unix domain socket.
2. **Sidecar Daemon** next to workloads: sanitizes application logs (stdout/file)
   before shipping via Fluent Bit/Vector.
3. **Kafka backstop**: re‑sanitize streams headed to the data lake.

## Why here?
- **Scales** with pods (no central choke point).
- **Fast** local call; stream‑based, no full buffering.
- **Zero app changes**; canary rollout with shadow mode.

## Policy Mapping (matches this script)
- **Standalone PII:** phone(10d), Aadhaar(12d), Passport([A-Z]\\d{7}), UPI(user@psp) → always redact.
- **Combinatorial PII:** any two of {full name, email, physical address (address OR city+pin), device_id/IP} → redact only when ≥2 occur.

## Modes
- **Shadow** (detect only) → **Mask** (default) → **Block** (sensitive write routes).
- Per‑route fail‑open/closed; Prometheus metrics.

## Ops
- Timeouts and backpressure; token buckets for surge.
- Idempotent masking; no storage of raw PII.
- CI gate: regression F1 ≥ 0.95 on synthetic datasets.

"""
