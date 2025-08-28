# Project Guardian 2.0 
# Deployment Strategy

## Overview
The PII Detector & Redactor is designed to identify and mask sensitive information (PII) in real-time data streams. The goal is to prevent unauthorized access or leakage of customer details that could lead to fraud.

## Deployment Location
The solution should be deployed as a **Sidecar container** next to services that process incoming/outgoing data streams (e.g., API Gateway, Ingress Controller).  

- **Why Sidecar?**
  - **Low latency:** Redaction happens locally, no external network calls.
  - **Scalability:** Each pod/service can have its own PII filter.
  - **Ease of integration:** Can be dropped in without rewriting the main app.
  - **Security:** Prevents raw PII from leaving the service boundary.

## Alternative Deployment Options
- **DaemonSet (Node Level):** Runs on every node to inspect logs and network traffic. Good for infra-level visibility, but higher latency.
- **API Gateway Plugin:** Centralized filtering at the ingress point. Works well for SaaS APIs but could become a bottleneck at scale.
- **Internal Tool Plugin:** Useful for compliance dashboards or developer logs but not sufficient for real-time defense.

## Recommended Approach
1. **Ingress Traffic:** Deploy as an **API Gateway plugin** (e.g., NGINX Lua plugin or Envoy filter) to sanitize PII before data enters backend systems.
2. **Service-Level:** Run as a **Sidecar container** for microservices that store/process logs, ensuring no raw PII is persisted.
3. **Asynchronous Monitoring:** Use a **DaemonSet** to scan historical logs and ensure compliance (non-blocking).

## Deployment Workflow
1. Incoming request → API Gateway plugin intercepts → Redacts PII → Forwards clean payload.  
2. Microservices process sanitized data.  
3. DaemonSet periodically scans logs/storage for PII leaks.  

## Benefits
- **Latency:** Regex/NER-based detection runs in microseconds per record.  
- **Scalability:** Horizontal scaling with microservices.  
- **Cost-effectiveness:** No extra infra beyond lightweight sidecars.  
- **Compliance:** Ensures GDPR/DPDP compliance by preventing PII exposure.

---
