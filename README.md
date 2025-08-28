# Project Guardian 2.0 

##  Overview
This project is part of the **Project Guardian 2.0** cybersecurity challenge.  
The goal is to detect and redact **Personally Identifiable Information (PII)** from structured data to prevent fraud and ensure compliance with privacy regulations (e.g., GDPR, DPDP Act).

The solution:
- Identifies **standalone PII** (e.g., phone numbers, Aadhaar, UPI IDs).
- Identifies **combinatorial PII** (e.g., name + email, address + IP).
- Redacts sensitive values while preserving data utility.
- Outputs a clean CSV file with a detection flag.

---

##  Features
-  Detects and redacts:
  - Phone numbers (10-digit), Aadhaar (12-digit), Passport numbers
  - UPI IDs, IP addresses, Device IDs
  - Names, Emails, Addresses (when combined)
-  Supports **standalone and combinatorial PII rules**
-  Exports a clean CSV with:
  - `record_id`
  - `redacted_data_json`
  - `is_pii` (True/False)
-  Lightweight, no external API calls, works offline
-  Ready for deployment as **sidecar container / API Gateway filter**

---

##  Requirements
- Python **3.8+**
- Standard libraries only (`json`, `csv`, `re`)

No external dependencies are required.

---

##  Usage

### 1. Input Format
CSV file with headers:
```
record_id,data_json
```

Where `data_json` is a JSON object stored as a string. Example:
```
1,"{""phone"": ""9876543210"", ""order_value"": 1299}"
2,"{""name"": ""Ravi Kumar"", ""email"": ""ravi@email.com""}"
```

### 2. Run the Script
```bash
python3 detector_full_candidate_name.py iscp_pii_dataset.csv
```

### 3. Output Format
The script generates:
```
redacted_output_candidate_full_name.csv
```

With columns:
```
record_id,redacted_data_json,is_pii
```

Example output:
```
1,"{""phone"": ""98XXXXXX10"", ""order_value"": 1299}",True
2,"{""name"": ""RXXX KXXX"", ""email"": ""raXXX@email.com""}",True
3,"{""first_name"": ""Priya"", ""product"": ""iPhone 14""}",False
```

---

##  PII Detection Rules
### Standalone PII → Always Sensitive
- Aadhaar (12 digits)
- Phone numbers (10 digits)
- Passport numbers
- UPI IDs
- Credit card numbers
- IP addresses

### Combinatorial PII → Sensitive Only in Combination
- Name + Email
- Name + Address
- Address + IP
- Device ID + Location

---

##  Deployment
- **Recommended:** Deploy as a **sidecar container** or **API Gateway plugin** for real-time PII redaction.  
- See [deployment.md](deployment.md) for detailed strategy.
