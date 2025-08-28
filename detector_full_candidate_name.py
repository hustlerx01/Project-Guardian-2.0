
# -*- coding: utf-8 -*-

import csv
import json
import re
import sys
from typing import Dict, Any

# ---------- Helpers ----------

PHONE_FIELDS = {"phone", "contact", "alt_phone", "mobile"}
AADHAR_FIELDS = {"aadhar", "aadhaar"}
PASSPORT_FIELDS = {"passport"}
UPI_FIELDS = {"upi", "upi_id"}
EMAIL_FIELDS = {"email", "alt_email", "username"}
NAME_FIELDS = {"name"}
FIRST_NAME = "first_name"
LAST_NAME = "last_name"
ADDRESS_FIELDS = {"address"}
IP_FIELDS = {"ip", "ip_address"}
DEVICE_FIELDS = {"device_id"}

email_regex = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
upi_regex = re.compile(r"\b[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}\b")
passport_regex = re.compile(r"\b[A-Z][0-9]{7}\b")
ten_digits = re.compile(r"\b\d{10}\b")
twelve_digits = re.compile(r"\b\d{12}\b")
pincode_regex = re.compile(r"\b\d{6}\b")  # Indian PIN code

def mask_phone(v: str) -> str:
    m = re.search(r"\d{10}", v)
    if not m: 
        return v
    s = m.group(0)
    return v.replace(s, f"{s[:2]}XXXXXX{s[-2:]}")

def mask_aadhar(v: str) -> str:
    m = re.search(r"\d{12}", v)
    if not m:
        return v
    s = m.group(0)
    return v.replace(s, f"{s[:4]}XXXX{s[-4:]}")

def mask_passport(v: str) -> str:
    m = passport_regex.search(v)
    if not m:
        return v
    s = m.group(0)
    return v.replace(s, s[0] + "XXXXXXX")

def mask_upi(v: str) -> str:
    if "@" not in v:
        return "[REDACTED_PII]"
    left, right = v.split("@", 1)
    if len(left) <= 2:
        left_mask = "XX"
    else:
        left_mask = left[:2] + "XXX"
    return f"{left_mask}@{right}"

def mask_email(v: str) -> str:
    if "@" not in v:
        return v
    left, right = v.split("@", 1)
    if len(left) <= 2:
        left_mask = "XX"
    else:
        left_mask = left[:2] + "XXX"
    return f"{left_mask}@{right}"

def mask_name(v: str) -> str:
    parts = [p for p in v.split() if p]
    return " ".join(p[0] + "X" * (len(p) - 1) for p in parts)

def mask_address(v: str) -> str:
    # keep PIN code visible if present
    pin = None
    m = pincode_regex.search(v)
    if m:
        pin = m.group(0)
    prefix = v[:3] + "XXX" if len(v) >= 3 else "XXX"
    trail = f", {pin}" if pin else ""
    return f"{prefix}...{trail}"

def mask_ip(v: str) -> str:
    try:
        a,b,c,d = v.split(".")
        return f"{a}.XXX.XXX.{d}"
    except Exception:
        return "[REDACTED_PII]"

def mask_device(v: str) -> str:
    v = str(v)
    if len(v) <= 6:
        return "XXXXXX"
    return v[:3] + "XXX" + v[-3:]

def looks_full_name(v: str) -> bool:
    # at least two alphabetic tokens
    tokens = [t for t in re.findall(r"[A-Za-z]+", v)]
    return len(tokens) >= 2

def is_physical_address(record: Dict[str, Any]) -> bool:
    addr = ""
    for f in ADDRESS_FIELDS:
        if f in record and record[f]:
            addr += str(record[f]) + " "
    # Use presence of address + (city/state/pin_code) OR 6-digit pin
    city = str(record.get("city", "")).strip()
    state = str(record.get("state", "")).strip()
    pin_code = str(record.get("pin_code", "")).strip()
    if addr and (city or state or pin_code or pincode_regex.search(addr)):
        return True
    return False

def has_standalone_pii(record: Dict[str, Any]) -> bool:
    # Phone (only in phone-like fields)
    for k in record:
        lk = k.lower()
        v = str(record[k])
        if lk in PHONE_FIELDS and ten_digits.search(v):
            return True
    # Aadhar
    for k in record:
        if k.lower() in AADHAR_FIELDS and twelve_digits.search(str(record[k])):
            return True
    # Passport
    for k in record:
        if k.lower() in PASSPORT_FIELDS and passport_regex.search(str(record[k])):
            return True
    # UPI
    for k in record:
        if k.lower() in UPI_FIELDS and upi_regex.search(str(record[k])):
            return True
    return False

def combinatorial_count(record: Dict[str, Any]) -> int:
    count = 0
    # Name
    name_present = False
    if any(f in record and record[f] for f in NAME_FIELDS):
        if looks_full_name(str(next(record[f] for f in NAME_FIELDS if f in record))):
            name_present = True
    if FIRST_NAME in record and LAST_NAME in record and record[FIRST_NAME] and record[LAST_NAME]:
        name_present = True
    if name_present:
        count += 1
    # Email
    email_present = any(f in record and record[f] and email_regex.search(str(record[f])) for f in EMAIL_FIELDS)
    if email_present:
        count += 1
    # Physical address
    if is_physical_address(record):
        count += 1
    # Device ID (only in user context)
    device_present = any(f in record and record[f] for f in DEVICE_FIELDS)
    user_ctx = name_present or email_present or any(f in record for f in PHONE_FIELDS)
    if device_present and user_ctx:
        count += 1
    # IP address (only with user context)
    ip_present = any(f in record and record[f] for f in IP_FIELDS)
    if ip_present and user_ctx:
        count += 1
    return count

def redact_record(record: Dict[str, Any], is_pii: bool) -> Dict[str, Any]:
    out = dict(record)
    # Standalone redactions always apply
    for k in list(out.keys()):
        v = out[k]
        if v is None:
            continue
        s = str(v)
        lk = k.lower()
        if lk in PHONE_FIELDS and re.search(r"\d{10}", s):
            out[k] = mask_phone(s)
        if lk in AADHAR_FIELDS and re.search(r"\d{12}", s):
            out[k] = mask_aadhar(s)
        if lk in PASSPORT_FIELDS and passport_regex.search(s):
            out[k] = mask_passport(s)
        if lk in UPI_FIELDS and upi_regex.search(s):
            out[k] = mask_upi(s)
    # Combinatorial redactions only if record qualifies
    if is_pii and combinatorial_count(record) >= 2:
        # Email
        for f in EMAIL_FIELDS:
            if f in out and out[f]:
                sv = str(out[f])
                if email_regex.search(sv):
                    out[f] = mask_email(sv)
        # Name (name field or first+last)
        for f in NAME_FIELDS:
            if f in out and out[f] and looks_full_name(str(out[f])):
                out[f] = mask_name(str(out[f]))
        if FIRST_NAME in out and LAST_NAME in out and out[FIRST_NAME] and out[LAST_NAME]:
            out[FIRST_NAME] = out[FIRST_NAME][0] + "X" * (len(str(out[FIRST_NAME])) - 1)
            out[LAST_NAME] = out[LAST_NAME][0] + "X" * (len(str(out[LAST_NAME])) - 1)
        # Address
        for f in ADDRESS_FIELDS:
            if f in out and out[f]:
                out[f] = mask_address(str(out[f]))
        # IP
        for f in IP_FIELDS:
            if f in out and out[f]:
                out[f] = mask_ip(str(out[f]))
        # Device
        for f in DEVICE_FIELDS:
            if f in out and out[f]:
                out[f] = mask_device(str(out[f]))
    return out

def process(input_csv: str, output_csv: str) -> None:
    with open(input_csv, "r", encoding="utf-8") as f_in, open(output_csv, "w", encoding="utf-8", newline="") as f_out:
        reader = csv.DictReader(f_in)
        writer = csv.DictWriter(f_out, fieldnames=["record_id","redacted_data_json","is_pii"])
        writer.writeheader()
        for row in reader:
            rec_id = str(row.get("record_id", ""))
            data_str = row.get("data_json") or row.get("Data_json") or row.get("Data_JSON")
            if not data_str:
                # write passthrough
                writer.writerow({"record_id": rec_id, "redacted_data_json": "{}", "is_pii": False})
                continue
            try:
                data = json.loads(data_str)
            except Exception:
                # malformed JSON; mark as False and pass through
                writer.writerow({"record_id": rec_id, "redacted_data_json": data_str, "is_pii": False})
                continue

            # Decide PII
            is_pii = has_standalone_pii(data) or (combinatorial_count(data) >= 2)

            # Redact accordingly
            redacted = redact_record(data, is_pii)
            writer.writerow({
                "record_id": rec_id,
                "redacted_data_json": json.dumps(redacted, ensure_ascii=False),
                "is_pii": bool(is_pii)
            })

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py iscp_pii_dataset.csv")
        sys.exit(1)
    input_csv = sys.argv[1]
    output_csv = "redacted_output_candidate_full_name.csv"
    process(input_csv, output_csv)
    print(f"OK: wrote {output_csv}")

if __name__ == "__main__":
    main()
