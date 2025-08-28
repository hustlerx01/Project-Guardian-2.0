#!/usr/bin/env python3

import sys
import csv
import json
import re
import ast
from typing import Dict, Any, Optional

# --- Constants & Regex ---

# Using pre-compiled regex for performance.
# The phone regex uses a negative lookbehind/ahead to avoid matching numbers within longer strings.
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b")
PASSPORT_RE = re.compile(r"^[A-Za-z][0-9]{7}$")
AADHAR_RE = re.compile(r"^\d{4}\s?\d{4}\s?\d{4}$") # handles spaces
PHONE10_RE = re.compile(r"(?<!\d)\d{10}(?!\d)")
UPI_RE = re.compile(r"^[\w.\-]{2,}@[A-Za-z][A-Za-z0-9.\-]{1,}$")

# Canonical key names to check against (case-insensitive)
# TODO: Maybe load these from a config file later?
PHONE_KEYS = {"phone", "contact", "mobile", "whatsapp", "contact_no", "phone_number"}
AADHAR_KEYS = {"aadhar", "aadhaar", "aadhar_number"}
PASSPORT_KEYS = {"passport", "passport_no"}
UPI_KEYS = {"upi_id", "vpa", "upi"}
NAME_KEYS = {"name", "first_name", "last_name"}
EMAIL_KEYS = {"email", "email_id"}
ADDR_KEYS = {"address", "residential_address", "shipping_address", "addr", "address_line1"}
CITY_KEYS = {"city"}
PIN_KEYS = {"pin_code", "pincode"}
DEVICE_KEYS = {"device_id"}
IP_KEYS = {"ip_address", "ip"}

# This function is a bit of a monster, but the input JSON is a complete mess.
# It tries a few different ways to parse what *should* be JSON.
def smart_json_loads(raw_data: Any) -> Dict[str, Any]:
    """Parse many real-world 'JSON in CSV' formats and return {} if parsing fails."""
    if isinstance(raw_data, dict):
        return raw_data
    if not raw_data:
        return {}
    
    s = str(raw_data).strip()
    # Skip empty or null-like strings
    if not s or s.lower() in {"none", "nan", "null"}:
        return {}

    try: # Standard JSON
        return json.loads(s)
    except json.JSONDecodeError:
        try: # Sometimes it's a Python literal (e.g., uses ' instead of ")
            return ast.literal_eval(s)
        except (ValueError, SyntaxError):
            try: # Ugh, sometimes the JSON is double-encoded as a string inside another JSON string
                return json.loads(json.loads(s))
            except (TypeError, ValueError, json.JSONDecodeError):
                # Final desperate attempt: sometimes it's wrapped in extra quotes
                if s.startswith('"') and s.endswith('"'):
                    try:
                        return json.loads(s[1:-1])
                    except json.JSONDecodeError:
                        pass # Give up
    return {} # If all else fails, return an empty dict

# --- Masking & Detection Functions ---

def mask_string(s: str, visible_start: int, visible_end: int, char: str = 'X') -> str:
    """Helper to mask a string, e.g., "1234567890" -> "12XXXXXX90" """
    if not s: return ""
    length = len(s)
    masked_len = length - (visible_start + visible_end)
    if masked_len <= 0: return char * length
    return f"{s[:visible_start]}{char * masked_len}{s[length-visible_end:]}"

def mask_phone(phone_str: str) -> str:
    return PHONE10_RE.sub(lambda m: mask_string(m.group(0), 2, 2), phone_str or "")

def mask_aadhar(aadhar_str: str) -> str:
    digits = re.sub(r"\s+", "", aadhar_str or "")
    if len(digits) != 12 or not digits.isdigit():
        return "[REDACTED_PII]"
    return f"XXXX XXXX {digits[-4:]}"

# Basic masking for various PII types
def mask_passport(s: str) -> str: return mask_string((s or "").strip(), 1, 2)
def mask_email(s: str) -> str:
    if "@" not in s: return "[REDACTED_PII]"
    user, domain = s.split("@", 1)
    return f"{mask_string(user, 2, 0)}@{domain}"
def mask_name(s: str) -> str:
    parts = (s or "").strip().split()
    return " ".join([f"{p[0]}{'X'*(len(p)-1)}" for p in parts]) if parts else ""
def mask_address(_s: str) -> str: return "[REDACTED_PII]"
def mask_pin(s: str) -> str: return mask_string(re.sub(r"\D", "", s or ""), 0, 2)
def mask_ip(_s: str) -> str: return "***.***.***.***"

def find_pii(record: Dict[str, Any]) -> Dict[str, bool]:
    """Scans a record and returns a dictionary of flags for found PII types."""
    # Normalize keys to lowercase for reliable matching
    normalized = {k.lower(): str(v or "") for k, v in record.items()}
    
    pii_flags = {
        "phone": any(k in PHONE_KEYS and PHONE10_RE.search(v) for k, v in normalized.items()),
        "aadhar": any(k in AADHAR_KEYS and AADHAR_RE.match(v.strip()) for k, v in normalized.items()),
        "passport": any(k in PASSPORT_KEYS and PASSPORT_RE.match(v.strip()) for k, v in normalized.items()),
        "upi": any(k in UPI_KEYS and UPI_RE.match(v.strip()) for k, v in normalized.items()),
        "email": any(k in EMAIL_KEYS and EMAIL_RE.match(v.strip()) for k, v in normalized.items()),
        "ip": any(k in IP_KEYS and IPV4_RE.search(v) for k, v in normalized.items()),
        "device": any(k in DEVICE_KEYS and v for k, v in normalized.items())
    }
    
    # Check for compound PII (e.g., name + address)
    has_name = bool(normalized.get("name", "").strip() or (normalized.get("first_name") and normalized.get("last_name")))
    has_addr = bool(any(k in ADDR_KEYS and v for k, v in normalized.items()))
    has_pin = any(k in PIN_KEYS and len(re.sub(r"\D", "", v)) == 6 for k, v in normalized.items())
    
    pii_flags["name"] = has_name
    pii_flags["address"] = has_addr and has_pin
    
    return pii_flags


def main(input_file):
    """Main execution block."""
    output_file = "redacted_output_candidate_full_name.csv"
    print(f"Processing '{input_file}'...")

    try:
        with open(input_file, encoding="utf-8-sig") as f:
            # Sniff out the json column instead of hardcoding it
            header = next(csv.reader(f), [])
            json_col = next((h for h in header if "json" in h.lower()), None)
            if not json_col:
                print("[-] FATAL: No column with 'json' in the header found. Aborting.")
                sys.exit(1)
    except FileNotFoundError:
        print(f"[-] ERROR: Input file '{input_file}' not found.")
        sys.exit(1)

    processed_count = 0
    with open(input_file, encoding="utf-8-sig") as f_in, \
         open(output_file, "w", encoding="utf-8", newline="") as f_out:

        reader = csv.DictReader(f_in)
        writer = csv.DictWriter(f_out, fieldnames=["record_id", "redacted_data_json", "is_pii"])
        writer.writeheader()

        for row in reader:
            processed_count += 1
            record_id = row.get("record_id", f"ROW_{processed_count}")
            raw_json = row.get(json_col, "")
            data = smart_json_loads(raw_json)
            
            # if not data: # a bit noisy, but good for debugging
            #     print(f"[!] Warning: Could not parse JSON for record_id '{record_id}'")

            pii_flags = find_pii(data)
            
            # PII is present if there's a strong identifier OR 2+ weaker ones
            strong_pii = pii_flags["phone"] or pii_flags["aadhar"] or pii_flags["passport"] or pii_flags["upi"]
            weak_pii_count = sum([pii_flags["name"], pii_flags["email"], pii_flags["address"], pii_flags["device"], pii_flags["ip"]])
            is_pii = strong_pii or (weak_pii_count >= 2)

            if is_pii:
                redacted_data = {}
                for k, v in data.items():
                    val_str = str(v or "")
                    k_lower = k.lower()
                    
                    # This if/elif block is getting long. Could be a dispatch dict... meh, works for now.
                    if k_lower in PHONE_KEYS and pii_flags["phone"]:
                        redacted_data[k] = mask_phone(val_str)
                    elif k_lower in AADHAR_KEYS and pii_flags["aadhar"]:
                        redacted_data[k] = mask_aadhar(val_str)
                    elif k_lower in PASSPORT_KEYS and pii_flags["passport"]:
                        redacted_data[k] = mask_passport(val_str)
                    elif k_lower in EMAIL_KEYS and pii_flags["email"]:
                        redacted_data[k] = mask_email(val_str)
                    elif k_lower in NAME_KEYS and pii_flags["name"]:
                         redacted_data[k] = mask_name(val_str)
                    elif k_lower in ADDR_KEYS and pii_flags["address"]:
                        redacted_data[k] = mask_address(val_str)
                    elif k_lower in PIN_KEYS and pii_flags["address"]:
                        redacted_data[k] = mask_pin(val_str)
                    elif k_lower in IP_KEYS and pii_flags["ip"]:
                         redacted_data[k] = mask_ip(val_str)
                    else:
                        redacted_data[k] = v # No redaction needed for this field
                
                redacted_json_str = json.dumps(redacted_data, ensure_ascii=False)
            else:
                redacted_json_str = json.dumps(data, ensure_ascii=False) # No PII, dump as-is

            writer.writerow({
                "record_id": record_id,
                "redacted_data_json": redacted_json_str,
                "is_pii": is_pii
            })

    print(f"\n[+] Done! Processed {processed_count} rows.")
    print(f"[+] Output written to '{output_file}'")


if __name__ == "__main__":
    # Super basic command line argument handling
    if len(sys.argv) != 2:
        print("Usage: python3 this_script.py <your_input_file.csv>")
        sys.exit(1)
    
    input_csv_file = sys.argv[1]
    main(input_csv_file)
