#!/usr/bin/env python3
"""Count statistics for UFDR_FILE.format"""

import json
from pathlib import Path

CASE_DIR = Path(__file__).parent / "data" / "UFDR's(new)" / "UFDR_FILE.format"

# Read all files
calls_file = CASE_DIR / "Artifacts" / "Calls" / "calls.json"
sms_file = CASE_DIR / "Artifacts" / "SMS" / "sms.json"
whatsapp_file = CASE_DIR / "Artifacts" / "WhatsApp" / "whatsapp.json"
contacts_file = CASE_DIR / "Artifacts" / "Contacts" / "contacts.json"

calls = json.load(open(calls_file, encoding='utf-8'))
sms = json.load(open(sms_file, encoding='utf-8'))
whatsapp = json.load(open(whatsapp_file, encoding='utf-8'))
contacts = json.load(open(contacts_file, encoding='utf-8'))

print("\n=== UFDR_FILE.format Statistics ===\n")
print(f"Call Logs: {len(calls)}")
print(f"SMS Messages: {len(sms)}")
print(f"WhatsApp Messages: {len(whatsapp)}")
print(f"Total Messages: {len(sms) + len(whatsapp)}")
print(f"Contacts: {len(contacts)}")
print("\n" + "="*40)

