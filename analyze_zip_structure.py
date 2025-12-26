#!/usr/bin/env python3
"""Analyze the structure of a UFDR zip file to understand validation errors."""

import zipfile
import json
import sys
import os

# Default to analyzing any UFDR zip file
zip_path = r"data/UFDR's(new)/UFDR_FILE.format.zip"

if not os.path.exists(zip_path):
    print(f"Error: {zip_path} not found")
    print("Usage: python analyze_zip_structure.py [path_to_ufdr_zip]")
    sys.exit(1)

print("=" * 80)
print("ANALYZING UFDR ZIP STRUCTURE")
print("=" * 80)

with zipfile.ZipFile(zip_path, 'r') as z:
    # Check SMS structure
    print("\n1. SMS STRUCTURE:")
    print("-" * 80)
    try:
        sms_data = json.loads(z.read('Artifacts/SMS/sms.json'))
        print(f"Type: {type(sms_data)}")
        if isinstance(sms_data, list):
            print(f"Length: {len(sms_data)}")
            if len(sms_data) > 0:
                print("\nFirst message:")
                print(json.dumps(sms_data[0], indent=2))
                print("\nKeys in first message:", list(sms_data[0].keys()) if isinstance(sms_data[0], dict) else "N/A")
        elif isinstance(sms_data, dict):
            print(f"Keys: {list(sms_data.keys())}")
            # Check if it's a wrapper
            for key in sms_data.keys():
                if isinstance(sms_data[key], list) and len(sms_data[key]) > 0:
                    print(f"\nFirst message in '{key}':")
                    print(json.dumps(sms_data[key][0], indent=2))
                    break
    except Exception as e:
        print(f"Error reading SMS: {e}")
    
    # Check WhatsApp structure
    print("\n\n2. WHATSAPP STRUCTURE:")
    print("-" * 80)
    try:
        whatsapp_data = json.loads(z.read('Artifacts/WhatsApp/whatsapp.json'))
        print(f"Type: {type(whatsapp_data)}")
        if isinstance(whatsapp_data, list):
            print(f"Length: {len(whatsapp_data)}")
            if len(whatsapp_data) > 0:
                print("\nFirst message:")
                print(json.dumps(whatsapp_data[0], indent=2))
                print("\nKeys in first message:", list(whatsapp_data[0].keys()) if isinstance(whatsapp_data[0], dict) else "N/A")
        elif isinstance(whatsapp_data, dict):
            print(f"Keys: {list(whatsapp_data.keys())}")
            for key in whatsapp_data.keys():
                if isinstance(whatsapp_data[key], list) and len(whatsapp_data[key]) > 0:
                    print(f"\nFirst message in '{key}':")
                    print(json.dumps(whatsapp_data[key][0], indent=2))
                    break
    except Exception as e:
        print(f"Error reading WhatsApp: {e}")
    
    # Check Contacts structure
    print("\n\n3. CONTACTS STRUCTURE:")
    print("-" * 80)
    try:
        contacts_data = json.loads(z.read('Artifacts/Contacts/contacts.json'))
        print(f"Type: {type(contacts_data)}")
        if isinstance(contacts_data, list):
            print(f"Length: {len(contacts_data)}")
            if len(contacts_data) > 0:
                print("\nFirst contact:")
                print(json.dumps(contacts_data[0], indent=2))
        elif isinstance(contacts_data, dict):
            print(f"Keys: {list(contacts_data.keys())}")
    except Exception as e:
        print(f"Error reading Contacts: {e}")
    
    # Check Calls structure
    print("\n\n4. CALLS STRUCTURE:")
    print("-" * 80)
    try:
        calls_data = json.loads(z.read('Artifacts/Calls/calls.json'))
        print(f"Type: {type(calls_data)}")
        if isinstance(calls_data, list):
            print(f"Length: {len(calls_data)}")
            if len(calls_data) > 0:
                print("\nFirst call:")
                print(json.dumps(calls_data[0], indent=2))
        elif isinstance(calls_data, dict):
            print(f"Keys: {list(calls_data.keys())}")
    except Exception as e:
        print(f"Error reading Calls: {e}")

print("\n" + "=" * 80)
print("ANALYSIS COMPLETE")
print("=" * 80)

