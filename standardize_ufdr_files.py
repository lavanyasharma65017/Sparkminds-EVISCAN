#!/usr/bin/env python3
"""
Script to standardize all UFDR files for consistency.
- Standardizes field names (caller/receiver -> from/to, message -> text, duration_sec -> duration)
- Standardizes timestamp formats (space to T separator)
- Fixes metadata directory names
- Fixes summary.json typo
"""

import json
import os
import re
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).parent / "data" / "UFDR's(new)"

def standardize_timestamp(ts):
    """Convert timestamp from 'YYYY-MM-DD HH:MM:SS' to 'YYYY-MM-DDTHH:MM:SS'"""
    if isinstance(ts, str):
        # Replace space with T if it's in the format YYYY-MM-DD HH:MM:SS
        if re.match(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', ts):
            return ts.replace(' ', 'T', 1)
    return ts

def standardize_calls_file(file_path):
    """Standardize calls.json file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        modified = False
        for call in data:
            # Convert caller/receiver to from/to
            if 'caller' in call:
                call['from'] = call.pop('caller')
                modified = True
            if 'receiver' in call:
                call['to'] = call.pop('receiver')
                modified = True
            
            # Convert duration_sec to duration
            if 'duration_sec' in call:
                call['duration'] = call.pop('duration_sec')
                modified = True
            
            # Standardize timestamp
            if 'timestamp' in call:
                new_ts = standardize_timestamp(call['timestamp'])
                if new_ts != call['timestamp']:
                    call['timestamp'] = new_ts
                    modified = True
        
        if modified:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"[OK] Standardized {file_path}")
            return True
    except Exception as e:
        print(f"[ERROR] Error processing {file_path}: {e}")
    return False

def standardize_sms_file(file_path):
    """Standardize sms.json file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        modified = False
        for sms in data:
            # Convert sender/receiver to from/to
            if 'sender' in sms and 'receiver' in sms:
                sms['from'] = sms.pop('sender')
                sms['to'] = sms.pop('receiver')
                modified = True
            
            # Convert message/body to text
            if 'message' in sms:
                sms['text'] = sms.pop('message')
                modified = True
            elif 'body' in sms:
                sms['text'] = sms.pop('body')
                modified = True
            
            # Standardize timestamp
            if 'timestamp' in sms:
                new_ts = standardize_timestamp(sms['timestamp'])
                if new_ts != sms['timestamp']:
                    sms['timestamp'] = new_ts
                    modified = True
        
        if modified:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"[OK] Standardized {file_path}")
            return True
    except Exception as e:
        print(f"[ERROR] Error processing {file_path}: {e}")
    return False

def standardize_whatsapp_file(file_path):
    """Standardize whatsapp.json file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        modified = False
        for msg in data:
            # Convert sender/receiver to from/to
            if 'sender' in msg and 'receiver' in msg:
                msg['from'] = msg.pop('sender')
                msg['to'] = msg.pop('receiver')
                modified = True
            
            # Convert message to text
            if 'message' in msg:
                msg['text'] = msg.pop('message')
                modified = True
            
            # Standardize timestamp
            if 'timestamp' in msg:
                new_ts = standardize_timestamp(msg['timestamp'])
                if new_ts != msg['timestamp']:
                    msg['timestamp'] = new_ts
                    modified = True
        
        if modified:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"[OK] Standardized {file_path}")
            return True
    except Exception as e:
        print(f"[ERROR] Error processing {file_path}: {e}")
    return False

def fix_metadata_directory(case_dir):
    """Rename metadata/ to __metadata__/ if it exists"""
    metadata_dir = case_dir / "metadata"
    if metadata_dir.exists() and metadata_dir.is_dir():
        new_dir = case_dir / "__metadata__"
        if not new_dir.exists():
            metadata_dir.rename(new_dir)
            print(f"[OK] Renamed metadata/ to __metadata__/ in {case_dir}")
            return True
    return False

def fix_summary_typo(case_dir):
    """Rename summery.json to summary.json if it exists"""
    summery_file = case_dir / "Reports" / "summery.json"
    if summery_file.exists():
        summary_file = case_dir / "Reports" / "summary.json"
        if not summary_file.exists():
            summery_file.rename(summary_file)
            print(f"[OK] Renamed summery.json to summary.json in {case_dir}")
            return True
    return False

def main():
    """Main function to standardize all UFDR files"""
    print("Starting UFDR file standardization...\n")
    
    if not BASE_DIR.exists():
        print(f"Error: Base directory {BASE_DIR} does not exist!")
        return
    
    # Find all case directories
    case_dirs = [d for d in BASE_DIR.iterdir() if d.is_dir() and not d.name.endswith('.zip')]
    
    total_processed = 0
    
    for case_dir in case_dirs:
        print(f"\nProcessing: {case_dir.name}")
        
        # Fix metadata directory name
        fix_metadata_directory(case_dir)
        
        # Fix summary.json typo
        fix_summary_typo(case_dir)
        
        # Standardize artifact files
        artifacts_dir = case_dir / "Artifacts"
        if artifacts_dir.exists():
            # Calls
            calls_file = artifacts_dir / "Calls" / "calls.json"
            if calls_file.exists():
                if standardize_calls_file(calls_file):
                    total_processed += 1
            
            # SMS
            sms_file = artifacts_dir / "SMS" / "sms.json"
            if sms_file.exists():
                if standardize_sms_file(sms_file):
                    total_processed += 1
            
            # WhatsApp
            whatsapp_file = artifacts_dir / "WhatsApp" / "whatsapp.json"
            if whatsapp_file.exists():
                if standardize_whatsapp_file(whatsapp_file):
                    total_processed += 1
    
    print(f"\n\n[OK] Standardization complete! Processed {total_processed} files.")

if __name__ == "__main__":
    main()

