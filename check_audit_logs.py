#!/usr/bin/env python3
"""Check audit logs in the database."""

import sys
import os
import sqlite3

# Add paths
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Get database paths
forensic_dir = os.path.dirname(os.path.abspath(__file__))
evi_scan_dir = os.path.dirname(forensic_dir)
auth_db = os.path.join(evi_scan_dir, 'Authentication', 'evi_scan.db')

# Session database (where audit logs are stored)
database_code_path = os.path.join(evi_scan_dir, 'database', 'code')
if database_code_path not in sys.path:
    sys.path.insert(0, database_code_path)

try:
    from session_db import get_db_connection
    
    print("=" * 80)
    print("AUDIT LOGS CHECK")
    print("=" * 80)
    
    # Check session database
    print("\n1. Checking Session Database:")
    print("-" * 80)
    conn = get_db_connection()
    if conn:
        cur = conn.cursor()
        
        # Check if audit_logs table exists
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_logs'")
        table_exists = cur.fetchone()
        
        if table_exists:
            print("✅ audit_logs table exists")
            
            # Get table structure
            cur.execute("PRAGMA table_info(audit_logs)")
            columns = cur.fetchall()
            print(f"\nTable structure ({len(columns)} columns):")
            for col in columns:
                print(f"  - {col[1]} ({col[2]})")
            
            # Count total logs
            cur.execute("SELECT COUNT(*) FROM audit_logs")
            total_count = cur.fetchone()[0]
            print(f"\nTotal audit log entries: {total_count}")
            
            if total_count > 0:
                # Get recent logs
                print("\n2. Recent Audit Logs (last 10):")
                print("-" * 80)
                cur.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 10")
                logs = cur.fetchall()
                
                # Get column names
                column_names = [description[0] for description in cur.description]
                print(f"\nColumns: {', '.join(column_names)}")
                print("\nRecent entries:")
                print("-" * 80)
                
                for log in logs:
                    log_dict = dict(zip(column_names, log))
                    print(f"\nTimestamp: {log_dict.get('timestamp', 'N/A')}")
                    print(f"  User ID: {log_dict.get('user_id', 'N/A')}")
                    print(f"  Action: {log_dict.get('action', 'N/A')}")
                    print(f"  Resource: {log_dict.get('resource', 'N/A')}")
                    print(f"  Success: {log_dict.get('success', 'N/A')}")
                    print(f"  IP: {log_dict.get('ip_address', 'N/A')}")
                    if log_dict.get('details'):
                        print(f"  Details: {log_dict.get('details', 'N/A')[:100]}...")
            else:
                print("\n⚠️ No audit log entries found in database")
        else:
            print("❌ audit_logs table does NOT exist")
            print("\nThe audit_logs table needs to be created.")
            print("This should happen automatically when the security module is loaded.")
        
        conn.close()
    else:
        print("❌ Could not connect to session database")
    
    # Check authentication database for users
    print("\n" + "=" * 80)
    print("3. Checking User Roles in Authentication Database:")
    print("-" * 80)
    if os.path.exists(auth_db):
        print(f"✅ Auth database found: {auth_db}")
        auth_conn = sqlite3.connect(auth_db)
        auth_cur = auth_conn.cursor()
        
        # Check users
        auth_cur.execute("SELECT id, email, username, role FROM users")
        users = auth_cur.fetchall()
        print(f"\nFound {len(users)} users:")
        for user in users:
            user_id, email, username, role = user
            print(f"  ID {user_id}: {username} ({email}) - Role: {role}")
        
        auth_conn.close()
    else:
        print(f"❌ Auth database not found: {auth_db}")
    
    print("\n" + "=" * 80)
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()


