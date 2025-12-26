#!/usr/bin/env python3
"""Debug script to check RBAC and user permissions."""

import sys
import os
import sqlite3

# Add paths
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'security'))
    from security_enhancements import RBAC
    
    print("=" * 80)
    print("RBAC DEBUG INFORMATION")
    print("=" * 80)
    
    # Check available roles
    print("\nAvailable Roles and Permissions:")
    print("-" * 80)
    for role, permissions in RBAC.ROLES.items():
        print(f"\n{role.upper()}:")
        for perm in permissions:
            print(f"  - {perm}")
    
    # Check database path
    print("\n" + "=" * 80)
    print("Database Path Check:")
    print("-" * 80)
    # debug_rbac.py is in: EVI-SCAN/FORENSIC/
    # Database is in: EVI-SCAN/Authentication/evi_scan.db
    current_file = os.path.abspath(__file__)
    # current_file: .../EVI-SCAN/FORENSIC/debug_rbac.py
    forensic_dir = os.path.dirname(current_file)  # .../EVI-SCAN/FORENSIC/
    evi_scan_dir = os.path.dirname(forensic_dir)  # .../EVI-SCAN/
    auth_db = os.path.join(evi_scan_dir, 'Authentication', 'evi_scan.db')
    print(f"Current file: {current_file}")
    print(f"FORENSIC directory: {forensic_dir}")
    print(f"EVI-SCAN directory: {evi_scan_dir}")
    print(f"Expected database path: {auth_db}")
    print(f"Database exists: {os.path.exists(auth_db)}")
    
    if os.path.exists(auth_db):
        # Check users table
        print("\n" + "=" * 80)
        print("Users in Database:")
        print("-" * 80)
        conn = sqlite3.connect(auth_db)
        cur = conn.cursor()
        
        # Check if role column exists
        cur.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cur.fetchall()]
        print(f"Users table columns: {columns}")
        
        if 'role' in columns:
            cur.execute("SELECT id, email, username, role FROM users")
            users = cur.fetchall()
            print(f"\nFound {len(users)} users:")
            print(f"{'ID':<5} {'Email':<30} {'Username':<20} {'Role':<15}")
            print("-" * 80)
            for user in users:
                user_id, email, username, role = user
                print(f"{user_id:<5} {email:<30} {username:<20} {role:<15}")
                
                # Check permissions for this user
                has_audit_permission = RBAC.has_permission('view_audit_logs', user_id)
                print(f"  → Has 'view_audit_logs' permission: {has_audit_permission}")
        else:
            print("\n⚠️ WARNING: 'role' column does not exist in users table!")
            print("You need to add the role column. Run: python security/add_role_column.py")
        
        conn.close()
    else:
        print(f"\n⚠️ ERROR: Database not found at {auth_db}")
        print("Please check the database path.")
    
    print("\n" + "=" * 80)
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()

