#!/usr/bin/env python3
"""Test user session and RBAC for current user."""

import sys
import os
import sqlite3

# Add paths
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Get database paths
forensic_dir = os.path.dirname(os.path.abspath(__file__))
evi_scan_dir = os.path.dirname(forensic_dir)
auth_db = os.path.join(evi_scan_dir, 'Authentication', 'evi_scan.db')

# Import RBAC directly
try:
    import sys
    security_path = os.path.join(forensic_dir, 'security')
    if security_path not in sys.path:
        sys.path.insert(0, security_path)
    from security_enhancements import RBAC
    print("✅ RBAC imported successfully")
except Exception as e:
    print(f"❌ Failed to import RBAC: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("=" * 80)
print("USER SESSION AND RBAC TEST")
print("=" * 80)

# Check all users
print("\n1. All Users in Authentication Database:")
print("-" * 80)
if os.path.exists(auth_db):
    conn = sqlite3.connect(auth_db)
    cur = conn.cursor()
    
    cur.execute("SELECT id, email, username, role FROM users")
    users = cur.fetchall()
    
    for user in users:
        user_id, email, username, role = user
        print(f"\nUser ID: {user_id}")
        print(f"  Email: {email}")
        print(f"  Username: {username}")
        print(f"  Role in DB: {role}")
        
        # Test RBAC lookup
        try:
            rbac_role = RBAC.get_user_role(user_id)
            has_permission = RBAC.has_permission('view_audit_logs', user_id)
            print(f"  RBAC Role: {rbac_role}")
            print(f"  Has 'view_audit_logs' permission: {has_permission}")
            
            if role != rbac_role:
                print(f"  ⚠️ WARNING: Role mismatch! DB says '{role}' but RBAC says '{rbac_role}'")
        except Exception as e:
            print(f"  ❌ Error checking RBAC: {e}")
    
    conn.close()
else:
    print(f"❌ Auth database not found: {auth_db}")

# Check for user "Devesh" specifically
print("\n" + "=" * 80)
print("2. Testing 'Devesh' User (ID 3):")
print("-" * 80)
try:
    user_id = 3
    role = RBAC.get_user_role(user_id)
    has_permission = RBAC.has_permission('view_audit_logs', user_id)
    
    print(f"User ID: {user_id}")
    print(f"Role: {role}")
    print(f"Has 'view_audit_logs' permission: {has_permission}")
    
    if role in RBAC.ROLES:
        permissions = RBAC.ROLES[role]
        print(f"Role '{role}' has permissions: {permissions}")
        print(f"'view_audit_logs' in permissions: {'view_audit_logs' in permissions}")
    else:
        print(f"⚠️ Role '{role}' not found in RBAC.ROLES")
        print(f"Available roles: {list(RBAC.ROLES.keys())}")
        
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 80)

