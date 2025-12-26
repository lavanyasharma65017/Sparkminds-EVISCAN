#!/usr/bin/env python3
"""Check current user in database and verify admin status."""

import sys
import os
import sqlite3

# Get database paths
forensic_dir = os.path.dirname(os.path.abspath(__file__))
evi_scan_dir = os.path.dirname(forensic_dir)
auth_db = os.path.join(evi_scan_dir, 'Authentication', 'evi_scan.db')

print("=" * 80)
print("CHECKING USER: deveshsah0042@gmail.com")
print("=" * 80)

if os.path.exists(auth_db):
    conn = sqlite3.connect(auth_db)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    
    # Find user by email
    cur.execute("SELECT id, email, username, role, first_name, last_name FROM users WHERE email = ?", 
                ('deveshsah0042@gmail.com',))
    user = cur.fetchone()
    
    if user:
        print(f"\n✅ User Found:")
        print(f"   ID: {user['id']}")
        print(f"   Email: {user['email']}")
        print(f"   Username: {user['username']}")
        print(f"   Name: {user['first_name']} {user['last_name']}")
        print(f"   Role in Database: {user['role']}")
        
        # Test RBAC
        try:
            sys.path.insert(0, forensic_dir)
            security_path = os.path.join(forensic_dir, 'security')
            if security_path not in sys.path:
                sys.path.insert(0, security_path)
            from security_enhancements import RBAC
            
            user_id = user['id']
            rbac_role = RBAC.get_user_role(user_id)
            has_permission = RBAC.has_permission('view_audit_logs', user_id)
            
            print(f"\n🔍 RBAC Check:")
            print(f"   User ID: {user_id}")
            print(f"   RBAC Role: {rbac_role}")
            print(f"   Has 'view_audit_logs' permission: {has_permission}")
            
            if user['role'] != rbac_role:
                print(f"\n⚠️ WARNING: Role mismatch!")
                print(f"   Database says: '{user['role']}'")
                print(f"   RBAC says: '{rbac_role}'")
            
            if has_permission:
                print(f"\n✅ User SHOULD have access to audit logs")
            else:
                print(f"\n❌ User does NOT have access to audit logs")
                print(f"\n   Role '{rbac_role}' permissions: {RBAC.ROLES.get(rbac_role, [])}")
        except Exception as e:
            print(f"\n❌ Error checking RBAC: {e}")
            import traceback
            traceback.print_exc()
    else:
        print(f"\n❌ User not found with email: deveshsah0042@gmail.com")
    
    conn.close()
else:
    print(f"\n❌ Auth database not found: {auth_db}")

print("\n" + "=" * 80)
print("RECOMMENDATION:")
print("=" * 80)
print("1. Make sure you are logged in as deveshsah0042@gmail.com")
print("2. Check your browser's session - the user_id should be 3")
print("3. Try logging out and logging back in")
print("4. Check server logs when accessing /audit-logs")
print("5. Visit /api/debug/rbac to see your current session permissions")


