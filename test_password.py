"""Test password verification"""
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import sqlite3

ph = PasswordHasher()

conn = sqlite3.connect('jarwis.db')
cursor = conn.cursor()
cursor.execute("SELECT email, hashed_password FROM users WHERE email='user1@jarwis.ai'")
row = cursor.fetchone()

if row:
    print(f"Testing user: {row[0]}")
    print(f"Hash: {row[1][:60]}...")
    
    # Test with correct password
    try:
        ph.verify(row[1], '12341234')
        print("[OK] SUCCESS: Password '12341234' verified!")
    except VerifyMismatchError:
        print("[X] FAILED: Password '12341234' mismatch!")
    
    # Test verify function from auth module
    import sys
    sys.path.insert(0, '.')
    from database.auth import verify_password
    
    result = verify_password('12341234', row[1])
    print(f"\nUsing verify_password function: {result}")
else:
    print("User not found!")

conn.close()
