#!/usr/bin/env python3
# =============================================================================
# code_quality/complex_spaghetti.py – TigerGate CNAPP Test: Code Quality / SAST
# =============================================================================
# PURPOSE: Intentional code quality violations designed to trigger SonarQube
# code smell, cognitive complexity, and duplicate code detection rules.
#
# SONARQUBE RULES TRIGGERED:
#   SQ-S3776: Cognitive Complexity (function is 15+ branches deep)
#   SQ-S134:  Multiple return statements
#   SQ-S1515: Nested functions should not have too many lines
#   SQ-S1541: Cyclomatic Complexity too high
#   SQ-S1186: Empty catch clauses (exception swallowed)
#   SQ-S2259: Null dereference  
#   CWE-259:  Hardcoded password in code
# =============================================================================

import os
import sys
import json
import pickle
import subprocess

# 🔴 VULN: CWE-259 - Hardcoded password in global constant
PASSWORD = "admin123"                      # BAD: Hardcoded credential
DB_CONN_STRING = "mysql://root:root123@localhost/db"  # BAD: Connection string with password

class UserManager:
    # 🔴 SQ-S1541: Class is too long and has too many responsibilities
    def __init__(self):
        self.users = {}
        self.cache = {}
        # 🔴 SQ-S2259: Potential NullPointerException — self.db is never initialized
        self.db = None

    def authenticate(self, user, password, role=None, domain=None, two_factor=None, otp=None, remember_me=False, session_id=None, ip=None):
        # 🔴 SQ-S107: Method has too many parameters (9!)
        # 🔴 SQ-S3776: Cognitive Complexity is very high (many nested branches)
        if user:
            if password:
                if user in self.users:
                    if self.users[user] == password:
                        if role:
                            if role == "admin":
                                if domain:
                                    if domain == "internal":
                                        if two_factor:
                                            if otp:
                                                return True   # MAX NESTING DEPTH
                                        else:
                                            return True
                                else:
                                    return False
                            elif role == "guest":
                                return True
                        else:
                            # 🔴 SQ-S134: Multiple return statements
                            return True
                    else:
                        return False
                else:
                    return False
            else:
                return False
        else:
            return None  # 🔴 SQ-S134: Returns None instead of consistent bool

    def process_user_data(self, data):
        # 🔴 SQ-S1186: Exception is caught and silently discarded
        try:
            # 🔴 VULN: CWE-502 - Unsafe pickle deserialization of untrusted data
            user_obj = pickle.loads(data)
            return user_obj
        except Exception:
            pass   # 🔴 BAD: Silent failure — hides RCE if pickle explodes

    def run_diagnostics(self, cmd):
        # 🔴 VULN: CWE-78 - OS Command Injection
        # 🔴 SQ-S4721: Improper neutralization of shell meta-characters
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return result.decode()

    def get_user(self, user_id):
        # 🔴 SQ-S2259: NullPointerException — self.db is always None from __init__
        return self.db.query(f"SELECT * FROM users WHERE id={user_id}")  # DUAL BUG: NPE + SQLi!

    # DUPLICATED LOGIC (triggers SonarQube S1192 and CPD)
    def calculate_score_v1(self, a, b, c):
        # 🔴 SQ-S1192: This is identically copy-pasted below
        total = 0
        for item in [a, b, c]:
            if item > 0:
                total += item * 1.5
            elif item == 0:
                total += 0
            else:
                total -= item
        return total

    def calculate_score_v2(self, a, b, c):
        # 🔴 SQ-S1192: Exact duplicate of calculate_score_v1 — triggers CPD
        total = 0
        for item in [a, b, c]:
            if item > 0:
                total += item * 1.5
            elif item == 0:
                total += 0
            else:
                total -= item
        return total


# Standalone God Function pattern (entire program flow in one function)
def main(args=None, config=None, debug=False, verbose=False, dry_run=False, timeout=30):
    # 🔴 SQ-S3776: Cognitive Complexity is extremely high
    manager = UserManager()
    
    if args is None:
        args = sys.argv[1:]
    
    if len(args) > 0:
        command = args[0]
        if command == "auth":
            if len(args) > 2:
                result = manager.authenticate(args[1], args[2])
                if result:
                    print(f"Welcome {args[1]}")
                    if debug:
                        print(f"DEBUG: Authenticated with password: {args[2]}")  # BAD: Password logged
                else:
                    print("Access denied")
            else:
                print("Usage: auth <user> <pass>")
        elif command == "diag":
            if len(args) > 1:
                # 🔴 VULN: Command from args passed directly to shell!
                output = manager.run_diagnostics(args[1])
                print(output)
            else:
                print("Usage: diag <command>")
        elif command == "dump":
            # 🔴 VULN: Dumps all users (incl plaintext passwords!) to stdout
            print(json.dumps(manager.users, indent=2))  # BAD: PII dump
        else:
            print(f"Unknown command: {command}")
    elif config:
        with open(config, 'r') as f:
            cfg = json.load(f)
        for key, val in cfg.items():
            if debug and verbose:
                print(f"Loading config: {key}={val}")
    else:
        print("No arguments provided")

if __name__ == "__main__":
    main()
