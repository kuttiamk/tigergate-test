#!/usr/bin/env python3
# =============================================================================
# code_quality/timing_attack.py — TigerGate CNAPP: Code Quality + SAST
# =============================================================================
# PURPOSE: Demonstrates timing attack vulnerabilities and other code quality
# security issues that SAST tools should flag.
#
# FINDINGS:
#   CQ-001: Non-constant-time string comparison → timing attack on tokens (CWE-208)
#   CQ-002: Weak random number generator for security purpose (CWE-330)
#   CQ-003: Hardcoded magic number for token length (CQ smell + security)
#   CQ-004: Race condition in file access (TOCTOU) (CWE-367)
#   CQ-005: Broad exception catch hides security errors (CWE-390)
#   CQ-006: MD5 used for password hashing (CWE-327 — broken algorithm)
#   CQ-007: Int overflow possible in session token (CWE-190)
# =============================================================================

import hashlib, random, time, os, secrets, hmac

# ── CQ-001: Timing Attack on Token Comparison ─────────────────────────────────
class AuthService:
    VALID_TOKEN = "megacorp_admin_EXAMPLE_token_2024xyz"  # 🔴 Hardcoded token!

    def verify_token_unsafe(self, provided_token: str) -> bool:
        """
        🔴 CQ-001: Using == for token comparison is vulnerable to timing attacks.
        Python short-circuits string comparison on the FIRST different character.
        Attacker measures response time to brute-force token character by character.
        A correct prefix takes slightly longer than an incorrect one.

        With enough requests (~1000 per character), attacker can recover any token!
        """
        return provided_token == self.VALID_TOKEN   # 🔴 CQ-001: Non-constant-time!

    def verify_token_safe(self, provided_token: str) -> bool:
        """✅ CORRECT: secrets.compare_digest is constant-time regardless of content."""
        return hmac.compare_digest(provided_token, self.VALID_TOKEN)

# ── CQ-002: Weak Random for Security Purpose ──────────────────────────────────
def generate_session_token_unsafe() -> str:
    """
    🔴 CQ-002: random.random() uses Mersenne Twister — predictable seeded PRNG!
    With 624 consecutive outputs, attacker can recover the internal state and
    predict ALL future tokens. Not safe for cryptographic purposes.
    """
    random.seed(int(time.time()))  # 🔴 CQ-002: Seed from timestamp — easily guessable!
    # 🔴 CQ-002: random.randint is NOT cryptographically secure
    token = ''.join([str(random.randint(0, 9)) for _ in range(32)])
    return token
    # Fix: return secrets.token_hex(32)

# ── CQ-003: Hardcoded Magic Numbers ───────────────────────────────────────────
def create_api_key(user_id: int) -> str:
    """🔴 CQ-003: Magic numbers 16, 256, 1000 — no named constants or documentation."""
    # 🔴 CQ-003: What does 16 mean? Why 256? Why mod 1000?
    token_part = hashlib.md5(str(user_id).encode()).hexdigest()[:16]   # 🔴 Also CQ-006!
    suffix = str(user_id % 1000).zfill(3)
    return f"key_{token_part}_{suffix}"

# ── CQ-004: TOCTOU Race Condition ─────────────────────────────────────────────
def process_upload(filename: str, data: bytes):
    """
    🔴 CQ-004: TOCTOU — Time of Check vs Time of Use race condition (CWE-367).
    Between os.path.exists() check and open() write, another thread/process
    can symlink filename to /etc/passwd — the write then goes to /etc/passwd!
    """
    upload_path = f"/var/www/uploads/{filename}"
    # 🔴 CQ-004: CHECK happens here
    if os.path.exists(upload_path):
        return {"error": "File already exists"}
    # 🔴 CQ-004: Gap between check and use — race condition window!
    # Attacker: while True: os.symlink('/etc/passwd', upload_path)
    time.sleep(0.001)   # Simulates I/O delay that widens the race window
    # 🔴 CQ-004: USE happens here — attacker may have symlinked to sensitive file
    with open(upload_path, 'wb') as f:   # Could be writing to /etc/passwd!
        f.write(data)

# ── CQ-005: Broad Exception Catch ─────────────────────────────────────────────
def authenticate_user(username: str, password: str) -> dict:
    """
    🔴 CQ-005: Catching Exception hides ALL errors — including security ones.
    An authentication bypass exception gets swallowed and returns {"authenticated": True}!
    """
    try:
        # Some authentication logic that might raise PermissionError, AuthError, etc.
        if username == "admin" and password == "admin":  # 🔴 Also: hardcoded credentials!
            return {"authenticated": True, "role": "admin"}
        return {"authenticated": False}
    except Exception:   # 🔴 CQ-005: Swallows ALL exceptions — authentication errors too!
        # 🔴 What if the authentication library raised "InvalidCredentials" 
        # but we catch it and return success?!
        return {"authenticated": True}   # 🔴 Potential auth bypass!

# ── CQ-006: MD5 for Password Hashing ─────────────────────────────────────────
def hash_password_unsafe(password: str) -> str:
    """
    🔴 CQ-006: MD5 is cryptographically broken — has known collision attacks.
    Also: no salt! Same password always produces same hash.
    MD5 can be cracked at 100+ BILLION hashes/second on modern GPUs.
    Entire MD5 hash lookup tables (rainbow tables) exist for common passwords.
    """
    return hashlib.md5(password.encode()).hexdigest()   # 🔴 CQ-006: MD5 + no salt!
    # Fix: return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# ── CQ-007: Integer Overflow in Session ID ───────────────────────────────────
def generate_numeric_session_id(user_id: int) -> int:
    """
    🔴 CQ-007: Integer overflow risk — if user_id is very large (attacker-controlled),
    the multiplication can overflow in some environments or produce predictable values.
    """
    timestamp = int(time.time())
    # 🔴 CQ-007: No bounds check on user_id before arithmetic
    session_id = (user_id * 1000000) + (timestamp % 1000000)  # Overflow risk!
    return session_id  # Predictable from timestamp!

if __name__ == '__main__':
    auth = AuthService()
    print("Token (unsafe):", auth.verify_token_unsafe("test"))
    print("Session token (unsafe):", generate_session_token_unsafe())
    print("Password hash (unsafe MD5):", hash_password_unsafe("password123"))
    print("Session ID (predictable):", generate_numeric_session_id(999999999))
