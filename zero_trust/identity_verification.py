# =============================================================================
# zero_trust/identity_verification.py – TigerGate CNAPP: Zero Trust Identity
# =============================================================================
# PURPOSE: Demonstrates Zero Trust identity violations — weak MFA, session
# management gaps, and lack of continuous verification (NIST SP 800-207 §3.3).
#
# ZERO TRUST IDENTITY FINDINGS:
#   ZT-ID-001: TOTP-based MFA bypass via SSRF to internal clock
#   ZT-ID-002: No step-up authentication for sensitive operations
#   ZT-ID-003: Long-lived sessions (no re-verification after sensitivity change)
#   ZT-ID-004: JWT algorithm confusion attack (RS256 → HS256)
#   ZT-ID-005: Continuous device trust not evaluated at resource access time
# =============================================================================

from flask import Flask, request, jsonify, session
import jwt, hashlib, time, os

app = Flask(__name__)
# 🔴 ZT-ID-004: Symmetric key used where asymmetric is expected
app.secret_key = "zero_trust_secret_key_weak"   # 🔴 Hardcoded, weak, symmetric!
JWT_SECRET = "megacorp_jwt_secret_123"

# ── ZT-ID-003: Session with no expiry / re-verification ─────────────────────
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    # 🔴 ZT-ID: MD5 password hash — non-FIPS, easily reversed
    if hashlib.md5(password.encode()).hexdigest() == "5f4dcc3b5aa765d61d8327deb882cf99":
        session['user'] = username
        session['authenticated_at'] = time.time()
        # 🔴 ZT-ID-003: Session never expires — valid for weeks/months
        # Zero Trust: sessions MUST have a short TTL (e.g. 1 hour max)
        # app.config['PERMANENT_SESSION_LIFETIME'] = 3600  ← NOT SET

        # 🔴 ZT-ID-004: JWT signed with HS256 using a predictable weak secret
        token = jwt.encode({'sub': username, 'role': 'user'}, JWT_SECRET, algorithm='HS256')
        return jsonify({'token': token, 'expires': 'never'})  # 🔴 Never expires!

    return jsonify({'error': 'invalid credentials'}), 401

# ── ZT-ID-002: Sensitive operation with no step-up auth ─────────────────────
@app.route('/api/transfer-funds', methods=['POST'])
def transfer_funds():
    """
    🔴 ZT-ID-002: Money transfer proceeds with initial login token only.
    Zero Trust requires step-up authentication for high-risk operations:
    re-prompt MFA, verify device posture, check location, log to SIEM.
    """
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    try:
        # 🔴 ZT-ID-004: No algorithm enforcement — accepts alg:none attack!
        # Attacker modifies JWT header to {"alg": "none"} — signature bypassed
        payload = jwt.decode(token, options={"verify_signature": False})  # 🔴 NO VERIFICATION!
    except Exception:
        return jsonify({'error': 'invalid token'}), 401

    amount = request.json.get('amount')
    destination = request.json.get('to_account')

    # 🔴 ZT-ID-002: No step-up MFA for high-value transfer (e.g. amount > $1000)
    # 🔴 ZT-ID-003: No check that session was authenticated recently
    # 🔴 ZT-ID-005: No device posture check (is this device MDM enrolled?)
    return jsonify({
        'status': 'transferred',
        'amount': amount,
        'to': destination,
        'authorized_by': payload.get('sub', 'unknown')
    })

# ── ZT-ID-001: MFA implementation with TOTP bypass via time manipulation ─────
@app.route('/api/verify-mfa', methods=['POST'])
def verify_mfa():
    """
    🔴 ZT-ID-001: TOTP window is 5 minutes ± (should be 30 seconds).
    This allows replay attacks — an intercepted OTP works for 10+ minutes.
    """
    provided_otp = request.json.get('otp')
    # 🔴 ZT-ID-001: Wide time window (300 seconds!) makes TOTP replay easy
    WINDOW = 300   # Should be 30 seconds
    current_time = int(time.time())

    # 🔴 ZT-ID-001: No rate limiting on MFA verification (brute-forceable 6-digit code)
    for t in range(current_time - WINDOW, current_time + WINDOW):
        # simplified TOTP: in real scenario, pyotp.TOTP(seed).verify(otp, valid_window=10) is wrong
        expected = str(t % 1000000).zfill(6)
        if provided_otp == expected:
            return jsonify({'verified': True})

    return jsonify({'verified': False})

# ── ZT-ID-005: Resource access with no device posture check ──────────────────
@app.route('/api/sensitive-data')
def get_sensitive_data():
    """
    🔴 ZT-ID-005: Returns sensitive data without verifying:
    - Is device enrolled in MDM?
    - Is OS up to date?
    - Is EDR running?
    - Is disk encrypted?
    Zero Trust: each resource request must re-evaluate ALL trust signals.
    """
    # No device fingerprint check, no MDM enrollment check, no geo-velocity check
    return jsonify({
        'data': 'classified_pii_records',    # 🔴 Sensitive data returned without trust signals
        'device_checked': False,              # 🔴 ZT-ID-005: Never checked!
        'mfa_recent': False,                 # 🔴 ZT-ID-003: Unknown — session may be days old
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000, debug=True)
