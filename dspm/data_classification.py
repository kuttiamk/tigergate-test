# =============================================================================
# dspm/data_classification.py — TigerGate CNAPP: DSPM – Data Exposure
# =============================================================================
# PURPOSE: Demonstrates how sensitive data (PII, PHI, financial) flows through
# insecure code paths — logging it, sending it to analytics, or exposing it
# via APIs without masking. DSPM tools should detect these data flows.
#
# DSPM FINDINGS:
#   DSPM-001: PII (SSN, DOB) returned in API response without masking
#   DSPM-002: Credit card number logged in plaintext
#   DSPM-003: PHI sent to unauthenticated third-party analytics endpoint
#   DSPM-004: Database query returns full SSN instead of masked version
#   DSPM-005: Customer PII written to S3 without encryption or tagging
#   DSPM-006: SSN/email in URL query string (logged by every proxy/WAF!)
# =============================================================================

from flask import Flask, request, jsonify
import logging, json, os, requests

app = Flask(__name__)
# 🔴 DSPM-002: Root logger set to DEBUG will log ALL data including PII
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Simulated customer database
CUSTOMERS = {
    "C001": {"name": "Alice Doe", "ssn": "123-45-6789", "dob": "1985-03-15",
             "email": "alice@example.com", "card": "4532015112830366", "cvv": "123",
             "diagnosis": "Type 2 Diabetes", "salary": 95000},
    "C002": {"name": "Bob Smith", "ssn": "987-65-4321", "dob": "1990-07-22",
             "email": "bob@example.com", "card": "5425233430109903", "cvv": "456",
             "diagnosis": "Hypertension", "salary": 75000}
}

# ── DSPM-001: Full PII returned in API response ───────────────────────────────
@app.route('/api/customer/<customer_id>')
def get_customer(customer_id):
    """
    🔴 DSPM-001: Returns ALL customer data including SSN, DOB, diagnosis.
    Should mask SSN: "***-**-6789", omit CVV, omit diagnosis from non-medical context.
    """
    customer = CUSTOMERS.get(customer_id, {})
    # 🔴 DSPM-001: SSN, card number, CVV, diagnosis all returned to caller
    return jsonify(customer)   # No masking! Full PII/PHI/PCI data exposed

# ── DSPM-002: PII logged in plaintext ────────────────────────────────────────
@app.route('/api/payment', methods=['POST'])
def process_payment():
    data = request.json
    card_number = data.get('card_number')
    cvv = data.get('cvv')
    amount = data.get('amount')
    # 🔴 DSPM-002: Card number AND CVV logged — PCI-DSS violation!
    # These logs go to CloudWatch, Splunk, ELK — accessible to many people
    logger.debug(f"Processing payment: card={card_number} cvv={cvv} amount={amount}")
    logger.info(f"Payment for customer: {data.get('ssn')} — card {card_number}")  # 🔴 SSN in log!
    return jsonify({"status": "processed"})

# ── DSPM-003: PHI sent to third-party analytics ──────────────────────────────
@app.route('/api/patient-analytics', methods=['POST'])
def patient_analytics():
    """
    🔴 DSPM-003: Patient PHI (name, diagnosis, SSN) sent to Mixpanel/Segment
    without consent or data processing agreement. HIPAA violation!
    """
    patient = request.json
    analytics_payload = {
        "event": "patient_visit",
        "patient_name": patient.get("name"),        # 🔴 DSPM-003: PHI in analytics!
        "ssn": patient.get("ssn"),                  # 🔴 DSPM-003: SSN to Mixpanel!
        "diagnosis": patient.get("diagnosis"),      # 🔴 DSPM-003: Medical data to 3rd party!
        "insurance_id": patient.get("insurance_id"),
    }
    # 🔴 DSPM-003: Sending PHI to external analytics service
    # requests.post("https://api.mixpanel.com/track", json=analytics_payload)
    logger.info(f"Sent to analytics: {analytics_payload}")
    return jsonify({"tracked": True})

# ── DSPM-004: Database query exposes full SSN ────────────────────────────────
def get_customer_ssn_unsafe(customer_id: str) -> str:
    """
    🔴 DSPM-004: Returns full SSN instead of masked version.
    The caller (e.g., a UI endpoint) only needs the last 4 digits.
    """
    customer = CUSTOMERS.get(customer_id, {})
    # 🔴 DSPM-004: Full SSN returned — not masked as "***-**-6789"
    return customer.get("ssn", "")

# ── DSPM-005: Write PII to S3 without classification ─────────────────────────
def export_customer_data():
    """🔴 DSPM-005: PII exported to S3 without encryption tag or data classification."""
    import boto3
    s3 = boto3.client('s3', region_name='us-east-1')
    customers_json = json.dumps(list(CUSTOMERS.values()))
    # 🔴 DSPM-005: No ServerSideEncryption, no tagging, no ACL restriction
    s3.put_object(
        Bucket="megacorp-exports",
        Key="customers-full-pii.json",
        Body=customers_json,
        # ServerSideEncryption="aws:kms"  ← NOT SET
        # Tagging="DataClassification=PII&GDPR=true"  ← NOT SET
    )

# ── DSPM-006: PII in URL query string ────────────────────────────────────────
@app.route('/api/search')
def search_customer():
    """
    🔴 DSPM-006: SSN and email passed in URL parameters.
    URL query strings are logged by: nginx, WAF, ALB, CloudFront, Splunk, browsers.
    Example: /api/search?ssn=123-45-6789&email=alice@example.com
    """
    ssn = request.args.get('ssn')   # 🔴 SSN in URL: /search?ssn=123-45-6789
    email = request.args.get('email')
    # These params appear in: access logs, browser history, referrer headers!
    results = [c for c in CUSTOMERS.values() if c.get("ssn") == ssn or c.get("email") == email]
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
