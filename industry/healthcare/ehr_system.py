# =============================================================================
# industry/healthcare/ehr_system.py – TigerGate CNAPP: Healthcare Industry
# =============================================================================
# PURPOSE: Simulates Electronic Health Record (EHR) vulnerabilities.
# Triggers HIPAA, DSPM, and SAST findings for healthcare-specific patterns.
#
# HIPAA SECURITY RULE VIOLATIONS:
#   HIPAA-001: §164.312(a)(1) – No access control on PHI endpoints
#   HIPAA-002: §164.312(b) – No audit logging of PHI access
#   HIPAA-003: §164.312(c) – PHI integrity not protected (no checksums)
#   HIPAA-004: §164.312(e)(1) – PHI transmitted without encryption
#   HIPAA-005: §164.314(a) – No Business Associate Agreement enforcement
#   HIPAA-006: §164.306(a)(3) – PHI data not de-identified before analytics
# =============================================================================

from flask import Flask, request, jsonify
import sqlite3, os, json, datetime

app = Flask(__name__)

# =============================================================================
# 🔴 HIPAA-001: PHI database with no access control on endpoints
# Protected Health Information (PHI) accessible to anonymous requests
# =============================================================================

# Sample PHI data structure (in-memory simulation)
PHI_RECORDS = [
    {
        "patient_id": "P-10001",
        "ssn": "123-45-6789",          # 🔴 HIPAA: SSN is PHI
        "full_name": "John Smith",
        "dob": "1978-03-15",            # 🔴 HIPAA: DOB is PHI
        "diagnosis_codes": ["F41.1", "E11.9", "I10"],  # Anxiety, Diabetes, Hypertension
        "medications": ["Metformin 500mg", "Lisinopril 10mg"],
        "treating_physician": "Dr. Sarah Johnson",
        "last_visit": "2026-04-10",
        "insurance_member_id": "BCBS-123456"
    }
]

@app.route('/api/patients', methods=['GET'])
def get_all_patients():
    """
    🔴 HIPAA-001: Returns ALL patients with full PHI to any requestor.
    No authentication, no role check, no minimum necessary standard (45 CFR 164.502(b)).
    """
    # 🔴 HIPAA-002: PHI access NOT logged to audit trail
    return jsonify({"patients": PHI_RECORDS})   # Returns SSN, diagnoses, medications!

@app.route('/api/patients/<patient_id>')
def get_patient(patient_id):
    """🔴 HIPAA-001/002: Individual PHI record accessible without auth or logging"""
    for p in PHI_RECORDS:
        if p['patient_id'] == patient_id:
            # 🔴 HIPAA-002: Should log: who accessed, when, what data, from where
            return jsonify(p)   # 🔴 Full PHI returned with no log entry
    return jsonify({"error": "not found"}), 404

@app.route('/api/search')
def search_patients():
    """🔴 HIPAA: SQL Injection on PHI data (full PHI leakable via SQLi)"""
    name = request.args.get('name', '')
    conn = sqlite3.connect('/tmp/ehr.db')
    # 🔴 VULN: SQLi on a table containing SSN, diagnosis, medication — full HIPAA breach
    query = f"SELECT * FROM patients WHERE name LIKE '%{name}%'"  # 🔴 SQLi on PHI!
    cursor = conn.cursor()
    cursor.execute(query)
    return jsonify({"results": cursor.fetchall()})

# =============================================================================
# 🔴 HIPAA-004: PHI transmitted over HTTP without TLS
# =============================================================================
@app.route('/api/lab-results', methods=['POST'])
def transmit_lab_results():
    """
    🔴 HIPAA-004: Lab results (PHI) sent/received over unencrypted HTTP.
    Per 45 CFR 164.312(e)(1), PHI must be encrypted in transit.
    """
    data = request.json
    patient_id = data.get('patient_id')
    lab_result = data.get('result')   # Contains HIV status, cancer markers, genetic data

    # 🔴 HIPAA-004: Storing PHI in /tmp without encryption
    with open(f'/tmp/lab_{patient_id}.json', 'w') as f:
        json.dump({'patient': patient_id, 'result': lab_result}, f)  # 🔴 Unencrypted PHI on disk

    # 🔴 HIPAA-006: PHI sent to analytics without de-identification
    analytics_payload = {'patient': patient_id, 'result': lab_result, 'facility': 'CityHospital'}
    # requests.post("http://analytics.partner.com/ingest", json=analytics_payload)  # HTTP + raw PHI!
    return jsonify({'status': 'stored', 'path': f'/tmp/lab_{patient_id}.json'})

# =============================================================================
# 🔴 HIPAA-006: PHI used in ML analytics without de-identification
# =============================================================================
@app.route('/api/analytics/predict-readmission')
def predict_readmission():
    """
    🔴 HIPAA-006: Patient data fed to ML model without stripping PHI.
    Should de-identify per Safe Harbor method first (remove 18 HIPAA identifiers).
    """
    # 🔴 BAD: All 18 HIPAA identifiers (name, DOB, SSN, diagnosis) sent to external ML
    raw_data = PHI_RECORDS   # Full PHI, not de-identified!
    # model.predict(raw_data)  — Would send raw PHI to external endpoint
    return jsonify({'warning': 'PHI de-identification bypassed', 'records_sent': len(raw_data)})

if __name__ == '__main__':
    # 🔴 HIPAA-004: Running on HTTP without TLS — PHI transmitted in the clear
    app.run(host='0.0.0.0', port=8000, debug=True, ssl_context=None)
