-- =============================================================================
-- dspm/pii_phi_data.sql – TigerGate CNAPP Test: Data Security Posture Mgmt
-- =============================================================================
-- PURPOSE: Simulates an unencrypted generic database dump containing 
-- sensitive PII, PHI, and Financial data to test DSPM scanner detections.
--
-- COMPLIANCE FRAMEWORKS TRIGGERED:
#   - HIPAA: Exposure of health records (PHI), Medical IDs, and prescriptions.
#   - PCI-DSS: Exposure of Credit Card numbers, Expiry, CVV in plaintext.
#   - SOC 2: Confidentiality / Privacy violation (plain text passwords, emails)
#   - GDPR / CCPA: Exposure of full names, SSN, DOB, Address.
-- =============================================================================

CREATE TABLE customers (
    id INT PRIMARY KEY,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    email VARCHAR(100),
    ssn VARCHAR(20),       -- 🔴 VULN: Plaintext SSN (GDPR/CCPA/SOC 2)
    dob DATE,
    address TEXT,
    password_hash VARCHAR(255)
);

INSERT INTO customers VALUES 
(1, 'John', 'Doe', 'jdoe@megacorp.internal', '123-45-6789', '1985-11-20', '123 Main St, New York, NY', 'password123'),  -- 🔴 VULN: Plaintext password
(2, 'Jane', 'Smith', 'jsmith@megacorp.internal', '987-65-4321', '1990-05-15', '456 Oak Ave, Austin, TX', 'qwerty456');

CREATE TABLE payment_cards (
    id INT PRIMARY KEY,
    customer_id INT,
    card_number VARCHAR(20), -- 🔴 VULN: Plaintext Credit Card (PCI-DSS violation)
    expiry_date VARCHAR(5),
    cvv VARCHAR(4),          -- 🔴 VULN: CVV stored! (Critical PCI-DSS violation)
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);

INSERT INTO payment_cards VALUES 
(1, 1, '4532015112830366', '12/28', '737'),
(2, 2, '5425233430109903', '08/29', '452');

CREATE TABLE health_records (
    id INT PRIMARY KEY,
    customer_id INT,
    medical_id VARCHAR(50),   -- 🔴 VULN: Medical ID (HIPAA violation)
    diagnosis TEXT,           -- 🔴 VULN: Health Information
    prescription TEXT,
    FOREIGN KEY (customer_id) REFERENCES customers(id)
);

INSERT INTO health_records VALUES 
(1, 1, 'MED-884-991', 'Hypertension, Type 2 Diabetes', 'Metformin 500mg, Lisinopril 10mg'),
(2, 2, 'MED-332-114', 'Asthma', 'Albuterol Inhaler');
