-- =============================================================================
-- database/init.sql – Database Initialization Script
-- =============================================================================
-- PURPOSE: Creates tables and inserts test data for ALL backend services.
--
-- ⚠️  INTENTIONAL ISSUES IN THIS FILE:
--   1. BAD: Passwords stored as PLAIN TEXT (should use bcrypt/argon2)
--   2. BAD: No foreign key constraints (data integrity issues)
--   3. BAD: No indexes on frequently queried columns (performance issue)
--   4. BAD: Admin user has ALL PRIVILEGES (principle of least privilege violated)
--   5. BAD: PII data (emails, credit cards) stored with no encryption
-- =============================================================================

CREATE DATABASE IF NOT EXISTS megadb;
USE megadb;

-- =============================================================================
-- USERS TABLE
-- BAD: password is stored in plain text — SonarQube flags this as a
--      "Sensitive data should not be stored without encryption"
-- =============================================================================
CREATE TABLE IF NOT EXISTS users (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    username    VARCHAR(100) NOT NULL,
    password    VARCHAR(255) NOT NULL,   -- BAD: Plain text passwords!
    email       VARCHAR(255) NOT NULL,   -- BAD: PII not encrypted
    role        VARCHAR(50)  DEFAULT 'user',
    created_at  TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
    -- BAD: No UNIQUE constraint on email — duplicates allowed
    -- BAD: No index on username or email — slow queries
);

-- =============================================================================
-- PRODUCTS TABLE
-- BAD: price stored as VARCHAR — causes comparison bugs
-- =============================================================================
CREATE TABLE IF NOT EXISTS products (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    name        VARCHAR(255),
    description TEXT,
    price       VARCHAR(50),             -- BAD: Should be DECIMAL(10,2)
    stock       INT DEFAULT 0
    -- BAD: No index on name
);

-- =============================================================================
-- ORDERS TABLE
-- BAD: No foreign key to users — orphan orders possible
-- BAD: No transaction support / audit trail
-- =============================================================================
CREATE TABLE IF NOT EXISTS orders (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT,                     -- BAD: Should be FK REFERENCES users(id)
    product_id  INT,                     -- BAD: Should be FK REFERENCES products(id)
    qty         INT,
    total       DOUBLE,                  -- BAD: DOUBLE for money causes rounding errors
    status      VARCHAR(50) DEFAULT 'pending',
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- LOGS TABLE
-- BAD: Full raw request/response stored — may expose sensitive data
-- =============================================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    user_id     INT,
    action      VARCHAR(255),
    payload     TEXT,                    -- BAD: Full request body logged (may contain passwords)
    ip_address  VARCHAR(100),
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- =============================================================================
-- SEED DATA
-- BAD: Real-looking passwords in seed data (hardcoded in source)
-- BAD: admin/admin is the simplest credential to brute-force
-- =============================================================================
INSERT INTO users (username, password, email, role) VALUES
    ('admin',     'admin123',      'admin@megacorp.com',    'admin'),   -- BAD: Weak credentials
    ('alice',     'password',      'alice@megacorp.com',    'user'),    -- BAD: "password" as password
    ('bob',       '123456',        'bob@megacorp.com',      'user'),    -- BAD: Extremely weak
    ('charlie',   'charlie',       'charlie@megacorp.com',  'user'),    -- BAD: Username = password
    ('testuser',  'Test@12345',    'test@megacorp.com',     'user');

INSERT INTO products (name, description, price, stock) VALUES
    ('Laptop Pro',    'High performance laptop',       '1299.99', 50),
    ('USB Hub',       'USB-C 7-port hub',              '29.99',   200),
    ('Keyboard',      'Mechanical keyboard',           '89.99',   75),
    ('Monitor',       '27-inch 4K monitor',            '599.00',  30),
    ('Webcam HD',     '1080p webcam with mic',         '49.99',   120);

INSERT INTO orders (user_id, product_id, qty, total, status) VALUES
    (2, 1, 1, 1299.99, 'completed'),
    (3, 3, 2, 179.98,  'pending'),
    (4, 2, 5, 149.95,  'shipped');

-- =============================================================================
-- GRANT ALL PRIVILEGES TO APP USER
-- BAD: App user should only have SELECT/INSERT/UPDATE on specific tables
--      Not ALL PRIVILEGES on the entire database
-- =============================================================================
GRANT ALL PRIVILEGES ON megadb.* TO 'appuser'@'%';          -- BAD: Too many privileges!
GRANT ALL PRIVILEGES ON megadb.* TO 'root'@'%';             -- BAD: Root accessible from anywhere!
FLUSH PRIVILEGES;
