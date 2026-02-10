-- Secure Hostel Visitor Management System - Database Schema

-- Users Table (Students and Wardens)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('Student', 'Warden')),
    email TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Visitors Table (with encrypted sensitive data)
CREATE TABLE IF NOT EXISTS visitors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT NOT NULL,
    encrypted_name TEXT NOT NULL,
    encrypted_phone TEXT NOT NULL,
    encrypted_purpose TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- OTP Sessions Table (for Multi-Factor Authentication)
CREATE TABLE IF NOT EXISTS otp_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT NOT NULL,
    otp TEXT NOT NULL,
    expiry TIMESTAMP NOT NULL,
    verified INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Visit Requests Table
CREATE TABLE IF NOT EXISTS visit_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    visitor_id INTEGER NOT NULL,
    student_id INTEGER NOT NULL,
    status TEXT DEFAULT 'Pending' CHECK(status IN ('Pending', 'Approved', 'Rejected')),
    request_date TIMESTAMP NOT NULL,
    approved_date TIMESTAMP,
    FOREIGN KEY (visitor_id) REFERENCES visitors(id),
    FOREIGN KEY (student_id) REFERENCES users(id)
);

-- Approvals Table (with Digital Signatures)
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER UNIQUE NOT NULL,
    approver_id INTEGER NOT NULL,
    approver_role TEXT NOT NULL,
    signature TEXT NOT NULL,
    signature_hash TEXT NOT NULL,
    approval_date TIMESTAMP NOT NULL,
    FOREIGN KEY (request_id) REFERENCES visit_requests(id),
    FOREIGN KEY (approver_id) REFERENCES users(id)
);

-- Access Logs Table (for audit trail)
CREATE TABLE IF NOT EXISTS access_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_role TEXT,
    action TEXT NOT NULL,
    resource TEXT,
    timestamp TIMESTAMP NOT NULL,
    ip_address TEXT,
    status TEXT DEFAULT 'SUCCESS'
);

-- Crypto Keys Table (optional - for key management)
CREATE TABLE IF NOT EXISTS crypto_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_type TEXT NOT NULL,
    key_data TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_visitors_phone ON visitors(phone);
CREATE INDEX IF NOT EXISTS idx_visit_requests_student ON visit_requests(student_id);
CREATE INDEX IF NOT EXISTS idx_visit_requests_status ON visit_requests(status);
CREATE INDEX IF NOT EXISTS idx_otp_phone ON otp_sessions(phone);
CREATE INDEX IF NOT EXISTS idx_access_logs_timestamp ON access_logs(timestamp);