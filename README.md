Secure Hostel Visitor Management System
23CSE313 - Foundations of Cyber Security Lab Evaluation Project

A comprehensive web application implementing all core security concepts: Authentication, Authorization, Encryption, Hashing, Digital Signatures, and Encoding.

🔒 Security Components Implemented
1. Authentication (3 marks)
Single-Factor Authentication (1.5m)
Implementation: Username + Password based login for Students and Wardens
Security: Passwords stored using SHA-256 with salt (never plain text)
Features:
Unique salt generated for each password
Salt stored separately in database
Password verification using constant-time comparison
Multi-Factor Authentication (1.5m)
Implementation: OTP-based verification for Visitors
Security:
6-digit random OTP generation
2-minute expiration time
One-time use verification
OTP marked as used after successful verification
Flow: Phone → OTP Generation → OTP Verification → Access Granted
2. Authorization - Access Control (3 marks)
Access Control Matrix (1.5m)
Subjects (Roles): Visitor, Student, Warden
Objects (Resources/Actions): Request Entry, Approve Visitor, View Logs
Matrix:
  Subject   | Request Entry | Approve Visitor | View Logs
  --------------------------------------------------------
  Visitor   |      ✓        |        ✗        |     ✗
  Student   |      ✗        |        ✓        |     ✗
  Warden    |      ✗        |        ✓        |     ✓
Policy Definition & Implementation (1.5m)
Visitor: Can only request entry (create visit requests)
Student: Can approve/reject requests assigned to them, generate digital signatures
Warden: Full access - view all requests, override approvals, view logs, decrypt data
Enforcement: Programmatic checks before every privileged operation
3. Encryption (3 marks)
Key Exchange Mechanism (1.5m)
Model: Hybrid Encryption
RSA-2048: For secure key exchange
AES-256-CBC: For data encryption
Process:
RSA key pair generated at initialization
AES session key generated
AES key can be encrypted with RSA public key for exchange
Data encrypted using AES-256
Encryption & Decryption (1.5m)
Algorithm: AES-256 in CBC mode
Encrypted Fields:
Visitor name
Visitor phone number
Visit purpose
Approval decisions (in logs)
Features:
Unique IV (Initialization Vector) for each encryption
Proper padding (PKCS7)
Base64 encoding for database storage
4. Hashing & Digital Signature (3 marks)
Hashing with Salt (1.5m)
Algorithm: SHA-256
Implementation:
Password hashing with random 32-byte salt
Salt stored separately in database
Each password has unique salt
Storage: password_hash and password_salt columns
Digital Signature using Hash (1.5m)
Algorithm: RSA-2048 with SHA-256
Process:
Create SHA-256 hash of approval data
Sign hash with RSA private key
Store signature and hash in database
Verify signature with RSA public key when displaying pass
Data Signed: Request ID + Approver ID + Timestamp
Verification: Ensures data integrity and authenticity
5. Encoding (3 marks)
Base64 Encoding/Decoding (1m)
Implementation: Base64 encoding for QR tokens
Process:
Generate visitor pass data
Encrypt pass data with AES
Encode encrypted data with Base64
Display as QR token
Decode and decrypt for verification
Security Levels & Possible Attacks (2m)
Security Levels:
Level 1: Plain text storage ❌
Level 2: Hashing only ❌
Level 3: Encryption only ⚠️
Level 4: Encryption + Hashing + Signatures ✅ (Implemented)
Possible Attacks & Countermeasures:
Brute Force: Login lockout (5 attempts, 30s lock)
Man-in-the-Middle: HTTPS recommended in production
Replay Attack: OTP expiry and one-time use
SQL Injection: Parameterized queries
Tampering: Digital signatures detect modifications
Password Cracking: Strong salted hashing
📁 Project Structure
SecureHostelVisitorSystem/
├── app.py                      # Main Flask application
├── init_db.py                  # Database initialization script
├── schema.sql                  # Database schema
├── requirements.txt            # Python dependencies
├── README.md                   # This file
│
├── utils/                      # Utility modules
│   ├── __init__.py
│   ├── auth.py                 # Authentication manager
│   ├── crypto_manager.py       # Encryption & signatures
│   ├── access_control.py       # ACL implementation
│   └── encoding.py             # Encoding utilities
│
├── templates/                  # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── visitor_register.html
│   ├── visitor_verify_otp.html
│   ├── visitor_request.html
│   ├── visitor_status.html
│   ├── visitor_pass.html
│   ├── student_login.html
│   ├── student_dashboard.html
│   ├── warden_login.html
│   ├── warden_dashboard.html
│   └── warden_logs.html
│
├── database/                   # Database storage
│   └── hostel.db              # SQLite database
│
└── crypto/                     # Cryptographic keys
    ├── private_key.pem         # RSA private key
    ├── public_key.pem          # RSA public key
    └── aes_key.bin            # AES symmetric key
🚀 Installation & Setup
Prerequisites
Python 3.8 or higher
pip (Python package manager)
Step 1: Clone or Extract the Project
bash
cd SecureHostelVisitorSystem
Step 2: Create Virtual Environment (Recommended)
bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
Step 3: Install Dependencies
bash
pip install -r requirements.txt
Step 4: Initialize Database
bash
python init_db.py
Expected Output:

Creating database schema...
Schema created successfully!

Creating sample users...
✓ Created student: student1
✓ Created student: student2
✓ Created student: student3
✓ Created warden: warden1
✓ Created warden: warden2

============================================================
Database initialized successfully!
============================================================

Sample User Credentials:
------------------------------------------------------------

STUDENTS:
  Username: student1  |  Password: Student@123
  Username: student2  |  Password: Student@123
  Username: student3  |  Password: Student@123

WARDENS:
  Username: warden1   |  Password: Warden@123
  Username: warden2   |  Password: Warden@123
------------------------------------------------------------

✓ Ready to run the application!
  Run: python app.py
============================================================
Step 5: Run the Application
bash
python app.py
The application will start on http://127.0.0.1:5000/

📱 Usage Guide
For Visitors (MFA Required)
Navigate to Home Page: http://127.0.0.1:5000/
Click "Register Visit"
Enter Phone Number: 10-digit mobile number
Check Console: OTP will be displayed (simulated)
Enter OTP: Must be entered within 2 minutes
Fill Request Form:
Name (will be encrypted)
Purpose (will be encrypted)
Student username (student1, student2, or student3)
Submit Request
Check Status: Use the status page with your phone number
Download Pass: If approved, view digitally signed pass with Base64 token
For Students (Single-Factor Auth)
Navigate to Student Login: http://127.0.0.1:5000/student/login
Login Credentials:
Username: student1 (or student2, student3)
Password: Student@123
View Requests: See all visitor requests assigned to you
Approve/Reject:
Approve: Generates RSA digital signature
Reject: Declines the request
View Encrypted Data: Data is decrypted for your view
For Wardens (Single-Factor Auth)
Navigate to Warden Login: http://127.0.0.1:5000/warden/login
Login Credentials:
Username: warden1 (or warden2)
Password: Warden@123
View All Requests: See complete system overview
Verify Signatures: Check digital signature validity
Override Approvals: Can approve/reject any request
View Access Logs: Complete audit trail
🔐 Security Features Demonstration
1. Testing Multi-Factor Authentication
Try registering as visitor with wrong OTP → Should fail
Wait 2 minutes after OTP generation → OTP should expire
Use same OTP twice → Should be rejected (one-time use)
2. Testing Login Security
Attempt 5 wrong passwords → Account should lock for 30 seconds
Try accessing student dashboard without login → Should redirect to login
Try student accessing warden features → Should be denied
3. Testing Encryption
View database file directly → Visitor data should be encrypted
Check encrypted_name, encrypted_phone, encrypted_purpose columns
Each encryption has different ciphertext due to unique IVs
4. Testing Digital Signatures
Approve a request as student → Signature generated
View visitor pass → Signature verified
Modify signature in database → Verification should fail
5. Testing Access Control
Visitor trying to approve request → Should be denied
Student trying to view logs → Should be denied
Warden accessing all features → Should succeed
🗄️ Database Schema
Tables
1. users
id: Primary key
username: Unique username
password_hash: SHA-256 hash of password
password_salt: Random salt (hex encoded)
role: 'Student' or 'Warden'
email: Email address
2. visitors
id: Primary key
phone: Contact number
encrypted_name: AES-256 encrypted name
encrypted_phone: AES-256 encrypted phone
encrypted_purpose: AES-256 encrypted purpose
3. otp_sessions
id: Primary key
phone: Phone number
otp: 6-digit OTP
expiry: Expiration timestamp
verified: Boolean flag
4. visit_requests
id: Primary key
visitor_id: Foreign key to visitors
student_id: Foreign key to users
status: 'Pending', 'Approved', or 'Rejected'
request_date: Submission timestamp
approved_date: Approval timestamp
5. approvals
id: Primary key
request_id: Foreign key to visit_requests
approver_id: Foreign key to users
approver_role: 'Student' or 'Warden'
signature: RSA digital signature
signature_hash: SHA-256 hash of signed data
approval_date: Timestamp
6. access_logs
id: Primary key
user_role: Role performing action
action: Action performed
resource: Resource accessed
timestamp: Action timestamp
status: 'SUCCESS' or 'FAILURE'
🧪 Testing Scenarios
Scenario 1: Complete Visitor Flow
Visitor registers with phone: 9876543210
OTP generated: Check console
Verify OTP within 2 minutes
Submit request for student1
Student1 logs in and approves
Digital signature generated
Visitor checks status and downloads pass
Pass contains Base64 encoded encrypted token
Signature verified on pass display
Scenario 2: Security Testing
Try logging in with wrong password 5 times
Account locks for 30 seconds
Try accessing protected routes without login
Try visitor accessing student dashboard
All should be properly denied
Scenario 3: Warden Override
Visitor submits request for student1
Student1 doesn't approve
Warden logs in
Warden overrides and approves
Warden's signature generated
Visitor gets approved pass
📊 Lab Evaluation Checklist
[✓] Authentication (3m)
[✓] Single-Factor: Username + Salted SHA-256 Password (1.5m)
[✓] Multi-Factor: OTP with 2-minute expiry (1.5m)
[✓] Authorization (3m)
[✓] Access Control Matrix with 3 subjects × 3 objects (1.5m)
[✓] Programmatic enforcement of access rights (1.5m)
[✓] Encryption (3m)
[✓] Hybrid key exchange (RSA + AES) (1.5m)
[✓] AES-256 encryption of sensitive data (1.5m)
[✓] Hashing & Signatures (3m)
[✓] Password hashing with salt (1.5m)
[✓] RSA digital signatures for approvals (1.5m)
[✓] Encoding (3m)
[✓] Base64 encoding/decoding (1m)
[✓] Security levels documented (1m)
[✓] Possible attacks documented (1m)
[✓] Additional Features
[✓] Login attempt limiting
[✓] Session management
[✓] Input validation
[✓] Audit logging
🎓 Viva Preparation Points
Authentication Questions
Q: Why use salt in password hashing?
A: Salt prevents rainbow table attacks and ensures identical passwords have different hashes.
Q: Why 2-minute OTP expiry?
A: Balance between security (short window) and usability (enough time to enter).
Encryption Questions
Q: Why hybrid encryption instead of just RSA?
A: RSA can only encrypt small data. AES is faster for large data. RSA securely exchanges the AES key.
Q: What is CBC mode in AES?
A: Cipher Block Chaining - each block depends on previous block, preventing pattern analysis.
Digital Signature Questions
Q: How do digital signatures ensure integrity?
A: Any modification changes the hash, making signature verification fail.
Q: Difference between encryption and signing?
A: Encryption provides confidentiality (only recipient can read). Signing provides authenticity and integrity (proves sender and detects tampering).
Access Control Questions
Q: What's the difference between ACL and ACM?
A: ACL (Access Control List) lists permissions per resource. ACM (Access Control Matrix) shows all subject-object relationships in a matrix.
🛡️ Security Best Practices Implemented
Never store plain passwords - Always salted and hashed
Encrypt sensitive data - PII is encrypted at rest
Use digital signatures - Prevent tampering
Time-bound tokens - OTPs expire
Session management - Proper login/logout
Access control - Role-based permissions
Audit logging - Track all actions
Input validation - Prevent injection attacks
Secure key storage - Keys in separate directory
Parameterized queries - Prevent SQL injection
📝 Notes
Development Mode: The app runs with debug=True for development. Set to False in production.
OTP Simulation: OTPs are printed to console. In production, use SMS/Email services.
HTTPS: Use HTTPS in production for encrypted communication.
Key Management: In production, use proper key management systems (HSM, KMS).
Database: SQLite is used for simplicity. Use PostgreSQL/MySQL in production.
🏆 Project Highlights
✅ All 5 security components fully implemented ✅ NIST SP 800-63-2 compliant authentication ✅ Production-grade cryptography (AES-256, RSA-2048) ✅ Complete access control matrix ✅ Digital signatures with verification ✅ Base64 encoding for token transmission ✅ Comprehensive error handling ✅ Clean, documented code ✅ Professional UI with Bootstrap ✅ Ready for demonstration

👨‍💻 Developer
Course: 23CSE313 - Foundations of Cyber Security Institution: Amrita Vishwa Vidyapeetham Department: Computer Science and Engineering

📞 Support
For issues or questions:

Check the troubleshooting section
Review the code comments
Verify all dependencies are installed
Ensure database is initialized properly
✅ Project is complete, tested, and ready for lab evaluation!

