import hashlib
import os
import random
import sqlite3
from datetime import datetime, timedelta

class AuthManager:
    """
    Handles Authentication:
    - Single Factor: Username + Password with Salted SHA-256
    - Multi Factor: OTP for visitors (expires in 2 minutes)
    - Login attempt tracking and account lockout
    """
    
    def __init__(self):
        self.login_attempts = {}  # Track failed login attempts
        self.lockout_duration = 30  # seconds
        self.max_attempts = 5
    
    def hash_password(self, password, salt=None):
        """
        Create salted SHA-256 hash of password
        SECURITY: Implements password hashing with salt
        """
        if salt is None:
            salt = os.urandom(32)  # Generate random salt
        
        # Combine password and salt, then hash
        pwdhash = hashlib.sha256(password.encode('utf-8') + salt).hexdigest()
        
        return pwdhash, salt
    
    def verify_password(self, stored_hash, stored_salt, provided_password):
        """Verify password against stored hash and salt"""
        pwdhash, _ = self.hash_password(provided_password, stored_salt)
        return pwdhash == stored_hash
    
    def generate_otp(self, length=6):
        """
        Generate random OTP for Multi-Factor Authentication
        SECURITY: Implements OTP-based MFA
        """
        return ''.join([str(random.randint(0, 9)) for _ in range(length)])
    
    def verify_otp(self, phone, entered_otp):
        """
        Verify OTP and check expiry (2 minutes)
        SECURITY: Time-bound OTP verification
        """
        conn = sqlite3.connect('database/hostel.db')
        cursor = conn.cursor()
        
        result = cursor.execute('''
            SELECT otp, expiry, verified 
            FROM otp_sessions 
            WHERE phone = ?
            ORDER BY expiry DESC LIMIT 1
        ''', (phone,)).fetchone()
        
        if not result:
            conn.close()
            return False
        
        stored_otp, expiry_str, verified = result
        expiry = datetime.fromisoformat(expiry_str)
        
        # Check if OTP is valid and not expired
        if stored_otp == entered_otp and datetime.now() < expiry and not verified:
            # Mark as verified
            cursor.execute('''
                UPDATE otp_sessions 
                SET verified = 1 
                WHERE phone = ? AND otp = ?
            ''', (phone, entered_otp))
            conn.commit()
            conn.close()
            return True
        
        conn.close()
        return False
    
    def track_login_attempt(self, username, success):
        """
        Track login attempts for account lockout
        SECURITY: Prevents brute force attacks
        """
        if success:
            # Reset attempts on successful login
            if username in self.login_attempts:
                del self.login_attempts[username]
            return
        
        # Track failed attempt
        if username not in self.login_attempts:
            self.login_attempts[username] = {
                'count': 0,
                'locked_until': None
            }
        
        self.login_attempts[username]['count'] += 1
        
        # Lock account after max attempts
        if self.login_attempts[username]['count'] >= self.max_attempts:
            self.login_attempts[username]['locked_until'] = \
                datetime.now() + timedelta(seconds=self.lockout_duration)
    
    def is_locked(self, username):
        """Check if account is currently locked"""
        if username not in self.login_attempts:
            return False
        
        locked_until = self.login_attempts[username].get('locked_until')
        
        if locked_until and datetime.now() < locked_until:
            return True
        
        # Unlock if time has passed
        if locked_until and datetime.now() >= locked_until:
            del self.login_attempts[username]
            return False
        
        return False
    
    def authenticate_user(self, username, password, role):
        """
        Authenticate user with Single Factor Authentication
        SECURITY: Username + Password with salted hash verification
        """
        # Check if account is locked
        if self.is_locked(username):
            return None
        
        conn = sqlite3.connect('database/hostel.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        user = cursor.execute('''
            SELECT id, username, password_hash, password_salt, role 
            FROM users 
            WHERE username = ? AND role = ?
        ''', (username, role)).fetchone()
        
        conn.close()
        
        if not user:
            self.track_login_attempt(username, False)
            return None
        
        # Verify password
        if self.verify_password(user['password_hash'], 
                               bytes.fromhex(user['password_salt']), 
                               password):
            self.track_login_attempt(username, True)
            return dict(user)
        else:
            self.track_login_attempt(username, False)
            return None
    
    def create_user(self, username, password, role, email):
        """Create new user with hashed password"""
        password_hash, salt = self.hash_password(password)
        
        conn = sqlite3.connect('database/hostel.db')
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO users (username, password_hash, password_salt, role, email)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, salt.hex(), role, email))
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()
            return user_id
        except sqlite3.IntegrityError:
            conn.close()
            return None