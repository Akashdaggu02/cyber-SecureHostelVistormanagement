from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
import sqlite3
import os
import json
from datetime import datetime, timedelta
from utils.auth import AuthManager
from utils.crypto_manager import CryptoManager
from utils.access_control import AccessControlManager
from utils.encoding import EncodingManager

app = Flask(__name__)
app.secret_key = os.urandom(24)
auth_manager = AuthManager()
crypto_manager = CryptoManager()
acl = AccessControlManager()
encoder = EncodingManager()

def get_db():
    conn = sqlite3.connect('database/hostel.db')
    conn.row_factory = sqlite3.Row
    return conn

def login_required(roles=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please login first', 'danger')
                return redirect(url_for('index'))
            if roles and session.get('role') not in roles:
                flash('Access denied', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/visitor/register', methods=['GET', 'POST'])
def visitor_register():
    if request.method == 'POST':
        phone = request.form.get('phone')
        otp = auth_manager.generate_otp()
        expiry = datetime.now() + timedelta(minutes=2)
        conn = get_db()
        conn.execute('INSERT OR REPLACE INTO otp_sessions (phone, otp, expiry, verified) VALUES (?, ?, ?, 0)',
                    (phone, otp, expiry.isoformat()))
        conn.commit()
        conn.close()
        print(f"\n{'='*50}\nOTP for {phone}: {otp}\nValid until: {expiry}\n{'='*50}\n")
        flash(f'OTP sent to {phone} (Check console)', 'info')
        return redirect(url_for('visitor_verify_otp', phone=phone))
    return render_template('visitor_register.html')

@app.route('/visitor/verify-otp/<phone>', methods=['GET', 'POST'])
def visitor_verify_otp(phone):
    if request.method == 'POST':
        if auth_manager.verify_otp(phone, request.form.get('otp')):
            session['visitor_phone'] = phone
            session['otp_verified'] = True
            flash('OTP verified successfully!', 'success')
            return redirect(url_for('visitor_request'))
        flash('Invalid or expired OTP', 'danger')
    return render_template('visitor_verify_otp.html', phone=phone)

@app.route('/visitor/request', methods=['GET', 'POST'])
def visitor_request():
    if not session.get('otp_verified'):
        flash('Please verify OTP first', 'warning')
        return redirect(url_for('visitor_register'))
    if request.method == 'POST':
        if not acl.check_access('Visitor', 'Request Entry'):
            flash('Access denied', 'danger')
            return redirect(url_for('index'))
        phone = session.get('visitor_phone')
        name, purpose, student = request.form.get('name'), request.form.get('purpose'), request.form.get('student_username')
        conn = get_db()
        student_rec = conn.execute('SELECT id FROM users WHERE username = ? AND role = "Student"', (student,)).fetchone()
        if not student_rec:
            flash('Student not found', 'danger')
            conn.close()
            return redirect(url_for('visitor_request'))
        cursor = conn.execute('INSERT INTO visitors (phone, encrypted_name, encrypted_phone, encrypted_purpose) VALUES (?, ?, ?, ?)',
                             (phone, crypto_manager.encrypt_data(name), crypto_manager.encrypt_data(phone), crypto_manager.encrypt_data(purpose)))
        visitor_id = cursor.lastrowid
        conn.execute('INSERT INTO visit_requests (visitor_id, student_id, status, request_date) VALUES (?, ?, "Pending", ?)',
                    (visitor_id, student_rec['id'], datetime.now().isoformat()))
        conn.execute('INSERT INTO access_logs (user_role, action, resource, timestamp) VALUES (?, ?, ?, ?)',
                    ('Visitor', 'CREATE', f'Request {visitor_id}', datetime.now().isoformat()))
        conn.commit()
        conn.close()
        flash('Request submitted successfully!', 'success')
        session['last_visitor_phone'] = phone
        session.pop('visitor_phone', None)
        session.pop('otp_verified', None)
        return redirect(url_for('visitor_status', phone=phone))
    return render_template('visitor_request.html')

@app.route('/visitor/status/<phone>')
def visitor_status(phone):
    conn = get_db()
    requests = conn.execute('''SELECT vr.id, vr.status, vr.request_date, vr.approved_date, u.username as student 
                              FROM visit_requests vr JOIN visitors v ON vr.visitor_id = v.id 
                              JOIN users u ON vr.student_id = u.id WHERE v.phone = ? ORDER BY vr.request_date DESC''', (phone,)).fetchall()
    conn.close()
    return render_template('visitor_status.html', requests=[dict(r) for r in requests], phone=phone)

@app.route('/visitor/pass/<int:request_id>')
def visitor_pass(request_id):
    conn = get_db()
    req = conn.execute('''SELECT vr.*, v.encrypted_name, v.encrypted_phone, v.encrypted_purpose, a.signature, a.signature_hash, u.username as student
                         FROM visit_requests vr JOIN visitors v ON vr.visitor_id = v.id LEFT JOIN approvals a ON vr.id = a.request_id
                         JOIN users u ON vr.student_id = u.id WHERE vr.id = ? AND vr.status = "Approved"''', (request_id,)).fetchone()
    conn.close()
    if not req:
        flash('Pass not found or request not approved', 'danger')
        return redirect(url_for('index'))
    
    if not req['signature'] or not crypto_manager.verify_signature(req['signature_hash'], req['signature']):
        flash('Invalid digital signature - Pass may be tampered!', 'danger')
        return redirect(url_for('index'))
    
    # Decrypt visitor data
    name = crypto_manager.decrypt_data(req['encrypted_name'])
    phone = crypto_manager.decrypt_data(req['encrypted_phone'])
    purpose = crypto_manager.decrypt_data(req['encrypted_purpose'])
    
    # Generate token data
    token_data = {
        'request_id': request_id, 
        'name': name,
        'phone': phone, 
        'student': req['student'],
        'approved_date': req['approved_date'], 
        'signature': req['signature']
    }
    
    # Encrypt and encode token
    encrypted_token = crypto_manager.encrypt_data(json.dumps(token_data))
    qr_token = encoder.encode_base64(encrypted_token)
    
    # Generate QR Code Image
    try:
        import qrcode
        from io import BytesIO
        import base64 as b64
        
        # Create QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(qr_token)
        qr.make(fit=True)
        
        # Create image
        img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to base64 for HTML display
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = b64.b64encode(buffered.getvalue()).decode()
        qr_image = f"data:image/png;base64,{img_str}"
    except Exception as e:
        print(f"QR Code generation error: {e}")
        qr_image = None
    
    return render_template('visitor_pass.html', 
                          name=name, 
                          phone=phone, 
                          purpose=purpose,
                          student=req['student'], 
                          approved_date=req['approved_date'], 
                          qr_token=qr_token,
                          qr_image=qr_image)

@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    if request.method == 'POST':
        user = auth_manager.authenticate_user(request.form.get('username'), request.form.get('password'), 'Student')
        if user:
            session.permanent = True
            session['user_id'], session['username'], session['role'] = user['id'], user['username'], user['role']
            flash('Login successful!', 'success')
            return redirect(url_for('student_dashboard'))
        flash('Account locked' if auth_manager.is_locked(request.form.get('username')) else 'Invalid credentials', 'danger')
    return render_template('student_login.html')

@app.route('/student/dashboard')
@login_required(roles=['Student'])
def student_dashboard():
    conn = get_db()
    requests = conn.execute('''SELECT vr.id, vr.status, vr.request_date, v.encrypted_name, v.encrypted_phone, v.encrypted_purpose
                              FROM visit_requests vr JOIN visitors v ON vr.visitor_id = v.id
                              WHERE vr.student_id = ? ORDER BY vr.request_date DESC''', (session['user_id'],)).fetchall()
    conn.close()
    requests_list = [{'id': r['id'], 'status': r['status'], 'request_date': r['request_date'],
                      'name': crypto_manager.decrypt_data(r['encrypted_name']),
                      'phone': crypto_manager.decrypt_data(r['encrypted_phone']),
                      'purpose': crypto_manager.decrypt_data(r['encrypted_purpose'])} for r in requests]
    return render_template('student_dashboard.html', requests=requests_list)

@app.route('/student/approve/<int:request_id>', methods=['POST'])
@login_required(roles=['Student'])
def student_approve(request_id):
    if not acl.check_access('Student', 'Approve Visitor'):
        flash('Access denied', 'danger')
        return redirect(url_for('student_dashboard'))
    action = request.form.get('action')
    conn = get_db()
    req = conn.execute('SELECT * FROM visit_requests WHERE id = ? AND student_id = ?', (request_id, session['user_id'])).fetchone()
    if not req:
        flash('Request not found', 'danger')
        conn.close()
        return redirect(url_for('student_dashboard'))
    if action == 'approve':
        conn.execute('UPDATE visit_requests SET status = "Approved", approved_date = ? WHERE id = ?',
                    (datetime.now().isoformat(), request_id))
        approval_data = f"Request:{request_id}|Student:{session['user_id']}|Time:{datetime.now().isoformat()}"
        sig_hash = crypto_manager.hash_data(approval_data)
        signature = crypto_manager.sign_data(sig_hash)
        conn.execute('INSERT INTO approvals (request_id, approver_id, approver_role, signature, signature_hash, approval_date) VALUES (?, ?, ?, ?, ?, ?)',
                    (request_id, session['user_id'], 'Student', signature, sig_hash, datetime.now().isoformat()))
        flash('Request approved with digital signature', 'success')
    elif action == 'reject':
        conn.execute('UPDATE visit_requests SET status = "Rejected", approved_date = ? WHERE id = ?',
                    (datetime.now().isoformat(), request_id))
        flash('Request rejected', 'info')
    conn.execute('INSERT INTO access_logs (user_role, action, resource, timestamp) VALUES (?, ?, ?, ?)',
                ('Student', action.upper(), f'Request {request_id}', datetime.now().isoformat()))
    conn.commit()
    conn.close()
    return redirect(url_for('student_dashboard'))

@app.route('/student/logout')
def student_logout():
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('index'))

@app.route('/warden/login', methods=['GET', 'POST'])
def warden_login():
    if request.method == 'POST':
        user = auth_manager.authenticate_user(request.form.get('username'), request.form.get('password'), 'Warden')
        if user:
            session.permanent = True
            session['user_id'], session['username'], session['role'] = user['id'], user['username'], user['role']
            flash('Login successful!', 'success')
            return redirect(url_for('warden_dashboard'))
        flash('Account locked' if auth_manager.is_locked(request.form.get('username')) else 'Invalid credentials', 'danger')
    return render_template('warden_login.html')

@app.route('/warden/dashboard')
@login_required(roles=['Warden'])
def warden_dashboard():
    if not acl.check_access('Warden', 'View Logs'):
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    conn = get_db()
    requests = conn.execute('''SELECT vr.id, vr.status, vr.request_date, vr.approved_date, v.encrypted_name, v.encrypted_phone,
                              v.encrypted_purpose, u.username as student, a.signature, a.signature_hash
                              FROM visit_requests vr JOIN visitors v ON vr.visitor_id = v.id
                              JOIN users u ON vr.student_id = u.id LEFT JOIN approvals a ON vr.id = a.request_id
                              ORDER BY vr.request_date DESC''').fetchall()
    conn.close()
    requests_list = [{'id': r['id'], 'status': r['status'], 'request_date': r['request_date'],
                      'approved_date': r['approved_date'], 'name': crypto_manager.decrypt_data(r['encrypted_name']),
                      'phone': crypto_manager.decrypt_data(r['encrypted_phone']),
                      'purpose': crypto_manager.decrypt_data(r['encrypted_purpose']), 'student': r['student'],
                      'signature_valid': crypto_manager.verify_signature(r['signature_hash'], r['signature']) if r['signature'] else True} for r in requests]
    return render_template('warden_dashboard.html', requests=requests_list)

@app.route('/warden/logs')
@login_required(roles=['Warden'])
def warden_logs():
    if not acl.check_access('Warden', 'View Logs'):
        return redirect(url_for('warden_dashboard'))
    conn = get_db()
    logs = conn.execute('SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT 100').fetchall()
    conn.close()
    return render_template('warden_logs.html', logs=logs)

@app.route('/warden/override/<int:request_id>', methods=['POST'])
@login_required(roles=['Warden'])
def warden_override(request_id):
    if not acl.check_access('Warden', 'Approve Visitor'):
        flash('Access denied', 'danger')
        return redirect(url_for('warden_dashboard'))
    
    action = request.form.get('action')
    conn = get_db()
    
    # Fetch the request to check current status
    req = conn.execute('SELECT * FROM visit_requests WHERE id = ?', (request_id,)).fetchone()
    
    if not req:
        flash('Request not found', 'danger')
        conn.close()
        return redirect(url_for('warden_dashboard'))
    
    if action == 'approve':
        # Update request status to Approved
        conn.execute('UPDATE visit_requests SET status = "Approved", approved_date = ? WHERE id = ?',
                    (datetime.now().isoformat(), request_id))
        
        # Generate warden's digital signature
        approval_data = f"Request:{request_id}|Warden:{session['user_id']}|Time:{datetime.now().isoformat()}"
        sig_hash = crypto_manager.hash_data(approval_data)
        signature = crypto_manager.sign_data(sig_hash)
        
        # Insert or replace approval record
        conn.execute('INSERT OR REPLACE INTO approvals (request_id, approver_id, approver_role, signature, signature_hash, approval_date) VALUES (?, ?, ?, ?, ?, ?)',
                    (request_id, session['user_id'], 'Warden', signature, sig_hash, datetime.now().isoformat()))
        
        flash(f'Request #{request_id} approved by Warden (Override)', 'success')
        
    elif action == 'reject':
        # Update request status to Rejected
        conn.execute('UPDATE visit_requests SET status = "Rejected", approved_date = ? WHERE id = ?',
                    (datetime.now().isoformat(), request_id))
        
        # Delete any existing approval (warden is overriding student's approval)
        conn.execute('DELETE FROM approvals WHERE request_id = ?', (request_id,))
        
        flash(f'Request #{request_id} rejected by Warden (Override)', 'warning')
    
    # Log the override action
    conn.execute('INSERT INTO access_logs (user_role, action, resource, timestamp) VALUES (?, ?, ?, ?)',
                ('Warden', 'OVERRIDE_' + action.upper(), f'Request {request_id}', datetime.now().isoformat()))
    
    conn.commit()
    conn.close()
    
    return redirect(url_for('warden_dashboard'))

@app.route('/warden/logout')
def warden_logout():
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)