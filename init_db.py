import sqlite3
import os
from utils.auth import AuthManager

def initialize_database():
    """
    Initialize database with schema and sample users
    """
    
    # Create database directory
    os.makedirs('database', exist_ok=True)
    os.makedirs('crypto', exist_ok=True)
    
    # Connect to database
    conn = sqlite3.connect('database/hostel.db')
    cursor = conn.cursor()
    
    print("Creating database schema...")
    
    # Read and execute schema
    with open('schema.sql', 'r') as f:
        schema = f.read()
        cursor.executescript(schema)
    
    print("Schema created successfully!")
    
    # Create sample users
    print("\nCreating sample users...")
    
    auth_manager = AuthManager()
    
    # Sample Students
    students = [
        ('student1', 'Student@123', 'student1@hostel.edu'),
        ('student2', 'Student@123', 'student2@hostel.edu'),
        ('student3', 'Student@123', 'student3@hostel.edu'),
    ]
    
    for username, password, email in students:
        password_hash, salt = auth_manager.hash_password(password)
        
        try:
            cursor.execute('''
                INSERT INTO users (username, password_hash, password_salt, role, email)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, salt.hex(), 'Student', email))
            print(f"✓ Created student: {username}")
        except sqlite3.IntegrityError:
            print(f"✗ Student {username} already exists")
    
    # Sample Wardens
    wardens = [
        ('warden1', 'Warden@123', 'warden1@hostel.edu'),
        ('warden2', 'Warden@123', 'warden2@hostel.edu'),
    ]
    
    for username, password, email in wardens:
        password_hash, salt = auth_manager.hash_password(password)
        
        try:
            cursor.execute('''
                INSERT INTO users (username, password_hash, password_salt, role, email)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password_hash, salt.hex(), 'Warden', email))
            print(f"✓ Created warden: {username}")
        except sqlite3.IntegrityError:
            print(f"✗ Warden {username} already exists")
    
    conn.commit()
    conn.close()
    
    print("\n" + "="*60)
    print("Database initialized successfully!")
    print("="*60)
    print("\nSample User Credentials:")
    print("-" * 60)
    print("\nSTUDENTS:")
    print("  Username: student1  |  Password: Student@123")
    print("  Username: student2  |  Password: Student@123")
    print("  Username: student3  |  Password: Student@123")
    print("\nWARDENS:")
    print("  Username: warden1   |  Password: Warden@123")
    print("  Username: warden2   |  Password: Warden@123")
    print("-" * 60)
    print("\n✓ Ready to run the application!")
    print("  Run: python app.py")
    print("="*60 + "\n")

if __name__ == '__main__':
    initialize_database()