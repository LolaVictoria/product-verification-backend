import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from app import create_app
from app.config.database import get_db_connection
import bcrypt
from datetime import datetime

def create_admin(email, password):
    app = create_app()
    with app.app_context():
        db = get_db_connection()
        
        existing = db.admins.find_one({'email': email})
        if existing:
            print(f"❌ Admin already exists: {email}")
            return False
        
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        admin = {
            'email': email,
            'password_hash': password_hash,
            'role': 'admin',
            'is_active': True,
            'created_at': datetime.datetime.now(datetime.UTC),
            'updated_at': datetime.datetime.now(datetime.UTC)
        }
        
        result = db.admins.insert_one(admin)
        print(f"✅ Admin created: {email} (ID: {result.inserted_id})")
        return True

if __name__ == '__main__':
    create_admin("damillolaoniyide11@gmail.com", "Damilola11264")
