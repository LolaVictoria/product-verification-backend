# scripts/backup_db.py
import subprocess
import datetime
import os
from pathlib import Path

def backup_database():
    """Backup MongoDB database"""
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = Path(f"backups/backup_{timestamp}")
    backup_dir.mkdir(parents=True, exist_ok=True)
    
    # MongoDB backup command
    cmd = [
        'mongodump',
        '--host', os.getenv('MONGODB_HOST', 'localhost:27017'),
        '--db', os.getenv('DATABASE_NAME', 'product_verification'),
        '--out', str(backup_dir)
    ]
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"Backup successful: {backup_dir}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Backup failed: {e.stderr}")
        return False

if __name__ == '__main__':
    backup_database()