from pymongo import MongoClient
from bson import ObjectId
from datetime import datetime
import os
from dotenv import load_dotenv

load_dotenv()

# Try different connection approaches
try:
    # First try your .env MONGODB_URI
    mongodb_uri = os.getenv('MONGODB_URI')
    print(f"Trying connection string: {mongodb_uri}")
    
    if mongodb_uri and 'mongodb+srv' in mongodb_uri:
        print("Using Atlas connection...")
        client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=5000)
    else:
        print("Using local MongoDB...")
        client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=5000)
    
    # Test connection
    client.admin.command('ping')
    print("Connection successful!")
    
except Exception as e:
    print(f"Connection failed: {e}")
    # Fallback to local MongoDB
    print("Trying local MongoDB as fallback...")
    client = MongoClient('mongodb://localhost:27017/')

# Use your actual database name
db_name = os.getenv('DB_NAME', 'product_verification')
db = client[db_name]

print(f"Connected to database: {db_name}")

# Update the product
try:
    result = db.products.update_one(
        {"_id": ObjectId("68aadb2f8db5c95e28fdb7bd")},
        {
            "$set": {
                "ownership_history": [{
                    "owner_address": "0x051051074B7BbfaB5bB1A72432129118218cDe97",
                    "owner_type": "manufacturer",
                    "owner_name": "ABC Ventures",
                    "transfer_date": datetime(2025, 8, 24, 9, 33, 18, 786000),
                    "transfer_type": "initial_registration",
                    "previous_owner": None,
                    "transaction_hash": "blockchain_tx_hash_here",
                    "notes": "Initial product registration on blockchain"
                }],
                "current_owner": "0x051051074B7BbfaB5bB1A72432129118218cDe97"
            }
        }
    )

    print(f"Modified {result.modified_count} document(s)")
    print(f"Matched {result.matched_count} document(s)")
    
    if result.matched_count > 0:
        print("Update successful!")
    else:
        print("No document found with that ID")

except Exception as e:
    print(f"Update failed: {e}")

finally:
    client.close()