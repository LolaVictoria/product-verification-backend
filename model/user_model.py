from bson import ObjectId
from datetime import datetime
from helper_functions import get_db_connection

def seed_database():
    try:
        db = get_db_connection()
        
        # Generate ObjectIds for referential integrity
        apple_id = ObjectId()
        samsung_id = ObjectId()
        google_id = ObjectId()
        retailer_id = ObjectId()
        consumer_id = ObjectId()

        # 1. Manufacturers Collection
        db.manufacturers.insert_many([
            {
                "_id": apple_id,
                "walletAddress": "0x742d35Cc622C4532c0532255c87A59B852b74f8d",
                "companyName": "Apple Inc",
                "email": "verify@apple.com",
                "country": "United States",
                "establishedYear": 1976,
                "headquarters": "Cupertino, California",
                "isVerified": True,
                "verificationDate": datetime(2024, 1, 15),
                "annualProduction": 230000000,
                "createdAt": datetime.now()
            },
            {
                "_id": samsung_id,
                "walletAddress": "0x8ba1f109551bD432803012645Hac136c461c11B6",
                "companyName": "Samsung Electronics",
                "email": "auth@samsung.com",
                "country": "South Korea",
                "establishedYear": 1969,
                "headquarters": "Seoul, South Korea",
                "isVerified": True,
                "verificationDate": datetime(2024, 1, 20),
                "annualProduction": 290000000,
                "createdAt": datetime.now()
            },
            {
                "_id": google_id,
                "walletAddress": "0x123abc456def789ghi012jkl345mno678pqr901st",
                "companyName": "Google LLC",
                "email": "security@google.com",
                "country": "United States",
                "establishedYear": 1998,
                "headquarters": "Mountain View, California",
                "isVerified": True,
                "verificationDate": datetime(2024, 1, 25),
                "annualProduction": 15000000,
                "createdAt": datetime.now()
            }
        ])

        # 2. Electronics/Devices Collection
        db.electronics.insert_many([
            {
                "_id": ObjectId(),
                "serialNumber": "AAPL-IPH15-PRO-128-2024-C02XY1234",
                "brand": "Apple",
                "model": "iPhone 15 Pro",
                "deviceType": "Smartphone",
                "storage": "128GB",
                "color": "Titanium Blue",
                "processor": "A17 Pro",
                "screenSize": "6.1 inch",
                "camera": "48MP Triple Camera",
                "operatingSystem": "iOS 17",
                "manufacturerId": apple_id,
                "currentOwnerId": consumer_id,
                "isOnBlockchain": True,
                "blockchainTxHash": "0xabc123def456ghi789jkl012mno345pqr678stu901vwx",
                "specificationHash": "0x1a2b3c4d5e6f789abc123def456ghi789jkl012mno345",
                "batchNumber": "BATCH-APL-2024-001",
                "retailPrice": 999,
                "manufacturingDate": datetime(2024, 2, 15),
                "registrationDate": datetime(2024, 2, 16),
                "isAuthentic": True,
                "warrantyPeriod": 12,  # months
                "createdAt": datetime.now()
            },
            {
                "_id": ObjectId(),
                "serialNumber": "SAMS-GAL-S24-256-2024-SM789012",
                "brand": "Samsung",
                "model": "Galaxy S24 Ultra",
                "deviceType": "Smartphone",
                "storage": "256GB",
                "color": "Phantom Black",
                "processor": "Snapdragon 8 Gen 3",
                "screenSize": "6.8 inch",
                "camera": "200MP Quad Camera",
                "operatingSystem": "Android 14",
                "manufacturerId": samsung_id,
                "currentOwnerId": retailer_id,
                "isOnBlockchain": False,
                "blockchainTxHash": None,
                "specificationHash": None,
                "batchNumber": "BATCH-SAM-2024-003",
                "retailPrice": 1299,
                "manufacturingDate": datetime(2024, 3, 1),
                "registrationDate": datetime(2024, 3, 2),
                "isAuthentic": True,
                "warrantyPeriod": 24,  # months
                "createdAt": datetime.now()
            },
            {
                "_id": ObjectId(),
                "serialNumber": "AAPL-MBA-M3-512-2024-FVFX3456",
                "brand": "Apple",
                "model": "MacBook Air M3",
                "deviceType": "Laptop",
                "storage": "512GB SSD",
                "color": "Space Gray",
                "processor": "Apple M3",
                "screenSize": "13.6 inch",
                "memory": "16GB",
                "operatingSystem": "macOS Sonoma",
                "manufacturerId": apple_id,
                "currentOwnerId": apple_id,  # Still with manufacturer
                "isOnBlockchain": True,
                "blockchainTxHash": "0xdef789ghi012jkl345mno678pqr901stu234vwx567",
                "specificationHash": "0x2b3c4d5e6f7g890abc123def456ghi789jkl012mno",
                "batchNumber": "BATCH-APL-2024-007",
                "retailPrice": 1499,
                "manufacturingDate": datetime(2024, 2, 20),
                "registrationDate": datetime(2024, 2, 21),
                "isAuthentic": True,
                "warrantyPeriod": 12,
                "createdAt": datetime.now()
            }
        ])

        # 3. Ownership History Collection
        db.ownershipHistory.insert_many([
            {
                "_id": ObjectId(),
                "serialNumber": "AAPL-IPH15-PRO-128-2024-C02XY1234",
                "previousOwner": {
                    "id": apple_id,
                    "name": "Apple Inc",
                    "type": "manufacturer"
                },
                "newOwner": {
                    "id": retailer_id,
                    "name": "Best Buy",
                    "type": "retailer"
                },
                "transferDate": datetime(2024, 2, 18),
                "transferReason": "Wholesale Distribution",
                "salePrice": 750,  # Wholesale price
                "transferMethod": "bulk_sale",
                "invoiceNumber": "INV-APL-2024-001234",
                "createdAt": datetime(2024, 2, 18)
            },
            {
                "_id": ObjectId(),
                "serialNumber": "AAPL-IPH15-PRO-128-2024-C02XY1234",
                "previousOwner": {
                    "id": retailer_id,
                    "name": "Best Buy",
                    "type": "retailer"
                },
                "newOwner": {
                    "id": consumer_id,
                    "name": "John Smith",
                    "type": "consumer"
                },
                "transferDate": datetime(2024, 3, 15),
                "transferReason": "Retail Purchase",
                "salePrice": 999,
                "transferMethod": "retail_sale",
                "invoiceNumber": "BB-2024-789012",
                "location": "Best Buy Store, New York",
                "createdAt": datetime(2024, 3, 15)
            }
        ])

        # 4. Verification Logs Collection
        db.verificationLogs.insert_many([
            {
                "_id": ObjectId(),
                "serialNumber": "AAPL-IPH15-PRO-128-2024-C02XY1234",
                "verificationType": "blockchain",
                "userIP": "192.168.1.100",
                "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "location": "New York, NY",
                "result": "authentic",
                "confidence": 98.5,
                "responseTime": 245,  # milliseconds
                "verificationMethod": "smart_contract_query",
                "gasUsed": 0,  # Free verification
                "timestamp": datetime.now(),
                "sessionId": "session_abc123",
                "verifiedBy": "consumer"
            },
            {
                "_id": ObjectId(),
                "serialNumber": "FAKE-IPH15-999-COUNTERFEIT",
                "verificationType": "database",
                "userIP": "203.45.67.89",
                "userAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
                "location": "Los Angeles, CA",
                "result": "counterfeit",
                "confidence": 99.9,
                "responseTime": 123,
                "verificationMethod": "serial_lookup",
                "flags": ["serial_not_found", "suspicious_format"],
                "timestamp": datetime.now(),
                "sessionId": "session_def456",
                "verifiedBy": "consumer"
            }
        ])

        # 5. Users/Owners Collection
        db.users.insert_many([
            {
                "_id": consumer_id,
                "userId": "consumer_001",
                "name": "John Smith",
                "email": "john.smith@email.com",
                "userType": "consumer",
                "walletAddress": "0xabc123def456ghi789jkl012mno345pqr678stu901",
                "country": "United States",
                "city": "New York",
                "registrationDate": datetime(2024, 1, 10),
                "devicesOwned": ["AAPL-IPH15-PRO-128-2024-C02XY1234"],
                "verificationsCount": 3,
                "lastActive": datetime.now(),
                "isVerified": True,
                "createdAt": datetime(2024, 1, 10)
            },
            {
                "_id": retailer_id,
                "userId": "retailer_001",
                "name": "Best Buy",
                "email": "verification@bestbuy.com",
                "userType": "retailer",
                "walletAddress": "0xdef456ghi789jkl012mno345pqr678stu901vwx234",
                "country": "United States",
                "businessLicense": "RET-LICENSE-2024-001",
                "registrationDate": datetime(2023, 8, 15),
                "devicesHandled": 15420,
                "verificationsCount": 8934,
                "lastActive": datetime.now(),
                "isVerified": True,
                "createdAt": datetime(2023, 8, 15)
            }
        ])

        # 6. System Statistics Collection
        db.systemStats.insert_one({
            "_id": ObjectId(),
            "date": datetime.now(),
            "totalDevices": 2000,
            "authenticDevices": 1600,
            "counterfeitDetected": 400,
            "blockchainVerifications": 1200,
            "databaseVerifications": 800,
            "averageResponseTime": 187.5,  # milliseconds
            "totalManufacturers": 15,
            "verifiedManufacturers": 12,
            "totalOwnershipTransfers": 3420,
            "averageTransferValue": 650,  # USD
            "monthlyVerifications": 15670,
            "counterfeitDetectionRate": 0.95,  # 95%
            "systemUptime": 99.8,  # percentage
            "createdAt": datetime.now()
        })

        # Create Indexes for optimal performance
        db.electronics.create_index("serialNumber")
        db.electronics.create_index("brand")
        db.electronics.create_index("deviceType")
        db.electronics.create_index("isOnBlockchain")
        db.electronics.create_index("manufacturerId")
        db.electronics.create_index("currentOwnerId")

        db.ownershipHistory.create_index("serialNumber")
        db.ownershipHistory.create_index([("transferDate", -1)])

        db.verificationLogs.create_index("serialNumber")
        db.verificationLogs.create_index([("timestamp", -1)])
        db.verificationLogs.create_index("result")

        db.manufacturers.create_index("walletAddress")
        db.manufacturers.create_index("companyName")

        db.users.create_index("userId")
        db.users.create_index("userType")
        db.users.create_index("walletAddress")

        print("Database seeded successfully!")

    except Exception as error:
        print(f"Error seeding database: {error}")

# Run the seeding function
if __name__ == "__main__":
    seed_database()