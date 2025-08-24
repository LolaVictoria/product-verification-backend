# corrected_seed_products.py - Fixed database seeding
from pymongo import MongoClient
from datetime import datetime, timezone
import random
import requests
from bson import ObjectId
import bcrypt

# Fix datetime deprecation warnings
def get_current_utc():
    return datetime.now(timezone.utc)

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def seed_database():
    """Seed both users and products"""
    
    # Connect to MongoDB
    try:
        client = MongoClient('mongodb://localhost:27017/')
        db = client['product_verification']
        print("✅  to MongoDB")
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        return
    
    # Clear existing data
    print("🧹 Clearing existing data...")
    db.users.delete_many({})
    db.products.delete_many({})
    db.api_keys.delete_many({})
    
    # Create test users
    print("👥 Creating test users...")
    
    # Admin user
    admin_user = {
        "email": "admin@blockverify.com",
        "password_hash": hash_password("admin123"),
        "role": "admin",
        "created_at": get_current_utc()
    }
    admin_id = db.users.insert_one(admin_user).inserted_id
    
    # Test customer
    customer_user = {
        "email": "customer@test.com",
        "password_hash": hash_password("customer123"),
        "role": "customer",
        "created_at": get_current_utc()
    }
    customer_id = db.users.insert_one(customer_user).inserted_id
    
    # Test developer
    developer_user = {
        "email": "developer@test.com",
        "password_hash": hash_password("developer123"),
        "role": "developer",
        "created_at": get_current_utc()
    }
    developer_id = db.users.insert_one(developer_user).inserted_id
    
    # Verified manufacturers
    manufacturers = [
        {
            "email": "apple@manufacturer.com",
            "password_hash": hash_password("apple123"),
            "role": "manufacturer",
            "company_name": "Apple Inc",
            "wallet_address": "0x742d35Cc6634C0532925a3b8D400AD96Cfb4c001",
            "verification_status": "approved",
            "created_at": get_current_utc()
        },
        {
            "email": "nike@manufacturer.com",
            "password_hash": hash_password("nike123"),
            "role": "manufacturer",
            "company_name": "Nike",
            "wallet_address": "0x8ba1f109551bD432803012645Hac136c92EB5e36",
            "verification_status": "approved",
            "created_at": get_current_utc()
        },
        {
            "email": "samsung@manufacturer.com",
            "password_hash": hash_password("samsung123"),
            "role": "manufacturer",
            "company_name": "Samsung",
            "wallet_address": "0x2da4f409651bD432803012645Hac136c92EB5e48",
            "verification_status": "approved",
            "created_at": get_current_utc()
        }
    ]
    
    manufacturer_ids = []
    for manufacturer in manufacturers:
        manufacturer_id = db.users.insert_one(manufacturer).inserted_id
        manufacturer_ids.append(manufacturer_id)
    
    # Pending manufacturer
    pending_manufacturer = {
        "email": "pending@manufacturer.com",
        "password_hash": hash_password("pending123"),
        "role": "manufacturer",
        "company_name": "Pending Corp",
        "wallet_address": "0x9ca2f208651bE432803012645Hac136c92EB5e99",
        "verification_status": "pending",
        "created_at": get_current_utc()
    }
    db.users.insert_one(pending_manufacturer)
    
    print(f"✅ Created {len(manufacturers) + 4} users")
    
    # Now seed products
    print("📦 Creating products...")
    
    all_products = []
    
    # Blockchain-verified premium products
    blockchain_products = [
        {
            "serial_number": "APPLE001",
            "name": "iPhone 15 Pro Max",
            "category": "Electronics",
            "description": "Latest iPhone with titanium design and advanced camera system",
            "manufacturer_id": manufacturer_ids[0],  # Apple
            "manufacturer_name": "Apple Inc",
            "price": 1199.99,
            "image_url": "https://images.unsplash.com/photo-1556656793-08538906a9f8?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0x1234567890abcdef1234567890abcdef12345678",
            "blockchain_block_number": 12345678,
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "NIKE001",
            "name": "Air Jordan 1 Retro High OG",
            "category": "Shoes",
            "description": "Classic basketball shoe with premium leather construction",
            "manufacturer_id": manufacturer_ids[1],  # Nike
            "manufacturer_name": "Nike",
            "price": 170.00,
            "image_url": "https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0xabcdef1234567890abcdef1234567890abcdef12",
            "blockchain_block_number": 12345679,
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "SAMSUNG001",
            "name": "Samsung Galaxy S24 Ultra",
            "category": "Electronics",
            "description": "Flagship Android phone with S Pen and advanced AI features",
            "manufacturer_id": manufacturer_ids[2],  # Samsung
            "manufacturer_name": "Samsung",
            "price": 1299.99,
            "image_url": "https://images.unsplash.com/photo-1610945265064-0e34e5519bbf?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0x5555666677778888999900001111222233334444",
            "blockchain_block_number": 12345680,
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "APPLE002",
            "name": "MacBook Pro 16-inch M3",
            "category": "Electronics",
            "description": "Professional laptop with M3 chip and liquid retina display",
            "manufacturer_id": manufacturer_ids[0],  # Apple
            "manufacturer_name": "Apple Inc",
            "price": 2499.99,
            "image_url": "https://images.unsplash.com/photo-1517336714731-489689fd1ca8?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0xbbbbccccddddeeeeffffaaaabbbbccccddddeeee",
            "blockchain_block_number": 12345681,
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "NIKE002",
            "name": "Nike Air Max 270",
            "category": "Shoes",
            "description": "Lifestyle sneaker with large visible air unit",
            "manufacturer_id": manufacturer_ids[1],  # Nike
            "manufacturer_name": "Nike",
            "price": 150.00,
            "image_url": "https://images.unsplash.com/photo-1549298916-b41d501d3772?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0x7777dddd8888eeee9999ffffaaaabbbbccccdddd",
            "blockchain_block_number": 12345682,
            "verified": True,
            "registered_at": get_current_utc()
        }
    ]
    
    all_products.extend(blockchain_products)
    
    # Fetch products from FakeStore API
    print("🌐 Fetching products from FakeStore API...")
    try:
        response = requests.get('https://fakestoreapi.com/products', timeout=10)
        if response.status_code == 200:
            fake_products = response.json()
            
            for item in fake_products:
                category_mapping = {
                    "men's clothing": "Clothing",
                    "women's clothing": "Clothing",
                    "jewelery": "Accessories",
                    "electronics": "Electronics"
                }
                
                product = {
                    "serial_number": f"FAKE{item['id']:03d}",
                    "name": item['title'][:50],  # Truncate long names
                    "category": category_mapping.get(item['category'], "General"),
                    "description": item['description'][:200],  # Truncate long descriptions
                    "manufacturer_name": "Generic Brand",
                    "price": float(item['price']),
                    "image_url": item['image'],
                    "blockchain_verified": False,
                    "verified": random.choice([True, True, False]),  # Mostly verified
                    "registered_at": get_current_utc()
                }
                all_products.append(product)
            
            print(f"✅ Added {len(fake_products)} products from FakeStore API")
        else:
            print("⚠️ Failed to fetch from FakeStore API")
    except Exception as e:
        print(f"⚠️ Error fetching from FakeStore API: {e}")
    
    # Additional regular products
    additional_products = [
        # More realistic products with proper manufacturer references
        {
            "serial_number": "GUCCI001",
            "name": "Gucci GG Marmont Bag",
            "category": "Bags",
            "description": "Luxury quilted leather bag with iconic GG hardware",
            "manufacturer_name": "Gucci",
            "price": 2100.00,
            "image_url": "https://images.unsplash.com/photo-1584917865442-de89df76afd3?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0xfedcba0987654321fedcba0987654321fedcba09",
            "blockchain_block_number": 12345683,
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "ROLEX001",
            "name": "Rolex Submariner",
            "category": "Accessories",
            "description": "Iconic diving watch with ceramic bezel and automatic movement",
            "manufacturer_name": "Rolex",
            "price": 8500.00,
            "image_url": "https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0x1111222233334444555566667777888899990000",
            "blockchain_block_number": 12345684,
            "verified": True,
            "registered_at": get_current_utc()
        },
        # Regular products
        {
            "serial_number": "CONVERSE001",
            "name": "Converse Chuck Taylor All Star",
            "category": "Shoes",
            "description": "Classic canvas sneaker in high-top design",
            "manufacturer_name": "Converse",
            "price": 60.00,
            "image_url": "https://images.unsplash.com/photo-1549298916-b41d501d3772?w=300&h=300&fit=crop",
            "blockchain_verified": False,
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "ZARA001",
            "name": "Zara Slim Fit Blazer",
            "category": "Clothing",
            "description": "Modern blazer with structured silhouette",
            "manufacturer_name": "Zara",
            "price": 79.90,
            "image_url": "https://images.unsplash.com/photo-1539109136881-3be0616acf4b?w=300&h=300&fit=crop",
            "blockchain_verified": False,
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "COUNTERFEIT001",
            "name": "Fake Designer Watch",
            "category": "Accessories",
            "description": "Suspicious product with questionable authenticity",
            "manufacturer_name": "Unknown",
            "price": 50.00,
            "image_url": "https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=300&h=300&fit=crop",
            "blockchain_verified": False,
            "verified": False,  # This one is not verified
            "registered_at": get_current_utc()
        }
    ]
    
    all_products.extend(additional_products)
    
    # Insert all products
    try:
        if all_products:
            result = db.products.insert_many(all_products)
            print(f"✅ Inserted {len(result.inserted_ids)} products")
        else:
            print("⚠️ No products to insert")
    except Exception as e:
        print(f"❌ Error inserting products: {e}")
        return
    
    # Count products by category and verification status
    categories = {}
    blockchain_count = 0
    verified_count = 0
    
    for product in all_products:
        category = product["category"]
        categories[category] = categories.get(category, 0) + 1
        
        if product.get("blockchain_verified", False):
            blockchain_count += 1
        if product.get("verified", False):
            verified_count += 1
    
    print(f"\n📊 Database seeding completed!")
    print(f"   Total products: {len(all_products)}")
    print(f"   Blockchain verified: {blockchain_count}")
    print(f"   Database verified: {verified_count}")
    print(f"   Unverified: {len(all_products) - verified_count}")
    
    print(f"\n📂 Products by category:")
    for category, count in sorted(categories.items()):
        print(f"   {category}: {count}")
    
    print(f"\n👥 Test accounts created:")
    print(f"   Admin: admin@blockverify.com / admin123")
    print(f"   Customer: customer@test.com / customer123")
    print(f"   Developer: developer@test.com / developer123")
    print(f"   Manufacturers: apple@manufacturer.com / apple123")
    print(f"                  nike@manufacturer.com / nike123")
    print(f"                  samsung@manufacturer.com / samsung123")
    
    # Verify database contents
    print(f"\n🔍 Database verification:")
    user_count = db.users.count_documents({})
    product_count = db.products.count_documents({})
    print(f"   Users in database: {user_count}")
    print(f"   Products in database: {product_count}")
    
    if user_count == 0 or product_count == 0:
        print("❌ WARNING: Database seeding may have failed!")
        print("   Check your MongoDB connection and try again")
    else:
        print("✅ Database seeding successful!")

def test_database_connection():
    """Test MongoDB connection before seeding"""
    try:
        client = MongoClient('mongodb://localhost:27017/', serverSelectionTimeoutMS=5000)
        # Force connection
        client.admin.command('ismaster')
        print("✅ MongoDB connection test successful")
        return True
    except Exception as e:
        print(f"❌ MongoDB connection test failed: {e}")
        print("💡 Make sure MongoDB is running: mongod --dbpath /path/to/your/db")
        return False

if __name__ == "__main__":
    print("🚀 Starting database seeding process...")
    
    # Test connection first
    if test_database_connection():
        seed_database()
    else:
        print("❌ Cannot proceed without MongoDB connection")
        print("💡 Start MongoDB with: brew services start mongodb/brew/mongodb-community")
        print("   Or: sudo systemctl start mongod")