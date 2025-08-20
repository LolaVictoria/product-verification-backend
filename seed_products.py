# enhanced_seed_products.py
from pymongo import MongoClient
from datetime import datetime, timezone
import random
import requests
import json

# Fix datetime deprecation warnings
def get_current_utc():
    return datetime.now(timezone.utc)

def seed_products():
    client = MongoClient('mongodb://localhost:27017/')
    db = client['product_verification']
    products_collection = db['products']
    
    # Clear existing products first
    products_collection.delete_many({})
    print("Cleared existing products")
    
    all_products = []
    
    # 1. Blockchain-verified premium products (20 products)
    blockchain_products = [
        {
            "serial_number": "APPLE001",
            "name": "iPhone 15 Pro Max",
            "category": "Electronics",
            "manufacturer_name": "Apple Inc",
            "manufacturer_wallet": "0x742d35Cc6634C0532925a3b8D400AD96Cfb4c001",
            "price": 1199.99,
            "image_url": "https://images.unsplash.com/photo-1556656793-08538906a9f8?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0x1234567890abcdef",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "NIKE001",
            "name": "Air Jordan 1 Retro High OG",
            "category": "Shoes",
            "manufacturer_name": "Nike",
            "manufacturer_wallet": "0x8ba1f109551bD432803012645Hac136c92EB5e36",
            "price": 170.00,
            "image_url": "https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0xabcdef1234567890",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "GUCCI001",
            "name": "Gucci GG Marmont Bag",
            "category": "Bags",
            "manufacturer_name": "Gucci",
            "manufacturer_wallet": "0x9ca2f208651bE432803012645Hac136c92EB5e46",
            "price": 2100.00,
            "image_url": "https://images.unsplash.com/photo-1584917865442-de89df76afd3?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0xfedcba0987654321",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "ROLEX001",
            "name": "Rolex Submariner",
            "category": "Accessories",
            "manufacturer_name": "Rolex",
            "manufacturer_wallet": "0x1ca3f309651bD432803012645Hac136c92EB5e47",
            "price": 8500.00,
            "image_url": "https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0x1111222233334444",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "SAMSUNG001",
            "name": "Samsung Galaxy S24 Ultra",
            "category": "Electronics",
            "manufacturer_name": "Samsung",
            "manufacturer_wallet": "0x2da4f409651bD432803012645Hac136c92EB5e48",
            "price": 1299.99,
            "image_url": "https://images.unsplash.com/photo-1610945265064-0e34e5519bbf?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0x5555666677778888",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "ADIDAS001",
            "name": "Adidas Ultraboost 22",
            "category": "Shoes",
            "manufacturer_name": "Adidas",
            "manufacturer_wallet": "0x3eb5f509651bD432803012645Hac136c92EB5e49",
            "price": 180.00,
            "image_url": "https://images.unsplash.com/photo-1549298916-b41d501d3772?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0x9999aaaabbbbcccc",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "CHANEL001",
            "name": "Chanel Classic Flap Bag",
            "category": "Bags",
            "manufacturer_name": "Chanel",
            "manufacturer_wallet": "0x4fc6f609651bD432803012645Hac136c92EB5e50",
            "price": 6800.00,
            "image_url": "https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0xddddeeeeffffaaaa",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "APPLE002",
            "name": "MacBook Pro 16-inch M3",
            "category": "Electronics",
            "manufacturer_name": "Apple Inc",
            "manufacturer_wallet": "0x742d35Cc6634C0532925a3b8D400AD96Cfb4c001",
            "price": 2499.99,
            "image_url": "https://images.unsplash.com/photo-1517336714731-489689fd1ca8?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0xbbbbccccddddeeee",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "VERSACE001",
            "name": "Versace Medusa T-Shirt",
            "category": "Clothing",
            "manufacturer_name": "Versace",
            "manufacturer_wallet": "0x5fd7f709651bD432803012645Hac136c92EB5e51",
            "price": 450.00,
            "image_url": "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0x1111ffff2222eeee",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "PRADA001",
            "name": "Prada Nylon Backpack",
            "category": "Bags",
            "manufacturer_name": "Prada",
            "manufacturer_wallet": "0x6ge8f809651bD432803012645Hac136c92EB5e52",
            "price": 1200.00,
            "image_url": "https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0x3333dddd4444cccc",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "SONY001",
            "name": "Sony WH-1000XM5 Headphones",
            "category": "Electronics",
            "manufacturer_name": "Sony",
            "manufacturer_wallet": "0x7hf9fa09651bD432803012645Hac136c92EB5e53",
            "price": 399.99,
            "image_url": "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0x5555bbbb6666aaaa",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "BALENCIAGA001",
            "name": "Balenciaga Triple S Sneakers",
            "category": "Shoes",
            "manufacturer_name": "Balenciaga",
            "manufacturer_wallet": "0x8igafb09651bD432803012645Hac136c92EB5e54",
            "price": 1090.00,
            "image_url": "https://images.unsplash.com/photo-1556906781-9a412961c28c?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0x7777cccc8888bbbb",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "HERMES001",
            "name": "Hermès Birkin 35",
            "category": "Bags",
            "manufacturer_name": "Hermès",
            "manufacturer_wallet": "0x9jhbfc09651bD432803012645Hac136c92EB5e55",
            "price": 15000.00,
            "image_url": "https://images.unsplash.com/photo-1584917865442-de89df76afd3?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0x9999aaaa0000dddd",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "TESLA001",
            "name": "Tesla Model S Plaid",
            "category": "Automotive",
            "manufacturer_name": "Tesla",
            "manufacturer_wallet": "0xajicgd09651bD432803012645Hac136c92EB5e56",
            "price": 129990.00,
            "image_url": "https://images.unsplash.com/photo-1560958089-b8a1929cea89?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0xbbbbffff1111eeee",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "DIOR001",
            "name": "Dior Lady Dior Bag",
            "category": "Bags",
            "manufacturer_name": "Christian Dior",
            "manufacturer_wallet": "0xbkjdhe09651bD432803012645Hac136c92EB5e57",
            "price": 4500.00,
            "image_url": "https://images.unsplash.com/photo-1584917865442-de89df76afd3?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0xdddd2222eeee3333",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "OMEGA001",
            "name": "Omega Speedmaster Professional",
            "category": "Accessories",
            "manufacturer_name": "Omega",
            "manufacturer_wallet": "0xclkeif09651bD432803012645Hac136c92EB5e58",
            "price": 5350.00,
            "image_url": "https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0xffff4444aaaa5555",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "BURBERRY001",
            "name": "Burberry Trench Coat",
            "category": "Clothing",
            "manufacturer_name": "Burberry",
            "manufacturer_wallet": "0xdmlfkg09651bD432803012645Hac136c92EB5e59",
            "price": 1890.00,
            "image_url": "https://images.unsplash.com/photo-1539109136881-3be0616acf4b?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0x1111aaaa2222bbbb",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "CARTIER001",
            "name": "Cartier Love Bracelet",
            "category": "Accessories",
            "manufacturer_name": "Cartier",
            "manufacturer_wallet": "0xenmigh09651bD432803012645Hac136c92EB5e60",
            "price": 6750.00,
            "image_url": "https://images.unsplash.com/photo-1515562141207-7a88fb7ce338?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0x3333cccc4444dddd",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "BOSE001",
            "name": "Bose QuietComfort 45",
            "category": "Electronics",
            "manufacturer_name": "Bose",
            "manufacturer_wallet": "0xfonjhi09651bD432803012645Hac136c92EB5e61",
            "price": 329.00,
            "image_url": "https://images.unsplash.com/photo-1505740420928-5e560c06d30e?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0x5555eeee6666ffff",
            "verified": True,
            "registered_at": get_current_utc()
        },
        {
            "serial_number": "YEEZY001",
            "name": "Yeezy Boost 350 V2",
            "category": "Shoes",
            "manufacturer_name": "Adidas x Yeezy",
            "manufacturer_wallet": "0x3eb5f509651bD432803012645Hac136c92EB5e49",
            "price": 220.00,
            "image_url": "https://images.unsplash.com/photo-1549298916-b41d501d3772?w=300&h=300&fit=crop",
            "blockchain_verified": True,
            "blockchain_tx_hash": "0x7777dddd8888eeee",
            "verified": True,
            "registered_at": get_current_utc()
        }
    ]
    
    all_products.extend(blockchain_products)
    
    # 2. Fetch products from FakeStore API (20 products)
    print("Fetching products from FakeStore API...")
    try:
        response = requests.get('https://fakestoreapi.com/products')
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
                    "name": item['title'],
                    "category": category_mapping.get(item['category'], "General"),
                    "manufacturer_name": "Generic Brand",
                    "price": float(item['price']),
                    "image_url": item['image'],
                    "blockchain_verified": False,
                    "verified": random.choice([True, True, False]),  # Most are verified
                    "registered_at": get_current_utc()
                }
                all_products.append(product)
            
            print(f"Added {len(fake_products)} products from FakeStore API")
        else:
            print("Failed to fetch from FakeStore API")
    except Exception as e:
        print(f"Error fetching from FakeStore API: {e}")
    
    # 3. Additional regular products to reach 70+ total (30+ more products)
    additional_products = [
        # Shoes
        {"serial_number": "CONVERSE001", "name": "Converse Chuck Taylor All Star", "category": "Shoes", "price": 60.00, "image_url": "https://images.unsplash.com/photo-1549298916-b41d501d3772?w=300&h=300&fit=crop"},
        {"serial_number": "VANS001", "name": "Vans Old Skool", "category": "Shoes", "price": 65.00, "image_url": "https://images.unsplash.com/photo-1525966222134-fcfa99b8ae77?w=300&h=300&fit=crop"},
        {"serial_number": "PUMA001", "name": "Puma RS-X", "category": "Shoes", "price": 110.00, "image_url": "https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=300&h=300&fit=crop"},
        {"serial_number": "REEBOK001", "name": "Reebok Classic Leather", "category": "Shoes", "price": 75.00, "image_url": "https://images.unsplash.com/photo-1549298916-b41d501d3772?w=300&h=300&fit=crop"},
        {"serial_number": "NEWBALANCE001", "name": "New Balance 990v5", "category": "Shoes", "price": 185.00, "image_url": "https://images.unsplash.com/photo-1542291026-7eec264c27ff?w=300&h=300&fit=crop"},
        
        # Bags
        {"serial_number": "HERSCHEL001", "name": "Herschel Little America Backpack", "category": "Bags", "price": 99.99, "image_url": "https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=300&h=300&fit=crop"},
        {"serial_number": "JANSPORT001", "name": "JanSport SuperBreak", "category": "Bags", "price": 36.00, "image_url": "https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=300&h=300&fit=crop"},
        {"serial_number": "KIPLING001", "name": "Kipling Seoul Laptop Backpack", "category": "Bags", "price": 79.00, "image_url": "https://images.unsplash.com/photo-1553062407-98eeb64c6a62?w=300&h=300&fit=crop"},
        {"serial_number": "MICHAEL001", "name": "Michael Kors Jet Set Tote", "category": "Bags", "price": 168.00, "image_url": "https://images.unsplash.com/photo-1584917865442-de89df76afd3?w=300&h=300&fit=crop"},
        {"serial_number": "COACH001", "name": "Coach Signature Canvas Tote", "category": "Bags", "price": 295.00, "image_url": "https://images.unsplash.com/photo-1584917865442-de89df76afd3?w=300&h=300&fit=crop"},
        
        # Clothing
        {"serial_number": "HM001", "name": "H&M Cotton T-Shirt", "category": "Clothing", "price": 9.99, "image_url": "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=300&h=300&fit=crop"},
        {"serial_number": "ZARA001", "name": "Zara Blazer", "category": "Clothing", "price": 79.90, "image_url": "https://images.unsplash.com/photo-1539109136881-3be0616acf4b?w=300&h=300&fit=crop"},
        {"serial_number": "UNIQLO001", "name": "Uniqlo Heattech Ultra Warm Crew Neck", "category": "Clothing", "price": 29.90, "image_url": "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=300&h=300&fit=crop"},
        {"serial_number": "GAP001", "name": "Gap Classic Fit Jeans", "category": "Clothing", "price": 69.95, "image_url": "https://images.unsplash.com/photo-1542272604-787c3835535d?w=300&h=300&fit=crop"},
        {"serial_number": "LEVIS001", "name": "Levi's 501 Original Jeans", "category": "Clothing", "price": 89.50, "image_url": "https://images.unsplash.com/photo-1542272604-787c3835535d?w=300&h=300&fit=crop"},
        {"serial_number": "CHAMPION001", "name": "Champion Reverse Weave Hoodie", "category": "Clothing", "price": 60.00, "image_url": "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=300&h=300&fit=crop"},
        
        # Electronics
        {"serial_number": "AMAZON001", "name": "Amazon Echo Dot", "category": "Electronics", "price": 49.99, "image_url": "https://images.unsplash.com/photo-1518444065439-e933c06ce9cd?w=300&h=300&fit=crop"},
        {"serial_number": "GOOGLE001", "name": "Google Nest Hub", "category": "Electronics", "price": 99.99, "image_url": "https://images.unsplash.com/photo-1518444065439-e933c06ce9cd?w=300&h=300&fit=crop"},
        {"serial_number": "FITBIT001", "name": "Fitbit Charge 5", "category": "Electronics", "price": 179.95, "image_url": "https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=300&h=300&fit=crop"},
        {"serial_number": "GOPRO001", "name": "GoPro HERO11 Black", "category": "Electronics", "price": 399.99, "image_url": "https://images.unsplash.com/photo-1518444065439-e933c06ce9cd?w=300&h=300&fit=crop"},
        {"serial_number": "NINTENDO001", "name": "Nintendo Switch OLED", "category": "Electronics", "price": 349.99, "image_url": "https://images.unsplash.com/photo-1518444065439-e933c06ce9cd?w=300&h=300&fit=crop"},
        
        # Accessories & Home
        {"serial_number": "RAYBAN001", "name": "Ray-Ban Aviator Classic", "category": "Accessories", "price": 154.00, "image_url": "https://images.unsplash.com/photo-1572635196237-14b3f281503f?w=300&h=300&fit=crop"},
        {"serial_number": "OAKLEY001", "name": "Oakley Holbrook", "category": "Accessories", "price": 103.00, "image_url": "https://images.unsplash.com/photo-1572635196237-14b3f281503f?w=300&h=300&fit=crop"},
        {"serial_number": "CASIO001", "name": "Casio G-Shock DW5600E", "category": "Accessories", "price": 99.00, "image_url": "https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=300&h=300&fit=crop"},
        {"serial_number": "FOSSIL001", "name": "Fossil Gen 6 Smartwatch", "category": "Accessories", "price": 255.00, "image_url": "https://images.unsplash.com/photo-1523275335684-37898b6baf30?w=300&h=300&fit=crop"},
        {"serial_number": "DYSON001", "name": "Dyson V15 Detect", "category": "Home Appliances", "price": 749.99, "image_url": "https://images.unsplash.com/photo-1558618666-fcd25c85cd64?w=300&h=300&fit=crop"},
        {"serial_number": "INSTANT001", "name": "Instant Pot Duo 7-in-1", "category": "Home Appliances", "price": 79.95, "image_url": "https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=300&fit=crop"},
        {"serial_number": "CUISINART001", "name": "Cuisinart Coffee Maker", "category": "Home Appliances", "price": 99.95, "image_url": "https://images.unsplash.com/photo-1559056199-641a0ac8b55e?w=300&h=300&fit=crop"},
        {"serial_number": "KITCHENAID001", "name": "KitchenAid Stand Mixer", "category": "Home Appliances", "price": 379.99, "image_url": "https://images.unsplash.com/photo-1556909114-f6e7ad7d3136?w=300&h=300&fit=crop"},
        
        # More categories
        {"serial_number": "MLB001", "name": "MLB Baseball Cap", "category": "Caps", "price": 29.99, "image_url": "https://images.unsplash.com/photo-1521369909029-2afed882baee?w=300&h=300&fit=crop"},
        {"serial_number": "NBA001", "name": "NBA Team Jersey", "category": "Clothing", "price": 109.99, "image_url": "https://images.unsplash.com/photo-1521572163474-6864f9cf17ab?w=300&h=300&fit=crop"},
        {"serial_number": "NEWERA001", "name": "New Era 9FIFTY Snapback", "category": "Caps", "price": 34.99, "image_url": "https://images.unsplash.com/photo-1521369909029-2afed882baee?w=300&h=300&fit=crop"},
    ]
    
    # Add manufacturer and verification status to additional products
    for product in additional_products:
        product.update({
            "manufacturer_name": "Various Brands",
            "blockchain_verified": False,
            "verified": random.choice([True, True, False]),  # Mostly verified
            "registered_at": get_current_utc()
        })
    
    all_products.extend(additional_products)
    
    # Insert all products
    products_collection.insert_many(all_products)
    
    # Count products by category
    categories = {}
    for product in all_products:
        category = product["category"]
        categories[category] = categories.get(category, 0) + 1
    
    print(f"\n✅ Seeded {len(all_products)} products successfully!")
    print("\n📊 Products by category:")
    for category, count in sorted(categories.items()):
        print(f"  {category}: {count} products")
    
    blockchain_count = len([p for p in all_products if p["blockchain_verified"]])
    regular_count = len(all_products) - blockchain_count
    print(f"\n🔗 Blockchain verified: {blockchain_count} products")
    print(f"📦 Regular products: {regular_count} products")

if __name__ == "__main__":
    seed_products()