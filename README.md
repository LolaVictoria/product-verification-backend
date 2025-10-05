# Product Verification Platform

A B2B SaaS platform that enables manufacturers to integrate product verification into their customer-facing applications. Think "Stripe for product authenticity."

## Features

- **Product Verification API** - REST API for verifying product authenticity
- **Blockchain Integration** - Immutable product registration on Ethereum
- **Cryptographic Signatures** - Digital signatures for tamper-proof verification
- **Real-time Analytics** - Usage metrics and verification insights
- **Webhook Integration** - Real-time notifications for verification events
- **Billing Integration** - Stripe-powered subscription management
- **Admin Dashboard** - Management interface for platform administrators
- **Demo Mode** - Try the platform without registration

## Requirements

- Python 3.9+
- MongoDB 5.0+
- Redis 6.0+ (for rate limiting)
- Ethereum Node/Infura (for blockchain features)

## Installation

### Local Development

1. **Clone the repository**
```bash
git clone https://github.com/your-org/product-verification-platform.git
cd product-verification-platform
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Set up environment variables**
```bash
cp .env.example .env
# Edit .env with your configuration
```

Required environment variables:
```bash
FLASK_ENV=development
MONGODB_URI=mongodb://localhost:27017/product_verification
JWT_SECRET_KEY=your-secret-key-here
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
BLOCKCHAIN_RPC_URL=https://sepolia.infura.io/v3/YOUR-PROJECT-ID
CONTRACT_ADDRESS=0x...
PRIVATE_KEY=0x...
```

5. **Start MongoDB**
```bash
docker-compose up -d mongodb
```

6. **Run the application**
```bash
python app.py
```

The API will be available at `http://localhost:5000`

### Docker Deployment

```bash
# Build and start all services
docker-compose up --build

# Or run in background
docker-compose up -d
```

## API Documentation

### Base URL

- Development: `http://localhost:5000`
- Production: `https://api.your-domain.com`

All API routes are versioned under `/api/v1/` prefix.

### Authentication

#### Register Manufacturer
```bash
curl -X POST http://localhost:5000/api/v1/auth/manufacturer/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "manufacturer@example.com",
    "password": "securepassword",
    "company_name": "Example Corp",
    "phone": "+1234567890"
  }'
```

#### Login
```bash
curl -X POST http://localhost:5000/api/v1/auth/manufacturer/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "manufacturer@example.com",
    "password": "securepassword"
  }'
```

Response:
```json
{
  "success": true,
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "...",
    "email": "manufacturer@example.com",
    "role": "manufacturer"
  }
}
```

### Demo Mode

Try the platform without registration:

```bash
# Start demo session
curl -X POST http://localhost:5000/api/v1/demo/start-session

# Verify product in demo mode
curl -X POST http://localhost:5000/api/v1/demo/verify \
  -H "Content-Type: application/json" \
  -d '{
    "serial_number": "DEMO123456"
  }'
```

### Product Management (Manufacturer Dashboard)

All manufacturer endpoints require JWT authentication:

```bash
# Register a product
curl -X POST http://localhost:5000/api/v1/manufacturer/products \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "serial_number": "ABC123456",
    "brand": "YourBrand",
    "model": "Model X",
    "manufacture_date": "2024-01-15",
    "registration_type": "blockchain"
  }'

# Get all products
curl -X GET http://localhost:5000/api/v1/manufacturer/products \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Get dashboard stats
curl -X GET http://localhost:5000/api/v1/manufacturer/dashboard/stats \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Bulk import products
curl -X POST http://localhost:5000/api/v1/manufacturer/products/bulk-import \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -F "file=@products.csv"
```

### API Key Management

Generate API keys for external integrations:

```bash
# Create API key
curl -X POST http://localhost:5000/api/v1/manufacturer/api-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production API Key",
    "permissions": ["verify", "register", "analytics"]
  }'

# List API keys
curl -X GET http://localhost:5000/api/v1/manufacturer/api-keys \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Revoke API key
curl -X POST http://localhost:5000/api/v1/manufacturer/api-keys/{key_id}/revoke \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### External API (For Customer-Facing Apps)

Use API keys for programmatic access:

```bash
# Verify single product
curl -X POST http://localhost:5000/api/external/verify \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "serial_number": "ABC123456",
    "customer_info": {
      "ip_address": "192.168.1.1"
    }
  }'

# Batch verification
curl -X POST http://localhost:5000/api/external/verify/batch \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "serial_numbers": ["ABC123", "DEF456", "GHI789"]
  }'

# Get product details
curl -X GET http://localhost:5000/api/external/products/ABC123456 \
  -H "X-API-Key: your-api-key"

# Test API connection
curl -X GET http://localhost:5000/api/external/test-connection \
  -H "X-API-Key: your-api-key"
```

### Public Verification (No Auth Required)

```bash
# Verify by serial number
curl -X GET http://localhost:5000/api/v1/verification/ABC123456

# Verify by QR code
curl -X GET http://localhost:5000/api/v1/verification/qr/QR_CODE_VALUE

# Get ownership history
curl -X GET http://localhost:5000/api/v1/verification/ownership-history/ABC123456
```

### Counterfeit Reporting

```bash
# Report counterfeit product
curl -X POST http://localhost:5000/api/v1/verification/counterfeit \
  -H "Content-Type: application/json" \
  -d '{
    "serial_number": "FAKE123",
    "description": "Found product with invalid serial",
    "reporter_email": "user@example.com"
  }'
```

### Analytics

```bash
# Get verification trends
curl -X GET http://localhost:5000/api/v1/manufacturer/analytics/verification-trends \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Get geographic distribution
curl -X GET http://localhost:5000/api/v1/manufacturer/analytics/geographic-distribution \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Export analytics data
curl -X POST http://localhost:5000/api/v1/manufacturer/analytics/export \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "format": "csv",
    "start_date": "2024-01-01",
    "end_date": "2024-12-31"
  }'
```

### Subscription & Billing

```bash
# Get subscription status
curl -X GET http://localhost:5000/api/v1/billing/subscription/status \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Upgrade subscription
curl -X POST http://localhost:5000/api/v1/billing/subscription/upgrade \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plan": "professional"
  }'

# Get available plans
curl -X GET http://localhost:5000/api/v1/billing/subscription/plans

# View invoices
curl -X GET http://localhost:5000/api/v1/billing/subscription/invoices \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Admin Endpoints

Admin routes require admin role JWT:

```bash
# Get all manufacturers
curl -X GET http://localhost:5000/api/v1/admin/manufacturers \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN"

# Approve manufacturer
curl -X POST http://localhost:5000/api/v1/admin/manufacturers/{id}/approve \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN"

# System health
curl -X GET http://localhost:5000/api/v1/admin/system/health \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN"

# Audit logs
curl -X GET http://localhost:5000/api/v1/admin/audit/logs \
  -H "Authorization: Bearer ADMIN_JWT_TOKEN"
```

## Webhooks

Configure webhooks to receive real-time notifications:

### Stripe Webhooks
```bash
POST /api/v1/billing/webhooks/stripe
```

### Blockchain Events
```bash
POST /api/external/webhooks/blockchain
```

### Verification Events
```bash
POST /api/external/webhooks/verification
```

## Integration Examples

### JavaScript/Node.js

```javascript
const axios = require('axios');

const client = axios.create({
  baseURL: 'https://api.your-domain.com',
  headers: {
    'X-API-Key': 'your-api-key'
  }
});

async function verifyProduct(serialNumber) {
  try {
    const response = await client.post('/api/external/verify', {
      serial_number: serialNumber
    });
    
    if (response.data.authentic) {
      console.log('Product is authentic!');
      console.log('Details:', response.data.product);
    } else {
      console.log('Warning: Product may be counterfeit');
    }
  } catch (error) {
    console.error('Verification failed:', error.message);
  }
}

verifyProduct('ABC123456');
```

### Python

```python
import requests

class ProductVerifier:
    def __init__(self, api_key):
        self.base_url = 'https://api.your-domain.com'
        self.headers = {'X-API-Key': api_key}
    
    def verify(self, serial_number):
        response = requests.post(
            f'{self.base_url}/api/external/verify',
            headers=self.headers,
            json={'serial_number': serial_number}
        )
        response.raise_for_status()
        return response.json()
    
    def batch_verify(self, serial_numbers):
        response = requests.post(
            f'{self.base_url}/api/external/verify/batch',
            headers=self.headers,
            json={'serial_numbers': serial_numbers}
        )
        response.raise_for_status()
        return response.json()

# Usage
verifier = ProductVerifier('your-api-key')
result = verifier.verify('ABC123456')
print('Authentic' if result['authentic'] else 'Counterfeit')
```

### PHP

```php
<?php

class ProductVerifier {
    private $apiKey;
    private $baseUrl = 'https://api.your-domain.com';
    
    public function __construct($apiKey) {
        $this->apiKey = $apiKey;
    }
    
    public function verify($serialNumber) {
        $ch = curl_init();
        
        curl_setopt_array($ch, [
            CURLOPT_URL => $this->baseUrl . '/api/external/verify',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode([
                'serial_number' => $serialNumber
            ]),
            CURLOPT_HTTPHEADER => [
                'X-API-Key: ' . $this->apiKey,
                'Content-Type: application/json'
            ]
        ]);
        
        $response = curl_exec($ch);
        curl_close($ch);
        
        return json_decode($response, true);
    }
}

$verifier = new ProductVerifier('your-api-key');
$result = $verifier->verify('ABC123456');
echo $result['authentic'] ? 'Authentic' : 'Counterfeit';
```

## Testing

### Run Tests

```bash
# All tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=app --cov-report=html

# Specific test file
pytest tests/test_auth.py -v
```

### Manual Testing

```bash
# Health check
curl http://localhost:5000/health

# Database test
curl http://localhost:5000/test-db

# Debug imports
curl http://localhost:5000/debug/imports
```

## Project Structure

```
product-verification-backend/
├── app/
│   ├── api/
│   │   ├── v1/
│   │   │   ├── auth_routes.py
│   │   │   ├── demo_routes.py
│   │   │   ├── manufacturer/
│   │   │   │   ├── dashboard_routes.py
│   │   │   │   ├── product_routes.py
│   │   │   │   ├── api_key_routes.py
│   │   │   │   ├── analytics_routes.py
│   │   │   │   └── onboarding_routes.py
│   │   │   ├── admin/
│   │   │   │   ├── manufacturer_management_routes.py
│   │   │   │   ├── system_routes.py
│   │   │   │   └── audit_routes.py
│   │   │   ├── billing/
│   │   │   │   ├── subscription_routes.py
│   │   │   │   └── webhook_routes.py
│   │   │   └── verification/
│   │   │       ├── public_routes.py
│   │   │       └── reporting_routes.py
│   │   ├── external/
│   │   │   ├── verification_routes.py
│   │   │   ├── crypto_routes.py
│   │   │   └── webhook_routes.py
│   │   ├── middleware/
│   │   │   ├── auth_middleware.py
│   │   │   ├── validation_middleware.py
│   │   │   ├── webhook_middleware.py
│   │   │   └── rate_limiting.py
│   │   └── route_registry.py
│   ├── services/
│   │   ├── auth/
│   │   ├── manufacturer/
│   │   ├── blockchain/
│   │   └── billing/
│   ├── models/
│   ├── utils/
│   └── config/
├── tests/
├── scripts/
├── docker/
└── requirements.txt
```

## Deployment

### Production Checklist

- Set `FLASK_ENV=production`
- Use strong `JWT_SECRET_KEY`
- Enable SSL/TLS certificates
- Configure MongoDB replica set
- Set up Redis for rate limiting
- Configure Stripe webhooks
- Enable monitoring and logging
- Set up backup procedures
- Configure CORS properly
- Use production WSGI server (gunicorn)

### Running with Gunicorn

```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Environment-Specific Settings

```bash
# Development
export FLASK_ENV=development
export DEBUG=True

# Production
export FLASK_ENV=production
export DEBUG=False
```

## Security

- All passwords hashed with bcrypt
- API keys hashed before storage
- JWT tokens expire after 1 hour
- Refresh tokens valid for 7 days
- Rate limiting on all endpoints
- Input validation and sanitization
- CORS properly configured
- Webhook signature verification
- SQL injection prevention (NoSQL)

## Monitoring

### Health Checks

```bash
# Basic health
curl http://localhost:5000/health

# API health with version
curl http://localhost:5000/api/health

# Database connection test
curl http://localhost:5000/test-db
```

### Key Metrics

- Total routes: 114
- Active manufacturers
- Verification requests per day
- API response times
- Error rates
- Blockchain transaction status

## Troubleshooting

### Common Issues

**Import Errors**
```bash
python check_imports.py
```

**Database Connection**
```bash
# Check MongoDB
docker-compose ps mongodb

# View logs
docker-compose logs mongodb
```

**JWT Token Issues**
```bash
# Verify token (without validation)
python -c "import jwt; print(jwt.decode('YOUR_TOKEN', options={'verify_signature': False}))"
```

## Support

- Documentation: Full API docs at `/docs`
- Issues: GitHub Issues
- Email: support@your-domain.com

## License

MIT License - see LICENSE file

## Version

**Version**: 1.0.0  
**Last Updated**: 2025-10-05  
**Total Routes**: 114  
**API Version**: v1