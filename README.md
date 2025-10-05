# Product Verification Platform

A B2B SaaS platform that enables manufacturers to integrate product verification into their customer-facing applications. Think "Stripe for product authenticity."

## 🚀 Features

- **Product Verification API** - REST API for verifying product authenticity
- **Cryptographic Signatures** - Digital signatures for tamper-proof verification
- **Multi-tenant Architecture** - Secure isolation between manufacturers
- **Real-time Analytics** - Usage metrics and verification insights
- **Webhook Integration** - Real-time notifications for verification events
- **Billing Integration** - Stripe-powered subscription management
- **Admin Dashboard** - Management interface for platform administrators

## 📋 Requirements

- Python 3.9+
- MongoDB 5.0+
- Redis 6.0+ (for rate limiting)
- Node.js 16+ (for frontend, if applicable)

## 🛠 Installation

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
pip install -r requirements/development.txt
```

4. **Set up environment variables**
```bash
cp .env.template .env
# Edit .env with your configuration
```

5. **Start services**
```bash
# Start MongoDB and Redis
docker-compose up -d mongo redis

# Run the application
flask run
```

### Docker Deployment

```bash
# Build and start all services
docker-compose up --build

# Or run in background
docker-compose up -d
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_ENV` | Environment (development/production) | `development` |
| `MONGODB_URI` | MongoDB connection string | `mongodb://localhost:27017/product_verification` |
| `REDIS_URL` | Redis connection string | `redis://localhost:6379/0` |
| `JWT_SECRET_KEY` | JWT signing secret | (required) |
| `STRIPE_SECRET_KEY` | Stripe API secret key | (required for billing) |
| `BLOCKCHAIN_RPC_URL` | Blockchain RPC endpoint | (optional) |

### Database Setup

```bash
# Initialize database
python scripts/init_db.py

# Create admin user
python scripts/create_admin.py --email admin@example.com --password securepassword

# Seed sample data (development only)
python scripts/seed_data.py
```

## 📚 API Documentation

### Authentication

```bash
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "manufacturer@example.com",
    "password": "password"
  }'
```

### Product Verification

```bash
curl -X GET http://localhost:5000/api/verify/ABC123456 \
  -H "Authorization: Bearer your-jwt-token"
```

### Manufacturer Integration

```bash
curl -X POST http://localhost:5000/api/v1/integration/verify/single \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "serial_number": "ABC123456",
    "customer_info": {
      "ip_address": "192.168.1.1"
    }
  }'
```

## 🧪 Testing

### Run Tests

```bash
# Unit tests
pytest tests/unit/ -v

# Integration tests  
pytest tests/integration/ -v

# All tests with coverage
pytest tests/ --cov=app --cov-report=html
```

### Test Data

```bash
# Create test manufacturer
python scripts/create_test_data.py --type manufacturer

# Create test products
python scripts/create_test_data.py --type products --count 10
```

## 🚀 Deployment

### Production Checklist

- [ ] Environment variables configured
- [ ] Database migrations applied
- [ ] SSL certificates configured
- [ ] Monitoring and logging set up
- [ ] Backup procedures in place
- [ ] Rate limiting configured
- [ ] Security headers enabled

### Health Checks

```bash
# Application health
curl http://localhost:5000/health

# Detailed health check
curl http://localhost:5000/health/detailed
```

## 📊 Monitoring

### Application Metrics

- Visit `/metrics` for Prometheus metrics
- Health checks available at `/health`
- Application logs in `logs/app.log`

### Key Metrics to Monitor

- Verification request rate
- API response times
- Database connection pool usage
- Authentication failure rate
- Error rates by endpoint

## 🔒 Security

### Best Practices

- All API keys are hashed before storage
- JWT tokens expire after 24 hours
- Rate limiting on all public endpoints
- Input validation on all user data
- CORS properly configured
- Security headers enabled

### API Key Management

```bash
# Generate new API key
curl -X POST http://localhost:5000/api/manufacturer/api-keys \
  -H "Authorization: Bearer your-jwt-token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production API Key",
    "permissions": ["verify", "analytics"]
  }'
```

## 📱 Integration Examples

### JavaScript/Node.js

```javascript
const response = await fetch('https://api.your-domain.com/api/verify/ABC123', {
  headers: {
    'X-API-Key': 'your-api-key'
  }
});
const result = await response.json();
console.log(result.authentic ? 'Authentic' : 'Counterfeit');
```

### Python

```python
import requests

response = requests.get(
    'https://api.your-domain.com/api/verify/ABC123',
    headers={'X-API-Key': 'your-api-key'}
)
result = response.json()
print('Authentic' if result['authentic'] else 'Counterfeit')
```

### PHP

```php
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://api.your-domain.com/api/verify/ABC123');
curl_setopt($ch, CURLOPT_HTTPHEADER, ['X-API-Key: your-api-key']);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);
$result = json_decode($response, true);
echo $result['authentic'] ? 'Authentic' : 'Counterfeit';
curl_close($ch);
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Workflow

```bash
# Install pre-commit hooks
pre-commit install

# Run code formatting
black app/ tests/
flake8 app/ tests/

# Run tests before committing
pytest tests/
```

## 📁 Project Structure

```
product-verification-platform/
├── app/
│   ├── api/                 # API routes
│   ├── core/                # Core utilities
│   ├── models/              # Data models
│   ├── services/            # Business logic
│   └── utils/               # Utility functions
├── tests/                   # Test files
├── scripts/                 # Deployment scripts
├── docker/                  # Docker configuration
├── docs/                    # Documentation
└── requirements/            # Python dependencies
```

## 🐛 Troubleshooting

### Common Issues

**Database Connection Failed**
```bash
# Check MongoDB status
docker-compose ps mongo

# View MongoDB logs
docker-compose logs mongo
```

**Authentication Issues**
```bash
# Verify JWT secret is set
echo $JWT_SECRET_KEY

# Check token expiry
python -c "import jwt; print(jwt.decode('your-token', verify=False))"
```

**High Memory Usage**
```bash
# Check application metrics
curl http://localhost:5000/metrics | grep memory

# Monitor processes
docker stats
```

## 📞 Support

- **Documentation**: [docs/](./docs/)
- **Issues**: [GitHub Issues](https://github.com/your-org/product-verification-platform/issues)
- **Email**: support@your-domain.com
- **Slack**: #product-verification

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Thanks to all contributors
- Built with Flask, MongoDB, and Redis
- Inspired by Stripe's API design philosophy

---

**Version**: 1.0.0  
**Last Updated**: 2024-01-15  
**Maintainers**: Your Development Team