!/bin/bash
set -e

echo "Deploying Product Verification Platform..."

# Pull latest code
git pull origin main

# Build Docker images
docker-compose build

# Backup database
./scripts/backup.sh

# Update containers
docker-compose up -d --remove-orphans

# Run migrations
docker-compose exec app python migrations/run_migrations.py

# Health check
sleep 30
curl -f http://localhost/health || exit 1

echo "Deployment complete!"
