# scripts/backup.sh
#!/bin/bash
set -e

BACKUP_DIR="backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p $BACKUP_DIR

echo "Creating database backup..."

# MongoDB backup
docker-compose exec mongo mongodump --host localhost --db product_verification --out /tmp/backup
docker cp $(docker-compose ps -q mongo):/tmp/backup $BACKUP_DIR/mongodb

# Application files backup (configs, uploads, etc.)
tar -czf $BACKUP_DIR/app_data.tar.gz \
    logs/ \
    uploads/ \
    .env

echo "Backup created in $BACKUP_DIR"