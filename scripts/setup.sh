scripts/setup.sh
#!/bin/bash
set -e

echo "Setting up Product Verification Platform..."

# Create virtual environment
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "Virtual environment created."
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements/development.txt

# Copy environment file
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "Environment file created. Please update .env with your settings."
fi

# Start MongoDB and Redis (if using Docker)
docker-compose up -d mongo redis

# Wait for MongoDB
echo "Waiting for MongoDB to be ready..."
sleep 10

# Run migrations
python migrations/run_migrations.py

echo "Setup complete! Run 'source venv/bin/activate' and 'python app.py' to start."
