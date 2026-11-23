#!/usr/bin/env bash
# ==============================================================================
# AntiTelguard — Automated Launcher Script
# ==============================================================================

set -e

echo "🛡️ Starting AntiTelguard Threat Intelligence Console..."

# Method 1: Check for Docker
if command -v docker &> /dev/null; then
    echo "✓ Docker detected. Launching via Docker Compose..."
    if docker compose version &> /dev/null; then
        docker compose up -d
    else
        docker-compose up -d
    fi
    echo ""
    echo "============================================================"
    echo "🚀 AntiTelguard is running!"
    echo "👉 Open your browser at: http://localhost:8080"
    echo "============================================================"
    exit 0
fi

# Method 2: Fallback to Python Virtual Environment
echo "! Docker not found. Falling back to local Python runtime..."

if ! command -v python3 &> /dev/null; then
    echo "❌ Error: python3 is not installed. Please install Python 3.10+ or Docker."
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment in ./venv..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install requirements
echo "Installing dependencies from requirements.txt..."
pip install --quiet --no-cache-dir -r requirements.txt

echo ""
echo "============================================================"
echo "🚀 AntiTelguard is starting on port 8080..."
echo "👉 Open your browser at: http://localhost:8080"
echo "============================================================"

# Run uvicorn
exec uvicorn app.main:app --host 0.0.0.0 --port 8080
