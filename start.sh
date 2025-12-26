#!/bin/bash

# Hybrid IDS Docker Startup Script
# This script handles container initialization and startup

set -e

echo "=================================="
echo "  Hybrid IDS Container Starting"
echo "=================================="

# Function to wait for services
wait_for_service() {
    local service_name=$1
    local port=$2
    local max_attempts=30
    local attempt=1
    
    echo "Waiting for $service_name to be ready..."
    
    while [ $attempt -le $max_attempts ]; do
        if nc -z localhost $port 2>/dev/null; then
            echo "$service_name is ready!"
            return 0
        fi
        
        echo "Attempt $attempt/$max_attempts - $service_name not ready yet..."
        sleep 2
        ((attempt++))
    done
    
    echo "Warning: $service_name did not become ready within timeout"
    return 1
}

# Function to initialize database
init_database() {
    echo "Initializing database..."
    
    # Check if database exists
    if [ ! -f "/app/ids_auth.db" ]; then
        echo "Creating new database..."
        python -c "
from database import db
print('Database initialized successfully')
"
    else
        echo "Database already exists, skipping initialization"
    fi
}

# Function to setup directories
setup_directories() {
    echo "Setting up directories..."
    
    # Create necessary directories
    mkdir -p /app/logs
    mkdir -p /app/data
    mkdir -p /app/backups
    
    # Set proper permissions
    chmod 755 /app/logs
    chmod 755 /app/data
    chmod 755 /app/backups
    
    echo "Directories created successfully"
}

# Function to validate configuration
validate_config() {
    echo "Validating configuration..."
    
    # Check required environment variables
    if [ -z "$SECRET_KEY" ]; then
        echo "WARNING: SECRET_KEY not set, using default"
    fi
    
    # Check network interface
    if [ -z "$NETWORK_INTERFACE" ]; then
        echo "WARNING: NETWORK_INTERFACE not set, using 'any'"
        export NETWORK_INTERFACE="any"
    fi
    
    # Check ML model availability
    if [ "$ML_ENABLED" = "true" ]; then
        if [ ! -d "/app/model" ] || [ -z "$(ls -A /app/model 2>/dev/null)" ]; then
            echo "WARNING: ML models not found, ML detection will be disabled"
            export ML_ENABLED="false"
        else
            echo "ML models found and will be enabled"
        fi
    fi
    
    echo "Configuration validation completed"
}

# Function to setup logging
setup_logging() {
    echo "Setting up logging..."
    
    # Create logs directory if it doesn't exist
    mkdir -p /app/logs
    
    # Set up log rotation
    if command -v logrotate >/dev/null 2>&1; then
        cat > /etc/logrotate.d/hybrid-ids << EOF
/app/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF
    fi
}

# Function to perform health checks
health_check() {
    echo "Performing health check..."
    
    # Check if required files exist
    if [ ! -f "main.py" ]; then
        echo "ERROR: main.py not found"
        exit 1
    fi
    
    if [ ! -f "auth.py" ]; then
        echo "ERROR: auth.py not found"
        exit 1
    fi
    
    if [ ! -f "database.py" ]; then
        echo "ERROR: database.py not found"
        exit 1
    fi
    
    # Check if templates directory exists
    if [ ! -d "templates" ]; then
        echo "ERROR: templates directory not found"
        exit 1
    fi
    
    echo "Health check passed"
}

# Function to start the application
start_application() {
    echo "Starting Hybrid IDS application..."
    
    # Export environment variables
    export FLASK_APP=main.py
    export PYTHONPATH=/app
    
    # Start the application
    if [ "$FLASK_ENV" = "development" ]; then
        echo "Starting in development mode..."
        exec python main.py
    else
        echo "Starting in production mode..."
        exec python main.py
    fi
}

# Main execution
main() {
    echo "Starting Hybrid IDS container initialization..."
    
    # Setup directories
    setup_directories
    
    # Initialize database
    init_database
    
    # Setup logging
    setup_logging
    
    # Validate configuration
    validate_config
    
    # Perform health checks
    health_check
    
    # Wait for dependent services if any
    if [ ! -z "$REDIS_URL" ]; then
        wait_for_service "Redis" 6379 || echo "Redis not available, continuing without it"
    fi
    
    # Start the application
    start_application
}

# Trap errors
trap 'echo "ERROR: Container startup failed"; exit 1' ERR

# Run main function
main "$@"
