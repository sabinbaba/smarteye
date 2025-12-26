#!/bin/bash

# Hybrid IDS Docker Setup and Testing Script
# This script helps with building, testing, and managing the Docker container

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

# Function to check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        exit 1
    fi
    print_status "Docker found: $(docker --version)"
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed"
        exit 1
    fi
    print_status "Docker Compose found: $(docker-compose --version)"
    
    # Check available memory
    available_memory=$(free -m | awk 'NR==2{printf "%.0f", $7}')
    if [ "$available_memory" -lt 2048 ]; then
        print_warning "Available memory is less than 2GB. Application may not run optimally."
    else
        print_status "Sufficient memory available: ${available_memory}MB"
    fi
}

# Function to setup environment
setup_environment() {
    print_header "Setting Up Environment"
    
    # Copy environment file if it doesn't exist
    if [ ! -f ".env" ]; then
        if [ -f ".env.example" ]; then
            cp .env.example .env
            print_status "Created .env file from .env.example"
            print_warning "Please edit .env file to configure your network interface"
        else
            print_warning ".env.example not found, creating basic .env"
            cat > .env << EOF
FLASK_ENV=development
FLASK_DEBUG=1
PYTHONUNBUFFERED=1
NETWORK_INTERFACE=any
PORT=8090
SECRET_KEY=hybrid-ids-secret-key-change-in-production-2024
EOF
        fi
    else
        print_status ".env file already exists"
    fi
    
    # Create necessary directories
    mkdir -p logs data backups
    print_status "Created necessary directories"
}

# Function to build Docker images
build_images() {
    print_header "Building Docker Images"
    
    print_status "Building production image..."
    docker-compose build hybrid-ids
    
    print_status "Building development image..."
    docker-compose build hybrid-ids-dev
}

# Function to run tests
run_tests() {
    print_header "Running Container Tests"
    
    # Test if containers can start
    print_status "Testing container startup..."
    docker-compose up -d --wait
    
    sleep 10
    
    # Test health check
    if curl -f http://localhost:8090/api/network-status &> /dev/null; then
        print_status "Health check passed"
    else
        print_warning "Health check failed, but container may still be starting"
    fi
    
    # Check logs
    print_status "Checking container logs..."
    if docker-compose logs hybrid-ids | grep -q "Hybrid IDS started"; then
        print_status "Application startup detected in logs"
    else
        print_warning "Application startup not clearly detected in logs"
    fi
}

# Function to start development mode
start_development() {
    print_header "Starting Development Mode"
    
    print_status "Starting with docker-compose watch for auto-reload..."
    docker-compose --profile dev up --watch
}

# Function to start production mode
start_production() {
    print_header "Starting Production Mode"
    
    print_status "Starting production containers..."
    docker-compose up -d
    
    print_status "Viewing logs..."
    docker-compose logs -f hybrid-ids
}

# Function to stop all services
stop_services() {
    print_header "Stopping Services"
    
    docker-compose down
    print_status "All services stopped"
}

# Function to clean up
cleanup() {
    print_header "Cleaning Up"
    
    print_warning "This will remove all containers, volumes, and images. Continue? (y/N)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        docker-compose down -v --rmi all
        print_status "Cleanup completed"
    else
        print_status "Cleanup cancelled"
    fi
}

# Function to show status
show_status() {
    print_header "Container Status"
    
    docker-compose ps
    echo
    docker stats --no-stream $(docker-compose ps -q hybrid-ids 2>/dev/null || echo "") 2>/dev/null || echo "No containers running"
}

# Function to show logs
show_logs() {
    print_header "Container Logs"
    
    docker-compose logs -f hybrid-ids
}

# Function to access shell
access_shell() {
    print_header "Accessing Container Shell"
    
    docker-compose exec hybrid-ids bash
}

# Function to check network interfaces
check_network() {
    print_header "Network Interface Information"
    
    print_status "Available network interfaces:"
    ip link show | grep -E "^[0-9]+:" | awk '{print $2}' | sed 's/://'
    
    echo
    print_status "Current configuration:"
    if [ -f ".env" ]; then
        grep NETWORK_INTERFACE .env || echo "NETWORK_INTERFACE not set in .env"
    else
        echo "No .env file found"
    fi
}

# Function to validate setup
validate_setup() {
    print_header "Validating Setup"
    
    local errors=0
    
    # Check if all required files exist
    local required_files=("Dockerfile" "docker-compose.yml" "requirements.txt" "main.py" "auth.py" "database.py")
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            print_error "Required file missing: $file"
            ((errors++))
        else
            print_status "Found: $file"
        fi
    done
    
    # Check templates directory
    if [ ! -d "templates" ]; then
        print_error "Templates directory missing"
        ((errors++))
    else
        print_status "Templates directory found"
    fi
    
    # Check model directory (optional)
    if [ -d "model" ]; then
        print_status "Model directory found"
        model_count=$(find model -name "*.h5" -o -name "*.pkl" | wc -l)
        if [ "$model_count" -gt 0 ]; then
            print_status "Found $model_count ML model files"
        else
            print_warning "Model directory exists but no model files found"
        fi
    else
        print_warning "Model directory not found (ML will be disabled)"
    fi
    
    # Check if ports are available
    if lsof -Pi :8090 -sTCP:LISTEN -t >/dev/null 2>&1; then
        print_warning "Port 8090 is already in use"
    else
        print_status "Port 8090 is available"
    fi
    
    if [ "$errors" -eq 0 ]; then
        print_status "Setup validation passed!"
        return 0
    else
        print_error "Setup validation failed with $errors errors"
        return 1
    fi
}

# Function to show help
show_help() {
    print_header "Hybrid IDS Docker Management Script"
    
    echo "Usage: $0 [COMMAND]"
    echo
    echo "Commands:"
    echo "  setup          - Setup environment and validate configuration"
    echo "  build          - Build Docker images"
    echo "  test           - Build and test container startup"
    echo "  dev            - Start development mode with auto-reload"
    echo "  prod           - Start production mode"
    echo "  start          - Start services in background"
    echo "  stop           - Stop all services"
    echo "  restart        - Restart services"
    echo "  logs           - Show container logs"
    echo "  status         - Show container status"
    echo "  shell          - Access container shell"
    echo "  network        - Check network interface configuration"
    echo "  validate       - Validate setup and configuration"
    echo "  cleanup        - Remove all containers, volumes, and images"
    echo "  help           - Show this help message"
    echo
    echo "Examples:"
    echo "  $0 setup       # Initial setup and validation"
    echo "  $0 dev         # Start development mode"
    echo "  $0 prod        # Start production mode"
    echo "  $0 logs        # View logs"
    echo
}

# Main script logic
case "${1:-help}" in
    "setup")
        check_prerequisites
        setup_environment
        validate_setup
        ;;
    "build")
        check_prerequisites
        build_images
        ;;
    "test")
        check_prerequisites
        setup_environment
        build_images
        run_tests
        ;;
    "dev")
        check_prerequisites
        setup_environment
        validate_setup
        start_development
        ;;
    "prod")
        check_prerequisites
        setup_environment
        start_production
        ;;
    "start")
        docker-compose up -d
        show_status
        ;;
    "stop")
        stop_services
        ;;
    "restart")
        docker-compose restart hybrid-ids
        show_status
        ;;
    "logs")
        show_logs
        ;;
    "status")
        show_status
        ;;
    "shell")
        access_shell
        ;;
    "network")
        check_network
        ;;
    "validate")
        validate_setup
        ;;
    "cleanup")
        cleanup
        ;;
    "help"|*)
        show_help
        ;;
esac
