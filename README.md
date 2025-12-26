# Hybrid IDS - Docker Containerization

This repository contains a Dockerized version of the Hybrid Intrusion Detection System (IDS) with support for docker-compose watch functionality.

## 🛡️ Application Overview

The Hybrid IDS is a real-time network intrusion detection system that combines:

- **Network Packet Analysis**: Real-time packet capture using Scapy
- **Machine Learning Detection**: TensorFlow-based attack classification
- **Web Dashboard**: Flask/Dash interface for monitoring and analysis
- **User Authentication**: Secure login system with SQLite database
- **Alert System**: Real-time attack notifications and logging

## 🚀 Quick Start

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- At least 2GB RAM available
- Network interface access (root privileges)

### 1. Clone and Setup

```bash
# Navigate to the application directory
cd /home/baba/Music/traffic-streaming/app

# Copy environment configuration
cp .env.example .env

# Edit configuration as needed
nano .env
```

### 2. Build and Run (Production)

```bash
# Build the production image
docker-compose build

# Start the application
docker-compose up -d

# View logs
docker-compose logs -f hybrid-ids
```

### 3. Development with Auto-Reload

```bash
# Start in development mode with auto-reload
docker-compose --profile dev up

# Or use docker compose watch for automatic synchronization
docker-compose up --watch
```

### 4. Access the Application

- **Main Dashboard**: http://localhost:8090
- **Network Traffic**: http://localhost:8090/network-traffic
- **Analysis**: http://localhost:8090/analysis
- **Attacks**: http://localhost:8090/attacks
- **Notifications**: http://localhost:8090/notifications
- **Settings**: http://localhost:8090/settings

## 📁 Project Structure

```
├── Dockerfile                 # Multi-stage Docker build
├── docker-compose.yml         # Production configuration
├── docker-compose.override.yml # Development overrides
├── .dockerignore             # Build context exclusions
├── .env.example              # Environment configuration template
├── requirements.txt          # Python dependencies
├── requirements_enhanced.txt # Additional requirements
├── start.sh                  # Container initialization script
├── main.py                   # Main Flask application
├── auth.py                   # Authentication middleware
├── database.py               # Database operations
├── templates/                # HTML templates
├── model/                    # ML model files
├── logs/                     # Log files
└── data/                     # Persistent data
```

## 🐳 Docker Configuration

### Production Setup

The production configuration includes:

- **Main Application**: Flask server with packet capture
- **Redis**: Session storage and caching
- **Persistent Volumes**: Database and logs
- **Health Checks**: Application monitoring
- **Resource Limits**: CPU and memory constraints

### Development Setup

The development configuration provides:

- **Live Code Reload**: Automatic synchronization with docker-compose watch
- **Volume Mounts**: Full source code access
- **Debug Mode**: Enhanced logging and development tools
- **Hot Reload**: Changes reflect immediately

## 🔧 Configuration

### Environment Variables

Key configuration options in `.env`:

```bash
# Network Interface (change from 'any' to your interface)
NETWORK_INTERFACE=any

# IDS Detection Thresholds
MAX_PACKETS=5000
DOS_PPS_THRESHOLD=500
DDOS_SOURCE_THRESHOLD=5
DDOS_TOTAL_PPS=1500

# Security
SECRET_KEY=your-secret-key-change-in-production

# ML Configuration
ML_ENABLED=true
```

### Network Interface Setup

To capture network packets, you may need to:

1. **Identify your network interface**:

   ```bash
   ip link show
   # or
   ifconfig
   ```

2. **Update configuration**:

   ```bash
   # Edit .env file
   NETWORK_INTERFACE=eth0  # or wlan0, etc.
   ```

3. **Ensure proper permissions**:
   - Container runs with `NET_ADMIN` and `NET_RAW` capabilities
   - May require running Docker with `--privileged` flag

## 🚦 Docker Compose Commands

### Basic Operations

```bash
# Start services
docker-compose up -d

# Stop services
docker-compose down

# View logs
docker-compose logs -f hybrid-ids

# Restart service
docker-compose restart hybrid-ids

# Scale service
docker-compose up -d --scale hybrid-ids=1
```

### Development Commands

```bash
# Start with development profile
docker-compose --profile dev up

# Use docker compose watch for auto-reload
docker-compose up --watch

# Build development image
docker-compose -f docker-compose.yml -f docker-compose.override.yml build

# Development with logs
docker-compose --profile dev up && docker-compose logs -f hybrid-ids
```

### Monitoring and Debugging

```bash
# Check service status
docker-compose ps

# Execute commands in container
docker-compose exec hybrid-ids bash
docker-compose exec hybrid-ids python -c "import main; print('OK')"

# View resource usage
docker stats hybrid-ids

# Check health status
docker-compose ps
curl -f http://localhost:8090/api/network-status
```

## 🔍 Troubleshooting

### Common Issues

1. **Packet Capture Not Working**:

   ```bash
   # Check network interface configuration
   docker-compose exec hybrid-ids ip link show

   # Verify capabilities
   docker-compose exec hybrid-ids capsh --print
   ```

2. **ML Models Not Loading**:

   ```bash
   # Check model files
   docker-compose exec hybrid-ids ls -la model/

   # Verify ML configuration
   docker-compose exec hybrid-ids python -c "import tensorflow; print('TensorFlow loaded')"
   ```

3. **Database Issues**:

   ```bash
   # Check database permissions
   docker-compose exec hybrid-ids ls -la ids_auth.db

   # Reset database
   docker-compose down -v
   docker-compose up -d
   ```

4. **Port Already in Use**:

   ```bash
   # Find process using port 8090
   lsof -i :8090

   # Change port in docker-compose.yml
   ports:
     - "8091:8090"  # Use different host port
   ```

### Logs and Debugging

```bash
# View all logs
docker-compose logs

# View specific service logs
docker-compose logs hybrid-ids
docker-compose logs redis

# Follow logs in real-time
docker-compose logs -f hybrid-ids

# View last 100 lines
docker-compose logs --tail=100 hybrid-ids
```

## 🛠️ Development

### Local Development Setup

1. **Setup virtual environment**:

   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\\Scripts\\activate
   pip install -r requirements.txt
   ```

2. **Run locally**:

   ```bash
   # Set environment
   export FLASK_ENV=development
   export FLASK_DEBUG=1

   # Run application
   python main.py
   ```

3. **With Docker for development**:

   ```bash
   # Start development environment
   docker-compose --profile dev up

   # Use docker compose watch for auto-reload
   docker-compose up --watch
   ```

### Adding New Features

1. **Update application code**
2. **Test changes locally first**
3. **Update requirements if needed**
4. **Rebuild Docker image**:
   ```bash
   docker-compose build hybrid-ids
   ```
5. **Deploy and test**

## 🔒 Security Considerations

### Container Security

- Runs as root user (required for packet capture)
- Uses minimal base image (python:3.9-slim)
- Includes security capabilities for network operations
- Health checks for monitoring

### Application Security

- Configure strong `SECRET_KEY` in production
- Use environment variables for sensitive data
- Regular security updates for dependencies
- Monitor logs for suspicious activity

### Production Hardening

- Use Docker secrets for sensitive configuration
- Implement proper firewall rules
- Enable SSL/TLS for web interface
- Regular backup of database and logs

## 📊 Monitoring

### Health Checks

The application includes built-in health checks:

- **HTTP Health Endpoint**: `http://localhost:8090/api/network-status`
- **Container Health**: Docker Compose health check
- **Service Dependencies**: Redis connectivity

### Metrics and Logging

- **Application Logs**: Available in `./logs/` directory
- **Attack Logs**: Stored in `attack_logs.log`
- **Container Logs**: Via `docker-compose logs`
- **Resource Monitoring**: `docker stats`

### Performance Tuning

- **Resource Limits**: Configured in docker-compose.yml
- **Database Optimization**: SQLite with proper indexing
- **ML Model Caching**: Models loaded at startup
- **Packet Buffer Management**: Configurable thresholds

## 🚀 Production Deployment

### Build Production Image

```bash
# Build optimized production image
docker-compose build --target production

# Tag for registry
docker tag hybrid-ids:latest your-registry/hybrid-ids:latest

# Push to registry
docker push your-registry/hybrid-ids:latest
```

### Production docker-compose.yml

```yaml
services:
  hybrid-ids:
    image: your-registry/hybrid-ids:latest
    # ... production configuration
```

### SSL/TLS Configuration

1. **Generate SSL certificates**:

   ```bash
   mkdir -p ssl
   openssl req -x509 -newkey rsa:4096 -keyout ssl/key.pem -out ssl/cert.pem -days 365
   ```

2. **Update configuration**:
   ```bash
   SSL_ENABLED=true
   SSL_CERT_PATH=/app/ssl/cert.pem
   SSL_KEY_PATH=/app/ssl/key.pem
   ```

## 📝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes and test thoroughly
4. Update documentation
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For issues and questions:

1. Check the troubleshooting section
2. Review application logs
3. Create an issue with detailed information
4. Include Docker and system information

---

**Note**: This application requires network interface access and may need to run with elevated privileges. Ensure proper security measures are in place for production deployment.
