# CleanAspire Debug Deployment

This directory contains Docker Compose configuration for debugging and development of the CleanAspire application.

## Quick Start

1. **Copy the environment file:**
   ```bash
   cp sample.env .env
   ```

2. **Update the `.env` file** with your specific configuration values (API keys, passwords, etc.)

3. **Build and run all services:**
   ```bash
   docker-compose -f docker-compose.debug.yml up --build
   ```

4. **Access the applications:**
   - **API Service**: http://localhost:8080 (HTTP) / https://localhost:8443 (HTTPS)
   - **WebApp (Blazor Server)**: http://localhost:8081 (HTTP) / https://localhost:8444 (HTTPS)
   - **ClientApp (Blazor WASM)**: http://localhost:8082 (HTTP) / https://localhost:8445 (HTTPS)
   - **MinIO Console**: http://localhost:9001

## Database

The application uses SQLite by default for development. The database file is managed by the API service and persisted through Docker volumes - no additional database service required.

## Development Commands

### Start specific services
```bash
# API only
docker-compose -f docker-compose.debug.yml up api

# WebApp only
docker-compose -f docker-compose.debug.yml up webapp

# ClientApp only
docker-compose -f docker-compose.debug.yml up clientapp
```

### View logs
```bash
# All services
docker-compose -f docker-compose.debug.yml logs -f

# Specific service
docker-compose -f docker-compose.debug.yml logs -f api
```

### Stop services
```bash
docker-compose -f docker-compose.debug.yml down
```

### Stop and remove volumes
```bash
docker-compose -f docker-compose.debug.yml down -v
```

### Rebuild services
```bash
docker-compose -f docker-compose.debug.yml build --no-cache
```

## Configuration

### Environment Variables
All configuration is done through the `.env` file. Key settings include:

- **Database**: Uses SQLite for development (default)
- **Authentication**: Configure Google and Microsoft OAuth providers
- **Email**: Set up SendGrid for email notifications
- **Push Notifications**: Configure Webpushr for push notifications
- **File Storage**: MinIO configuration for file uploads

### SSL Certificates
The applications use self-signed certificates for HTTPS in development. For production, replace with proper SSL certificates.

### CORS Configuration
Update `CORS_ORIGINS` in `.env` to match your development URLs.

## Troubleshooting

### Port Conflicts
If you encounter port conflicts, update the port mappings in `docker-compose.debug.yml`:
```yaml
ports:
  - "YOUR_PORT:80"  # Change YOUR_PORT to an available port
```

### Database Connection Issues
- Ensure the database service is running before the API service
- Check the connection string format in `.env`
- Verify database credentials

### File Upload Issues
- Ensure MinIO service is running
- Check MinIO credentials in `.env`
- Verify the bucket name configuration

## Security Notes

⚠️ **Important**: This configuration is for development only!

- Default passwords and keys are used
- Self-signed certificates are generated
- Debug mode is enabled
- Change all credentials before production use

## Additional Resources

- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [.NET Docker Documentation](https://docs.microsoft.com/en-us/dotnet/core/docker/)
- [Blazor Documentation](https://docs.microsoft.com/en-us/aspnet/core/blazor/)
