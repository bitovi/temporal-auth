# Temporal Auth Server

This repository provides a custom authentication and authorization solution for Temporal, integrating with a custom OIDC provider for user authentication and role-based access control.

> This is using Tilt for local development and using Docker Desktop for the Kubernetes cluster.


## Features

- OIDC Authentication
- Role-based access control for Temporal namespaces
- Environment-based configuration
- Local development setup with Kubernetes
- Automatic secret management

## Prerequisites

- Docker Desktop with Kubernetes enabled
- [Tilt](https://tilt.dev/) for local development
- [Helm](https://helm.sh/) for Kubernetes deployments
- Go 1.23 or later

## Getting Started

1. Clone the repository:
```bash
git clone https://github.com/your-repo/temporal-auth-server.git
cd temporal-auth-server
```

2. Copy the environment template and fill in your values:

## Configuration

### Authentication

Authentication is configured through environment variables and Kubernetes secrets:

- `TEMPORAL_AUTH_ISSUER_URL`: OIDC issuer URL
- `TEMPORAL_AUTH_CLIENT_ID`: OAuth client ID
- `TEMPORAL_AUTH_CLIENT_SECRET`: OAuth client secret

### Authorization

Access control is managed through group mappings:

- `admin`: Full system access
- `bitovi`: Access to bitovi-related namespaces
- `finance`: Access to finance-related namespaces

### Development

The development environment is managed through Tilt and uses:

- Local Kubernetes cluster
- PostgreSQL for persistence
- Automatic code reloading
- Environment variable management
- Port forwarding for easy access

## Usage

### Accessing the Web UI

The Temporal Web UI is available at: http://localhost:8080

### Using the API

The Temporal API is available at: localhost:7233

## Development

### Project Structure

```
├── server/            # Custom Temporal server implementation
│   └── config/        # Server configuration
├── k8s/               # Kubernetes configuration
│   └── dev/           # Development environment configuration
```

### Making Changes

1. Update the code in `server/`
2. Tilt will automatically rebuild and deploy changes
3. Check the Tilt UI for build and deployment status

## Troubleshooting

Common issues and solutions:

1. **Authentication Failures**
   - Check the `.env` file contains correct credentials
   - Verify the OIDC provider is accessible
   - Check the logs for token validation errors

2. **Build Failures**
   - Ensure Docker is running
   - Check Go module dependencies
   - Verify Kubernetes context is correct

3. **Deployment Issues**
   - Check Tilt logs for deployment errors
   - Verify Kubernetes secrets are created
   - Check pod logs for runtime errors

4. **Creating a new namespace**
   - Run `tctl --ns bitovi-project n re`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request


