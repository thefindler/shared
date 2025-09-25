# 📦 Findler Shared Packages

Shared Go packages for authentication, configuration, and logging across Findler services.

## 🎯 **Purpose**

This repository provides common functionality to eliminate code duplication across Findler services:

- **`config/`** - Centralized configuration management (Azure Key Vault, env files)
- **`auth/`** - JWT authentication and authorization
- **`logger/`** - Structured logging with PII masking

## 🏗️ **Package Structure**

```
findler-shared/
├── config/
│   ├── manager.go           # ConfigManager and core logic
│   ├── global.go           # Global config instance
│   └── providers/
│       ├── interface.go    # ConfigProvider interface
│       ├── env_file.go     # Environment file provider
│       └── azure_keyvault.go # Azure Key Vault provider
├── auth/
│   ├── types.go            # JWT types and claims
│   ├── config.go           # JWT configuration
│   ├── generator.go        # Token creation functions
│   ├── validator.go        # Token validation functions
│   └── fiber/
│       └── middleware.go   # Fiber-specific middleware
├── logger/
│   ├── logger.go           # Core logging interface
│   ├── google_cloud.go     # Google Cloud Logging
│   ├── file.go             # File logging
│   └── pii_masking.go      # PII masking for compliance
└── examples/
    ├── fiber-api/          # Example Fiber integration
    └── gin-api/            # Example Gin integration
```

## 🚀 **Usage**

### Quick Start

```go
import (
    "shared/config"
    "shared/auth"
    "shared/logger"
)

func main() {
    // Initialize config
    if err := config.InitGlobalConfig(); err != nil {
        log.Fatal("Failed to initialize config:", err)
    }
    
    // Initialize auth
    if err := auth.InitializeJWTConfig(); err != nil {
        log.Fatal("Failed to initialize JWT:", err)
    }
    
    // Initialize logger
    if err := logger.InitLogger(); err != nil {
        log.Fatal("Failed to initialize logger:", err)
    }
    
    // Use shared packages
    secretKey := config.GetConfig("JWT_SECRET_KEY")
    token, err := auth.CreateAccessToken(userID, orgID, username, role)
    logger.Info("Service started", map[string]interface{}{
        "service": "my-service",
        "version": "1.0.0",
    })
}
```

### Fiber Integration

```go
import "shared/auth/fiber"

app := fiber.New()
app.Use(fiber_auth.JWTMiddleware(fiber_auth.Config{
    RequireOrgIsolation: true,
}))
```

## 📋 **Migration Status**

Current implementation status:

- ⏳ **Config Package**: In Progress
- ⏳ **Auth Package**: Pending  
- ⏳ **Logger Package**: Pending

## 🔧 **Development**

### Prerequisites

- Go 1.21+
- Access to Azure Key Vault (for config)
- Google Cloud Project (for logging)

### Testing

```bash
go test ./...
```

### Building

```bash
go build ./...
```

## 📚 **Documentation**

- [Configuration Guide](./config/README.md)
- [Authentication Guide](./auth/README.md)  
- [Logging Guide](./logger/README.md)
- [Migration Guide](./docs/MIGRATION.md)

## 🔄 **Versioning**

We use semantic versioning:

- `v1.0.x` - Config package
- `v1.1.x` - Config + Auth packages
- `v1.2.x` - Config + Auth + Logger packages

## 🤝 **Contributing**

1. Create feature branch from `main`
2. Make changes with tests
3. Update documentation
4. Submit pull request

## 📄 **License**

Internal Findler package - not for external use.