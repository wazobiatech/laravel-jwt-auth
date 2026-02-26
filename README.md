# Laravel Auth Guard

<div align="center">

![Laravel](https://img.shields.io/badge/Laravel-9%2B%20%7C%2010%20%7C%2011%20%7C%2012-FF2D20?style=for-the-badge&logo=laravel&logoColor=white)
![PHP](https://img.shields.io/badge/PHP-8.0%2B-777BB4?style=for-the-badge&logo=php&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-Required-DC382D?style=for-the-badge&logo=redis&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)

**Enterprise-grade JWT and Project authentication middleware for Laravel applications**

[Installation](#installation) • [Configuration](#configuration) • [Usage](#usage) • [GraphQL Support](#graphql-setup-lighthouse) • [Documentation](#documentation)

</div>

---

## 🎯 **Complete Feature Parity with Node.js Implementation**

### **Mercury GraphQL Integration**
- ✅ **ServiceAuthService** - Complete CLIENT_ID/CLIENT_SECRET → Mercury GraphQL integration
- ✅ **generateToken()** - Service token generation using Mercury API
- ✅ **getServiceById()** - Dynamic service UUID lookup from Mercury
- ✅ **Proper Service Validation** - Validates service is in `enabled_services[]`

### **Advanced JWKS Management** 
- ✅ **Per-tenant JWKS caching** - `jwks_cache:{tenantId}` pattern
- ✅ **Service JWKS endpoint** - Separate endpoint for service tokens
- ✅ **Auto-refresh on key miss** - Fetches fresh JWKS when key not found
- ✅ **Signature-based authentication** - Mercury API authentication

### **Redis Connection Management**
- ✅ **Graceful fallback** - Works with or without Redis
- ✅ **Health checking** - Automatic reconnection on failures
- ✅ **Per-tenant secret versioning** - Cached secret version validation

### **Complete GraphQL Directive Suite**
- ✅ **@userAuth** - JWT user authentication with optional scopes
- ✅ **@projectAuth** - Platform/project token authentication with scopes
- ✅ **@serviceAuth** - Service-only authentication (CLIENT_ID/CLIENT_SECRET tokens only)
- ✅ **@combineAuth** - Dual authentication (User JWT + Platform token required)
- ✅ **@scopes** - Standalone granular permission validation

### **Configuration Management**
- ✅ **Comprehensive config file** - `config/auth-guard.php`
- ✅ **Environment fallbacks** - Config → env → defaults
- ✅ **Laravel standards** - Proper service provider, middleware registration

## 🎯 Features

- **JWT User Authentication** - Secure user authentication with RS512 algorithm and scope validation
- **Platform Token Authentication** - HMAC-based platform/project token validation with tenant isolation
- **Service Authentication** - CLIENT_ID/CLIENT_SECRET authentication for service-to-service communication
- **Combined Authentication** - Support for dual authentication (JWT + Platform/Project token)
- **Comprehensive Scope System** - Granular permission validation with scope inheritance and combination
- **JWKS Support** - Automatic public key rotation and caching with per-tenant isolation
- **GraphQL First** - Complete Lighthouse GraphQL integration with dedicated directives
- **Redis-Powered** - Fast token validation, caching, and revocation with Redis
- **Mercury Integration** - Full integration with Mercury GraphQL API for token management
- **Docker-Ready** - Seamless operation in containerized environments
- **Laravel Standards** - Follows Laravel conventions with service provider auto-discovery

---

## 📋 Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
  - [Redis Setup](#redis-setup)
  - [Service Provider](#service-provider)
- [GraphQL Setup](#graphql-setup-lighthouse)
- [Usage](#usage)
  - [REST API Routes](#rest-api-routes)
  - [GraphQL Schema](#graphql-schema)
  - [Resolvers](#graphql-resolvers)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Advanced Usage](#advanced-usage)
- [Support](#support)

---

## ⚙️ Requirements

| Requirement | Version |
|-------------|---------|
| PHP | `^8.0` |
| Laravel | `^9.0 \| ^10.0 \| ^11.0 \| ^12.0` |
| Redis | `Latest` |
| Predis or PhpRedis | `Latest` |
| Lighthouse GraphQL | `^6.0 \| ^7.0` *(optional)* |

---

## 📦 Installation

### Step 1: Install the Package

```bash
composer require wazobia/laravel-auth-guard
```

The service provider will be automatically registered via Laravel's package discovery.

### Step 2: Install Redis Client

**Option A: Predis (PHP Redis client)**
```bash
composer require predis/predis
```

**Option B: PhpRedis Extension (Better Performance)**

```bash
# Ubuntu/Debian
sudo apt-get install php-redis

# Alpine Linux (Docker)
apk add php81-pecl-redis

# macOS
pecl install redis
```

### Step 3: Publish Configuration

```bash
php artisan vendor:publish --tag=auth-guard-config
```

This creates `config/auth-guard.php` in your project.

---

## 🔧 Configuration

### Environment Variables

Add these **mandatory** variables to your `.env` file:

```properties
# Mercury JWKS Service (REQUIRED)
MERCURY_BASE_URL=https://mercury.example.com
SIGNATURE_SHARED_SECRET=your_shared_secret_key

# Service Authentication (REQUIRED)
CLIENT_ID=your-service-client-id
CLIENT_SECRET=your-service-client-secret

# Redis Authentication Database (REQUIRED) 
REDIS_AUTH_URL=redis://localhost:6379/5

# JWT Algorithm (REQUIRED)
JWT_ALGORITHM=RS512
```

**Optional Environment Variables:**

```properties
# Mercury Configuration
MERCURY_TIMEOUT=10
SIGNATURE_ALGORITHM=sha256

# Redis Standard Configuration  
REDIS_CLIENT=predis
REDIS_URL=redis://localhost:6379/0
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=null
REDIS_DB=0

# Cache Settings
CACHE_EXPIRY_TIME=900
AUTH_CACHE_TTL=900
AUTH_CACHE_PREFIX=auth_guard

# Custom Headers 
AUTH_JWT_HEADER=Authorization
AUTH_PROJECT_TOKEN_HEADER=x-project-token
```

# Cache Settings
CACHE_EXPIRY_TIME=900
AUTH_CACHE_TTL=900
AUTH_CACHE_PREFIX=auth_guard
AUTH_CACHE_DRIVER=redis

# JWT Settings
JWT_ALGORITHM=RS512
JWT_LEEWAY=0

# Custom Headers (Optional)
AUTH_JWT_HEADER=Authorization
AUTH_PROJECT_TOKEN_HEADER=x-project-token

# Logging
AUTH_GUARD_LOGGING=true
AUTH_GUARD_LOG_CHANNEL=stack
```

> **💡 Docker Users:** If using Docker Compose, set `REDIS_HOST=redis` (the service name), not `127.0.0.1`

### Redis Setup

Update `config/database.php`:

```php
<?php

return [
    // ... other config

    'redis' => [
        'client' => env('REDIS_CLIENT', 'predis'),

        'options' => [
            'cluster' => env('REDIS_CLUSTER', 'redis'),
            'prefix' => env('REDIS_PREFIX', Str::slug(env('APP_NAME', 'laravel'), '_').'_database_'),
        ],

        'default' => [
            'url' => env('REDIS_URL'),
            'host' => env('REDIS_HOST', '127.0.0.1'),
            'username' => env('REDIS_USERNAME'),
            'password' => env('REDIS_PASSWORD'),
            'port' => env('REDIS_PORT', '6379'),
            'database' => env('REDIS_DB', '0'),
        ],

        'cache' => [
            'url' => env('REDIS_URL'),
            'host' => env('REDIS_HOST', '127.0.0.1'),
            'username' => env('REDIS_USERNAME'),
            'password' => env('REDIS_PASSWORD'),
            'port' => env('REDIS_PORT', '6379'),
            'database' => env('REDIS_CACHE_DB', '1'),
        ],
        
        'auth' => [
            'url' => env('REDIS_URL'),
            'host' => env('REDIS_HOST', '127.0.0.1'),
            'username' => env('REDIS_USERNAME'),
            'password' => env('REDIS_PASSWORD'),
            'port' => env('REDIS_PORT', '6379'),
            'database' => env('REDIS_DB', '0'),
            'prefix' => '', // No prefix!
        ],
    ],
];
```

### Verify Redis Connection

```bash
php artisan tinker
```

Test inside Tinker:
```php
Redis::ping();  // Should return: "+PONG"

Redis::set('test', 'Hello');
Redis::get('test');  // Should return: "Hello"

exit
```

### Service Provider

If not using auto-discovery, add to `config/app.php`:

```php
'providers' => [
    // ...
    Wazobia\LaravelAuthGuard\AuthGuardServiceProvider::class,
],
```

---

## 🎨 GraphQL Setup (Lighthouse)

### Step 1: Install Lighthouse

```bash
composer require nuwave/lighthouse
```

### Step 2: Configure Directives

Edit `config/lighthouse.php` and add the directive namespace:

```php
<?php

return [
    'namespaces' => [
        'models' => ['App', 'App\\Models'],
        'queries' => 'App\\GraphQL\\Queries',
        'mutations' => 'App\\GraphQL\\Mutations',
        'subscriptions' => 'App\\GraphQL\\Subscriptions',
        'interfaces' => 'App\\GraphQL\\Interfaces',
        'unions' => 'App\\GraphQL\\Unions',
        'scalars' => 'App\\GraphQL\\Scalars',
        
        'directives' => [
            'App\\GraphQL\\Directives',
            'Wazobia\\LaravelAuthGuard\\GraphQL\\Directives', // ← Add this line
        ],
    ],
];
```

### Step 3: Clear All Caches

```bash
php artisan cache:clear
php artisan config:clear
php artisan route:clear
php artisan lighthouse:clear-cache
composer dump-autoload
```

### Step 4: Clear Caches and Validate

```bash
php artisan lighthouse:clear-cache
php artisan lighthouse:validate-schema
```

---

## 🚀 Usage

### REST API Routes

Create routes in `routes/api.php`:

```php
<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Http\Request;

// Public route (no authentication)
Route::get('/public', function () {
    return ['message' => 'Public endpoint'];
});

// JWT Authentication only
Route::middleware('auth.jwt')->group(function () {
    Route::get('/user/profile', function (Request $request) {
        $user = $request->user();
        return [
            'uuid' => $user->uuid,
            'email' => $user->email,
            'name' => $user->name,
            'permissions' => $user->permissions ?? [],
        ];
    });
});

// Project Authentication only
Route::middleware('auth.project')->group(function () {
    Route::get('/project/info', function (Request $request) {
        $authProject = $request->get('auth_project', []);
        return [
            'project_uuid' => $authProject['project_uuid'] ?? null,
            'tenant_id' => $authProject['tenant_id'] ?? null,
            'scopes' => $authProject['scopes'] ?? [],
        ];
    });
});

// Combined Authentication (JWT + Project)
Route::middleware(['auth.jwt', 'auth.project'])->group(function () {
    Route::post('/secure/resource', function (Request $request) {
        return [
            'user' => $request->user(),
            'project' => $request->get('auth_project', []),
            'message' => 'Both authentications passed'
        ];
    });
});
```

### GraphQL Schema

Create or update `graphql/schema.graphql`:

```graphql
type Query {
  # Public query (no authentication)
  hello: String!
  
  # JWT user authentication required
  me: User! @userAuth
  userProfile: User! @userAuth(scopes: ["users:read"])
  
  # Project/platform token authentication required
  projectInfo: Project! @projectAuth(scopes: ["projects:manage"])
  
  # Service-only authentication required
  serviceStatus: ServiceInfo! @serviceAuth(scopes: ["services:read"])
  
  # Dual authentication (User + Project) required
  secureData: SecureData! @combineAuth(scopes: ["users:read", "projects:manage"])
}

type Mutation {
  # User mutations
  updateProfile(name: String!): User! @userAuth(scopes: ["users:update"])
  
  # Project mutations
  updateProjectSettings(settings: JSON!): Project! @projectAuth(scopes: ["projects:manage"])
  
  # Service mutations
  updateServiceConfig(config: JSON!): ServiceInfo! @serviceAuth(scopes: ["services:manage"])
  
  # Combined authentication mutations
  createSecureResource(data: JSON!): Resource! @combineAuth(scopes: ["users:create", "projects:manage"])
}

type User {
  uuid: ID!
  email: String!
  name: String!
  permissions: [String!]!
}

type Project {
  project_uuid: ID!
  tenant_id: ID!
  enabled_services: [String!]!
  scopes: [String!]!
}

type ServiceInfo {
  service_name: String!
  client_id: String!
  scopes: [String!]!
  is_active: Boolean!
}

type SecureData {
  id: ID!
  content: String!
  user: User!
  project: Project!
  created_at: String!
}

type Resource {
  id: ID!
  data: JSON
  owner: User!
  project: Project!
}
```

### GraphQL Resolvers

**app/GraphQL/Queries/Me.php**

```php
<?php

namespace App\GraphQL\Queries;

class Me
{
    public function __invoke($rootValue, array $args, $context)
    {
        $user = $context->user;
        $authUser = $context->request->get('auth_user', []);
        
        return [
            'uuid' => $user->uuid ?? $authUser['uuid'] ?? null,
            'email' => $user->email ?? $authUser['email'] ?? null,
            'name' => $user->name ?? $authUser['name'] ?? null,
            'permissions' => $authUser['permissions'] ?? [],
        ];
    }
}
```

**app/GraphQL/Queries/ProjectInfo.php**

```php
<?php

namespace App\GraphQL\Queries;

class ProjectInfo
{
    public function __invoke($rootValue, array $args, $context)
    {
        $authProject = $context->request->get('auth_project', []);
        $authPlatform = $context->request->get('auth_platform', []);
        $projectData = $authProject ?: $authPlatform;
        
        return [
            'project_uuid' => $projectData['project_uuid'] ?? null,
            'tenant_id' => $projectData['tenant_id'] ?? null,
            'scopes' => $projectData['scopes'] ?? [],
        ];
    }
}
```

**app/GraphQL/Queries/ServiceStatus.php**

```php
<?php

namespace App\GraphQL\Queries;

class ServiceStatus  
{
    public function __invoke($rootValue, array $args, $context)
    {
        $authService = $context->request->get('auth_service', []);
        
        return [
            'service_name' => $authService['service_name'] ?? 'unknown',
            'client_id' => $authService['client_id'] ?? 'unknown',
            'scopes' => $authService['scopes'] ?? [],
            'is_active' => !empty($authService),
        ];
    }
}
```

---

## 🧪 Testing

The package includes a comprehensive test suite with working GraphQL test endpoints:

### Built-in Test Endpoints

The package provides ready-to-use test resolvers in `app/GraphQL/Queries/TestAuth.php`:

```graphql
# User Authentication Tests
query { testUserAuth }  # Basic JWT auth
query { testUserAuthWithScopes }  # JWT with scope validation (@userAuth(scopes: ["projects:manage"]))

# Project/Platform Authentication Tests  
query { testProjectAuth }  # Basic platform token auth
query { testProjectAuthWithScopes }  # Platform token with scopes

# Service Authentication Tests
query { testServiceAuth }  # Basic service token auth  
query { testServiceAuthWithScopes }  # Service token with scopes (@serviceAuth(scopes: ["services:read"]))

# Combined Authentication Tests
query { testCombineAuth }  # Dual auth (User + Platform)
query { testCombineAuthWithScopes }  # Dual auth with combined scope validation

# Scope Tests
query { testScopes }  # Standalone scope validation (@scopes(scopes: ["users:read", "projects:manage"]))
```

### Test Scripts

The package includes ready-to-run test scripts:

```bash
# Generate service token and test @serviceAuth
./tests/test_service_auth.sh

# Test service authentication with scope validation
./tests/test_service_scopes.sh

# Test combined authentication scenarios
./tests/test_combine_auth.sh

# Test all authentication directives
./tests/test_all_auth.sh
```

### REST API with cURL

**JWT User Authentication**
```bash
curl -X GET http://localhost:8000/api/user/profile \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Accept: application/json"
```

**Project/Platform Authentication**
```bash
curl -X GET http://localhost:8000/api/project/info \
  -H "x-project-token: Bearer YOUR_PLATFORM_TOKEN" \
  -H "Accept: application/json"
```

**Service Authentication**
```bash
curl -X GET http://localhost:8000/api/service/status \
  -H "x-project-token: Bearer YOUR_SERVICE_TOKEN" \
  -H "Accept: application/json"
```

**Combined Authentication**
```bash
curl -X POST http://localhost:8000/api/secure/resource \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "x-project-token: Bearer YOUR_PLATFORM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"data": "test"}'
```

### GraphQL Queries

**JWT User Authentication**
```bash
curl -X POST http://localhost:8000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"query":"query { me { uuid email name permissions } }"}'
```

**Project/Platform Token Authentication**
```bash
curl -X POST http://localhost:8000/graphql \
  -H "Content-Type: application/json" \
  -H "x-project-token: Bearer YOUR_PLATFORM_TOKEN" \
  -d '{"query":"query { projectInfo { project_uuid tenant_id scopes } }"}'
```

**Service Authentication**
```bash
curl -X POST http://localhost:8000/graphql \
  -H "Content-Type: application/json" \
  -H "x-project-token: Bearer YOUR_SERVICE_TOKEN" \
  -d '{"query":"query { serviceStatus { service_name client_id scopes is_active } }"}'
```

**Combined Authentication (User + Platform)**
```bash
curl -X POST http://localhost:8000/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "x-project-token: Bearer YOUR_PLATFORM_TOKEN" \
  -d '{"query":"query { secureData { id content user { uuid email } project { project_uuid } } }"}'
```

### GraphQL Playground

1. Access GraphQL Playground at `http://localhost:8000/graphql-playground`
2. Add headers in the bottom left:

```json
{
  "Authorization": "Bearer YOUR_JWT_TOKEN",
  "x-project-token": "Bearer YOUR_PROJECT_TOKEN"
}
```

3. Run queries:

```graphql
# Test JWT Authentication
query TestUser {
  me {
    uuid
    email
    name
    permissions
  }
}

# Test Project Authentication 
query TestProject {
  projectInfo {
    project_uuid
    tenant_id
    scopes
  }
}

# Test Service Authentication
query TestService {
  serviceStatus {
    service_name
    client_id
    scopes
    is_active
  }
}

# Test Combined Authentication
query TestCombined {
  secureData {
    id
    content
    user {
      uuid
      email
    }
    project {
      project_uuid
      tenant_id
    }
  }
}
```

---

## 🔍 Troubleshooting

<details>
<summary><strong>❌ "No directive found for jwtAuth"</strong></summary>

**Solution:**
1. Add directive namespace to `config/lighthouse.php`
2. Clear all caches:
```bash
php artisan config:clear
php artisan lighthouse:clear-cache
composer dump-autoload
```
</details>

<details>
<summary><strong>❌ "Class Predis\Client not found"</strong></summary>

**Solution:**
```bash
composer require predis/predis
php artisan config:clear
```

Or change `.env`:
```properties
REDIS_CLIENT=phpredis
```
</details>

<details>
<summary><strong>❌ "Could not connect to Redis"</strong></summary>

**Solution:**

1. Verify Redis is running:
```bash
redis-cli ping  # Should return: PONG
```

2. Check your `.env`:
```properties
# For Docker
REDIS_HOST=redis

# For local
REDIS_HOST=127.0.0.1
```

3. Test connection:
```bash
php artisan tinker
Redis::ping();
```
</details>

<details>
<summary><strong>❌ "JWKS endpoint returned 401"</strong></summary>

**Solution:**

Check that `SIGNATURE_SHARED_SECRET` in `.env` matches your Mercury service configuration.
</details>

<details>
<summary><strong>❌ "Token has been revoked or expired"</strong></summary>

**Solution:**

The project token is either:
- Not found in Redis (expired)
- Manually revoked

Generate a new project token from your provisioning service.
</details>

### Docker-Specific Issues

**Redis Connection Refused**

Update `docker-compose.yml`:
```yaml
services:
  app:
    depends_on:
      - redis
    environment:
      - REDIS_HOST=redis
      
  redis:
    image: redis:alpine
    ports:
      - "6379:6379"
```

**PhpRedis Not Installed**

Add to your `Dockerfile`:
```dockerfile
RUN pecl install redis && docker-php-ext-enable redis
```

Then rebuild:
```bash
docker-compose build --no-cache
docker-compose up -d
```

---

## 🔥 Advanced Usage

### Programmatic Token Validation

```php
use Wazobia\LaravelAuthGuard\Services\JwtAuthService;
use Wazobia\LaravelAuthGuard\Services\ProjectAuthService;

class AuthController
{
    public function validateJwt(JwtAuthService $jwtService, Request $request)
    {
        try {
            $token = $request->bearerToken();
            $user = $jwtService->authenticate($token);
            
            return response()->json(['user' => $user]);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 401);
        }
    }
    
    public function validateProject(ProjectAuthService $projectService, Request $request)
    {
        try {
            $token = $request->header('x-project-token');
            $serviceId = config('auth-guard.service_id');
            
            $project = $projectService->authenticateWithToken($token, $serviceId);
            
            return response()->json(['project' => $project]);
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 401);
        }
    }
}
```

### Token Revocation

```php
use Wazobia\LaravelAuthGuard\Services\JwtAuthService;

Route::post('/logout', function (JwtAuthService $jwtService, Request $request) {
    $jti = $request->input('jti'); // JWT ID from token payload
    $ttl = 3600; // Revoke for 1 hour
    
    $jwtService->revokeToken($jti, $ttl);
    
    return response()->json(['message' => 'Token revoked']);
})->middleware('jwt.auth');
```

---

## 📚 Documentation

| Topic | Description |
|-------|-------------|
| **Middleware** | `jwt.auth`, `project.auth`, `combined.auth` |
| **Directives** | `@userAuth`, `@projectAuth`, `@serviceAuth`, `@combineAuth`, `@scopes` |
| **Services** | `JwtAuthService`, `ProjectAuthService`, `ServiceAuthService` |
| **Caching** | Redis-based JWKS caching with per-tenant isolation |
| **Token Types** | JWT (RS512), Platform/Project (HMAC), Service (CLIENT_ID/SECRET) |

---

## 🤝 Support

For issues or questions:

- **GitHub Issues:** [Report an issue](https://github.com/wazobia/laravel-auth-guard/issues)
- **Email:** developer@wazobia.tech
- **Documentation:** [Full Documentation](https://docs.wazobia.tech)

---

## ✅ Implementation Status\n\nThis Laravel Auth Guard package is **production-ready** with comprehensive testing:\n\n### ✅ Fully Implemented Features\n- **JWT User Authentication** (`@userAuth`) - Complete with scope validation\n- **Platform Token Authentication** (`@projectAuth`) - HMAC validation with tenant isolation  \n- **Service Authentication** (`@serviceAuth`) - CLIENT_ID/CLIENT_SECRET with Mercury integration\n- **Combined Authentication** (`@combineAuth`) - Dual token validation with scope merging\n- **JWKS Integration** - Per-tenant key caching with auto-refresh\n- **Mercury GraphQL Integration** - Complete service token lifecycle\n- **Comprehensive Error Handling** - Detailed error messages and logging\n\n### 🔧 Complete Test Suite\n- GraphQL test endpoints for all authentication directives\n- Automated test scripts with real Mercury token generation\n- Scope validation testing (success and failure scenarios)\n- Combined authentication with dual token validation\n- Service authentication with CLIENT_ID/CLIENT_SECRET flow\n\n---\n\n## 📄 License

This package is open-sourced software licensed under the [MIT license](LICENSE.md).

---

<div align="center">

**Made with ❤️ by [Wazobia Technologies](https://wazobia.tech)**

⭐ Star us on GitHub if this helped you!

</div>