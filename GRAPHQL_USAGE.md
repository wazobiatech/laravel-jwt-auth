# GraphQL Authentication Usage Guide

This guide shows you how to use authentication directives with scopes in your GraphQL mutations and queries.

## Available Directives

### 1. `@jwtAuth` - JWT User Authentication with Scopes

```graphql
# Basic JWT authentication
extend type Query {
  userProfile: User @jwtAuth
}

# JWT authentication with specific permissions/scopes
extend type Mutation {
  updateProfile(input: UpdateProfileInput!): User 
    @jwtAuth(scopes: ["profile:write"])
    
  deleteAccount: Boolean 
    @jwtAuth(scopes: ["account:delete", "admin"])
}
```

### 2. `@projectAuth` - Project Authentication with Scopes

```graphql
# Basic project authentication
extend type Mutation {
  createPost(input: CreatePostInput!): Post 
    @projectAuth
}

# Project authentication with specific scopes
extend type Mutation {
  deletePost(id: ID!): Boolean 
    @projectAuth(scopes: ["posts:delete", "admin"])
    
  updatePost(id: ID!, input: UpdatePostInput!): Post 
    @projectAuth(scopes: ["posts:write"])
}
```

### 3. `@serviceAuth` - Service-Only Authentication with Scopes

```graphql
# Service authentication ONLY accepts service tokens
# Requires x-project-token header with type: 'service'
extend type Mutation {
  createAPIKey(input: CreateAPIKeyInput!): APIKey 
    @serviceAuth(scopes: ["keys:create"])
    
  revokeAPIKey(id: ID!): Boolean 
    @serviceAuth(scopes: ["keys:revoke", "admin"])
    
  # Service-to-service operations
  bulkImportData(input: BulkImportInput!): ImportResult
    @serviceAuth(scopes: ["data:import", "bulk:operations"])
}
```

### 4. `@combinedAuth` - Both JWT and Project Authentication

```graphql
# Requires both JWT user token AND project token
extend type Mutation {
  adminDeleteUser(id: ID!): Boolean 
    @combinedAuth(scopes: ["users:delete", "admin"])
    
  # Combines user permissions + project scopes
  secureOperation(input: SecureInput!): SecureResult
    @combinedAuth(scopes: ["operations:execute", "security:high"])
}
```

### 5. `@scopes` - Standalone Scope Validation

```graphql
# Use after other auth directives for additional scope checking
extend type Query {
  sensitiveData: SensitiveData 
    @projectAuth
    @scopes(requires: ["analytics:read", "sensitive:access"])
}
```

## Complete Example Schema

```graphql
# schema.graphql

extend type Query {
  # Public endpoint - no authentication required
  publicPosts: [Post]
  
  # Requires JWT user authentication only
  userProfile: User @jwtAuth
  
  # JWT with user permissions
  adminUsers: [User] @jwtAuth(scopes: ["users:read", "admin"])
  
  # Requires project authentication 
  projectStats: ProjectStats @projectAuth
  
  # Project authentication with scopes
  adminReport: AdminReport 
    @projectAuth(scopes: ["reports:read", "admin"])
    
  # Requires both JWT and project authentication
  secureUserData: SecureData 
    @combinedAuth(scopes: ["data:read"])
}

extend type Mutation {
  # JWT user authentication for user actions
  updateProfile(input: UpdateProfileInput!): User 
    @jwtAuth(scopes: ["profile:write"])
  
  # Project auth for content management
  createPost(input: CreatePostInput!): Post 
    @projectAuth
  
  # Project auth with write permissions
  updatePost(id: ID!, input: UpdatePostInput!): Post 
    @projectAuth(scopes: ["posts:write"])
  
  # Admin-only operations requiring elevated privileges
  deletePost(id: ID!): Boolean 
    @projectAuth(scopes: ["posts:delete", "admin"])
  
  # Service-only operations for API key management
  createAPIKey(input: CreateAPIKeyInput!): APIKey 
    @serviceAuth(scopes: ["keys:create"])
  
  # Service-to-service bulk operations
  bulkImportData(input: BulkImportInput!): ImportResult
    @serviceAuth(scopes: ["data:import", "bulk:operations"])
  
  # Combined auth for user management
  updateUser(id: ID!, input: UpdateUserInput!): User 
    @combinedAuth(scopes: ["users:write"])
    
  # Dangerous operations requiring multiple scopes
  purgeUserData(userId: ID!): Boolean 
    @combinedAuth
    @scopes(requires: ["users:delete", "data:purge", "admin", "compliance"])
}
```

## Request Headers

### For JWT Authentication (@jwtAuth)

```bash
# User JWT token in Authorization header
curl -X POST \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIsImtpZCI6..." \
  -H "Content-Type: application/json" \
  -d '{"query": "{ userProfile { id name email } }"}' \
  https://your-api.com/graphql
```

### For Project Authentication (@projectAuth)

```bash
# Project token in x-project-token header
curl -X POST \
  -H "x-project-token: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIs..." \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { createPost(input: { title: \"New Post\" }) { id } }"}' \
  https://your-api.com/graphql
```

### For Combined Authentication (@combinedAuth)

```bash
# Both JWT and project tokens required
curl -X POST \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIs..." \
  -H "x-project-token: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIs..." \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { updateUser(id: \"123\", input: { name: \"Updated\" }) { id } }"}' \
  https://your-api.com/graphql
```

## Scope Validation

### JWT User Scopes (@jwtAuth)
- Validates against `permissions` array in JWT payload
- Also checks `scopes` array if present
- Example JWT payload: `{"sub": {...}, "permissions": ["profile:write", "admin"]}`

### Project Scopes (@projectAuth)
- Platform tokens: `scopes` array with platform-level permissions
- Project tokens: `scopes` array with project-specific permissions  
- Service tokens: `scopes` array parsed from space-separated string

### Service Scopes (@serviceAuth)
- **Requires service tokens ONLY** - fails if platform or project tokens are used
- Service tokens: `scopes` array with service-specific permissions
- Use for strict service-to-service authentication
- More secure than @projectAuth for service operations

### Combined Scopes (@combinedAuth)
- Merges scopes from both JWT user permissions AND project scopes
- User must have required scopes in EITHER JWT or project token
- More flexible for operations requiring both contexts

## Error Responses

### Missing Authentication

```json
{
  "errors": [
    {
      "message": "No authorization header provided",
      "extensions": {
        "category": "authentication"
      }
    }
  ]
}
```

### Insufficient Scopes/Permissions

```json
{
  "errors": [
    {
      "message": "Insufficient permissions. Required: [profile:write, admin], Missing: [admin]",
      "extensions": {
        "category": "authentication"
      }
    }
  ]
}
```

## Environment Configuration

Set these in your `.env` file:

```env
# Service identification 
SERVICE_NAME=your-service-name

# Mercury authentication service
MERCURY_BASE_URL=https://mercury.yourdomain.com
SIGNATURE_SHARED_SECRET=your_shared_secret

# Service credentials for internal API calls  
CLIENT_ID=your_service_client_id
CLIENT_SECRET=your_service_client_secret

# Redis for caching and token validation
REDIS_URL=redis://localhost:6379
```

## Directive Parameters

### All Directives Support:
- `scopes` (Array of Strings, optional): Required scopes/permissions for this operation

### @scopes Directive:
- `requires` (Array of Strings, required): Additional scopes to validate

## Authentication Context in Resolvers

```php
public function deletePost($root, array $args, $context)
{
    // JWT user data (from @jwtAuth or @combinedAuth)
    $user = request()->get('auth_user');
    // Contains: uuid, email, name, permissions, etc.
    
    // Project context (from @projectAuth or @combinedAuth)
    $project = request()->get('auth_project');
    // Contains: tenant_id, project_uuid, enabled_services, scopes, etc.
    
    $platform = request()->get('auth_platform'); 
    // Contains: tenant_id, scopes, token_id, expires_at
    
    $service = request()->get('auth_service');
    // Contains: client_id, service_name, scopes, token_id
    
    // Your mutation logic here
    return $this->postService->deletePost($args['id'], $user, $project);
}
```

## Summary

✅ **@jwtAuth** - Now supports scopes via `permissions` in JWT payload  
✅ **@projectAuth** - Supports scopes from project/platform/service tokens  
✅ **@serviceAuth** - Requires service tokens ONLY with service-specific scopes  
✅ **@combinedAuth** - Merges scopes from both JWT and project contexts  
✅ **serviceName removed** - Uses `SERVICE_NAME` environment variable  

All directives now validate scopes automatically! 🔒

## Request Headers

### For JWT Authentication (@jwtAuth)

```bash
# User JWT token in Authorization header
curl -X POST \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIsImtpZCI6..." \
  -H "Content-Type: application/json" \
  -d '{"query": "{ userProfile { id name email } }"}' \
  https://your-api.com/graphql
```

### For Project Authentication (@projectAuth)

```bash
# Project token in x-project-token header
curl -X POST \
  -H "x-project-token: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIs..." \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { createPost(input: { title: \"New Post\" }) { id } }"}' \
  https://your-api.com/graphql
```

### For Combined Authentication (@combinedAuth)

```bash
# Both JWT and project tokens required
curl -X POST \
  -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIs..." \
  -H "x-project-token: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzUxMiIs..." \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { updateUser(id: \"123\", input: { name: \"Updated\" }) { id } }"}' \
  https://your-api.com/graphql
```

## Scope Validation

The system validates scopes from the token payload:

### Platform Tokens
- Contains `scopes` array with platform-level permissions
- Example: `["platform:admin", "projects:manage"]`

### Project Tokens  
- Contains `scopes` array with project-specific permissions
- Example: `["posts:read", "posts:write", "users:read"]`

### Service Tokens
- Contains `scopes` array parsed from space-separated string
- Example: `["services:read", "internal:api"]`

## Error Responses

### Missing Authentication

```json
{
  "errors": [
    {
      "message": "Unauthorized: No token provided, required_header: 'x-project-token'",
      "extensions": {
        "category": "authentication"
      }
    }
  ]
}
```

### Insufficient Scopes

```json
{
  "errors": [
    {
      "message": "Insufficient scopes. Required: [posts:delete, admin], Missing: [admin]",
      "extensions": {
        "category": "authentication"
      }
    }
  ]
}
```

### Invalid Token

```json
{
  "errors": [
    {
      "message": "Invalid JWT token: Token has expired",
      "extensions": {
        "category": "authentication"
      }
    }
  ]
}
```

## Environment Configuration

Set these in your `.env` file:

```env
# Service identification (used when serviceName not specified in directive)
SERVICE_NAME=your-service-name

# Mercury authentication service
MERCURY_BASE_URL=https://mercury.yourdomain.com
SIGNATURE_SHARED_SECRET=your_shared_secret

# Service credentials for internal API calls  
CLIENT_ID=your_service_client_id
CLIENT_SECRET=your_service_client_secret

# Redis for caching and token validation
REDIS_URL=redis://localhost:6379
```

## Directive Parameters

### @projectAuth Parameters
- `serviceName` (String, optional): Override default service name from environment
- `scopes` (Array of Strings, optional): Required scopes for this operation

### @serviceAuth Parameters
- `scopes` (Array of Strings, optional): Required service scopes for this operation

### @combinedAuth Parameters  
- `serviceName` (String, optional): Override default service name from environment
- `scopes` (Array of Strings, optional): Required scopes for this operation

### @scopes Parameters
- `requires` (Array of Strings, required): Additional scopes to validate

## Best Practices

1. **Use environment variables for service names** to avoid hardcoding in schema
2. **Define granular scopes** like `posts:read`, `posts:write`, `posts:delete` 
3. **Use @combinedAuth for user-specific operations** that also need project context
4. **Stack @scopes directive** for operations requiring multiple permission levels
5. **Handle authentication errors gracefully** in your frontend applications