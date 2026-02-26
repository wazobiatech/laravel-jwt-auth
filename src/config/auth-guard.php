<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Mercury Service Configuration
    |--------------------------------------------------------------------------
    |
    | Configuration for JWT validation and JWKS endpoints
    |
    */
    'mercury' => [
        'base_url' => env('MERCURY_BASE_URL', 'http://localhost:4000'),
        'timeout' => env('MERCURY_TIMEOUT', 10),
    ],

    /*
    |--------------------------------------------------------------------------
    | Service Authentication Configuration
    |--------------------------------------------------------------------------
    |
    | Configuration for service-to-service authentication
    |
    */
    'service' => [
        'client_id' => env('CLIENT_ID', ''),
        'client_secret' => env('CLIENT_SECRET', ''),
        'name' => env('SERVICE_NAME', 'muse'),
        'default_scope' => env('SERVICE_DEFAULT_SCOPE', 'services:read'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Redis Connection Configuration
    |--------------------------------------------------------------------------
    |
    | Redis connections used for caching and token storage
    |
    */
    'redis' => [
        'connection' => env('REDIS_AUTH_CONNECTION', 'auth'),
        'cache_connection' => env('REDIS_CACHE_CONNECTION', 'cache'),
        'prefix' => env('REDIS_AUTH_PREFIX', ''),
        'database' => env('REDIS_AUTH_DB', 0),
    ],

    /*
    |--------------------------------------------------------------------------
    | JWKS Configuration
    |--------------------------------------------------------------------------
    |
    | JSON Web Key Set configuration for JWT validation
    |
    */
    'jwks' => [
        'cache_ttl' => env('JWKS_CACHE_TTL', 3600), // 1 hour
        'cache_prefix' => env('JWKS_CACHE_PREFIX', 'jwks_cache'),
        'service_endpoint' => env('JWKS_SERVICE_ENDPOINT', '/.well-known/jwks.json'),
        'user_endpoint_pattern' => env('JWKS_USER_ENDPOINT_PATTERN', '/auth/projects/{tenant_id}/.well-known/jwks.json'),
        'retry_attempts' => env('JWKS_RETRY_ATTEMPTS', 3),
    ],

    /*
    |--------------------------------------------------------------------------
    | Signature Configuration
    |--------------------------------------------------------------------------
    |
    | Shared secret for HMAC signature validation
    |
    */
    'signature' => [
        'shared_secret' => env('SIGNATURE_SHARED_SECRET', ''),
        'algorithm' => env('SIGNATURE_ALGORITHM', 'sha256'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Cache Configuration
    |--------------------------------------------------------------------------
    |
    | Cache settings for tokens and JWKS
    |
    */
    'cache' => [
        'ttl' => env('AUTH_CACHE_TTL', 900), // 15 minutes
        'prefix' => env('AUTH_CACHE_PREFIX', 'auth_guard'),
        'driver' => env('AUTH_CACHE_DRIVER', 'redis'),
    ],

    /*
    |--------------------------------------------------------------------------
    | JWT Configuration
    |--------------------------------------------------------------------------
    |
    | JWT specific settings
    |
    */
    'jwt' => [
        'algorithm' => env('JWT_ALGORITHM', 'RS512'),
        'leeway' => env('JWT_LEEWAY', 0),
        'required_claims' => ['iss', 'sub', 'exp'],
        'verify_signature' => env('JWT_VERIFY_SIGNATURE', true),
        'verify_issuer' => env('JWT_VERIFY_ISSUER', true),
        'verify_audience' => env('JWT_VERIFY_AUDIENCE', false),
    ],

    /*
    |--------------------------------------------------------------------------
    | Token Configuration
    |--------------------------------------------------------------------------
    |
    | Token expiration and validation settings
    |
    */
    'tokens' => [
        'revocation_ttl' => env('TOKEN_REVOCATION_TTL', 86400), // 24 hours
        'grace_period' => env('TOKEN_GRACE_PERIOD', 30), // 30 seconds
        'max_age' => env('TOKEN_MAX_AGE', 3600), // 1 hour
    ],

    /*
    |--------------------------------------------------------------------------
    | Scope Configuration
    |--------------------------------------------------------------------------
    |
    | Default scopes and scope validation settings
    |
    */
    'scopes' => [
        'delimiter' => env('SCOPE_DELIMITER', ':'),
        'case_sensitive' => env('SCOPE_CASE_SENSITIVE', true),
        'inheritance' => env('SCOPE_INHERITANCE', true),
        'default_user_scopes' => ['users:read'],
        'default_service_scopes' => ['services:read'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging Configuration
    |--------------------------------------------------------------------------
    |
    | Enable/disable debug logging
    |
    */
    'logging' => [
        'enabled' => env('AUTH_GUARD_LOGGING', true),
        'channel' => env('AUTH_GUARD_LOG_CHANNEL', 'stack'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Headers Configuration
    |--------------------------------------------------------------------------
    |
    | Custom header names for authentication
    |
    */
    'headers' => [
        'jwt' => env('AUTH_JWT_HEADER', 'Authorization'),
        'project_token' => env('AUTH_PROJECT_TOKEN_HEADER', 'x-project-token'),
        'service_token' => env('AUTH_SERVICE_TOKEN_HEADER', 'x-project-token'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Error Handling Configuration
    |--------------------------------------------------------------------------
    |
    | Error response and debugging settings
    |
    */
    'errors' => [
        'include_trace' => env('AUTH_INCLUDE_TRACE', false),
        'log_failures' => env('AUTH_LOG_FAILURES', true),
        'detailed_messages' => env('AUTH_DETAILED_MESSAGES', true),
        'hide_sensitive_data' => env('AUTH_HIDE_SENSITIVE_DATA', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Configuration
    |--------------------------------------------------------------------------
    |
    | Security-related settings
    |
    */
    'security' => [
        'rate_limit' => [
            'enabled' => env('AUTH_RATE_LIMIT_ENABLED', false),
            'requests_per_minute' => env('AUTH_RATE_LIMIT_RPM', 60),
            'cache_prefix' => env('AUTH_RATE_LIMIT_PREFIX', 'auth_rate_limit'),
        ],
        'user_context' => [
            'model_class' => env('AUTH_USER_MODEL_CLASS', 'Wazobia\LaravelAuthGuard\Models\GenericUser'),
            'inject_permissions' => env('AUTH_INJECT_PERMISSIONS', true),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Environment Configuration
    |--------------------------------------------------------------------------
    |
    | Environment-specific settings
    |
    */
    'environment' => [
        'development' => env('APP_ENV', 'production') !== 'production',
        'testing' => env('APP_ENV') === 'testing',
        'debug_mode' => env('AUTH_DEBUG_MODE', false),
    ],
];