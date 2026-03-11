<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Mercury Base URL
    |--------------------------------------------------------------------------
    |
    | The base URL for the Mercury authentication service for JWKS and
    | service authentication endpoints.
    |
    */
    'mercury_base_url' => env('MERCURY_BASE_URL', 'https://mercury.example.com'),

    /*
    |--------------------------------------------------------------------------
    | Mercury Authentication Configuration
    |--------------------------------------------------------------------------
    |
    | Configuration for JWKS signature-based authentication with Mercury.
    |
    */
    'signature_shared_secret' => env('SIGNATURE_SHARED_SECRET', ''),
    'signature_algorithm' => env('SIGNATURE_ALGORITHM', 'sha256'),
    'mercury_timeout' => env('MERCURY_TIMEOUT', 10),
    'mercury_connect_timeout' => env('MERCURY_CONNECT_TIMEOUT', 5),
    'mercury_retry_attempts' => env('MERCURY_RETRY_ATTEMPTS', 3),
    'mercury_retry_delay' => env('MERCURY_RETRY_DELAY', 1000), // milliseconds
    'mercury_pool_size' => env('MERCURY_POOL_SIZE', 50),
    
    /*
    |--------------------------------------------------------------------------
    | Circuit Breaker Configuration
    |--------------------------------------------------------------------------
    |
    | Configuration for circuit breaker pattern to prevent cascading failures
    | during high load or Mercury service issues.
    |
    */
    'circuit_breaker' => [
        'failure_threshold' => env('MERCURY_CIRCUIT_BREAKER_THRESHOLD', 5),
        'reset_timeout' => env('MERCURY_CIRCUIT_BREAKER_RESET', 60),
        'half_open_max_calls' => env('MERCURY_CIRCUIT_BREAKER_HALF_OPEN', 3),
    ],

    /*
    |--------------------------------------------------------------------------
    | Service Authentication
    |--------------------------------------------------------------------------
    |
    | Client credentials for service-to-service authentication with Mercury.
    | These are used to generate service tokens and get service UUIDs.
    |
    */
    'client_id' => env('CLIENT_ID', ''),
    'client_secret' => env('CLIENT_SECRET', ''),

    /*
    |--------------------------------------------------------------------------
    | JWT Configuration
    |--------------------------------------------------------------------------
    |
    | JWT algorithm and validation settings.
    |
    */
    'jwt_algorithm' => env('JWT_ALGORITHM', 'RS512'),
    'jwt_leeway' => env('JWT_LEEWAY', 0),

    /*
    |--------------------------------------------------------------------------
    | Redis Configuration
    |--------------------------------------------------------------------------
    |
    | Redis connection settings for authentication database and caching.
    |
    */
    'redis' => [
        'auth_url' => env('REDIS_AUTH_URL', env('REDIS_URL', 'redis://localhost:6379/5')),
        'client' => env('REDIS_CLIENT', 'predis'),
        'host' => env('REDIS_HOST', '127.0.0.1'),
        'port' => env('REDIS_PORT', '6379'),
        'password' => env('REDIS_PASSWORD', null),
        'database' => env('REDIS_DB', '0'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Cache Configuration
    |--------------------------------------------------------------------------
    |
    | Settings for JWKS and token caching.
    |
    */
    'cache' => [
        'expiry_time' => env('AUTH_CACHE_TTL', env('CACHE_EXPIRY_TIME', 900)),
        'prefix' => env('AUTH_CACHE_PREFIX', 'auth_guard'),
        'driver' => env('AUTH_CACHE_DRIVER', 'redis'),
        'jwks_ttl' => 18000, // 5 hours for JWKS cache
        'service_token_ttl' => env('SERVICE_TOKEN_CACHE_TTL', 3300), // 55 minutes
        'service_uuid_ttl' => env('SERVICE_UUID_CACHE_TTL', 86400), // 24 hours
    ],

    /*
    |--------------------------------------------------------------------------
    | Custom Headers
    |--------------------------------------------------------------------------
    |
    | Custom header names for authentication tokens.
    |
    */
    'headers' => [
        'jwt' => env('AUTH_JWT_HEADER', 'Authorization'),
        'project_token' => env('AUTH_PROJECT_TOKEN_HEADER', 'x-project-token'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging Configuration
    |--------------------------------------------------------------------------
    |
    | Enable/disable logging and configure log channel.
    |
    */
    'logging' => [
        'enabled' => env('AUTH_GUARD_LOGGING', true),
        'channel' => env('AUTH_GUARD_LOG_CHANNEL', 'stack'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Security Configuration
    |--------------------------------------------------------------------------
    |
    | Various security-related settings.
    |
    */
    'security' => [
        'ssl_verify' => env('AUTH_GUARD_SSL_VERIFY', true),
        'max_token_age' => env('MAX_TOKEN_AGE', 86400), // 24 hours
        'rate_limit' => env('AUTH_RATE_LIMIT', 100), // requests per minute
    ],
];