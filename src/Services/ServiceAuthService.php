<?php

namespace Wazobia\LaravelAuthGuard\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Wazobia\LaravelAuthGuard\Exceptions\ServiceAuthenticationException;
use Wazobia\LaravelAuthGuard\Utils\RedisConnectionManager;

/**
 * Service authentication functions matching Node.js implementation
 */
class ServiceAuthService
{
    private string $mercuryBaseUrl;
    private string $clientId;
    private string $clientSecret;
    private int $tokenCacheTTL;
    private int $serviceCacheTTL;

    public function __construct()
    {
        $this->mercuryBaseUrl = config('auth-guard.mercury_base_url', env('MERCURY_BASE_URL', 'http://localhost:4000'));
        $this->clientId = config('auth-guard.client_id', env('CLIENT_ID', ''));
        $this->clientSecret = config('auth-guard.client_secret', env('CLIENT_SECRET', ''));
        
        // Load configurable cache TTL values
        $this->tokenCacheTTL = config('auth-guard.cache.service_token_ttl', 3300);
        $this->serviceCacheTTL = config('auth-guard.cache.service_uuid_ttl', 86400);
        
        if (!$this->clientId) {
            throw new ServiceAuthenticationException("Missing required configuration: CLIENT_ID");
        }
        if (!$this->clientSecret) {
            throw new ServiceAuthenticationException("Missing required configuration: CLIENT_SECRET");
        }
        if (!$this->mercuryBaseUrl) {
            throw new ServiceAuthenticationException("Missing required configuration: MERCURY_BASE_URL");
        }
    }

    /**
     * Generates a service token using the provided client credentials.
     * Uses Redis cache to avoid repeated API calls during load testing.
     * @return string The generated service token
     */
    public function generateToken(): string
    {
        $cacheKey = "service_token:{$this->clientId}";
        
        // Check Redis cache first
        $redis = RedisConnectionManager::getInstance();
        if ($redis) {
            $cachedToken = $redis->get($cacheKey);
            if ($cachedToken) {
                Log::debug('Using cached service token');
                return $cachedToken;
            }
        }
        
        Log::debug('Generating new service token from Mercury');
        
        $mutation = '
            mutation GenerateServiceToken($input: ServiceTokenInput!) {
                generateServiceToken(input: $input) {
                    access_token
                    token_type
                    expires_in
                    scope
                }
            }
        ';

        $variables = [
            'input' => [
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'scope' => 'services:read'
            ]
        ];

        $timeout = config('auth-guard.mercury_timeout', 10);
        $connectTimeout = config('auth-guard.mercury_connect_timeout', 5);
        
        $response = Http::timeout($timeout)
            ->connectTimeout($connectTimeout)
            ->withOptions([
                'pool' => true,
                'http_errors' => false,
            ])
            ->retry(
                config('auth-guard.mercury_retry_attempts', 3),
                config('auth-guard.mercury_retry_delay', 1000),
                function ($exception) {
                    return $exception instanceof \Illuminate\Http\Client\ConnectionException;
                }
            )
            ->post("{$this->mercuryBaseUrl}/graphql", [
                'query' => $mutation,
                'variables' => $variables
            ]);

        if (!$response->successful()) {
            Log::error("Error generating service token", ['status' => $response->status(), 'body' => $response->body()]);
            throw new ServiceAuthenticationException("Failed to generate service token");
        }

        $data = $response->json();
        
        if (isset($data['errors'])) {
            Log::error("GraphQL error generating service token", ['errors' => $data['errors']]);
            throw new ServiceAuthenticationException("Failed to generate service token");
        }

        if (!isset($data['data']['generateServiceToken']['access_token'])) {
            throw new ServiceAuthenticationException("No access token returned from generateServiceToken");
        }

        $accessToken = $data['data']['generateServiceToken']['access_token'];
        
        // Cache the token in Redis
        if ($redis) {
            $redis->setex($cacheKey, $this->tokenCacheTTL, $accessToken);
            Log::debug('Service token cached successfully', ['cache_key' => $cacheKey]);
        }

        return $accessToken;
    }

    /**
     * Fetches the service UUID from Mercury using the provided access token.
     * Uses Redis cache to avoid repeated lookups during load testing.
     * @param string $accessToken The access token to authenticate the request
     * @return string The UUID of the registered service
     */
    public function getServiceById(string $accessToken): string
    {
        $cacheKey = "service_uuid:{$this->clientId}";
        
        // Check Redis cache first
        $redis = RedisConnectionManager::getInstance();
        if ($redis) {
            $cachedUuid = $redis->get($cacheKey);
            if ($cachedUuid) {
                Log::debug('Using cached service UUID');
                return $cachedUuid;
            }
        }
        
        Log::debug('Fetching service UUID from Mercury');
        
        $mutation = '
            mutation GetRegisteredServiceByClientId($input: GetRegisteredServiceByClientIdInput!) {
                getRegisteredServiceByClientId(input: $input) {
                    uuid
                    is_active
                }
            }
        ';

        $variables = [
            'input' => [
                'client_id' => $this->clientId
            ]
        ];

        $timeout = config('auth-guard.mercury_timeout', 10);
        $connectTimeout = config('auth-guard.mercury_connect_timeout', 5);
        
        $response = Http::timeout($timeout)
            ->connectTimeout($connectTimeout)
            ->withHeaders([
                'x-project-token' => "Bearer {$accessToken}",
            ])
            ->withOptions([
                'pool' => true,
                'http_errors' => false,
            ])
            ->retry(
                config('auth-guard.mercury_retry_attempts', 3),
                config('auth-guard.mercury_retry_delay', 1000),
                function ($exception) {
                    return $exception instanceof \Illuminate\Http\Client\ConnectionException;
                }
            )
            ->post("{$this->mercuryBaseUrl}/graphql", [
                'query' => $mutation,
                'variables' => $variables
            ]);

        if (!$response->successful()) {
            Log::error("Error fetching service by ID", ['status' => $response->status(), 'body' => $response->body()]);
            throw new ServiceAuthenticationException("Failed to fetch service by ID");
        }

        $data = $response->json();
        
        if (isset($data['errors'])) {
            Log::error("GraphQL error fetching service by ID", ['errors' => $data['errors']]);
            throw new ServiceAuthenticationException("Failed to fetch service by ID");
        }

        if (!isset($data['data']['getRegisteredServiceByClientId']['uuid'])) {
            throw new ServiceAuthenticationException("No service UUID returned from getRegisteredServiceByClientId");
        }

        $serviceUuid = $data['data']['getRegisteredServiceByClientId']['uuid'];
        
        // Cache the service UUID in Redis (longer TTL since it rarely changes)
        if ($redis) {
            $redis->setex($cacheKey, $this->serviceCacheTTL, $serviceUuid);
            Log::debug('Service UUID cached successfully', ['cache_key' => $cacheKey]);
        }

        return $serviceUuid;
    }

    /**
     * Clear cached service authentication data
     * Useful for debugging or deployment cache invalidation
     */
    public function clearCache(): void
    {
        $redis = RedisConnectionManager::getInstance();
        if ($redis) {
            $tokenKey = "service_token:{$this->clientId}";
            $uuidKey = "service_uuid:{$this->clientId}";
            
            $redis->del($tokenKey);
            $redis->del($uuidKey);
            
            Log::info('Service authentication cache cleared', [
                'keys_cleared' => [$tokenKey, $uuidKey]
            ]);
        }
    }
}