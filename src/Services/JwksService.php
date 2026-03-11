<?php

namespace Wazobia\LaravelAuthGuard\Services;

use Wazobia\LaravelAuthGuard\Utils\RedisConnectionManager;
use Illuminate\Support\Facades\Log;
use Wazobia\LaravelAuthGuard\Exceptions\JwtAuthenticationException;

/**
 * JWKS Service matching Node.js implementation with Redis caching
 */
class JwksService
{
    private string $mercuryBaseUrl;
    private string $sharedSecret;
    private int $jwksCacheTTL = 18000; // 5 hours

    public function __construct()
    {
        $this->mercuryBaseUrl = config('auth-guard.mercury.base_url', env('MERCURY_BASE_URL', 'http://localhost:4000'));
        $this->sharedSecret = config('auth-guard.signature_shared_secret', env('SIGNATURE_SHARED_SECRET', ''));
        $this->jwksCacheTTL = config('auth-guard.cache.jwks_ttl', 18000);
    }

    /**
     * Get public key for JWT verification with auto-refresh on key miss
     */
    public function getPublicKey(string $token, ?string $tenantId = null): string
    {
        $header = $this->decodeJwtHeader($token);
        if (!isset($header['kid'])) {
            throw new JwtAuthenticationException('Missing key ID (kid) in token header');
        }

        $payload = $this->decodeJwtPayload($token);
        
        // Determine cache key and JWKS path based on token type
        if (isset($payload['type'])) {
            if ($payload['type'] === 'service') {
                $cacheKey = 'service_jwks_cache';
                $jwksPath = 'auth/service/.well-known/jwks.json';
                Log::info('Service token detected, using service JWKS endpoint');
            } else {
                // Platform/Project tokens - per-tenant cache
                $tenantId = $payload['tenant_id'] ?? $tenantId;
                $cacheKey = "jwks_cache:{$tenantId}";
                $jwksPath = "auth/projects/{$tenantId}/.well-known/jwks.json";
                Log::info("{$payload['type']} token detected", ['tenant_id' => $tenantId]);
            }
        } else {
            // Check for user tokens by issuer and type
            if (isset($payload['iss_type']) && $payload['iss_type'] === 'user') {
                // User tokens might use "muse" as a pseudo-tenant-id based on audience
                $audienceTenantId = $payload['aud'] ?? 'muse';
                $cacheKey = "jwks_cache:{$audienceTenantId}";
                $jwksPath = "auth/projects/{$audienceTenantId}/.well-known/jwks.json";
                Log::info('User token detected, using audience as tenant', [
                    'iss_type' => $payload['iss_type'],
                    'sub' => $payload['sub'] ?? 'no-sub',
                    'audience_tenant' => $audienceTenantId
                ]);
            } else {
                // Legacy project tokens 
                $tenantId = $payload['tenant_id'] ?? $payload['project_uuid'] ?? $tenantId;
                $cacheKey = "jwks_cache:{$tenantId}";
                $jwksPath = "auth/projects/{$tenantId}/.well-known/jwks.json";
                Log::info('Legacy project token detected', ['tenant_id' => $tenantId]);
            }
        }

        // Check Redis for cached JWKS
        $redis = RedisConnectionManager::getInstance();
        $cachedJwks = null;
        
        if ($redis) {
            $cachedJwks = $redis->get($cacheKey);
        } else {
            Log::debug('Redis not available, skipping JWKS cache lookup');
        }

        if ($cachedJwks) {
            Log::info('Using cached JWKS from Redis');
            $jwksData = json_decode($cachedJwks, true);
            
            // Try to find the key
            $publicKey = $this->findKeyInJwks($jwksData, $header['kid']);
            if ($publicKey) {
                return $publicKey;
            }
            
            // Key not found in cache, fetch fresh JWKS
            Log::info("Key {$header['kid']} not found in cache, fetching fresh JWKS");
        } else {
            Log::info('No cached JWKS found, fetching from Mercury');
        }

        // Fetch and cache fresh JWKS
        $jwksData = $this->fetchAndCacheJWKS($jwksPath, $cacheKey);
        
        $publicKey = $this->findKeyInJwks($jwksData, $header['kid']);
        if (!$publicKey) {
            throw new JwtAuthenticationException("Key {$header['kid']} not found even after JWKS refresh");
        }
        
        return $publicKey;
    }

    /**
     * Find key in JWKS and convert to PEM
     */
    private function findKeyInJwks(array $jwksData, string $kid): ?string
    {
        $keys = $jwksData['keys'] ?? [];
        if (!is_array($keys)) {
            $keys = [$keys];
        }
        
        foreach ($keys as $key) {
            if (($key['kid'] ?? '') === $kid) {
                return $this->jwkToPem($key);
            }
        }
        
        return null;
    }

    /**
     * Fetch JWKS from Mercury and cache in Redis
     */
    private function fetchAndCacheJWKS(string $path, string $cacheKey): array
    {
        try {
            $jwksUri = "{$this->mercuryBaseUrl}/{$path}";
            $timestamp = (string)(time() * 1000); // Match Node.js timestamp format
            $signatureInput = 'GET' . "/{$path}" . $timestamp;
            
            $signature = hash_hmac('sha256', $signatureInput, $this->sharedSecret);

            Log::info("Fetching JWKS from {$jwksUri}");

            $timeout = config('auth-guard.mercury_timeout', 10);
            
            // Use curl instead of Http facade to avoid dependency issues
            $context = stream_context_create([
                'http' => [
                    'method' => 'GET',
                    'header' => [
                        'Accept: application/json',
                        'User-Agent: Mercury-Auth-SDK/2.0',
                        "X-Timestamp: {$timestamp}",
                        "X-Signature: {$signature}"
                    ],
                    'timeout' => $timeout,
                    'ignore_errors' => true
                ]
            ]);

            $responseBody = file_get_contents($jwksUri, false, $context);
            
            if ($responseBody === false) {
                $error = error_get_last();
                throw new JwtAuthenticationException(
                    "JWKS endpoint request failed: " . ($error['message'] ?? 'Unknown error')
                );
            }

            $data = json_decode($responseBody, true);
            if (!$data) {
                throw new JwtAuthenticationException('Invalid JSON response from JWKS endpoint');
            }
            if (!isset($data['keys'])) {
                throw new JwtAuthenticationException('Invalid JWKS response: missing keys');
            }

            // Ensure keys is array
            if (!is_array($data['keys'])) {
                $data['keys'] = [$data['keys']];
            }

            // Cache JWKS in Redis
            $redis = RedisConnectionManager::getInstance();
            if ($redis) {
                $redis->setex($cacheKey, $this->jwksCacheTTL, json_encode($data));
                Log::info("JWKS cached successfully", ['cache_key' => $cacheKey]);
            } else {
                Log::debug('Redis not available, skipping JWKS caching');
            }

            return $data;
        } catch (\Exception $error) {
            if ($error instanceof JwtAuthenticationException) {
                throw $error;
            }
            
            throw new JwtAuthenticationException("Failed to fetch JWKS: {$error->getMessage()}");
        }
    }

    /**
     * Decode JWT header to extract kid
     */
    private function decodeJwtHeader(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new JwtAuthenticationException('Invalid JWT format');
        }

        $headerJson = base64_decode($parts[0]);
        return json_decode($headerJson, true) ?: [];
    }

    /**
     * Decode JWT payload (without verification)
     */
    private function decodeJwtPayload(string $token): array
    {
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new JwtAuthenticationException('Invalid JWT format');
        }

        $payloadJson = base64_decode($parts[1]);
        return json_decode($payloadJson, true) ?: [];
    }

    /**
     * Convert JWK to PEM format
     */
    private function jwkToPem(array $jwk): string
    {
        if (($jwk['kty'] ?? '') !== 'RSA') {
            throw new JwtAuthenticationException('Unsupported key type: ' . ($jwk['kty'] ?? 'unknown'));
        }

        $n = $this->base64UrlDecode($jwk['n'] ?? '');
        $e = $this->base64UrlDecode($jwk['e'] ?? '');

        $rsa = \phpseclib3\Crypt\RSA::loadPublicKey([
            'n' => new \phpseclib3\Math\BigInteger($n, 256),
            'e' => new \phpseclib3\Math\BigInteger($e, 256),
        ]);

        return $rsa->toString('PKCS8');
    }

    /**
     * Base64 URL decode helper
     */
    private function base64UrlDecode(string $data): string
    {
        $remainder = strlen($data) % 4;
        if ($remainder) {
            $data .= str_repeat('=', 4 - $remainder);
        }
        return base64_decode(strtr($data, '-_', '+/'));
    }
}