<?php

namespace Wazobia\LaravelAuthGuard\Services;

use Wazobia\LaravelAuthGuard\Exceptions\JwtAuthenticationException;
use Wazobia\LaravelAuthGuard\Contracts\JwtAuthenticatable;
use Wazobia\LaravelAuthGuard\Utils\RedisConnectionManager;
use Wazobia\LaravelAuthGuard\Types\AuthUser;
use Illuminate\Support\Facades\Log;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * JWT Authentication Service matching Node.js implementation
 */
class JwtAuthService implements JwtAuthenticatable
{
    private JwksService $jwksService;
    private string $expectedIssuer;

    public function __construct()
    {
        $this->jwksService = new JwksService();
        $domain = env('MERCURY_BASE_URL', 'http://localhost:4000');
        $this->expectedIssuer = $domain;
    }

    /**
     * Authenticate JWT token matching Node.js implementation
     */
    public function authenticate(array &$request): void
    {
        Log::error('[JwtAuthService] Starting JWT authentication', [
            'request_structure' => array_keys($request),
            'headers_present' => isset($request['headers']),
            'authorization_present' => isset($request['headers']['authorization']),
        ]);
        
        $authHeader = $request['headers']['authorization'] ?? null;
        if (!$authHeader) {
            Log::error('[JwtAuthService] No authorization header provided');
            throw new JwtAuthenticationException('No authorization header provided');
        }

        $token = str_starts_with($authHeader, 'Bearer ')
            ? substr($authHeader, 7) 
            : $authHeader;

        if (!$token) {
            Log::error('[JwtAuthService] No token provided after processing header', [
                'auth_header' => $authHeader,
                'processed_token' => $token,
            ]);
            throw new JwtAuthenticationException('No token provided');
        }
        
        Log::error('[JwtAuthService] Processing JWT token', [
            'token_length' => strlen($token),
            'token_starts_with' => substr($token, 0, 20) . '...',
        ]);

        try {
            // Get signing key from JWKS
            $publicKey = $this->getSigningKey($token);
            
            Log::error('[JwtAuthService] Got signing key from JWKS', [
                'public_key_type' => gettype($publicKey),
                'public_key_length' => is_string($publicKey) ? strlen($publicKey) : 'not_string',
            ]);
            
            // Validate token  
            $user = $this->validate($token, $publicKey);
            
            Log::error('[JwtAuthService] Token validation completed', [
                'user_type' => gettype($user),
                'user_data' => $user,
                'user_keys' => is_array($user) ? array_keys($user) : 'not_array',
            ]);
            
            // Set user data in request array
            $userData = [
                'uuid' => $user['uuid'] ?? 'missing_uuid',
                'email' => $user['email'] ?? 'missing_email', 
                'name' => $user['name'] ?? 'missing_name',
                'tenant_id' => $user['tenant_id'] ?? 'missing_tenant_id',
                'permissions' => $user['permissions'] ?? [],
                'token_id' => $user['token_id'] ?? 'missing_token_id'
            ];
            
            Log::error('[JwtAuthService] Setting user data in request', [
                'user_data_to_set' => $userData,
                'request_before_user_set' => array_keys($request),
            ]);
            
            $request['user'] = $userData;
            
            Log::error('[JwtAuthService] User data set in request successfully', [
                'request_after_user_set' => array_keys($request),
                'user_data_in_request' => $request['user'],
            ]);
        } catch (\Exception $error) {
            throw new JwtAuthenticationException("Invalid JWT token: {$error->getMessage()}");
        }
    }

    /**
     * Decode JWT token to extract tenant ID
     */
    private function decodeJWTTokenForTenantId(string $rawJwtToken): ?string
    {
        try {
            $parts = explode('.', $rawJwtToken);
            if (count($parts) !== 3) {
                return null;
            }

            $decoded = json_decode(base64_decode($parts[1]), true);
            if (!$decoded) {
                return null;
            }

            return $decoded['tenant_id'] ?? null;
        } catch (\Exception $error) {
            return null;
        }
    }

    /**
     * Get signing key from JWKS
     */
    private function getSigningKey(string $rawJwtToken): string
    {
        try {
            $tenantId = $this->decodeJWTTokenForTenantId($rawJwtToken);
            return $this->jwksService->getPublicKey($rawJwtToken, $tenantId);
        } catch (\Exception $error) {
            throw new JwtAuthenticationException("Unable to get signing key: {$error->getMessage()}");
        }
    }

    /**
     * Create token cache key
     */
    private function createTokenCacheKey(string $rawToken): string
    {
        $tokenHash = substr(hash('sha256', $rawToken), 0, 32);
        return "validated_token:{$tokenHash}";
    }

    /**
     * Cache validated token in Redis
     */
    private function cacheValidatedToken($payload, string $rawToken): void
    {
        try {
            $redis = RedisConnectionManager::getInstance();
            
            // Skip caching if Redis is not available
            if (!$redis) {
                Log::debug('Skipping token caching - Redis not available');
                return;
            }
            
            $cacheExpiryTime = (int)(env('CACHE_EXPIRY_TIME', '3600'));

            $cacheKey = $this->createTokenCacheKey($rawToken);
            $payloadString = json_encode($payload);

            $redis->setex($cacheKey, $cacheExpiryTime, $payloadString);
            Log::debug('Token cached successfully', ['key' => $cacheKey]);
        } catch (\Exception $error) {
            Log::warning('Failed to cache token', ['error' => $error->getMessage()]);
        }
    }

    /**
     * Get cached token from Redis  
     */
    private function getCachedToken(string $rawToken): ?array
    {
        try {
            $redis = RedisConnectionManager::getInstance();
            
            // Skip cache lookup if Redis is not available
            if (!$redis) {
                Log::debug('Skipping cache lookup - Redis not available');
                return null;
            }
            
            $cacheKey = $this->createTokenCacheKey($rawToken);
            $cachedPayload = $redis->get($cacheKey);

            if ($cachedPayload && is_string($cachedPayload)) {
                $payload = json_decode($cachedPayload, true);
                
                // Validate cached payload structure
                if (!isset($payload['sub']['uuid']) || !isset($payload['sub']['email'])) {
                    $redis->del($cacheKey);
                    return null;
                }

                $now = time();
                if (isset($payload['exp']) && $payload['exp'] < $now) {
                    $redis->del($cacheKey);
                    return null;
                }

                return $payload;
            }

            return null;
        } catch (\Exception $error) {
            try {
                $cacheKey = $this->createTokenCacheKey($rawToken);
                $redis = RedisConnectionManager::getInstance();
                $redis->del($cacheKey);
            } catch (\Exception $cleanupError) {
                Log::error('[JWT-DEBUG] Failed to cleanup corrupted cache entry', 
                    ['error' => $cleanupError->getMessage()]);
            }
            return null;
        }
    }

    /**
     * Validate JWT token
     */
    private function validate(string $rawToken, string $publicKey): array
    {
        Log::error('[JwtAuthService] Starting token validation', [
            'raw_token_length' => strlen($rawToken),
            'public_key_length' => strlen($publicKey),
            'public_key_preview' => substr($publicKey, 0, 100) . '...',
        ]);
        
        // Check cache first
        $cachedPayload = $this->getCachedToken($rawToken);
        if ($cachedPayload) {
            Log::error('[JwtAuthService] Using cached token payload', [
                'cached_payload' => $cachedPayload,
                'cached_payload_keys' => array_keys($cachedPayload),
            ]);
            
            $userData = [
                'uuid' => $cachedPayload['sub']['uuid'],
                'email' => $cachedPayload['sub']['email'],
                'name' => $cachedPayload['sub']['name'],
                'tenant_id' => $cachedPayload['tenant_id'] ?? $cachedPayload['project_uuid'] ?? null,
                'permissions' => $cachedPayload['permissions'] ?? [],
                'token_id' => $cachedPayload['jti'] ?? ''
            ];
            
            Log::error('[JwtAuthService] Returning cached user data', [
                'user_data' => $userData,
            ]);
            
            return $userData;
        }

        try {
            Log::error('[JwtAuthService] Decoding JWT token with public key');
            
            // Verify the token using the public key
            $verified = JWT::decode($rawToken, new Key($publicKey, 'RS512'));
            
            Log::error('[JwtAuthService] JWT decode successful', [
                'verified_type' => gettype($verified),
                'verified_object' => is_object($verified) ? get_object_vars($verified) : $verified,
            ]);
            
            if (!is_object($verified)) {
                throw new JwtAuthenticationException('Invalid JWT payload');
            }

            $payload = json_decode(json_encode($verified), true);
            
            Log::error('[JwtAuthService] JWT payload extracted', [
                'payload' => $payload,
                'payload_keys' => array_keys($payload),
                'sub_data' => $payload['sub'] ?? 'NO_SUB_DATA',
            ]);

            // Validate the payload structure
            if (!isset($payload['sub']['uuid'])) {
                Log::error('[JwtAuthService] Invalid payload structure - missing sub.uuid', [
                    'payload_sub' => $payload['sub'] ?? 'NO_SUB',
                    'available_keys' => array_keys($payload),
                ]);
                throw new JwtAuthenticationException('Invalid JWT payload structure');
            }

            // Validate issuer
            if (($payload['iss'] ?? '') !== $this->expectedIssuer) {
                throw new JwtAuthenticationException(
                    "Invalid issuer. Expected: {$this->expectedIssuer}, Got: " . ($payload['iss'] ?? 'none')
                );
            }

            // Validate timestamps
            $now = time();
            if (isset($payload['exp']) && $payload['exp'] < $now) {
                throw new JwtAuthenticationException('Token expired');
            }

            if (isset($payload['nbf']) && $payload['nbf'] > $now) {
                throw new JwtAuthenticationException('Token not yet valid');
            }

            // Check Redis for token revocation
            if (isset($payload['jti'])) {
                try {
                    $redis = RedisConnectionManager::getInstance();
                    $revocationKey = "revoked_token:{$payload['jti']}";
                    $isRevoked = $redis->get($revocationKey);

                    if ($isRevoked) {
                        throw new JwtAuthenticationException('Token has been revoked');
                    }
                } catch (JwtAuthenticationException $e) {
                    throw $e;
                } catch (\Exception $error) {
                    throw new JwtAuthenticationException("Redis error: {$error->getMessage()}");
                }
            }

            // Cache the validated token
            $this->cacheValidatedToken($payload, $rawToken);

            $userData = [
                'uuid' => $payload['sub']['uuid'],
                'email' => $payload['sub']['email'],
                'name' => $payload['sub']['name'], 
                'tenant_id' => $payload['tenant_id'] ?? $payload['project_uuid'] ?? null,
                'permissions' => $payload['permissions'] ?? [],
                'token_id' => $payload['jti'] ?? ''
            ];
            
            Log::error('[JwtAuthService] JWT validation successful - returning user data', [
                'user_data' => $userData,
                'original_payload_keys' => array_keys($payload),
                'sub_data' => $payload['sub'],
                'permissions_found' => !empty($payload['permissions']),
                'tenant_id_source' => isset($payload['tenant_id']) ? 'tenant_id' : (isset($payload['project_uuid']) ? 'project_uuid' : 'none'),
            ]);
            
            return $userData;
        } catch (JwtAuthenticationException $e) {
            throw $e;
        } catch (\Exception $error) {
            throw new JwtAuthenticationException("Token validation failed: {$error->getMessage()}");
        }
    }

    /**
     * Revoke a token by JTI
     */
    public function revokeToken(string $jti, int $ttl = null): void
    {
        try {
            $redis = RedisConnectionManager::getInstance();
            $revocationKey = "revoked_token:{$jti}";
            
            if ($ttl) {
                $redis->setex($revocationKey, $ttl, '1');
            } else {
                $redis->set($revocationKey, '1');
            }
            
            Log::info('Token revoked', ['jti' => $jti]);
        } catch (\Exception $error) {
            Log::error('Failed to revoke token', ['jti' => $jti, 'error' => $error->getMessage()]);
            throw new JwtAuthenticationException("Failed to revoke token: {$error->getMessage()}");
        }
    }
}