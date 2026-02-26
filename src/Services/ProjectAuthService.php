<?php

namespace Wazobia\LaravelAuthGuard\Services;

use Wazobia\LaravelAuthGuard\Exceptions\ProjectAuthenticationException;
use Wazobia\LaravelAuthGuard\Contracts\ProjectAuthenticatable;
use Wazobia\LaravelAuthGuard\Utils\RedisConnectionManager;
use Illuminate\Support\Facades\Log;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * Project Authentication Service matching Node.js implementation
 * Supports platform, project, and service tokens
 */
class ProjectAuthService implements ProjectAuthenticatable
{
    private JwksService $jwksService;
    private string $serviceName;

    public function __construct(string $serviceName)
    {
        $this->jwksService = new JwksService();
        $this->serviceName = strtolower($serviceName);
    }

    /**
     * Main authentication method for platform, project and service tokens
     */
    public function authenticate(array &$request): void
    {
        try {
            \Log::info('🔍 ProjectAuth Service - Received request', [
                'request_structure' => $request,
                'headers' => $request['headers'] ?? 'NO_HEADERS'
            ]);
            
            // Extract token from x-project-token header
            $authHeader = $request['headers']['x-project-token'] ?? null;

            \Log::info('🔍 ProjectAuth Service - Token extraction', [
                'auth_header' => $authHeader,
                'is_null' => is_null($authHeader),
                'is_empty' => empty($authHeader)
            ]);

            if (!$authHeader) {
                throw new ProjectAuthenticationException("No token provided, required_header: 'x-project-token'");
            }

            // Handle Bearer prefix
            $token = str_starts_with($authHeader, 'Bearer ')
                ? substr($authHeader, 7)
                : $authHeader;

            if (!$token) {
                throw new ProjectAuthenticationException('Empty token');
            }

            // Validate token using cached JWKS
            $validation = $this->validateToken($token);

            if (!$validation['isValid']) {
                throw new ProjectAuthenticationException("Invalid token: {$validation['error']}");
            }

            $payload = $validation['payload'];

            // Route based on token type
            switch ($payload['type']) {
                case 'platform':
                    $this->injectPlatformContext($request, $payload);
                    break;
                case 'project':
                    $this->injectProjectContext($request, $payload);
                    break;
                case 'service':
                    $this->injectServiceContext($request, $payload);
                    break;
                default:
                    throw new ProjectAuthenticationException("Invalid token type: " . json_encode($payload));
            }

        } catch (ProjectAuthenticationException $e) {
            throw $e;
        } catch (\Exception $error) {
            throw new ProjectAuthenticationException("Authentication service error: {$error->getMessage()}");
        }
    }

    /**
     * Inject platform token context
     */
    private function injectPlatformContext(array &$request, array $payload): void
    {
        \Log::info('🔍 Injecting Platform Context', [
            'payload' => $payload,
            'scopes_in_payload' => $payload['scopes'] ?? 'NO_SCOPES'
        ]);
        
        $request['platform'] = [
            'tenant_id' => $payload['tenant_id'],
            'project_uuid' => $payload['tenant_id'],
            'scopes' => $payload['scopes'] ?? [],
            'token_id' => $payload['token_id'],
            'expires_at' => $payload['exp']
        ];
        
        \Log::info('🔍 Platform Context Set', [
            'request_platform' => $request['platform'],
            'scopes_set' => $request['platform']['scopes']
        ]);
    }

    /**
     * Inject project token context
     */
    private function injectProjectContext(array &$request, array $payload): void
    {
        try {
            $enabledServices = $payload['enabled_services'] ?? [];

            $this->log('info', 'Injecting project context', [
                'tenant_id' => $payload['tenant_id'],
                'token_id' => $payload['token_id'],
                'enabled_services' => $enabledServices,
            ]);

            // Generate service token using CLIENT_ID/CLIENT_SECRET
            $serviceAuth = new ServiceAuthService();
            $accessToken = $serviceAuth->generateToken();
            $this->log('info', "Access token generated", ['access_token' => substr($accessToken, 0, 20)]);

            // Get service UUID from Mercury
            $serviceId = $serviceAuth->getServiceById($accessToken);
            $this->log('info', "Service uuid found", ['serviceId' => $serviceId]);

            // Validate service is enabled for this project
            if (!in_array($serviceId, $enabledServices)) {
                $this->log('error', 'Service access denied', [
                    'tenant_id' => $payload['tenant_id'],
                    'token_id' => $payload['token_id'],
                    'service_id' => $serviceId,
                    'enabled_services' => $enabledServices,
                ]);
                throw new ProjectAuthenticationException(
                    "Service access denied. Service '{$serviceId}' is not enabled for this project. " .
                    "Enabled services: " . implode(', ', $enabledServices)
                );
            }

            $this->log('info', "Service is enabled for this project", [
                'enabledServices' => $enabledServices, 
                'serviceId' => $serviceId
            ]);

            $request['project'] = [
                'tenant_id' => $payload['tenant_id'],
                'project_uuid' => $payload['tenant_id'],
                'enabled_services' => $enabledServices,
                'scopes' => $payload['scopes'] ?? [],
                'secret_version' => $payload['secret_version'],
                'token_id' => $payload['token_id'],
                'expires_at' => $payload['exp'],
            ];

            $this->log('info', 'Project context injected successfully', [
                'tenant_id' => $payload['tenant_id'],
                'token_id' => $payload['token_id'],
                'service_id' => $serviceId,
                'scopes' => $request['project']['scopes'],
            ]);

        } catch (ProjectAuthenticationException $e) {
            throw $e;
        } catch (\Exception $err) {
            $this->log('error', 'Unexpected error during project context injection', [
                'tenant_id' => $payload['tenant_id'] ?? null,
                'token_id' => $payload['token_id'] ?? null,
                'error' => $err->getMessage(),
            ]);
            
            if ($err instanceof \Exception) throw $err;
            throw new \Exception((string)$err);
        }
    }

    /**
     * Inject service token context
     */
    private function injectServiceContext(array &$request, array $payload): void
    {
        // Parse scopes from space-separated string
        $scopes = isset($payload['scope']) ? explode(' ', $payload['scope']) : [];

        $request['service'] = [
            'client_id' => $payload['client_id'],
            'service_name' => $payload['service_name'],
            'scopes' => $scopes,
            'token_id' => $payload['jti'],
            'issued_at' => $payload['iat'],
            'expires_at' => $payload['exp']
        ];

        $this->log('info', "Service authenticated: {$payload['service_name']}, scopes: " . implode(', ', $scopes));
    }

    /**
     * Validate token using cached JWKS + RSA verification
     */
    private function validateToken(string $token): array
    {
        try {
            // Get public key from cached JWKS
            $publicKey = $this->getPublicKeyFromCache($token);

            // Verify JWT with RSA public key
            $verified = JWT::decode($token, new Key($publicKey, 'RS512'));

            if (!is_object($verified)) {
                return [
                    'isValid' => false,
                    'error' => 'Invalid token payload'
                ];
            }

            $payload = json_decode(json_encode($verified), true);

            // Validate based on token type
            if ($payload['type'] === 'platform') {
                return $this->validatePlatformToken($payload);
            } elseif ($payload['type'] === 'project') {
                return $this->validateProjectToken($payload);
            } elseif ($payload['type'] === 'service') {
                return $this->validateServiceToken($payload);
            } else {
                return [
                    'isValid' => false,
                    'error' => "Unsupported token type: {$payload['type']}."
                ];
            }

        } catch (\Exception $error) {
            return [
                'isValid' => false,
                'error' => $error->getMessage()
            ];
        }
    }

    /**
     * Validate platform token structure and revocation
     */
    private function validatePlatformToken(array $payload): array
    {
        // Validate structure
        if (!isset($payload['tenant_id']) || !isset($payload['token_id'])) {
            return [
                'isValid' => false,
                'error' => 'Invalid platform token structure'
            ];
        }

        $redis = RedisConnectionManager::getInstance();

        // Check if token is revoked
        $tokenExists = $redis->exists("platform_token:{$payload['token_id']}");

        if ($tokenExists === 0) {
            return [
                'isValid' => false,
                'error' => 'Token has been revoked'
            ];
        }

        return [
            'isValid' => true,
            'payload' => $payload
        ];
    }

    /**
     * Validate project token structure, secret version, and revocation
     */
    private function validateProjectToken(array $payload): array
    {
        // Validate structure
        if (!isset($payload['tenant_id']) || !isset($payload['token_id']) || 
            !isset($payload['enabled_services']) || !is_array($payload['enabled_services'])) {
            return [
                'isValid' => false,
                'error' => 'Invalid project token structure'
            ];
        }

        $redis = RedisConnectionManager::getInstance();

        // Check secret version
        $currentSecretVersion = $this->getCurrentSecretVersion($payload['tenant_id']);
        if ($currentSecretVersion > 0 && ($payload['secret_version'] ?? 0) < $currentSecretVersion) {
            return [
                'isValid' => false,
                'error' => "Token secret version outdated (token: {$payload['secret_version']}, current: {$currentSecretVersion}) - re-authentication required"
            ];
        }

        // Check if token is revoked
        $tokenExists = $redis->exists("project_token:{$payload['token_id']}");

        if ($tokenExists === 0) {
            return [
                'isValid' => false,
                'error' => 'Token has been revoked'
            ];
        }

        return [
            'isValid' => true,
            'payload' => $payload
        ];
    }

    /**
     * Validate service token structure (stateless - no revocation check)
     */
    private function validateServiceToken(array $payload): array
    {
        // Validate structure
        if (!isset($payload['client_id']) || !isset($payload['service_name']) || !isset($payload['jti'])) {
            return [
                'isValid' => false,
                'error' => 'Invalid service token structure'
            ];
        }

        // Service tokens are stateless - no Redis revocation check
        // Only signature + expiration validation (done by JWT::decode)

        return [
            'isValid' => true,
            'payload' => $payload
        ];
    }

    /**
     * Get RSA public key from cached JWKS with auto-refresh on key miss
     */
    private function getPublicKeyFromCache(string $token): string
    {
        return $this->jwksService->getPublicKey($token);
    }

    /**
     * Get current secret version from Redis (cached by Mercury)
     */
    private function getCurrentSecretVersion(string $tenantId): int
    {
        try {
            $redis = RedisConnectionManager::getInstance();
            $cacheKey = "tenant_secret_version:{$tenantId}";
            $cachedVersion = $redis->get($cacheKey);

            if ($cachedVersion) {
                return (int) $cachedVersion;
            }

            return 0; // Default to allow if version not found
        } catch (\Exception $error) {
            throw new ProjectAuthenticationException("Failed to get secret version: {$error->getMessage()}");
        }
    }

    private function log(string $level, string $message, array $context = []): void
    {
        Log::$level("[LaravelAuthGuard] {$message}", $context);
    }
}