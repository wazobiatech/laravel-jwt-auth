<?php

namespace Wazobia\LaravelAuthGuard\Types;

/**
 * Token payload types matching Node.js implementation exactly
 */

// ==================== TOKEN PAYLOAD TYPES ====================

class PlatformTokenPayload
{
    public string $tenant_id;
    public int $secret_version;
    public string $token_id;
    public string $type = 'platform';
    public array $scopes;
    public int $iat;
    public int $nbf;
    public int $exp;
    public string $iss;
    public string $aud;
}

class ProjectTokenPayload
{
    public string $tenant_id;
    public int $secret_version;
    public array $enabled_services;
    public string $token_id;
    public string $type = 'project';
    public array $scopes;
    public int $iat;
    public int $nbf;
    public int $exp;
    public string $iss;
    public string $aud;
}

class UserTokenPayload
{
    public string $user_id;
    public string $tenant_id;
    public string $token_id;
    public string $type = 'user';
    public array $scopes;
    public int $iat;
    public int $nbf;
    public int $exp;
    public string $iss;
    public string $aud;
    public ?string $jti = null;
}

class ServiceTokenPayload
{
    public string $type = 'service';
    public string $client_id;
    public string $service_name;
    public string $scope; // space-separated scopes
    public string $jti;
    public int $iat;
    public int $nbf;
    public int $exp;
    public string $iss;
    public string $aud;
}

// ==================== CONTEXT TYPES ====================

class PlatformContext
{
    public string $tenant_id;
    public string $project_uuid;
    public array $scopes;
    public string $token_id;
    public int $expires_at;
}

class ProjectContext
{
    public string $tenant_id;
    public string $project_uuid;
    public array $enabled_services;
    public array $scopes;
    public int $secret_version;
    public string $token_id;
    public int $expires_at;
}

class ServiceContext
{
    public string $client_id;
    public string $service_name;
    public array $scopes;
    public string $token_id;
    public int $issued_at;
    public int $expires_at;
}

// ==================== LEGACY/DEPRECATED TYPES ====================

/**
 * @deprecated Use specific token payload types instead
 */
class JwtPayload
{
    public ?object $sub = null;
    public ?string $project_uuid = null;
    public ?array $permissions = null;
    public ?array $scopes = null;
    public ?string $tenant_id = null;
    public string $type;
    public string $iss;
    public string $aud;
    public int $exp;
    public int $nbf;
    public int $iat;
    public ?string $jti = null;
}

class AuthUser
{
    public string $uuid;
    public string $email;
    public string $name;
    public ?string $tenant_id = null;
    public ?array $permissions = null;
    public ?string $role = null;
    public ?string $token_id = null;
}

class AuthenticatedRequest
{
    public ?PlatformContext $platform = null;
    public ?ProjectContext $project = null;
    public ?ServiceContext $service = null;
    public ?AuthUser $user = null;
}