<?php

namespace Wazobia\LaravelAuthGuard\Contracts;

/**
 * JWT Authentication interface matching Node.js implementation
 */
interface JwtAuthenticatable
{
    /**
     * Authenticate user JWT token
     */
    public function authenticate(array &$request): void;
    
    /**
     * Revoke a specific token by JTI
     */
    public function revokeToken(string $jti, int $ttl = null): void;
}