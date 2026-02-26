<?php

namespace Wazobia\LaravelAuthGuard\Models;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * JWT User model that implements Laravel's Authenticatable contract.
 * This allows JWT user data to be compatible with Laravel's authentication system.
 */
class JwtUser implements Authenticatable
{
    protected array $attributes = [];

    public function __construct(array $userData)
    {
        $this->attributes = $userData;
    }

    public function getAuthIdentifierName(): string
    {
        return 'uuid';
    }

    public function getAuthIdentifier()
    {
        return $this->attributes['uuid'] ?? null;
    }

    public function getAuthPassword(): ?string
    {
        return null; // JWT users don't have passwords in our system
    }

    public function getRememberToken(): ?string
    {
        return null; // Not used for JWT
    }

    public function setRememberToken($value): void
    {
        // Not used for JWT
    }

    public function getRememberTokenName(): ?string
    {
        return null; // Not used for JWT
    }

    /**
     * Get a user attribute
     */
    public function getAttribute(string $key)
    {
        return $this->attributes[$key] ?? null;
    }

    /**
     * Set a user attribute
     */
    public function setAttribute(string $key, $value): void
    {
        $this->attributes[$key] = $value;
    }

    /**
     * Get all attributes
     */
    public function getAttributes(): array
    {
        return $this->attributes;
    }

    /**
     * Magic getter for attributes
     */
    public function __get(string $key)
    {
        return $this->getAttribute($key);
    }

    /**
     * Magic setter for attributes
     */
    public function __set(string $key, $value): void
    {
        $this->setAttribute($key, $value);
    }

    /**
     * Check if attribute exists
     */
    public function __isset(string $key): bool
    {
        return isset($this->attributes[$key]);
    }

    /**
     * Convert to array for logging/debugging
     */
    public function toArray(): array
    {
        return $this->attributes;
    }
}