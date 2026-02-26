<?php

namespace Wazobia\LaravelAuthGuard\Contracts;

/**
 * Project Authentication interface matching Node.js implementation
 */
interface ProjectAuthenticatable
{
    /**
     * Authenticate project, platform, and service tokens
     */
    public function authenticate(array &$request): void;
}