<?php

namespace Wazobia\LaravelAuthGuard\Utils;

use Predis\Client;
use Illuminate\Support\Facades\Log;

/**
 * Redis Connection Manager matching Node.js implementation
 * With graceful fallback when Redis is not available
 */
class RedisConnectionManager
{
    private static ?Client $instance = null;
    private static ?Client $connecting = null;
    private static bool $isShuttingDown = false;
    private static bool $redisAvailable = false; // Cache Redis availability check (default false)

    private function __construct() {}

    /**
     * Check if Redis is available and configured
     */
    private static function isRedisAvailable(): bool
    {
        static $checked = false;
        
        if ($checked) {
            return self::$redisAvailable;
        }
        
        $checked = true;

        // Check for Redis URL environment variable
        $redisUrl = config('auth-guard.redis.auth_url', env('REDIS_AUTH_URL'));
        if (!$redisUrl) {
            Log::info("Redis not available - REDIS_AUTH_URL not configured");
            self::$redisAvailable = false;
            return false;
        }

        self::$redisAvailable = true;
        return true;
    }

    public static function getInstance(): ?Client
    {
        // Prevent new connections during shutdown
        if (self::$isShuttingDown) {
            throw new \Exception("Redis connection manager is shutting down");
        }

        // If Redis is not available, return null
        if (!self::isRedisAvailable()) {
            Log::debug("Redis connection unavailable - returning null");
            return null;
        }

        // If already connected, verify it's still healthy
        if (self::$instance) {
            try {
                // Quick health check
                self::$instance->ping();
                return self::$instance;
            } catch (\Exception $error) {
                Log::warning("Redis health check failed, reconnecting", ['error' => $error->getMessage()]);
                // Reset instance to trigger reconnection
                self::$instance = null;
            }
        }

        // If currently connecting, wait for that connection
        if (self::$connecting) {
            return self::$connecting;
        }

        // Get Redis URL (we know it exists from isRedisAvailable())
        $redisUrl = config('auth-guard.redis.auth_url', env('REDIS_AUTH_URL'));

        // Parse Redis URL
        $urlParts = parse_url($redisUrl);
        
        $config = [
            'scheme' => $urlParts['scheme'] ?? 'tcp',
            'host' => $urlParts['host'] ?? 'localhost',
            'port' => $urlParts['port'] ?? 6379,
        ];
        
        if (isset($urlParts['pass'])) {
            $config['password'] = $urlParts['pass'];
        }
        
        if (isset($urlParts['path'])) {
            $config['database'] = (int) ltrim($urlParts['path'], '/');
        }

        // Start new connection
        try {
            $client = new Client($config, [
                'parameters' => [
                    'timeout' => 10.0,
                    'read_write_timeout' => 10.0,
                ]
            ]);

            // Test connection
            $client->ping();
            
            self::$instance = $client;
            self::$connecting = null;
            
            Log::info("Redis connection established successfully");
            
            return self::$instance;
            
        } catch (\Exception $error) {
            // Connection failed - mark Redis as unavailable for this request
            self::$redisAvailable = false;
            self::$instance = null;
            self::$connecting = null;
            
            Log::warning("Redis connection failed, caching disabled", [
                'error' => $error->getMessage(),
                'config' => array_merge($config, ['password' => isset($config['password']) ? '***' : null])
            ]);
            
            return null;
        }
    }

    public static function shutdown(): void
    {
        self::$isShuttingDown = true;
        
        if (self::$instance) {
            try {
                self::$instance->disconnect();
                Log::info("Redis connection closed gracefully");
            } catch (\Exception $error) {
                Log::warning("Error closing Redis connection", ['error' => $error->getMessage()]);
            }
        }
        
        self::$instance = null;
        self::$connecting = null;
    }

    public static function reset(): void
    {
        self::$instance = null;
        self::$connecting = null;
        self::$isShuttingDown = false;
        self::$redisAvailable = false;
        
        Log::debug("Redis connection manager reset");
    }
}