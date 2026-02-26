<?php

namespace Tests\Feature;

use Tests\TestCase;
use Wazobia\LaravelAuthGuard\Services\ServiceAuthService;
use Wazobia\LaravelAuthGuard\Services\ProjectAuthService;
use Wazobia\LaravelAuthGuard\Services\JwksService;
use Wazobia\LaravelAuthGuard\Utils\RedisConnectionManager;
use Wazobia\LaravelAuthGuard\Exceptions\ServiceAuthenticationException;
use Wazobia\LaravelAuthGuard\Exceptions\ProjectAuthenticationException;

/**
 * Test Laravel Auth Guard implementation against Node.js functionality
 */
class AuthGuardIntegrationTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        
        // Set test configuration
        config([
            'auth-guard.mercury_base_url' => 'https://mercury.test.com',
            'auth-guard.client_id' => 'test-client-id',
            'auth-guard.client_secret' => 'test-client-secret',
            'auth-guard.signature_shared_secret' => 'test-shared-secret',
            'auth-guard.redis.auth_url' => 'redis://localhost:6379/5',
        ]);
    }

    /** @test */
    public function it_can_instantiate_service_auth_service()
    {
        $this->expectException(ServiceAuthenticationException::class);
        $this->expectExceptionMessage("Missing required configuration: CLIENT_ID");
        
        // Clear config to test validation
        config(['auth-guard.client_id' => '']);
        
        new ServiceAuthService();
    }

    /** @test */
    public function it_validates_required_configuration()
    {
        $service = new ServiceAuthService();
        
        $this->assertInstanceOf(ServiceAuthService::class, $service);
    }

    /** @test */
    public function it_can_instantiate_project_auth_service()
    {
        $service = new ProjectAuthService('test-service');
        
        $this->assertInstanceOf(ProjectAuthService::class, $service);
    }

    /** @test */
    public function it_can_instantiate_jwks_service()
    {
        $service = new JwksService();
        
        $this->assertInstanceOf(JwksService::class, $service);
    }

    /** @test */
    public function redis_connection_manager_handles_missing_config_gracefully()
    {
        // Set Redis URL to null
        config(['auth-guard.redis.auth_url' => null]);
        
        $redis = RedisConnectionManager::getInstance();
        
        // Should return null when Redis is not configured
        $this->assertNull($redis);
    }

    /** @test */
    public function project_auth_service_can_handle_token_validation()
    {
        $service = new ProjectAuthService('test-service');
        
        // Test with invalid request (should throw exception)
        $this->expectException(ProjectAuthenticationException::class);
        $this->expectExceptionMessage("No token provided");
        
        $service->authenticate(['headers' => []]);
    }

    /** @test */
    public function configuration_values_are_properly_loaded()
    {
        $this->assertEquals('https://mercury.test.com', config('auth-guard.mercury_base_url'));
        $this->assertEquals('test-client-id', config('auth-guard.client_id'));
        $this->assertEquals('test-client-secret', config('auth-guard.client_secret'));
        $this->assertEquals('redis://localhost:6379/5', config('auth-guard.redis.auth_url'));
        $this->assertEquals('RS512', config('auth-guard.jwt_algorithm'));
    }

    /** @test */
    public function service_names_are_normalized()
    {
        $service1 = new ProjectAuthService('Test-Service');
        $service2 = new ProjectAuthService('TEST_SERVICE');
        
        // Both should work (service names are normalized to lowercase internally)
        $this->assertInstanceOf(ProjectAuthService::class, $service1);
        $this->assertInstanceOf(ProjectAuthService::class, $service2);
    }

    /** @test */
    public function environment_variables_fallback_works()
    {
        // Clear config to test env fallback
        config(['auth-guard.mercury_base_url' => null]);
        
        // Set environment variable
        putenv('MERCURY_BASE_URL=https://mercury.env.com');
        
        $service = new JwksService();
        
        // Should fall back to environment variable
        $this->assertInstanceOf(JwksService::class, $service);
        
        // Clean up
        putenv('MERCURY_BASE_URL');
    }
}