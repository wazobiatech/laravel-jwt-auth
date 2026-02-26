<?php

namespace Wazobia\LaravelAuthGuard;

use Illuminate\Support\ServiceProvider;
use Illuminate\Routing\Router;
use Wazobia\LaravelAuthGuard\Middleware\{
    JwtAuthMiddleware,
    ProjectAuthMiddleware,
    CombinedAuthMiddleware
};
use Wazobia\LaravelAuthGuard\Services\{
    JwtAuthService,
    ProjectAuthService,
    JwksService,
    ServiceAuthService
};
use Wazobia\LaravelAuthGuard\GraphQL\Directives\{
    JwtAuthDirective,
    ProjectAuthDirective,
    CombinedAuthDirective,
    CombineAuthDirective,
    UserAuthDirective,
    ServiceAuthDirective,
    ScopesDirective
};

/**
 * Laravel Auth Guard Service Provider matching Node.js implementation
 */
class AuthGuardServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        // Register core services
        $this->app->singleton(JwtAuthService::class);
        $this->app->singleton(JwksService::class);
        $this->app->singleton(ServiceAuthService::class);
        
        // Project auth service requires service name parameter, so bind as factory
        $this->app->bind(ProjectAuthService::class, function ($app, $parameters) {
            $serviceName = $parameters['serviceName'] ?? env('SERVICE_NAME', 'default');
            return new ProjectAuthService($serviceName);
        });

        // Register GraphQL directives
        $this->registerGraphQLDirectives();
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        $this->registerMiddleware();
        $this->publishConfig();
    }

    /**
     * Register middleware with router
     */
    protected function registerMiddleware(): void
    {
        $router = $this->app->make(Router::class);
        
        // Register middleware that don't require parameters
        $router->aliasMiddleware('jwt.auth', JwtAuthMiddleware::class);
        
        // Register middleware factories for those requiring parameters
        $router->aliasMiddleware('project.auth', function ($serviceName = null) {
            if (!$serviceName) {
                $serviceName = env('SERVICE_NAME', 'default');
            }
            return ProjectAuthMiddleware::create($serviceName);
        });
        
        $router->aliasMiddleware('combined.auth', function ($serviceName = null) {
            if (!$serviceName) {
                $serviceName = env('SERVICE_NAME', 'default');
            }
            return CombinedAuthMiddleware::create($serviceName);
        });
    }

    /**
     * Register GraphQL directives for Lighthouse
     */
    protected function registerGraphQLDirectives(): void
    {
        if (class_exists('Nuwave\Lighthouse\LighthouseServiceProvider')) {
            $this->app->singleton(JwtAuthDirective::class);
            $this->app->singleton(ProjectAuthDirective::class);
            $this->app->singleton(CombinedAuthDirective::class);
            $this->app->singleton(CombineAuthDirective::class);
            $this->app->singleton(UserAuthDirective::class);
            $this->app->singleton(ServiceAuthDirective::class);
            $this->app->singleton(ScopesDirective::class);
        }
    }

    /**
     * Publish config files
     */
    protected function publishConfig(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/auth-guard.php' => config_path('auth-guard.php'),
            ], 'auth-guard-config');
        }
    }
}