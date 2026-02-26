<?php

namespace Wazobia\LaravelAuthGuard\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

/**
 * Combined Authentication Middleware matching Node.js behavior
 * Handles both JWT and Project authentication in sequence
 */
class CombinedAuthMiddleware
{
    private string $serviceName;

    public function __construct(string $serviceName)
    {
        $this->serviceName = $serviceName;
    }

    /**
     * Handle an incoming request with both authentications.
     */
    public function handle(Request $request, Closure $next): Response
    {
        try {
            // Run JWT authentication first
            $jwtMiddleware = new JwtAuthMiddleware();
            $jwtResult = $jwtMiddleware->handle($request, function ($req) {
                return $req;
            });

            // Check if JWT auth failed
            if ($jwtResult instanceof \Illuminate\Http\JsonResponse) {
                return $jwtResult;
            }

            // Run Project authentication second
            $projectMiddleware = new ProjectAuthMiddleware($this->serviceName);
            $projectResult = $projectMiddleware->handle($request, function ($req) {
                return $req;
            });

            // Check if Project auth failed
            if ($projectResult instanceof \Illuminate\Http\JsonResponse) {
                return $projectResult;
            }

            // Both authentications passed
            return $next($request);
        } catch (\Exception $error) {
            return response()->json([
                'error' => 'Authentication Error',
                'message' => $error->getMessage()
            ], 500);
        }
    }

    /**
     * Static factory method for middleware binding
     */
    public static function create(string $serviceName): \Closure
    {
        return function (Request $request, Closure $next) use ($serviceName) {
            $middleware = new self($serviceName);
            return $middleware->handle($request, $next);
        };
    }
}