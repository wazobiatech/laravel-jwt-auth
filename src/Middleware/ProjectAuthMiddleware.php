<?php

namespace Wazobia\LaravelAuthGuard\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Wazobia\LaravelAuthGuard\Services\ProjectAuthService;
use Wazobia\LaravelAuthGuard\Exceptions\ProjectAuthenticationException;

/**
 * Project Authentication Middleware matching Node.js implementation
 * Supports platform, project, and service tokens
 */
class ProjectAuthMiddleware
{
    private ProjectAuthService $authService;

    public function __construct(string $serviceName)
    {
        $this->authService = new ProjectAuthService($serviceName);
    }

    /**
     * Handle project authentication matching Node.js behavior
     */
    public function handle(Request $request, Closure $next): Response
    {
        try {
            // Convert Laravel request to array format matching Node.js
            $requestArray = [
                'headers' => [
                    'x-project-token' => $request->header('x-project-token')
                ]
            ];

            // Authenticate using the service
            $this->authService->authenticate($requestArray);

            // Inject context data into the request
            if (isset($requestArray['platform'])) {
                $request->merge(['auth_platform' => $requestArray['platform']]);
            }
            
            if (isset($requestArray['project'])) {
                $request->merge(['auth_project' => $requestArray['project']]);
            }
            
            if (isset($requestArray['service'])) {
                $request->merge(['auth_service' => $requestArray['service']]);
            }

            return $next($request);
        } catch (ProjectAuthenticationException $error) {
            return response()->json([
                'error' => 'Unauthorized',
                'message' => $error->getMessage()
            ], 401);
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