<?php

namespace Wazobia\LaravelAuthGuard\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Wazobia\LaravelAuthGuard\Services\JwtAuthService;
use Wazobia\LaravelAuthGuard\Exceptions\JwtAuthenticationException;

/**
 * JWT Authentication Middleware matching Node.js implementation
 */
class JwtAuthMiddleware
{
    private JwtAuthService $authService;

    public function __construct()
    {
        $this->authService = new JwtAuthService();
    }

    /**
     * Handle JWT authentication matching Node.js behavior
     */
    public function handle(Request $request, Closure $next): Response
    {
        try {
            // Convert Laravel request to array format matching Node.js
            $requestArray = [
                'headers' => [
                    'authorization' => $request->header('Authorization')
                ]
            ];

            // Authenticate using the service
            $this->authService->authenticate($requestArray);

            // Inject user data into the request
            if (isset($requestArray['user'])) {
                $request->merge(['auth_user' => $requestArray['user']]);
                $request->setUserResolver(function () use ($requestArray) {
                    return (object) $requestArray['user'];
                });
            }

            return $next($request);
        } catch (JwtAuthenticationException $error) {
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
}