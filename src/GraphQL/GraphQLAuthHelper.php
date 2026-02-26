<?php

namespace Wazobia\LaravelAuthGuard\GraphQL;

use Closure;
use Exception;
use Wazobia\LaravelAuthGuard\Services\JwtAuthService;
use Wazobia\LaravelAuthGuard\Services\ProjectAuthService;
use Wazobia\LaravelAuthGuard\Exceptions\JwtAuthenticationException;
use Wazobia\LaravelAuthGuard\Exceptions\ProjectAuthenticationException;

/**
 * GraphQL Authentication Helper matching Node.js implementation
 */
class GraphQLAuthHelper
{
    /**
     * JWT authentication for GraphQL matching Node.js behavior
     */
    public static function jwtAuth($root, array $args, $context, $info, Closure $next)
    {
        $request = $context->request ?? request();
        
        try {
            $jwtService = new JwtAuthService();
            
            // Convert to array format matching Node.js
            $requestArray = [
                'headers' => [
                    'authorization' => $request->header('Authorization')
                ]
            ];
            
            // Authenticate using service
            $jwtService->authenticate($requestArray);
            
            // Inject user data
            if (isset($requestArray['user'])) {
                $request->merge(['auth_user' => $requestArray['user']]);
                $request->setUserResolver(function () use ($requestArray) {
                    return (object) $requestArray['user'];
                });
            }
            
        } catch (JwtAuthenticationException $e) {
            throw new Exception("Unauthorized: {$e->getMessage()}");
        } catch (\Exception $e) {
            throw new Exception("Authentication Error: {$e->getMessage()}");
        }
        
        return $next($root, $args, $context, $info);
    }
    
    /**
     * Project authentication for GraphQL matching Node.js behavior
     */
    public static function projectAuth(string $serviceName)
    {
        return function ($root, array $args, $context, $info, Closure $next) use ($serviceName) {
            $request = $context->request ?? request();
            
            try {
                $projectService = new ProjectAuthService($serviceName);
                
                // Convert to array format matching Node.js
                $requestArray = [
                    'headers' => [
                        'x-project-token' => $request->header('x-project-token')
                    ]
                ];
                
                // Authenticate using service
                $projectService->authenticate($requestArray);
                
                // Inject context data
                if (isset($requestArray['platform'])) {
                    $request->merge(['auth_platform' => $requestArray['platform']]);
                }
                
                if (isset($requestArray['project'])) {
                    $request->merge(['auth_project' => $requestArray['project']]);
                }
                
                if (isset($requestArray['service'])) {
                    $request->merge(['auth_service' => $requestArray['service']]);
                }
                
            } catch (ProjectAuthenticationException $e) {
                throw new Exception("Unauthorized: {$e->getMessage()}");
            } catch (\Exception $e) {
                throw new Exception("Authentication Error: {$e->getMessage()}");
            }
            
            return $next($root, $args, $context, $info);
        };
    }
    
    /**
     * Combined authentication for GraphQL
     */
    public static function combinedAuth(string $serviceName)
    {
        return function ($root, array $args, $context, $info, Closure $next) use ($serviceName) {
            // Run JWT auth first
            self::jwtAuth($root, $args, $context, $info, function () {
                return null; // No-op closure for chaining
            });
            
            // Then run project auth
            $projectAuthClosure = self::projectAuth($serviceName);
            $projectAuthClosure($root, $args, $context, $info, function () {
                return null; // No-op closure for chaining
            });
            
            return $next($root, $args, $context, $info);
        };
    }
}
            // Use custom property name (not $context->user which is typed)
            $context->authUser = $userObject;
            
            return $next($root, $args, $context, $info);
            
        } catch (Exception $e) {
            throw new Exception('JWT Authentication failed: ' . $e->getMessage());
        }
    }

    /**
     * Project authentication for GraphQL
     */
    public static function projectAuth($root, array $args, $context, $info, Closure $next)
    {
        $request = $context->request ?? request();
        
        try {
            // Get the service directly instead of middleware
            $projectService = app(ProjectAuthService::class);
            
            $tokenHeader = config('auth-guard.headers.project_token', 'x-project-token');
            $authHeader = $request->header($tokenHeader);
            
            if (!$authHeader) {
                throw new Exception("No project token provided, required_header: '{$tokenHeader}'");
            }
            
            // Extract token
            $token = str_starts_with($authHeader, 'Bearer ') 
                ? substr($authHeader, 7) 
                : $authHeader;
            
            if (empty($token)) {
                throw new Exception('Empty project token');
            }
            
            // Create request array for authenticate method
            $authRequest = [
                'headers' => [
                    'x-project-token' => $authHeader
                ]
            ];
            
            // Authenticate - this modifies $authRequest by reference
            $projectService->authenticate($authRequest);
            
            // Extract the project data from the modified request
            $project = $authRequest['project'] ?? $authRequest['platform'] ?? $authRequest['service'] ?? null;
            
            if (!$project) {
                throw new Exception('No project context found after authentication');
            }
            
            // Convert to object
            $projectObject = (object) $project;
            
            // Set project in request
            $request->merge(['project' => $project]);
            $request->project = $projectObject;
            
            // Use custom property name
            $context->authProject = $projectObject;
            
            return $next($root, $args, $context, $info);
            
        } catch (Exception $e) {
            throw new Exception('Project Authentication failed: ' . $e->getMessage());
        }
    }

    /**
     * Combined authentication for GraphQL
     */
    public static function combinedAuth($root, array $args, $context, $info, Closure $next)
    {
        $request = $context->request ?? request();
        
        try {
            // Run JWT authentication first
            $jwtService = app(JwtAuthService::class);
            
            $jwtHeader = config('auth-guard.headers.jwt', 'Authorization');
            $authHeader = $request->header($jwtHeader);
            
            if (!$authHeader) {
                throw new Exception('No authorization header provided');
            }
            
            $token = str_starts_with($authHeader, 'Bearer ') 
                ? substr($authHeader, 7) 
                : $authHeader;
            
            if (!$token) {
                throw new Exception('Empty authorization token');
            }
            
            $user = $jwtService->authenticate($token);
            $userObject = (object) $user;
            
            $request->merge(['user' => $user]);
            $request->setUserResolver(function () use ($userObject) {
                return $userObject;
            });
            
            // Use custom property name
            $context->authUser = $userObject;
            
            // Run Project authentication second
            $projectService = app(ProjectAuthService::class);
            
            $projectHeader = config('auth-guard.headers.project_token', 'x-project-token');
            $projectAuthHeader = $request->header($projectHeader);
            
            if (!$projectAuthHeader) {
                throw new Exception("No project token provided, required_header: '{$projectHeader}'");
            }
            
            $projectToken = str_starts_with($projectAuthHeader, 'Bearer ') 
                ? substr($projectAuthHeader, 7) 
                : $projectAuthHeader;
            
            if (empty($projectToken)) {
                throw new Exception('Empty project token');
            }
            
            // Create request array for authenticate method
            $projectAuthRequest = [
                'headers' => [
                    'x-project-token' => $projectAuthHeader
                ]
            ];
            
            // Authenticate - this modifies $projectAuthRequest by reference
            $projectService->authenticate($projectAuthRequest);
            
            // Extract the project data from the modified request
            $project = $projectAuthRequest['project'] ?? $projectAuthRequest['platform'] ?? $projectAuthRequest['service'] ?? null;
            
            if (!$project) {
                throw new Exception('No project context found after authentication');
            }
            
            $projectObject = (object) $project;
            
            $request->merge(['project' => $project]);
            $request->project = $projectObject;
            
            // Use custom property name
            $context->authProject = $projectObject;
            
            return $next($root, $args, $context, $info);
            
        } catch (Exception $e) {
            throw new Exception('Authentication failed: ' . $e->getMessage());
        }
    }
}