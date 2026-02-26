<?php

namespace Wazobia\LaravelAuthGuard\GraphQL\Directives;

use Closure;
use Nuwave\Lighthouse\Schema\Directives\BaseDirective;
use Nuwave\Lighthouse\Support\Contracts\FieldMiddleware;
use Nuwave\Lighthouse\Schema\Values\FieldValue;
use Wazobia\LaravelAuthGuard\Services\{JwtAuthService, ProjectAuthService};
use Wazobia\LaravelAuthGuard\Exceptions\{JwtAuthenticationException, ProjectAuthenticationException};
use GraphQL\Type\Definition\ResolveInfo;
use Nuwave\Lighthouse\Exceptions\AuthenticationException;

class CombineAuthDirective extends BaseDirective implements FieldMiddleware
{
    public static function definition(): string
    {
        return /** @lang GraphQL */ '
            """
            Requires both user JWT authentication AND project token authentication with combined scope validation
            """
            directive @combineAuth(
                scopes: [String!]
            ) on FIELD_DEFINITION
        ';
    }

    public function handleField(FieldValue $fieldValue): void
    {
        $fieldValue->wrapResolver(function (callable $resolver) {
            return function ($root, array $args, $context, ResolveInfo $info) use ($resolver) {
                $this->authenticate($context);
                return $resolver($root, $args, $context, $info);
            };
        });
    }

    protected function authenticate($context): void
    {
        $request = $context->request ?? request();
        
        try {
            // Get required scopes from directive argument
            $requiredScopes = $this->directiveArgValue('scopes') ?? [];
            
            // Debug logging
            \Log::info('🔍 CombineAuth Debug', [
                'required_scopes' => $requiredScopes,
                'authorization_header' => $request->header('Authorization', 'no-auth-header'),
                'project_token_header' => $request->header('x-project-token', 'no-project-token'),
                'all_headers' => array_keys($request->headers->all())
            ]);
            
            // Step 1: Authenticate User JWT (Authorization Bearer)
            $authHeader = $request->header('Authorization');
            if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
                throw new AuthenticationException("User JWT required. Provide 'Authorization: Bearer <token>' header");
            }
            
            // Authenticate user token using JWT Auth Service
            $jwtAuthService = new JwtAuthService();
            $userRequestArray = [
                'headers' => [
                    'authorization' => $authHeader
                ]
            ];
            
            $jwtAuthService->authenticate($userRequestArray);
            
            // Extract user from JWT response
            $user = null;
            if (isset($userRequestArray['user'])) {
                $user = (object) $userRequestArray['user'];
            }
            
            \Log::info('✅ CombineAuth - User authentication successful', [
                'user_data' => $userRequestArray['user'] ?? 'no-user',
                'user_uuid' => isset($userRequestArray['user']['uuid']) ? $userRequestArray['user']['uuid'] : 'no-uuid'
            ]);
            
            // Step 2: Authenticate Project Token (x-project-token)
            $projectTokenHeader = $request->header('x-project-token');
            if (!$projectTokenHeader) {
                throw new AuthenticationException("Project token required. Provide 'x-project-token' header");
            }
            
            // Get service name from environment
            $serviceName = env('SERVICE_NAME', 'default');
            $projectService = new ProjectAuthService($serviceName);
            
            // Convert Laravel request to array format for project service
            $requestArray = [
                'headers' => [
                    'x-project-token' => $projectTokenHeader
                ]
            ];
            
            // Authenticate project token (this will inject platform/project/service context)
            $projectService->authenticate($requestArray);
            
            \Log::info('✅ CombineAuth - Project authentication successful', [
                'platform_context' => $requestArray['platform'] ?? 'no-platform',
                'project_context' => $requestArray['project'] ?? 'no-project',
                'service_context' => $requestArray['service'] ?? 'no-service'
            ]);
            
            // Step 3: Combined Scope Validation
            if (!empty($requiredScopes)) {
                \Log::info('🔍 CombineAuth - Starting combined scope validation', [
                    'required_scopes' => $requiredScopes
                ]);
                
                $this->validateCombinedScopes($userRequestArray, $requestArray, $requiredScopes);
                \Log::info('✅ CombineAuth - Combined scope validation passed');
            } else {
                \Log::info('⚠️ CombineAuth - No scope validation required');
            }
            
            // Step 4: Inject contexts into request
            // Inject user context using Laravel's built-in GenericUser
            if (isset($userRequestArray['user'])) {
                // Create GenericUser object that implements Authenticatable
                $authUser = new \Illuminate\Auth\GenericUser($userRequestArray['user']);
                $context->user = $authUser;
                $request->merge(['auth_user' => $userRequestArray['user']]);
            }
            
            // Inject project contexts
            if (isset($requestArray['platform'])) {
                $request->merge(['auth_platform' => $requestArray['platform']]);
            }
            
            if (isset($requestArray['project'])) {
                $request->merge(['auth_project' => $requestArray['project']]);
            }
            
            if (isset($requestArray['service'])) {
                $request->merge(['auth_service' => $requestArray['service']]);
            }
            
            \Log::info('✅ CombineAuth - All contexts injected successfully');
            
        } catch (JwtAuthenticationException $e) {
            throw new AuthenticationException("User Authentication Error: {$e->getMessage()}");
        } catch (ProjectAuthenticationException $e) {
            throw new AuthenticationException("Project Authentication Error: {$e->getMessage()}");
        } catch (\Exception $e) {
            throw new AuthenticationException("Combine Authentication Error: {$e->getMessage()}");
        }
    }
    
    protected function validateCombinedScopes($userRequestArray, array $requestArray, array $requiredScopes): void
    {
        // Collect all available scopes from both user and project contexts
        $allScopes = [];
        
        // Get user scopes (permissions field in JWT payload)
        if (isset($userRequestArray['user']['permissions'])) {
            $userScopes = $userRequestArray['user']['permissions'];
            $allScopes = array_merge($allScopes, $userScopes);
            \Log::info('🔍 CombineAuth - User scopes', ['user_scopes' => $userScopes]);
        }
        
        // Get platform/project/service scopes 
        if (isset($requestArray['platform']['scopes'])) {
            $platformScopes = $requestArray['platform']['scopes'];
            $allScopes = array_merge($allScopes, $platformScopes);
            \Log::info('🔍 CombineAuth - Platform scopes', ['platform_scopes' => $platformScopes]);
        }
        
        if (isset($requestArray['project']['scopes'])) {
            $projectScopes = $requestArray['project']['scopes'];
            $allScopes = array_merge($allScopes, $projectScopes);
            \Log::info('🔍 CombineAuth - Project scopes', ['project_scopes' => $projectScopes]);
        }
        
        if (isset($requestArray['service']['scopes'])) {
            $serviceScopes = $requestArray['service']['scopes'];
            $allScopes = array_merge($allScopes, $serviceScopes);
            \Log::info('🔍 CombineAuth - Service scopes', ['service_scopes' => $serviceScopes]);
        }
        
        // Remove duplicates
        $allScopes = array_unique($allScopes);
        
        // Check if all required scopes are present
        $missingScopes = array_diff($requiredScopes, $allScopes);
        
        \Log::info('🔍 CombineAuth - Combined scope validation', [
            'required_scopes' => $requiredScopes,
            'all_available_scopes' => $allScopes,
            'missing_scopes' => $missingScopes,
            'has_missing' => !empty($missingScopes)
        ]);
        
        if (!empty($missingScopes)) {
            \Log::error('❌ CombineAuth - Combined scope validation failed', [
                'missing_scopes' => $missingScopes
            ]);
            throw new AuthenticationException(
                'Insufficient combined scopes. Required: [' . implode(', ', $requiredScopes) . 
                '], Missing: [' . implode(', ', $missingScopes) . ']'
            );
        }
        
        \Log::info('✅ CombineAuth - Combined scope validation successful', [
            'validated_scopes' => $requiredScopes
        ]);
    }
}