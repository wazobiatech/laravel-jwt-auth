<?php

namespace Wazobia\LaravelAuthGuard\GraphQL\Directives;

use Closure;
use Nuwave\Lighthouse\Schema\Directives\BaseDirective;
use Nuwave\Lighthouse\Support\Contracts\FieldMiddleware;
use Nuwave\Lighthouse\Schema\Values\FieldValue;
use Wazobia\LaravelAuthGuard\Services\ProjectAuthService;
use Wazobia\LaravelAuthGuard\Exceptions\ProjectAuthenticationException;
use GraphQL\Type\Definition\ResolveInfo;
use Nuwave\Lighthouse\Exceptions\AuthenticationException;

class ProjectAuthDirective extends BaseDirective implements FieldMiddleware
{
    public static function definition(): string
    {
        return /** @lang GraphQL */ '
            """
            Requires project authentication with optional scopes
            """
            directive @projectAuth(
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
            // Get service name from environment
            $serviceName = env('SERVICE_NAME', 'default');
            
            // Get required scopes from directive argument
            $requiredScopes = $this->directiveArgValue('scopes') ?? [];
            
            // Debug logging
            \Log::info('🔍 ProjectAuth Debug', [
                'service_name' => $serviceName,
                'required_scopes' => $requiredScopes,
                'has_scopes_param' => !empty($requiredScopes),
                'x_project_token_exact' => $request->header('x-project-token'),
                'x_project_token_normalized' => $request->header('X-Project-Token'),
                'all_headers' => $request->headers->all()
            ]);
            
            $projectService = new ProjectAuthService($serviceName);
            
            // Convert Laravel request to array format matching Node.js
            $requestArray = [
                'headers' => [
                    'x-project-token' => $request->header('x-project-token')
                ]
            ];
            
            \Log::info('🔍 About to call authenticate with', [
                'request_array' => $requestArray,
                'has_token' => !empty($requestArray['headers']['x-project-token'])
            ]);
            
            // Authenticate using the service
            try {
                // Pass by reference to ensure array is modified
                $projectService->authenticate($requestArray);
                \Log::info('✅ Authentication completed successfully');
            } catch (\Exception $authError) {
                \Log::error('❌ Authentication failed', [
                    'error' => $authError->getMessage(),
                    'exception_class' => get_class($authError)
                ]);
                throw $authError;
            }
            
            // Debug: Log what authentication returned
            \Log::info('🔍 ProjectAuth After Authentication', [
                'full_request_array' => $requestArray,
                'platform_exists' => isset($requestArray['platform']),
                'project_exists' => isset($requestArray['project']), 
                'service_exists' => isset($requestArray['service']),
                'platform_scopes' => $requestArray['platform']['scopes'] ?? 'not_set',
                'project_scopes' => $requestArray['project']['scopes'] ?? 'not_set',
                'service_scopes' => $requestArray['service']['scopes'] ?? 'not_set'
            ]);
            
            // Check scopes if required
            if (!empty($requiredScopes)) {
                \Log::info('🔍 Starting scope validation', [
                    'required_scopes' => $requiredScopes
                ]);
                $this->validateScopes($requestArray, $requiredScopes);
                \Log::info('✅ Scope validation passed');
            } else {
                \Log::info('⚠️ No scope validation - requiredScopes is empty');
            }
            
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
            
        } catch (ProjectAuthenticationException $e) {
            throw new AuthenticationException($e->getMessage());
        } catch (\Exception $e) {
            throw new AuthenticationException("Authentication Error: {$e->getMessage()}");
        }
    }
    
    protected function validateScopes(array $requestArray, array $requiredScopes): void
    {
        $userScopes = [];
        
        // Get scopes from the authenticated context
        if (isset($requestArray['platform']['scopes'])) {
            $userScopes = $requestArray['platform']['scopes'];
            \Log::info('🔍 Using platform scopes', ['scopes' => $userScopes]);
        } elseif (isset($requestArray['project']['scopes'])) {
            $userScopes = $requestArray['project']['scopes'];
            \Log::info('🔍 Using project scopes', ['scopes' => $userScopes]);
        } elseif (isset($requestArray['service']['scopes'])) {
            $userScopes = $requestArray['service']['scopes'];
            \Log::info('🔍 Using service scopes', ['scopes' => $userScopes]);
        } else {
            \Log::warning('⚠️ No scopes found in any context');
        }
        
        // Check if user has all required scopes
        $missingScopes = array_diff($requiredScopes, $userScopes);
        
        \Log::info('🔍 Scope validation check', [
            'required_scopes' => $requiredScopes,
            'user_scopes' => $userScopes,
            'missing_scopes' => $missingScopes,
            'has_missing' => !empty($missingScopes)
        ]);
        
        if (!empty($missingScopes)) {
            \Log::error('❌ Scope validation failed', [
                'missing_scopes' => $missingScopes
            ]);
            throw new ProjectAuthenticationException(
                'Insufficient scopes. Required: [' . implode(', ', $requiredScopes) . 
                '], Missing: [' . implode(', ', $missingScopes) . ']'
            );
        }
        
        \Log::info('✅ Scope validation successful');
    }
}