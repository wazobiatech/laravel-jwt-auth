<?php

namespace Wazobia\LaravelAuthGuard\GraphQL\Directives;

use Closure;
use GraphQL\Type\Definition\ResolveInfo;
use Illuminate\Http\Request;
use Nuwave\Lighthouse\Schema\Directives\BaseDirective;
use Nuwave\Lighthouse\Support\Contracts\FieldMiddleware;
use Nuwave\Lighthouse\Exceptions\AuthenticationException;
use Nuwave\Lighthouse\Schema\Values\FieldValue;
use Nuwave\Lighthouse\Support\Contracts\GraphQLContext;
use Wazobia\LaravelAuthGuard\Exceptions\ProjectAuthenticationException;
use Wazobia\LaravelAuthGuard\Services\ProjectAuthService;

class ServiceAuthDirective extends BaseDirective implements FieldMiddleware
{
    public static function definition(): string
    {
        return /** @lang GraphQL */ '
        """
        Requires service token authentication with specific scopes.
        This directive ONLY accepts service tokens, not platform or project tokens.
        Use for service-to-service operations that require strict service authentication.
        """
        directive @serviceAuth(
            """
            Required service scopes for this operation.
            """
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
        try {
            $request = $context->request() ?? app(Request::class);
            $requiredScopes = $this->directiveArgValue('scopes') ?? [];
            
            \Log::info('🔍 ServiceAuth Starting Authentication', [
                'required_scopes' => $requiredScopes,
                'has_x_project_token' => $request->hasHeader('x-project-token'),
                'x_project_token_value' => $request->header('x-project-token') ? 'EXISTS' : 'NOT_SET'
            ]);

            // Use ProjectAuthService for authentication
            $projectService = app(ProjectAuthService::class);
            $requestArray = [
                'headers' => [
                    'x-project-token' => $request->header('x-project-token')
                ]
            ];
            
            \Log::info('🔍 ServiceAuth Request Array Before Auth', [
                'request_array' => $requestArray
            ]);
            
            $projectService->authenticate($requestArray);
            
            \Log::info('🔍 ServiceAuth After Authentication', [
                'service_exists' => isset($requestArray['service']),
                'platform_exists' => isset($requestArray['platform']),
                'project_exists' => isset($requestArray['project'])
            ]);

            // ServiceAuth ONLY accepts service tokens - fail if not service
            if (!isset($requestArray['service'])) {
                \Log::error('❌ ServiceAuth requires service token', [
                    'found_platform' => isset($requestArray['platform']),
                    'found_project' => isset($requestArray['project']),
                    'found_service' => false
                ]);
                throw new ProjectAuthenticationException(
                    'This operation requires service authentication. Only service tokens are accepted.'
                );
            }

            \Log::info('✅ ServiceAuth service token validated');

            // Validate service scopes if required
            if (!empty($requiredScopes)) {
                \Log::info('🔍 Starting service scope validation', [
                    'required_scopes' => $requiredScopes,
                    'service_scopes' => $requestArray['service']['scopes'] ?? 'not_set'
                ]);
                $this->validateServiceScopes($requestArray, $requiredScopes);
                \Log::info('✅ Service scope validation passed');
            } else {
                \Log::info('⚠️ No scope validation - requiredScopes is empty');
            }
            
            // Inject service context into the request
            $request->merge(['auth_service' => $requestArray['service']]);
            
        } catch (ProjectAuthenticationException $e) {
            throw new AuthenticationException($e->getMessage());
        } catch (\Exception $e) {
            throw new AuthenticationException("Service Authentication Error: {$e->getMessage()}");
        }
    }

    protected function validateServiceScopes(array $requestArray, array $requiredScopes): void
    {
        $serviceScopes = $requestArray['service']['scopes'] ?? [];
        
        \Log::info('🔍 Service scope validation', [
            'service_scopes' => $serviceScopes,
            'required_scopes' => $requiredScopes
        ]);
        
        // Check if service has all required scopes
        $missingScopes = array_diff($requiredScopes, $serviceScopes);
        
        \Log::info('🔍 Service scope validation check', [
            'required_scopes' => $requiredScopes,
            'service_scopes' => $serviceScopes,
            'missing_scopes' => $missingScopes,
            'has_missing' => !empty($missingScopes)
        ]);
        
        if (!empty($missingScopes)) {
            \Log::error('❌ Service scope validation failed', [
                'missing_scopes' => $missingScopes
            ]);
            throw new ProjectAuthenticationException(
                'Insufficient service scopes. Required: [' . implode(', ', $requiredScopes) . 
                '], Missing: [' . implode(', ', $missingScopes) . ']'
            );
        }
        
        \Log::info('✅ Service scope validation successful');
    }
}