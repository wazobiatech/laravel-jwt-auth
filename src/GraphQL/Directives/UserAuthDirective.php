<?php

namespace Wazobia\LaravelAuthGuard\GraphQL\Directives;

use Closure;
use Nuwave\Lighthouse\Schema\Directives\BaseDirective;
use Nuwave\Lighthouse\Support\Contracts\FieldMiddleware;
use Nuwave\Lighthouse\Schema\Values\FieldValue;
use Wazobia\LaravelAuthGuard\Services\JwtAuthService;
use Wazobia\LaravelAuthGuard\Exceptions\JwtAuthenticationException;
use GraphQL\Type\Definition\ResolveInfo;
use Nuwave\Lighthouse\Exceptions\AuthenticationException;
use Illuminate\Support\Facades\Log;

class UserAuthDirective extends BaseDirective implements FieldMiddleware
{
    public static function definition(): string
    {
        return /** @lang GraphQL */ '
            """
            Requires user authentication (JWT) with optional scopes
            """
            directive @userAuth(
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
        
        // Add comprehensive logging for debugging
        Log::error('[UserAuthDirective] Starting user authentication', [
            'directive_called' => true,
            'request_headers' => $request->headers->all(),
            'auth_header' => $request->header('Authorization'),
            'has_auth_header' => $request->hasHeader('Authorization'),
            'context_user_before' => $context->user ?? 'null',
        ]);
        
        try {
            $jwtService = new JwtAuthService();
            
            // Get required scopes from directive argument
            $requiredScopes = $this->directiveArgValue('scopes') ?? [];
            
            Log::error('[UserAuthDirective] Processing authentication', [
                'required_scopes' => $requiredScopes,
                'jwt_service_created' => true,
            ]);
            
            // Convert to array format matching Node.js
            $requestArray = [
                'headers' => [
                    'authorization' => $request->header('Authorization')
                ]
            ];
            
            Log::error('[UserAuthDirective] Created request array', [
                'request_array_structure' => array_keys($requestArray),
                'authorization_header_present' => !empty($requestArray['headers']['authorization']),
                'auth_header_length' => strlen($requestArray['headers']['authorization'] ?? ''),
            ]);
            
            // Authenticate using service
            $jwtService->authenticate($requestArray);
            
            Log::error('[UserAuthDirective] JWT authentication completed', [
                'request_array_after_auth' => array_keys($requestArray),
                'user_data_present' => isset($requestArray['user']),
                'user_data_keys' => isset($requestArray['user']) ? array_keys($requestArray['user']) : 'NO_USER_DATA',
                'user_permissions' => $requestArray['user']['permissions'] ?? 'NO_PERMISSIONS',
            ]);
            
            // Check scopes if required
            if (!empty($requiredScopes)) {
                $this->validateScopes($requestArray, $requiredScopes);
            }
            
            // Inject user data into context
            if (isset($requestArray['user'])) {
                Log::error('[UserAuthDirective] Injecting user data into context', [
                    'user_data' => $requestArray['user'],
                    'context_user_before_injection' => $context->user ?? 'null',
                ]);
                
                // Store user data in request for access in resolvers
                $request->merge(['auth_user' => $requestArray['user']]);
                
                // Create JwtUser object for GraphQL context compatibility
                $userData = is_array($requestArray['user']) ? $requestArray['user'] : (array)$requestArray['user'];
                $jwtUser = new \Wazobia\LaravelAuthGuard\Models\JwtUser($userData);
                $context->user = $jwtUser;
                    
                Log::error('[UserAuthDirective] JwtUser injection completed', [
                    'jwt_user_uuid' => $jwtUser->uuid ?? 'no_uuid',
                    'jwt_user_email' => $jwtUser->email ?? 'no_email',
                    'context_user_type' => get_class($context->user ?? null),
                    'auth_user_in_request' => $request->get('auth_user', 'not_found'),
                ]);
            } else {
                Log::error('[UserAuthDirective] No user data to inject', [
                    'request_array_contents' => $requestArray,
                ]);
            }
            
        } catch (JwtAuthenticationException $e) {
            Log::error('[UserAuth Debug] JWT Authentication failed', ['error' => $e->getMessage()]);
            throw new AuthenticationException($e->getMessage());
        } catch (\Exception $e) {
            Log::error('[UserAuth Debug] General authentication error', [
                'error' => $e->getMessage(),
                'class' => get_class($e),
                'trace' => $e->getTraceAsString()
            ]);
            throw new AuthenticationException("User Authentication Error: {$e->getMessage()}");
        }
    }
    
    protected function validateScopes(array $requestArray, array $requiredScopes): void
    {
        $userScopes = $requestArray['user']['permissions'] ?? [];
        
        Log::info('[UserAuth Debug] Scope validation', [
            'required_scopes' => $requiredScopes,
            'user_permissions' => $userScopes,
            'user_scopes_field' => $requestArray['user']['scopes'] ?? 'NOT_SET'
        ]);
        
        // Also check if there are scopes in the user data
        if (isset($requestArray['user']['scopes'])) {
            $userScopes = array_merge($userScopes, $requestArray['user']['scopes']);
            Log::info('[UserAuth Debug] Merged scopes from user.scopes field', ['merged_scopes' => $userScopes]);
        }
        
        // Remove duplicates
        $userScopes = array_unique($userScopes);
        
        // Check if user has all required scopes
        $missingScopes = array_diff($requiredScopes, $userScopes);
        
        Log::info('[UserAuth Debug] Final scope validation result', [
            'final_user_scopes' => $userScopes,
            'required_scopes' => $requiredScopes,
            'missing_scopes' => $missingScopes,
            'validation_passes' => empty($missingScopes)
        ]);
        
        if (!empty($missingScopes)) {
            throw new JwtAuthenticationException(
                'Insufficient user scopes. Required: [' . implode(', ', $requiredScopes) . 
                '], Missing: [' . implode(', ', $missingScopes) . ']'
            );
        }
        
        Log::info('[UserAuth Debug] Scope validation passed!');
    }
}