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
        
        try {
            $jwtService = new JwtAuthService();
            
            // Get required scopes from directive argument
            $requiredScopes = $this->directiveArgValue('scopes') ?? [];
            
            // Convert to array format matching Node.js
            $requestArray = [
                'headers' => [
                    'authorization' => $request->header('Authorization')
                ]
            ];
            
            Log::info('[UserAuth Debug] Starting authentication', [
                'required_scopes' => $requiredScopes,
                'auth_header' => substr($request->header('Authorization') ?? '', 0, 50) . '...'
            ]);
            
            // Authenticate using service
            $jwtService->authenticate($requestArray);
            
            Log::info('[UserAuth Debug] JWT authentication succeeded', [
                'user_data_keys' => array_keys($requestArray['user'] ?? []),
                'user_permissions' => $requestArray['user']['permissions'] ?? 'NOT_FOUND',
                'user_scopes' => $requestArray['user']['scopes'] ?? 'NOT_FOUND'
            ]);
            
            // Check scopes if required
            if (!empty($requiredScopes)) {
                $this->validateScopes($requestArray, $requiredScopes);
            }
            
            // Inject user data
            if (isset($requestArray['user'])) {
                $request->merge(['auth_user' => $requestArray['user']]);
                $request->setUserResolver(function () use ($requestArray) {
                    return (object) $requestArray['user'];
                });
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