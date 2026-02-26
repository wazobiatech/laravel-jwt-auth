<?php

namespace Wazobia\LaravelAuthGuard\GraphQL\Directives;

use Closure;
use Nuwave\Lighthouse\Schema\Directives\BaseDirective;
use Nuwave\Lighthouse\Support\Contracts\FieldMiddleware;
use Nuwave\Lighthouse\Schema\Values\FieldValue;
use Wazobia\LaravelAuthGuard\Services\JwtAuthService;
use Wazobia\LaravelAuthGuard\Services\ProjectAuthService;
use Wazobia\LaravelAuthGuard\Exceptions\{JwtAuthenticationException, ProjectAuthenticationException};
use GraphQL\Type\Definition\ResolveInfo;
use Nuwave\Lighthouse\Exceptions\AuthenticationException;

class CombinedAuthDirective extends BaseDirective implements FieldMiddleware
{
    public static function definition(): string
    {
        return /** @lang GraphQL */ '
            """
            Requires both JWT and project authentication with optional scopes
            """
            directive @combinedAuth(
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
            // JWT Authentication first
            $jwtService = new JwtAuthService();
            $jwtRequestArray = [
                'headers' => [
                    'authorization' => $request->header('Authorization')
                ]
            ];
            $jwtService->authenticate($jwtRequestArray);
            
            // Inject JWT user data
            if (isset($jwtRequestArray['user'])) {
                $request->merge(['auth_user' => $jwtRequestArray['user']]);
                $request->setUserResolver(function () use ($jwtRequestArray) {
                    return (object) $jwtRequestArray['user'];
                });
            }
            
            // Project Authentication second
            $serviceName = env('SERVICE_NAME', 'default');
            $requiredScopes = $this->directiveArgValue('scopes') ?? [];
            
            $projectService = new ProjectAuthService($serviceName);
            $projectRequestArray = [
                'headers' => [
                    'x-project-token' => $request->header('x-project-token')
                ]
            ];
            $projectService->authenticate($projectRequestArray);
            
            // Check scopes if required (combine both JWT and project scopes)
            if (!empty($requiredScopes)) {
                $this->validateScopes($jwtRequestArray, $projectRequestArray, $requiredScopes);
            }
            
            // Inject project context data
            if (isset($projectRequestArray['platform'])) {
                $request->merge(['auth_platform' => $projectRequestArray['platform']]);
            }
            if (isset($projectRequestArray['project'])) {
                $request->merge(['auth_project' => $projectRequestArray['project']]);
            }
            if (isset($projectRequestArray['service'])) {
                $request->merge(['auth_service' => $projectRequestArray['service']]);
            }
            
        } catch (JwtAuthenticationException | ProjectAuthenticationException $e) {
            throw new AuthenticationException($e->getMessage());
        } catch (\Exception $e) {
            throw new AuthenticationException("Authentication Error: {$e->getMessage()}");
        }
    }
    
    protected function validateScopes(array $jwtRequestArray, array $projectRequestArray, array $requiredScopes): void
    {
        $allScopes = [];
        
        // Get scopes from JWT user (permissions)
        if (isset($jwtRequestArray['user']['permissions'])) {
            $allScopes = array_merge($allScopes, $jwtRequestArray['user']['permissions']);
        }
        
        if (isset($jwtRequestArray['user']['scopes'])) {
            $allScopes = array_merge($allScopes, $jwtRequestArray['user']['scopes']);
        }
        
        // Get scopes from project context
        if (isset($projectRequestArray['platform']['scopes'])) {
            $allScopes = array_merge($allScopes, $projectRequestArray['platform']['scopes']);
        } elseif (isset($projectRequestArray['project']['scopes'])) {
            $allScopes = array_merge($allScopes, $projectRequestArray['project']['scopes']);
        } elseif (isset($projectRequestArray['service']['scopes'])) {
            $allScopes = array_merge($allScopes, $projectRequestArray['service']['scopes']);
        }
        
        // Remove duplicates
        $allScopes = array_unique($allScopes);
        
        // Check if user has all required scopes
        $missingScopes = array_diff($requiredScopes, $allScopes);
        
        if (!empty($missingScopes)) {
            throw new ProjectAuthenticationException(
                'Insufficient permissions/scopes. Required: [' . implode(', ', $requiredScopes) . 
                '], Missing: [' . implode(', ', $missingScopes) . ']'
            );
        }
    }
}