<?php

namespace Wazobia\LaravelAuthGuard\GraphQL\Directives;

use Nuwave\Lighthouse\Schema\Directives\BaseDirective;
use Nuwave\Lighthouse\Support\Contracts\FieldMiddleware;
use Nuwave\Lighthouse\Schema\Values\FieldValue;
use Wazobia\LaravelAuthGuard\Exceptions\ProjectAuthenticationException;
use GraphQL\Type\Definition\ResolveInfo;
use Nuwave\Lighthouse\Exceptions\AuthenticationException;

class ScopesDirective extends BaseDirective implements FieldMiddleware
{
    public static function definition(): string
    {
        return /** @lang GraphQL */ '
            """
            Requires specific scopes for this field (use after @projectAuth or @combinedAuth)
            """
            directive @scopes(
                requires: [String!]!
            ) on FIELD_DEFINITION
        ';
    }

    public function handleField(FieldValue $fieldValue): void
    {
        $fieldValue->wrapResolver(function (callable $resolver) {
            return function ($root, array $args, $context, ResolveInfo $info) use ($resolver) {
                $this->validateScopes($context);
                return $resolver($root, $args, $context, $info);
            };
        });
    }

    protected function validateScopes($context): void
    {
        $request = $context->request ?? request();
        $requiredScopes = $this->directiveArgValue('requires') ?? [];
        
        if (empty($requiredScopes)) {
            return;
        }
        
        $userScopes = [];
        
        // Get scopes from authenticated contexts
        $platform = $request->get('auth_platform');
        $project = $request->get('auth_project'); 
        $service = $request->get('auth_service');
        
        if ($platform && isset($platform['scopes'])) {
            $userScopes = array_merge($userScopes, $platform['scopes']);
        }
        
        if ($project && isset($project['scopes'])) {
            $userScopes = array_merge($userScopes, $project['scopes']);
        }
        
        if ($service && isset($service['scopes'])) {
            $userScopes = array_merge($userScopes, $service['scopes']);
        }
        
        // Remove duplicates
        $userScopes = array_unique($userScopes);
        
        // Check if user has all required scopes
        $missingScopes = array_diff($requiredScopes, $userScopes);
        
        if (!empty($missingScopes)) {
            throw new AuthenticationException(
                'Insufficient scopes. Required: [' . implode(', ', $requiredScopes) . 
                '], Missing: [' . implode(', ', $missingScopes) . ']'
            );
        }
    }
}