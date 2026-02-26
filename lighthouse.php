<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Lighthouse GraphQL Directives
    |--------------------------------------------------------------------------
    |
    | Register authentication directives for Lighthouse GraphQL
    |
    */
    
    'directives' => [
        Wazobia\LaravelAuthGuard\GraphQL\Directives\JwtAuthDirective::class,
        Wazobia\LaravelAuthGuard\GraphQL\Directives\ProjectAuthDirective::class,
        Wazobia\LaravelAuthGuard\GraphQL\Directives\CombinedAuthDirective::class,
        Wazobia\LaravelAuthGuard\GraphQL\Directives\ScopesDirective::class,
    ],
];