<?php

namespace Wazobia\LaravelAuthGuard\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use Wazobia\LaravelAuthGuard\Exceptions\ServiceAuthenticationException;

/**
 * Service authentication functions matching Node.js implementation
 */
class ServiceAuthService
{
    private string $mercuryBaseUrl;
    private string $clientId;
    private string $clientSecret;

    public function __construct()
    {
        $this->mercuryBaseUrl = config('auth-guard.mercury_base_url', env('MERCURY_BASE_URL', 'http://localhost:4000'));
        $this->clientId = config('auth-guard.client_id', env('CLIENT_ID', ''));
        $this->clientSecret = config('auth-guard.client_secret', env('CLIENT_SECRET', ''));
        
        if (!$this->clientId) {
            throw new ServiceAuthenticationException("Missing required configuration: CLIENT_ID");
        }
        if (!$this->clientSecret) {
            throw new ServiceAuthenticationException("Missing required configuration: CLIENT_SECRET");
        }
        if (!$this->mercuryBaseUrl) {
            throw new ServiceAuthenticationException("Missing required configuration: MERCURY_BASE_URL");
        }
    }

    /**
     * Generates a service token using the provided client credentials.
     * @return string The generated service token
     */
    public function generateToken(): string
    {
        $mutation = '
            mutation GenerateServiceToken($input: ServiceTokenInput!) {
                generateServiceToken(input: $input) {
                    access_token
                    token_type
                    expires_in
                    scope
                }
            }
        ';

        $variables = [
            'input' => [
                'client_id' => $this->clientId,
                'client_secret' => $this->clientSecret,
                'scope' => 'services:read'
            ]
        ];

        $response = Http::timeout(10)
            ->post("{$this->mercuryBaseUrl}/graphql", [
                'query' => $mutation,
                'variables' => $variables
            ]);

        if (!$response->successful()) {
            Log::error("Error generating service token", ['status' => $response->status(), 'body' => $response->body()]);
            throw new ServiceAuthenticationException("Failed to generate service token");
        }

        $data = $response->json();
        
        if (isset($data['errors'])) {
            Log::error("GraphQL error generating service token", ['errors' => $data['errors']]);
            throw new ServiceAuthenticationException("Failed to generate service token");
        }

        if (!isset($data['data']['generateServiceToken']['access_token'])) {
            throw new ServiceAuthenticationException("No access token returned from generateServiceToken");
        }

        return $data['data']['generateServiceToken']['access_token'];
    }

    /**
     * Fetches the service UUID from Mercury using the provided access token.
     * @param string $accessToken The access token to authenticate the request
     * @return string The UUID of the registered service
     */
    public function getServiceById(string $accessToken): string
    {
        $mutation = '
            mutation GetRegisteredServiceByClientId($input: GetRegisteredServiceByClientIdInput!) {
                getRegisteredServiceByClientId(input: $input) {
                    uuid
                    is_active
                }
            }
        ';

        $variables = [
            'input' => [
                'client_id' => $this->clientId
            ]
        ];

        $response = Http::timeout(10)
            ->withHeaders([
                'x-project-token' => "Bearer {$accessToken}",
            ])
            ->post("{$this->mercuryBaseUrl}/graphql", [
                'query' => $mutation,
                'variables' => $variables
            ]);

        if (!$response->successful()) {
            Log::error("Error fetching service by ID", ['status' => $response->status(), 'body' => $response->body()]);
            throw new ServiceAuthenticationException("Failed to fetch service by ID");
        }

        $data = $response->json();
        
        if (isset($data['errors'])) {
            Log::error("GraphQL error fetching service by ID", ['errors' => $data['errors']]);
            throw new ServiceAuthenticationException("Failed to fetch service by ID");
        }

        if (!isset($data['data']['getRegisteredServiceByClientId']['uuid'])) {
            throw new ServiceAuthenticationException("No service UUID returned from getRegisteredServiceByClientId");
        }

        return $data['data']['getRegisteredServiceByClientId']['uuid'];
    }
}