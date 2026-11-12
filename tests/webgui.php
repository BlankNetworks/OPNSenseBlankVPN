<?php

declare(strict_types=1);

namespace OPNsense\Base {
    final class RequestFixture
    {
        public function __construct(private string $scheme)
        {
        }

        public function getScheme(): string
        {
            return $this->scheme;
        }

        public function isPost(): bool
        {
            return true;
        }

        public function getPost(string $key, ?string $filter, string $default): string
        {
            return $key === 'account' ? '0000000000000000' : $default;
        }
    }

    final class SessionFixture
    {
        private array $data = [];

        public function get(string $key): mixed
        {
            return $this->data[$key] ?? null;
        }

        public function set(string $key, mixed $value): void
        {
            $this->data[$key] = $value;
        }

        public function remove(string $key): void
        {
            unset($this->data[$key]);
        }
    }

    class ApiControllerBase
    {
        protected RequestFixture $request;
        protected SessionFixture $session;
        protected object $response;

        public function __construct(string $scheme)
        {
            $this->request = new RequestFixture($scheme);
            $this->session = new SessionFixture();
            $this->response = new class {
                public function setHeader(string $key, string $value): void
                {
                }
            };
        }

        protected function isExternalClient(): bool
        {
            return false;
        }

        public function getUserName(): string
        {
            return 'test-operator';
        }
    }
}

namespace OPNsense\Core {
    final class Config
    {
        public static function getInstance(): self
        {
            return new self();
        }

        public function object(): object
        {
            return (object)['system' => (object)['webgui' => (object)[]]];
        }
    }
}

namespace OPNsense\BlankVpn {
    final class Mullvad
    {
        public static int $calls = 0;

        public function authenticate(string $account): array
        {
            self::$calls++;
            if ($account !== '0000000000000000') {
                throw new \RuntimeException('Unexpected fixture account.');
            }
            return [
                'token' => 'test-provider-token',
                'expires' => time() + 600,
                'account' => ['maxDevices' => 5]
            ];
        }
    }
}

namespace {
    use OPNsense\BlankVpn\Api\ServiceController;
    use OPNsense\BlankVpn\Mullvad;

    require __DIR__ . '/../src/opnsense/mvc/app/controllers/OPNsense/BlankVpn/Api/ServiceController.php';

    function checkWebGui(bool $value, string $message): void
    {
        if (!$value) {
            throw new RuntimeException($message);
        }
    }

    // OPNsense 26.7 uses its own request wrapper, which exposes getScheme().
    $http = new ServiceController('http');
    $rejected = $http->accountAction();
    checkWebGui(!$rejected['ok'] && str_contains($rejected['error'], 'HTTPS') && Mullvad::$calls === 0,
        'Reject HTTP before contacting the provider and return a specific message.');
    $https = new ServiceController('https');
    $signedIn = $https->accountAction();
    checkWebGui($signedIn === ['ok' => true, 'maxDevices' => 5] && Mullvad::$calls === 1,
        'The native request wrapper must allow HTTPS sign-in without exposing the token.');
    $token = new ReflectionMethod(ServiceController::class, 'mullvadToken');
    checkWebGui($token->invoke($https) === 'test-provider-token', 'Sign-in must retain the token for tunnel creation.');
    checkWebGui($https->logoutMullvadAction()['ok'] && $token->invoke($https) === null,
        'Signing out must remove the provider token.');
    echo "OPNsense WebGUI request and Mullvad session fixtures passed.\n";
}
