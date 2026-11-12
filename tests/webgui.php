<?php

declare(strict_types=1);

namespace OPNsense\Base {
    final class RequestFixture
    {
        public function __construct(private string $scheme, private array $fields)
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

        public function getPost(string $key, ?string $filter = null, mixed $default = null): mixed
        {
            return $this->fields[$key] ?? ($key === 'account' ? '0000000000000000' : $default);
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

        public function __construct(string $scheme, array $fields = [], private string $user = 'test-operator')
        {
            $this->request = new RequestFixture($scheme, $fields);
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
            return $this->user;
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
    final class Operations
    {
        public static function exclusive(callable $operation): mixed
        {
            return $operation();
        }
    }

    final class Resolver
    {
        public static function command(array $command, bool $required): string
        {
            if ($command !== ['/sbin/ping', '-n', '-c', '1', '-W', '1500', '-t', '3', '8.8.8.8']) {
                throw new \RuntimeException('Unexpected ping target or arguments.');
            }
            return '64 bytes from 8.8.8.8: icmp_seq=0 ttl=115 time=12.345 ms';
        }
    }

    final class Mullvad
    {
        public static int $calls = 0;
        private static array $saved = [];

        public function relays(): array
        {
            return ['relays' => [['id' => 'ca-test-wg-001', 'ipv4' => '8.8.8.8', 'active' => true]]];
        }

        public function saveAccount(string $user, ?string $account): void
        {
            self::$saved[$user] = $account;
        }

        public function savedAccount(string $user): ?string
        {
            return self::$saved[$user] ?? null;
        }

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
    checkWebGui($signedIn === ['ok' => true, 'maxDevices' => 5, 'saved' => false] && Mullvad::$calls === 1,
        'The native request wrapper must allow HTTPS sign-in without exposing the token.');
    $token = new ReflectionMethod(ServiceController::class, 'mullvadToken');
    checkWebGui($token->invoke($https) === 'test-provider-token', 'Sign-in must retain the token for tunnel creation.');
    checkWebGui($https->logoutMullvadAction()['ok'] && $token->invoke($https) === null,
        'Signing out must remove the provider token.');
    checkWebGui(!$https->restoreMullvadAction()['ok'], 'Temporary login must not be saved.');
    $remember = new ServiceController('https', ['saveLogin' => true]);
    checkWebGui($remember->accountAction()['saved'] === true, 'Save login must be explicitly requested.');
    $nextSession = new ServiceController('https');
    checkWebGui($nextSession->restoreMullvadAction()['saved'] === true && $token->invoke($nextSession) === 'test-provider-token',
        'A new WebGUI session must restore and reauthenticate its saved login.');
    $otherUser = new ServiceController('https', [], 'another-operator');
    checkWebGui(!$otherUser->restoreMullvadAction()['ok'], 'Another user must not inherit a saved credential.');
    $nextSession->logoutMullvadAction();
    checkWebGui(!$nextSession->restoreMullvadAction()['ok'], 'Sign-out must forget the saved credential.');
    $ping = new ServiceController('https', ['relay' => 'ca-test-wg-001']);
    checkWebGui($ping->testRelayAction() === ['ok' => true, 'relay' => 'ca-test-wg-001', 'replied' => true, 'milliseconds' => 12.345],
        'The ping must use a catalog IP and report its latency.');
    $unknown = new ServiceController('https', ['relay' => '127.0.0.1']);
    checkWebGui(!$unknown->testRelayAction()['ok'], 'The relay test must reject caller-supplied destinations.');
    echo "OPNsense WebGUI request and Mullvad session fixtures passed.\n";
}
