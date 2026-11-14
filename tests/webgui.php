<?php

declare(strict_types=1);

namespace OPNsense\Base {
    final class RequestFixture
    {
        public function __construct(private string $scheme, private array $fields, private bool $post)
        {
        }

        public function getScheme(): string
        {
            return $this->scheme;
        }

        public function isPost(): bool
        {
            return $this->post;
        }

        public function isGet(): bool
        {
            return !$this->post;
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

    class UserException extends \RuntimeException
    {
    }

    class ApiControllerBase
    {
        protected RequestFixture $request;
        protected SessionFixture $session;
        protected object $response;

        public function __construct(
            string $scheme,
            array $fields = [],
            private string $user = 'test-operator',
            bool $post = true
        ) {
            $this->request = new RequestFixture($scheme, $fields, $post);
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

        protected function throwReadOnly(): void
        {
            if ($this->user === 'readonly') {
                throw new UserException('Read-only WebGUI session.');
            }
        }

        protected function throwNotFullAdmin(): void
        {
            if ($this->user !== 'admin') {
                throw new UserException('Full administrator required.');
            }
        }
    }
}

namespace OPNsense\Core {
    final class Backend
    {
        public static array $calls = [];

        public function configdpRun(string $action, array $arguments, bool $async, int $timeout): string
        {
            self::$calls[] = [$action, $arguments, $async, $timeout];
            return '{"ok":true,"enabled":true,"available":"0.8.16"}';
        }
    }

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
    final class PackageUpdate
    {
        public static function status(): array
        {
            return ['installed' => '0.8.15', 'enabled' => false];
        }
    }

    final class Operations
    {
        public static function exclusive(callable $operation): mixed
        {
            return $operation();
        }
    }

    final class WireGuard
    {
        public static function pingRelay(string $address): array
        {
            if ($address !== '8.8.8.8') {
                throw new \RuntimeException('Unexpected ping target.');
            }
            return ['replied' => true, 'milliseconds' => 12.345];
        }
    }

    final class ProxyRuntime
    {
        public static function testNode(string $id): array
        {
            if ($id === 'unexpected') {
                throw new \Error('Fixture detail that must stay server-side.');
            }
            throw new \RuntimeException('Proxy connection timed out.');
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
    use OPNsense\BlankVpn\Api\UpdateController;
    use OPNsense\BlankVpn\Mullvad;
    use OPNsense\Core\Backend;

    require __DIR__ . '/../src/opnsense/mvc/app/controllers/OPNsense/BlankVpn/Api/ServiceController.php';
    require __DIR__ . '/../src/opnsense/mvc/app/controllers/OPNsense/BlankVpn/Api/UpdateController.php';

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
    $failedProxy = (new ServiceController('https', ['id' => 'offline']))->testProxyNodeAction();
    checkWebGui($failedProxy === ['ok' => false, 'error' => 'Proxy connection timed out.'],
        'An expected proxy failure must be returned to the server row.');
    $unexpected = (new ServiceController('https', ['id' => 'unexpected']))->testProxyNodeAction();
    checkWebGui($unexpected['ok'] === false && str_contains($unexpected['error'], 'Log reference') &&
        !str_contains($unexpected['error'], 'Fixture detail'), 'Unexpected proxy errors must return a reference without crashing.');

    $updateStatus = (new UpdateController('https', [], 'admin', false))->statusAction();
    checkWebGui($updateStatus === ['installed' => '0.8.15', 'enabled' => false, 'ok' => true] && Backend::$calls === [],
        'Reading update status must not invoke configd or enable the repository.');
    foreach ([
        new UpdateController('https', [], 'admin', false),
        new UpdateController('http', [], 'admin'),
        new UpdateController('https', [], 'readonly'),
        new UpdateController('https'),
    ] as $session) {
        checkWebGui(!$session->checkAction()['ok'] && Backend::$calls === [],
            'Only a full administrator making an HTTPS POST can ask configd to check for an update.');
    }
    $checked = (new UpdateController('https', [], 'admin'))->checkAction();
    checkWebGui($checked === ['ok' => true, 'enabled' => true, 'available' => '0.8.16'] &&
        Backend::$calls === [['blankvpnupdate check', [], false, 40]],
        'An explicit check must use one configd action and report the available release.');
    echo "OPNsense WebGUI request, Mullvad session and package update fixtures passed.\n";
}
