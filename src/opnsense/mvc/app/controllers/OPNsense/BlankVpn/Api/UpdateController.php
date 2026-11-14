<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn\Api;

use DomainException;
use OPNsense\Base\ApiControllerBase;
use OPNsense\BlankVpn\PackageUpdate;
use OPNsense\Core\Backend;
use RuntimeException;

final class UpdateController extends ApiControllerBase
{
    public function statusAction(): array
    {
        return $this->respond(false, static fn (): array => PackageUpdate::status());
    }

    public function enableAction(): array
    {
        return $this->respond(true, fn (): array => $this->run('enable'));
    }

    public function checkAction(): array
    {
        return $this->respond(true, fn (): array => $this->run('check', [], 40));
    }

    public function applyAction(): array
    {
        return $this->respond(true, function (): array {
            $version = $this->request->getPost('version');
            if (!PackageUpdate::validVersion($version)) {
                throw new DomainException('Choose an available Blank VPN version.');
            }
            $this->getLogger('audit')->notice(sprintf('[Blank VPN] %s requested package update %s', $this->getUserName(), $version));
            return $this->run('apply', [$version]);
        });
    }

    private function run(string $action, array $arguments = [], int $timeout = 12): array
    {
        $response = (new Backend())->configdpRun('blankvpnupdate ' . $action, $arguments, false, $timeout);
        $result = json_decode(trim($response), true);
        if (!is_array($result) || !is_bool($result['ok'] ?? null)) {
            throw new RuntimeException('The package update service did not respond. Refresh status and try again.');
        }
        return $result;
    }

    private function respond(bool $post, callable $operation): array
    {
        $this->response->setHeader('Cache-Control', 'no-store');
        try {
            if ($this->request->getScheme() !== 'https' || $this->isExternalClient() ||
                !is_string($this->getUserName()) || $this->getUserName() === '' ||
                ($post ? !$this->request->isPost() : !$this->request->isGet())) {
                throw new DomainException('Open the OPNsense WebGUI over HTTPS to manage package updates.');
            }
            if ($post) {
                $this->throwReadOnly();
                $this->throwNotFullAdmin();
            }
            $result = $operation();
            return $result + ['ok' => true];
        } catch (DomainException | RuntimeException | \OPNsense\Base\UserException $error) {
            return ['ok' => false, 'error' => $error->getMessage()];
        } catch (\Throwable $error) {
            syslog(LOG_ERR, 'Blank VPN update service failed: ' . $error::class);
            return ['ok' => false, 'error' => 'The package update operation could not be verified. Check the router log.'];
        }
    }
}
