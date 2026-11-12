<?php

namespace OPNsense\BlankVpn\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\BlankVpn\Operations;
use OPNsense\BlankVpn\Policy;
use OPNsense\BlankVpn\ProxyCores;

final class CoreController extends ApiControllerBase
{
    public function statusAction(): array
    {
        return $this->respond(static function (): void {}, false);
    }

    public function checkAction(): array
    {
        return $this->respond(static fn () => ProxyCores::refresh());
    }

    public function installAction(): array
    {
        return $this->respond(function () {
            $core = $this->field('core', '/^[a-z0-9-]{1,12}$/D');
            $digest = $this->field('digest', '/^[0-9a-f]{64}$/D');
            $path = null;
            if ($this->request->getPost('upload') === '1') {
                $file = $_FILES['archive'] ?? [];
                $path = $file['tmp_name'] ?? null;
                if (($file['error'] ?? null) !== UPLOAD_ERR_OK || !is_string($path) ||
                    !is_uploaded_file($path) || ($file['size'] ?? 0) > 100 * 1024 * 1024) {
                    throw new \DomainException('The archive was not received. Try the root CLI if the WebGUI upload limit is lower.');
                }
            }
            ProxyCores::install($core, $path, $digest);
        });
    }

    public function rollbackAction(): array
    {
        return $this->respond(fn () => ProxyCores::rollback($this->field('core', '/^[a-z0-9-]{1,12}$/D')));
    }

    private function field(string $name, string $pattern): string
    {
        $value = $this->request->getPost($name);
        if (!is_string($value) || !preg_match($pattern, $value)) {
            throw new \DomainException('The requested core or release checksum is invalid.');
        }
        return $value;
    }

    private function respond(callable $operation, bool $post = true): array
    {
        $this->response->setHeader('Cache-Control', 'no-store');
        try {
            if (!$this->request->isSecure() || ($post && !$this->request->isPost()) ||
                !function_exists('posix_geteuid') || posix_geteuid() !== 0) {
                throw new \DomainException('Open the standard OPNsense WebGUI over HTTPS to manage cores.');
            }
            Policy::stateDirectory();
            if ($post) {
                Operations::exclusive($operation);
            }
            return ['ok' => true] + ProxyCores::status();
        } catch (\DomainException $error) {
            return ['ok' => false, 'error' => $error->getMessage()];
        } catch (\Throwable $error) {
            syslog(LOG_ERR, 'Blank VPN core management failed: ' . $error::class);
            return ['ok' => false, 'error' => 'The core operation could not be verified. Check the router log and refresh status.'];
        }
    }
}
