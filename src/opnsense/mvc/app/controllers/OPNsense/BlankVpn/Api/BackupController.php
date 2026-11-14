<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn\Api;

use DomainException;
use OPNsense\Base\ApiControllerBase;
use OPNsense\BlankVpn\BlankVpn;
use OPNsense\BlankVpn\Operations;
use OPNsense\BlankVpn\RoutingBackup;
use OPNsense\Core\Config;
use RuntimeException;

final class BackupController extends ApiControllerBase
{
    public function exportAction(): array
    {
        return $this->respond(static fn (): array => ['backup' => RoutingBackup::export(new BlankVpn())]);
    }

    public function previewAction(): array
    {
        return $this->respond(fn (string $user): array => RoutingBackup::preview(new BlankVpn(), $this->backupInput(), $user));
    }

    public function restoreAction(): array
    {
        return $this->respond(function (string $user): array {
            $backup = $this->backupInput();
            $token = $this->request->getPost('confirmation');
            if (!is_string($token) || !preg_match('/^[0-9a-f]{64}$/D', $token)) {
                throw new DomainException('Preview this settings file before confirming restore.');
            }
            return Operations::change(static fn (BlankVpn $model): array => RoutingBackup::restore($model, $backup, $user, $token));
        });
    }

    private function backupInput(): string
    {
        $backup = $this->request->getPost('backup');
        if (!is_string($backup) || $backup === '' || strlen($backup) > RoutingBackup::MAX_BYTES) {
            throw new DomainException('Choose a Blank VPN settings backup of up to 2 MiB.');
        }
        return $backup;
    }

    private function respond(callable $operation): array
    {
        $this->response->setHeader('Cache-Control', 'no-store');
        try {
            $user = $this->getUserName();
            if (!$this->request->isPost() || $this->request->getScheme() !== 'https' || $this->isExternalClient() ||
                !is_string($user) || $user === '' || isset(Config::getInstance()->object()->system->webgui->noroot) ||
                is_file('/var/run/www_non_root')) {
                throw new DomainException('Open the standard OPNsense WebGUI over HTTPS to manage backups.');
            }
            $this->throwReadOnly();
            return ['ok' => true] + Operations::exclusive(static fn (): array => $operation($user));
        } catch (DomainException | \InvalidArgumentException | \OPNsense\Base\UserException $error) {
            return ['ok' => false, 'error' => $error->getMessage()];
        } catch (RuntimeException $error) {
            if ($error::class === RuntimeException::class) {
                return ['ok' => false, 'error' => $error->getMessage()];
            }
            return ['ok' => false, 'error' => 'Blank VPN could not verify the settings backup.'];
        } catch (\Throwable $error) {
            syslog(LOG_ERR, 'Blank VPN backup operation failed: ' . $error::class . ' at ' .
                basename($error->getFile()) . ':' . $error->getLine());
            return ['ok' => false, 'error' => 'The backup operation could not be completed. Check the router log.'];
        }
    }
}
