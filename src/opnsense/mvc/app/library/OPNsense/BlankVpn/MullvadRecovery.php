<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

/** Bounded recovery for saved Mullvad keys removed outside this plug-in. */
final class MullvadRecovery
{
    private const STATE = 'mullvad-recovery.json';
    private const CHECK_SECONDS = 600;
    private const NEXT_REPAIR_SECONDS = 60;
    private const RETRY_SECONDS = 900;
    private const TRANSIENT_RETRY_SECONDS = 120;
    private const KEY_RETRY_SECONDS = 300;

    public static function status(): array
    {
        $path = Policy::STATE_DIR . '/' . self::STATE;
        $bytes = is_file($path) ? @file_get_contents($path, false, null, 0, 16385) : false;
        $state = is_string($bytes) && strlen($bytes) <= 16384 ? json_decode($bytes, true) : null;
        if (!is_array($state)) {
            return [];
        }
        return [
            'lastChecked' => is_int($state['lastChecked'] ?? null) ? $state['lastChecked'] : 0,
            'nextCheck' => is_int($state['nextCheck'] ?? null) ? $state['nextCheck'] : 0,
            'outcome' => is_string($state['outcome'] ?? null) ? $state['outcome'] : '',
            'attempts' => is_array($state['attempts'] ?? null) ? $state['attempts'] : [],
        ];
    }

    /** Called under the existing once-per-minute maintenance lock. */
    public static function due(BlankVpn $model): bool
    {
        $profiles = array_filter(Policy::profiles($model), static fn (array $profile): bool =>
            ($profile['relay'] ?? '') !== '');
        if ($profiles === []) {
            return false;
        }
        $now = time();
        $state = self::status();
        if (($state['nextCheck'] ?? 0) > $now) {
            return false;
        }
        $attempts = array_filter($state['attempts'] ?? [], static fn ($time): bool =>
            is_int($time) && $time > $now - self::KEY_RETRY_SECONDS && $time <= $now);
        // Record the attempt before contacting Mullvad, so a crash cannot cause an API retry loop.
        $state = ['lastChecked' => $now, 'nextCheck' => $now + self::RETRY_SECONDS,
            'outcome' => 'checking', 'attempts' => $attempts];
        try {
            self::save($state);
            $mullvad = new Mullvad();
            $accounts = $mullvad->savedAccountsForRecovery();
            if ($accounts === []) {
                $state['outcome'] = 'no-saved-login';
                $state['nextCheck'] = $now + self::RETRY_SECONDS;
                self::save($state);
                return false;
            }
            $result = self::reconcile($profiles, $mullvad, $accounts, $attempts,
                static function (string $id, array $profile, array $matched, string $token, Mullvad $provider) use (&$state, $now): void {
                    $state['attempts'][$id] = $now;
                    self::save($state);
                    self::restore($id, $profile, $matched, $token, $provider);
                });
            $state['outcome'] = $result['restored'] !== null ? 'restored'
                : (!$result['matched'] ? 'no-matching-login' : ($result['missing'] ? 'waiting' : 'healthy'));
            $state['nextCheck'] = $now + ($result['restored'] !== null ? self::NEXT_REPAIR_SECONDS
                : (!$result['matched'] ? self::RETRY_SECONDS
                    : ($result['missing'] ? self::TRANSIENT_RETRY_SECONDS : self::CHECK_SECONDS)));
            self::save($state);
            return $result['restored'] !== null;
        } catch (\Throwable $error) {
            // Mullvad can briefly reject a newly removed key with HTTP 400 before accepting
            // the same public key again. Keep the per-key cooldown and retry sooner.
            $transient = $error->getCode() === 400;
            $state['outcome'] = $transient ? 'retrying' : 'error';
            $state['nextCheck'] = $now + ($transient ? self::TRANSIENT_RETRY_SECONDS : self::RETRY_SECONDS);
            try {
                self::save($state);
            } catch (\Throwable) {
                // Keep normal maintenance running when recovery state storage is unavailable.
            }
            syslog(LOG_WARNING, 'Blank VPN could not reconcile saved Mullvad device registrations.');
            return false;
        }
    }

    /** Return one missing key per run, leaving registration and apply to the caller. */
    public static function reconcile(
        array $profiles,
        Mullvad $mullvad,
        array $accounts,
        array $recentAttempts,
        callable $restore
    ): array {
        $missing = false;
        $matchedIds = [];
        $lastError = null;
        foreach ($accounts as $account) {
            try {
                $token = $mullvad->tokenForRecovery($account);
                $matched = $mullvad->routerProfiles($token, $profiles);
            } catch (\RuntimeException $error) {
                $lastError = $error;
                continue;
            }
            // One router key serves every relay. Legacy per-relay keys removed by the
            // owner must not be registered again when this account already has a
            // working router key; those profiles require local consolidation.
            $registeredKey = null;
            foreach ($matched as $candidate) {
                if (!empty($candidate['registered'])) {
                    $registeredKey = $candidate['identityKey'];
                    break;
                }
            }
            foreach ($matched as $id => $profile) {
                $matchedIds[$id] = true;
                if ($profile['registered'] && $profile['identity'] !== '' &&
                    $profile['address'] === $profile['registeredAddress'] &&
                    $profile['address6'] === $profile['registeredAddress6']) {
                    continue;
                }
                $missing = true;
                if ($registeredKey !== null && !hash_equals($registeredKey, $profile['identityKey'])) {
                    continue;
                }
                if (isset($recentAttempts[$id])) {
                    continue;
                }
                $restore($id, $profiles[$id], $profile, $token, $mullvad);
                return ['restored' => $id, 'missing' => true, 'matched' => true];
            }
        }
        if ($matchedIds === [] && $lastError !== null) {
            throw $lastError;
        }
        return ['restored' => null, 'missing' => $missing,
            'matched' => count($matchedIds) === count($profiles)];
    }

    private static function restore(string $id, array $profile, array $matched, string $token, Mullvad $mullvad): void
    {
        // A foreign or edited native WireGuard object must never trigger a provider registration.
        WireGuard::ownedPrivateKey($profile);
        $device = $mullvad->restoreDeviceWithToken($token, $matched);
        if ($profile['identity'] === $device['id'] && $profile['address'] === $device['address'] &&
            $profile['address6'] === $device['address6']) {
            return;
        }
        Operations::change(static function (BlankVpn $model) use ($id, $profile, $device): array {
            $current = Policy::profiles($model)[$id] ?? null;
            if ($current === null || !hash_equals($profile['identityKey'], $current['identityKey'])) {
                throw new \RuntimeException('The saved Mullvad tunnel changed during recovery.');
            }
            $source = explode('/', $device['address'], 2)[0];
            foreach (Policy::localNetworks(Policy::settings($model)) as $network) {
                if (Policy::contains($network, $source)) {
                    throw new \RuntimeException('The restored Mullvad address overlaps a local network.');
                }
            }
            $updated = WireGuard::restoreMullvadDevice($current, $device);
            $ownership = array_diff_key($updated, array_flip(['id', 'name', 'relay']));
            $model->profiles->profile->getChild($id)->ownership =
                json_encode($ownership, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
            $health = Firewall::health();
            unset($health[$id]);
            Policy::writeState('health.json', json_encode($health, JSON_THROW_ON_ERROR));
            return empty($current['disabled']) ? ['added' => $ownership, 'reload' => true] : ['reload' => true];
        });
        try {
            $route = Policy::routes(new BlankVpn())[$id] ?? null;
            if ($route !== null) {
                $loaded = Firewall::loadedRules() ?? [];
                $targets = Firewall::probePathsInstalled($route, $loaded, Firewall::loadedNat());
                if (count($targets) === count(Policy::PROBE_TARGETS) &&
                    WireGuard::probe($route, $targets)['reachable'] === true) {
                    Operations::recordSuccessfulProbe(new BlankVpn(), $route);
                }
            }
        } catch (\Throwable) {
            // Registration and native apply succeeded; a later protected probe can verify it.
            syslog(LOG_WARNING, 'Blank VPN restored a Mullvad device but could not verify its tunnel yet.');
        }
    }

    private static function save(array $state): void
    {
        Policy::writeState(self::STATE, json_encode($state, JSON_THROW_ON_ERROR));
    }
}
