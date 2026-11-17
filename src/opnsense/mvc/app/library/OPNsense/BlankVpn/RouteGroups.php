<?php

declare(strict_types=1);

namespace OPNsense\BlankVpn;

use DomainException;

/** Ordered, named sets of saved exits used by routing policy. */
final class RouteGroups
{
    private const PREFIX = 'group-';
    private const MAX_GROUPS = 128;
    private const MAX_MEMBERS = 128;
    private const ACTIVE_FILE = 'route-groups.json';

    public static function all(BlankVpn $model): array
    {
        $groups = [];
        if (!isset($model->groups)) {
            return [];
        }
        foreach ($model->groups->group->iterateItems() as $rawId => $node) {
            $id = self::PREFIX . $rawId;
            $row = Policy::fields($node);
            $members = json_decode($row['members'] ?? '', true);
            $groups[$id] = [
                'id' => (string)$id,
                'name' => $row['name'] ?? '',
                'members' => is_array($members) ? array_values(array_filter($members, 'is_string')) : []
            ];
        }
        return $groups;
    }

    public static function isId(string $id): bool
    {
        return preg_match('/^group-[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/D', $id) === 1;
    }

    /** Validate a saved group and preserve member order as failover priority. */
    public static function validate(string $name, array $members, array $routes): array
    {
        $name = trim($name);
        if ($name === '' || strlen($name) > 80 || preg_match('/[\p{C}<>]/u', $name)) {
            throw new DomainException('Enter a group name of up to 80 characters.');
        }
        if ($members === [] || count($members) > self::MAX_MEMBERS) {
            throw new DomainException('Select between 1 and 128 VPN or proxy servers for this group.');
        }
        $ordered = [];
        foreach ($members as $member) {
            if (!is_string($member) || !isset($routes[$member]) || isset($ordered[$member])) {
                throw new DomainException('A group contains a duplicate or unavailable server. Refresh the list and try again.');
            }
            $route = $routes[$member];
            if (!SmartRouting::canResolve($route)) {
                throw new DomainException('Every VPN server in a routing group must have an IPv4 DNS resolver.');
            }
            $ordered[$member] = true;
        }
        return ['name' => $name, 'members' => array_keys($ordered)];
    }

    public static function save(BlankVpn $model, ?string $id, string $name, array $members, array $routes): string
    {
        $groups = self::all($model);
        if ($id === null || $id === '') {
            if (count($groups) >= self::MAX_GROUPS) {
                throw new DomainException('The maximum of 128 saved groups has been reached.');
            }
            $node = $model->groups->group->add();
            $id = self::PREFIX . (string)$node->getAttribute('uuid');
        } elseif (!self::isId($id) || !isset($groups[$id])) {
            throw new DomainException('This server group changed. Refresh the page and try again.');
        } else {
            $node = $model->groups->group->getChild(substr($id, strlen(self::PREFIX)));
        }
        $group = self::validate($name, $members, $routes);
        $node->name = $group['name'];
        $node->members = json_encode($group['members'], JSON_THROW_ON_ERROR);
        return $id;
    }

    /** Return logical group routes, retaining the real member ID for health/state tracking. */
    public static function aliases(
        BlankVpn $model,
        array $routes,
        array $health,
        bool $requireOwned = false,
        ?int $minute = null,
        bool $persist = true
    ): array
    {
        $aliases = [];
        $active = $persist ? self::activeState() : [];
        $changed = false;
        foreach (self::all($model) as $id => $group) {
            $current = is_string($active[$id] ?? null) ? $active[$id] : null;
            $member = self::nextUsable($group['members'], $routes, $health, $current, $requireOwned);
            if ($member !== null) {
                if ($persist && $current !== $member) {
                    $active[$id] = $member;
                    $changed = true;
                }
                $route = $routes[$member];
            } else {
                // Keep a failed member in the logical route so PF can hold the
                // Kill Switch while maintenance probes the group for recovery.
                $candidates = array_values(array_filter($group['members'], static function (string $candidate) use ($routes, $requireOwned): bool {
                    return isset($routes[$candidate]) && (!$requireOwned || !empty($routes[$candidate]['owned']));
                }));
                if ($candidates === []) {
                    continue;
                }
                $probeIndex = ($minute ?? (int)gmdate('i')) % count($candidates);
                $route = $routes[$candidates[$probeIndex]];
            }
            $route['groupId'] = $id;
            $route['groupName'] = $group['name'];
            $aliases[$id] = $route;
        }
        if ($persist && $changed) {
            Policy::writeState(self::ACTIVE_FILE, json_encode($active, JSON_THROW_ON_ERROR));
        }
        return $aliases;
    }

    /** Keep a live member selected until it fails; then advance in saved order. */
    public static function nextUsable(
        array $members,
        array $routes,
        array $health,
        ?string $current = null,
        bool $requireOwned = false
    ): ?string {
        if ($members === []) {
            return null;
        }
        $currentIndex = $current === null ? -1 : array_search($current, $members, true);
        if ($currentIndex === false) {
            $currentIndex = -1;
        }
        if ($currentIndex >= 0) {
            $route = $routes[$current] ?? null;
            if ($route !== null && (!$requireOwned || !empty($route['owned'])) &&
                (($health[$current]['reachable'] ?? true) !== false)) {
                return $current;
            }
        }
        for ($offset = 1; $offset <= count($members); $offset++) {
            $member = $members[($currentIndex + $offset) % count($members)];
            $route = $routes[$member] ?? null;
            if ($route === null || ($requireOwned && empty($route['owned'])) ||
                (($health[$member]['reachable'] ?? true) === false)) {
                continue;
            }
            return $member;
        }
        return null;
    }

    private static function activeState(): array
    {
        if (is_link(Policy::STATE_DIR) || !is_dir(Policy::STATE_DIR)) {
            return [];
        }
        $path = Policy::STATE_DIR . '/' . self::ACTIVE_FILE;
        if (!is_file($path) || is_link($path)) {
            return [];
        }
        $raw = @file_get_contents($path);
        $state = is_string($raw) ? json_decode($raw, true) : null;
        return is_array($state) ? $state : [];
    }

    public static function expand(array $choices, array $groups): array
    {
        $result = [];
        foreach ($choices as $choice) {
            if (isset($groups[$choice])) {
                array_push($result, ...$groups[$choice]['members']);
            } else {
                $result[] = $choice;
            }
        }
        return array_values(array_unique($result));
    }

    /** Resolve logical destinations to their current member for health probing. */
    public static function activeIds(BlankVpn $model, array $choices): array
    {
        $routes = Policy::routes($model, false);
        $aliases = self::aliases($model, $routes, Firewall::health());
        foreach ($choices as $key => $choice) {
            if (isset($aliases[$choice])) {
                $choices[$key] = $aliases[$choice]['id'];
            }
        }
        return array_values(array_unique($choices));
    }

    public static function failedChoice(array $groups, string $choice, array $failed): bool
    {
        if (in_array($choice, $failed, true)) {
            return true;
        }
        $group = $groups[$choice] ?? null;
        return $group !== null && array_intersect($group['members'], $failed) !== [];
    }

    public static function resetActive(string $id): void
    {
        $active = self::activeState();
        if (!array_key_exists($id, $active)) {
            return;
        }
        unset($active[$id]);
        Policy::writeState(self::ACTIVE_FILE, json_encode($active, JSON_THROW_ON_ERROR));
    }
}
