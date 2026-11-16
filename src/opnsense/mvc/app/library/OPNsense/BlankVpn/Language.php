<?php

namespace OPNsense\BlankVpn;

use OPNsense\Core\Config;

/** Follow the WebGUI language list instead of maintaining a second locale allowlist. */
class Language
{
    private const STRINGS = [
        'Sign in', 'Sign in and save', 'Sign out', 'Save', 'Apply', 'Refresh',
        'Country', 'City', 'Server', 'Choose a server', 'Refresh servers',
        'Use saved login', 'Save login on this router', 'Check approval',
        'Approve sign-in', 'Authenticator code', 'Mullvad account number',
        'Signing in to Mullvad…', 'Reconnecting saved Mullvad login…',
        'Signed in to Mullvad.', 'Mullvad sign-in completed.',
        'VPN login saved.', 'IVPN sign-in checked.', 'Mysterium VPN sign-in checked.',
        'Mysterium approval link created.', 'Login saved on this router.',
        'Open the OPNsense WebGUI over HTTPS to sign in.',
        'Sign in to load the provider’s WireGuard servers.',
        'Approve the sign-in in Mysterium VPN, then select Check approval.',
        'The approval link expired. Sign in again.',
        'Enter the 16-digit Mullvad account number.'
    ];

    public static function resolve(string $configured, array $available): string
    {
        return isset($available[$configured]) ? $configured : (isset($available['en_US']) ? 'en_US' : ((string)array_key_first($available) ?: 'en_US'));
    }

    public static function dashboard(): array
    {
        if (!function_exists('get_locale_list')) {
            require_once 'system.inc';
        }
        $available = function_exists('get_locale_list') ? get_locale_list() : ['en_US' => 'English'];
        $configured = (string)(Config::getInstance()->object()->system->language ?? 'en_US');
        $locale = self::resolve($configured, $available);
        $translations = [];
        foreach (self::STRINGS as $source) {
            $translations[$source] = gettext($source);
        }
        return ['locale' => $locale, 'available' => $available, 'translations' => $translations];
    }
}
