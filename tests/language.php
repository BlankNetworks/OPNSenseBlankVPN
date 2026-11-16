<?php

namespace OPNsense\Core {
    class Config
    {
        public static function getInstance(): self
        {
            return new self();
        }

        public function object(): object
        {
            return (object)['system' => (object)['language' => 'ja_JP']];
        }
    }
}

namespace {
    function get_locale_list(): array
    {
        return ['en_US' => 'English', 'fr_FR' => 'French', 'ja_JP' => 'Japanese', 'fa_IR' => 'Persian'];
    }

    require_once __DIR__ . '/../src/opnsense/mvc/app/library/OPNsense/BlankVpn/Language.php';

    $available = get_locale_list();
    foreach (['fr_FR' => 'fr_FR', 'ja_JP' => 'ja_JP', 'fa_IR' => 'fa_IR',
        'default' => 'en_US', 'unsupported' => 'en_US'] as $configured => $expected) {
        if (\OPNsense\BlankVpn\Language::resolve($configured, $available) !== $expected) {
            throw new \RuntimeException("Wrong locale selected for $configured");
        }
    }
    if (\OPNsense\BlankVpn\Language::resolve('default', []) !== 'en_US') {
        throw new \RuntimeException('Empty locale lists must fall back to English');
    }
    $dashboard = \OPNsense\BlankVpn\Language::dashboard();
    if ($dashboard['locale'] !== 'ja_JP' || $dashboard['available'] !== $available ||
        !isset($dashboard['translations']['Sign in'])) {
        throw new \RuntimeException('Dashboard language catalog did not follow OPNsense');
    }
    echo "Language selection: PASS\n";
}
