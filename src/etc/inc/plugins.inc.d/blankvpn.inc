<?php

function blankvpn_firewall($firewall)
{
    \OPNsense\BlankVpn\Firewall::installRules($firewall);
}
