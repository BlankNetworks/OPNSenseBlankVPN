<?php

namespace OPNsense\BlankVpn;

use OPNsense\Base\IndexController as BaseIndexController;

class IndexController extends BaseIndexController
{
    public function indexAction()
    {
        $this->view->pick('OPNsense/BlankVpn/index');
    }
}
