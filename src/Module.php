<?php

namespace Dkim;

/**
 * @see \DkimTest\ModuleTest
 */
class Module
{
    public function getConfig(): array
    {
        $provider = new ConfigProvider();

        return [
            'service_manager' => $provider->getDependencyConfig(),
        ];
    }
}
