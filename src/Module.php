<?php

namespace Kynx\Laminas\Dkim;

/**
 * @see \KynxTest\Laminas\Dkim\ModuleTest
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
