<?php

namespace Kynx\Laminas\Dkim;

/**
 * @see \KynxTest\Laminas\Dkim\ModuleTest
 */
final class Module
{
    public function getConfig(): array
    {
        $provider = new ConfigProvider();

        return [
            'service_manager' => $provider->getDependencyConfig(),
        ];
    }
}
