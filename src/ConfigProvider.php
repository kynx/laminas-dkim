<?php

namespace Kynx\Laminas\Dkim;

use Kynx\Laminas\Dkim\Signer\Signer;
use Kynx\Laminas\Dkim\Signer\SignerFactory;

/**
 * @see \KynxTest\Laminas\Dkim\ConfigProviderTest
 */
final class ConfigProvider
{
    /**
     * Retrieve Dkim default configuration.
     *
     * @return array
     */
    public function __invoke()
    {
        return [
            'dkim'         => $this->getDkimConfig(),
            'dependencies' => $this->getDependencyConfig(),
        ];
    }

    public function getDkimConfig(): array
    {
        return [
            'params' => [
                'domain'           => '', // _must_ be set in config.local.php
                'canonicalization' => 'relaxed/simple',
                'identifier'       => '',
            ],
        ];
    }

    /**
     * Retrieve Dkim default dependency configuration.
     */
    public function getDependencyConfig(): array
    {
        return [
            'factories' => [
                Signer::class => SignerFactory::class,
            ],
            'aliases'   => [
                'DkimSigner' => Signer::class,
            ],
        ];
    }
}
