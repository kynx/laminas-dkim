<?php

namespace Dkim;

use Dkim\Signer\Signer;
use Dkim\Signer\SignerFactory;

/**
 * @see \DkimTest\ConfigProviderTest
 */
class ConfigProvider
{
    /**
     * Retrieve Dkim default configuration.
     *
     * @return array
     */
    public function __invoke()
    {
        return [
            'dependencies' => $this->getDependencyConfig(),
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
