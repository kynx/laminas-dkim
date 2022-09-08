<?php

declare(strict_types=1);

namespace KynxTest\Laminas\Dkim;

use Kynx\Laminas\Dkim\Module;
use Kynx\Laminas\Dkim\Signer\Params;
use Kynx\Laminas\Dkim\Signer\Signer;
use Kynx\Laminas\Dkim\Signer\SignerFactory;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Kynx\Laminas\Dkim\Module
 */
final class ModuleTest extends TestCase
{
    public function testGetConfigReturnsConfig(): void
    {
        $expected = [
            'dkim'            => [
                'params' => [
                    'domain'           => '',
                    'canonicalization' => Params::RELAXED_SIMPLE,
                    'identifier'       => '',
                ],
            ],
            'service_manager' => [
                'factories' => [
                    Signer::class => SignerFactory::class,
                ],
                'aliases'   => [
                    'DkimSigner' => Signer::class,
                ],
            ],
        ];

        $module = new Module();
        $actual = $module->getConfig();
        self::assertSame($expected, $actual);
    }
}
