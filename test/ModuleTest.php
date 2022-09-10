<?php

declare(strict_types=1);

namespace DkimTest;

use Dkim\Module;
use Dkim\Signer\Signer;
use Dkim\Signer\SignerFactory;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Dkim\Module
 */
final class ModuleTest extends TestCase
{
    public function testGetConfigReturnsConfig(): void
    {
        $expected = [
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
