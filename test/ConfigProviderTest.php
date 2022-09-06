<?php

declare(strict_types=1);

namespace DkimTest;

use Dkim\ConfigProvider;
use Dkim\Signer\Signer;
use Dkim\Signer\SignerFactory;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Dkim\ConfigProvider
 */
final class ConfigProviderTest extends TestCase
{
    public function testInvokeReturnsConfig(): void
    {
        $expected = [
            'dependencies' => [
                'factories' => [
                    Signer::class => SignerFactory::class,
                ],
                'aliases'   => [
                    'DkimSigner' => Signer::class,
                ],
            ],
        ];

        $configProvider = new ConfigProvider();
        $actual         = $configProvider();
        self::assertSame($expected, $actual);
    }
}
