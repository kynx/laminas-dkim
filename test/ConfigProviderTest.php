<?php

declare(strict_types=1);

namespace KynxTest\Laminas\Dkim;

use Kynx\Laminas\Dkim\ConfigProvider;
use Kynx\Laminas\Dkim\Signer\Signer;
use Kynx\Laminas\Dkim\Signer\SignerFactory;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Kynx\Laminas\Dkim\ConfigProvider
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
