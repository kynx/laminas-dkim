<?php

declare(strict_types=1);

namespace KynxTest\Laminas\Dkim;

use Kynx\Laminas\Dkim\ConfigProvider;
use Kynx\Laminas\Dkim\Signer\Params;
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
            'dkim'         => [
                'params' => [
                    'domain'           => '',
                    'headers'          => [
                        'CC',
                        'Content-Type',
                        'Date',
                        'From',
                        'MIME-Version',
                        'Reply-To',
                        'Subject',
                        'To',
                    ],
                    'canonicalization' => Params::RELAXED_RELAXED,
                    'identifier'       => '',
                ],
            ],
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
