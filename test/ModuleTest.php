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
