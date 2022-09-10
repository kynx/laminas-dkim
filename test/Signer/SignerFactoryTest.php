<?php

declare(strict_types=1);

namespace KynxTest\Laminas\Dkim\Signer;

use Exception;
use Kynx\Laminas\Dkim\Signer\Signer;
use Kynx\Laminas\Dkim\Signer\SignerFactory;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

/**
 * @uses \Kynx\Laminas\Dkim\Signer\Signer
 *
 * @covers \Kynx\Laminas\Dkim\Signer\SignerFactory
 */
final class SignerFactoryTest extends TestCase
{
    public function testInvokeMissingConfigThrowsException(): void
    {
        $container = $this->createStub(ContainerInterface::class);
        $container->method('get')
            ->with('config')
            ->willReturn([]);

        $factory = new SignerFactory();
        self::expectException(Exception::class);
        self::expectExceptionMessage("No 'dkim' config option set.");
        $factory($container, Signer::class);
    }

    public function testInvokeReturnsInstance(): void
    {
        $container = $this->createStub(ContainerInterface::class);
        $container->method('get')
            ->with('config')
            ->willReturn(['dkim' => []]);

        $factory = new SignerFactory();
        $actual  = $factory($container, Signer::class);
        self::assertInstanceOf(Signer::class, $actual);
    }
}
