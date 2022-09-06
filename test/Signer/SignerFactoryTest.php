<?php

declare(strict_types=1);

namespace DkimTest\Signer;

use Dkim\Signer\Signer;
use Dkim\Signer\SignerFactory;
use Exception;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

/**
 * @uses \Dkim\Signer\Signer
 *
 * @covers \Dkim\Signer\SignerFactory
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
