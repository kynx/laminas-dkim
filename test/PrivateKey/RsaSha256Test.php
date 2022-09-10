<?php

declare(strict_types=1);

namespace KynxTest\Laminas\Dkim\PrivateKey;

use Kynx\Laminas\Dkim\Exception\InvalidPrivateKeyException;
use Kynx\Laminas\Dkim\PrivateKey\RsaSha256;
use KynxTest\Laminas\Dkim\PrivateKeyTrait;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Kynx\Laminas\Dkim\PrivateKey\RsaSha256
 */
final class RsaSha256Test extends TestCase
{
    use PrivateKeyTrait;

    public function testConstructEmptySelectorThrowsException(): void
    {
        self::expectException(InvalidPrivateKeyException::class);
        self::expectExceptionMessage("Selector cannot be empty");
        new RsaSha256('', 'foo');
    }

    public function testConstructInvalidPrivateKeyThrowsException(): void
    {
        self::expectException(InvalidPrivateKeyException::class);
        self::expectExceptionMessage("Invalid private key");
        new RsaSha256('k1', 'foo');
    }

    public function testCreateSignatureReturnsSignature(): void
    {
        // phpcs:disable Generic.Files.LineLength.TooLong
        $expected = 'nhSrBEqWyOeTx5VAzuUqlcU6bG6i9Q8uTWfEZEr1xw5TJlHbpptiEdyIyI/1N6J+6XIAGikC8 8oHT+Ha+N17iNcAeAa3W8nte9mYGVG0yLy9FDubRLk19OIGf/5Slq3+FRP2+if+we1MaF+9J8 VmhUWrfMXfxkdKnJ60lN99udk=';
        // phpcs:enable
        $privateKey = new RsaSha256('k1', $this->getPrivateKeyString());
        $actual     = $privateKey->createSignature('foo');
        self::assertSame($expected, $actual);
    }

    public function testGetAlgorithm(): void
    {
        $privateKey = new RsaSha256('k1', $this->getPrivateKeyString());
        $actual     = $privateKey->getAlgorithm();
        self::assertSame('rsa-sha256', $actual);
    }

    public function testGetSelector(): void
    {
        $selector   = 'sel1';
        $privateKey = new RsaSha256($selector, $this->getPrivateKeyString());
        $actual     = $privateKey->getSelector();
        self::assertSame($selector, $actual);
    }
}
