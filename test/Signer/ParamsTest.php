<?php

declare(strict_types=1);

namespace KynxTest\Laminas\Dkim\Signer;

use Kynx\Laminas\Dkim\Exception\InvalidParamException;
use Kynx\Laminas\Dkim\Signer\Params;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Kynx\Laminas\Dkim\Signer\Params
 */
final class ParamsTest extends TestCase
{
    public function testConstructorSetsParams(): void
    {
        $domain           = 'example.com';
        $headers          = ['date', 'from', 'subject'];
        $canonicalization = Params::RELAXED_SIMPLE;
        $identifier       = 'foo@example.com';

        $params = new Params($domain, $headers, $canonicalization, $identifier);
        self::assertSame($domain, $params->getDomain());
        self::assertSame($headers, $params->getHeaders());
        self::assertSame($canonicalization, $params->getCanonicalization());
        self::assertSame($identifier, $params->getIdentifier());
    }

    public function testConstructorSetsDefaults(): void
    {
        $expectedHeaders = ['date', 'from', 'reply-to', 'sender', 'subject'];

        $params = new Params('example.com');
        self::assertSame($expectedHeaders, $params->getHeaders());
        self::assertSame(Params::RELAXED_SIMPLE, $params->getCanonicalization());
        self::assertSame('', $params->getIdentifier());
        self::assertSame(1, $params->getVersion());
        self::assertSame('rsa-sha256', $params->getAlgorithm());
    }

    public function testConstructorAddsFromToHeaders(): void
    {
        $params = new Params('example.com', []);
        self::assertSame(['from'], $params->getHeaders());
    }

    public function testConstructorEmptyDomainThrowsException(): void
    {
        self::expectException(InvalidParamException::class);
        self::expectExceptionMessage("Domain cannot be empty");
        new Params('');
    }

    public function testConstructorInvalidCanonicalizationThrowsException(): void
    {
        self::expectException(InvalidParamException::class);
        self::expectExceptionMessage("Only 'relaxed/simple' canonicalization supported");
        new Params('example.com', ['from'], Params::RELAXED_RELAXED);
    }
}
