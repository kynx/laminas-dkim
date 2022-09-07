<?php

declare(strict_types=1);

namespace KynxTest\Laminas\Dkim\Header;

use Kynx\Laminas\Dkim\Header\Dkim;
use Laminas\Mail\Header\Exception\InvalidArgumentException;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Kynx\Laminas\Dkim\Header\Dkim
 */
final class DkimTest extends TestCase
{
    private const DKIM = "v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=foo; t=1662112117; "
        . "i=@example.com; bh=WOKNhNvM0pOSDCYr+EFO8sZz5oL6EwFB2cm3zKUS3B0=; "
        . "h=Date:From:To:Subject:Message-ID:Content-Type:From:To:Cc:Subject; "
        . "b=2aMnLYo9cI1NPJxBdtVzfr8EF54YdLzSzcvyhPWEOtSLH7sQgvNBPHABdkQMbtlce\r\n"
        . "	 r7d2TR+Rhz4ZwLDi7YBKl2f3euGG6GLYULlcPg8lkAKXu+do8mEAmvARlIU6nMkEtX\r\n"
        . "	 xvUO8qQPojgRkCKyKV5pQel4ZCK0z5NiOBUfJkE0=";

    public function testFromStringInvalidHeaderThrowsException(): void
    {
        $header = 'Date: Fri, 02 Sep 2022 09:48:37 +0000';
        self::expectException(InvalidArgumentException::class);
        Dkim::fromString($header);
    }

    public function testFromStringParsesHeader(): void
    {
        $header = 'DKIM-Signature: ' . self::DKIM;
        $dkim   = Dkim::fromString($header);
        self::assertSame(self::DKIM, $dkim->getFieldValue());
    }

    public function testGetFieldName(): void
    {
        $expected = 'DKIM-Signature';
        $dkim     = new Dkim('');
        self::assertSame($expected, $dkim->getFieldName());
    }

    public function testSetEncodingHasNoEffect(): void
    {
        $dkim = (new Dkim(''))
            ->setEncoding('UTF-8');
        self::assertSame('ASCII', $dkim->getEncoding());
    }

    public function testToString(): void
    {
        $expected = 'DKIM-Signature: ' . self::DKIM;
        $dkim     = new Dkim(self::DKIM);
        self::assertSame($expected, $dkim->toString());
    }
}
