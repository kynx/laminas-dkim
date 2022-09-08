<?php

declare(strict_types=1);

namespace KynxTest\Laminas\Dkim\Signer;

use Kynx\Laminas\Dkim\Header\Dkim;
use Kynx\Laminas\Dkim\PrivateKey\PrivateKeyInterface;
use Kynx\Laminas\Dkim\PrivateKey\RsaSha256;
use Kynx\Laminas\Dkim\Signer\Params;
use Kynx\Laminas\Dkim\Signer\Signer;
use KynxTest\Laminas\Dkim\PrivateKeyTrait;
use Laminas\Mail\Message;
use Laminas\Mime\Message as MimeMessage;
use Laminas\Mime\Part;
use PHPUnit\Framework\TestCase;

use function array_values;
use function str_repeat;

/**
 * @uses \Kynx\Laminas\Dkim\Header\Dkim
 * @uses \Kynx\Laminas\Dkim\PrivateKey\RsaSha256
 * @uses \Kynx\Laminas\Dkim\Signer\Params
 *
 * @covers \Kynx\Laminas\Dkim\Signer\Signer
 */
final class SignerTest extends TestCase
{
    use PrivateKeyTrait;

    // phpcs:disable Generic.Files.LineLength.TooLong
    private const DEFALT_DKIM = 'v=1; a=rsa-sha256; bh=36+kqoyJsuwP2NJR3Fl95HuripBg2zfO++jH/8Df2LM=; c=relaxed/simple; d=example.com; h=from:to:subject; s=202209; b=TpDEopkzCtJzchi1ZoXG1jg3aPNFEA0/WSfW6ysfJtBbjge1YuKacxRe/873WCN/3VdhU8hBZ 1+ZnoYWzJIAO3LHNooA66AU/Jq0ghiJcHONBU50IZdccvPoy8e0180pMLwJtYDF7KQUo65vkk PHIYClotwT29OjxFUdMl1mTEY=';
    // phpcs:enable

    private Message $message;
    private PrivateKeyInterface $privateKey;
    private Params $params;

    protected function setUp(): void
    {
        $this->message = new Message();
        $this->message->setEncoding('ASCII');
        $this->message->setFrom('from@example.com');
        $this->message->addTo('to@example.com');
        $this->message->addCc('cc@example.com');
        $this->message->setSubject('Subject Subject');
        $this->message->setBody("Hello world!\r\nHello Again!\r\n");

        $this->privateKey = $this->getPrivateKey();
        $this->params     = new Params('example.com', ['From', 'To', 'Subject']);
    }

    public function testConstructorSetsPrivateKeyAndParams(): void
    {
        $signer = new Signer($this->params, $this->privateKey);

        $signed = $signer->signMessage($this->message);
        $header = $signed->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame(self::DEFALT_DKIM, $header->getFieldValue());
    }

    /**
     * @dataProvider paramProvider
     * @param string|array $value
     */
    public function testConstructorParamsAreUsed(string $param, $value, string $expected): void
    {
        $arguments         = [
            'domain'           => 'example.com',
            'headers'          => ['From', 'To', 'Subject'],
            'canonicalization' => Params::RELAXED_SIMPLE,
            'identifier'       => '',
        ];
        $arguments[$param] = $value;

        $params = new Params(...array_values($arguments));
        $signer = new Signer($params, $this->privateKey);

        $signed = $signer->signMessage($this->message);
        $header = $signed->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame($expected, $header->getFieldValue());
    }

    public function paramProvider(): array
    {
        return [
            // phpcs:disable Generic.Files.LineLength.TooLong
            'domain'     => ['domain', 'example.org', 'v=1; a=rsa-sha256; bh=36+kqoyJsuwP2NJR3Fl95HuripBg2zfO++jH/8Df2LM=; c=relaxed/simple; d=example.org; h=from:to:subject; s=202209; b=jZlbMcYSrFH70zxi1Z9/EIX/B+VA54GZ9BFaMofx7P/mqcQFxaZ7pPwRwyLMHCXjfQC3whsXC OI4YkbG/n3l7g+V9L4BCyJ4ANBO9ZOCYeujXPmxp9J/p13No/O2TmAjJITEKRY7PkGu8fAOmG /czQYxvPZk8+taAc431L2EDkQ='],
            'headers'    => ['headers', ['From', 'To', 'CC'], 'v=1; a=rsa-sha256; bh=36+kqoyJsuwP2NJR3Fl95HuripBg2zfO++jH/8Df2LM=; c=relaxed/simple; d=example.com; h=from:to:cc; s=202209; b=lKFpHlViWca4UVRYOyVhvLyjqoPH1XkWbIp7Pkw/wpRdb9c+hmix2uJludOQyXQyB39JGaQQe HJH7LxH7Q48nO83nxlh52RrNNScwX+5O+N16n+yjp7Dg7feidPrVluQUqvYcR9pUHGPm2cD5N XnUFqHWRAX98CuxjDHTWX+kGo='],
            'identifier' => ['identifier', 'foo@example.com', 'v=1; a=rsa-sha256; bh=36+kqoyJsuwP2NJR3Fl95HuripBg2zfO++jH/8Df2LM=; c=relaxed/simple; d=example.com; h=from:to:subject; s=202209; i=foo@example.com; b=kLaUEm4y7cKZcIdraKT1wQvhH6tdrtnuAmEIqNX699CDVAbG3CXShc+YuVD8AE1qtbchMKUFS 30drkJ0idrCvd6zmnGp7qjNbEeQoz2/ZEwNCaAd7O6Wii9VHDJ+G7/iUBg6zZNrLnlnvex+tN MGmTD4gc0BarEdaYywbm8Us+Y='],
            // phpcs:enable
        ];
    }

    public function testSignMessageHandlesMimeMessage(): void
    {
        // phpcs:disable Generic.Files.LineLength.TooLong
        $expected = 'v=1; a=rsa-sha256; bh=yGIXoM91E1DiKjvCBcC8NlWyw54TdfMQ08sdtwtOO4I=; c=relaxed/simple; d=example.com; h=from:to:subject; s=202209; b=k5ndIRQ0AJNEFtycHqN0FBye3WCyxHsy7vGITgMW7LyTL2fOhYXHdJhu7y2yK5CciuJ4Dd6Hy 7S+13U87VcYEc2b3fXOafH+lIGLsvlZPWMKBe8rkHuzdWehPeL6SnhhOWXStVOb8RyqbGZTTq poAUw/SFt8W3eI66y9nWFYMHs=';
        // phpcs:enable
        $mime = new MimeMessage();
        $mime->addPart(new Part("Hello world"));
        $this->message->setBody($mime);

        $signer = new Signer($this->params, $this->privateKey);
        $signed = $signer->signMessage($this->message);
        $header = $signed->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame($expected, $header->getFieldValue());
    }

    public function testSignMessageUsesPrivateKeySelector(): void
    {
        // phpcs:disable Generic.Files.LineLength.TooLong
        $expected = 'v=1; a=rsa-sha256; bh=36+kqoyJsuwP2NJR3Fl95HuripBg2zfO++jH/8Df2LM=; c=relaxed/simple; d=example.com; h=from:to:subject; s=foo; b=XV496nVuq62XEpZ7G/DxJiPy30uyTvFgcsrfaHmHsTImgdVjuAHvMl0yDBW23Vpd2Eksll1qd seRHxFa8V5OLHteElZELoz4HqA0jGo3sGqTNjoLzeZodAdiZ/VHJcdU5ZKeB/qJDyonQhN4Wr z2eWmRIWdFPY5Ex9olzPVtrBw=';
        // phpcs:enable
        $privateKey = new RsaSha256('foo', $this->getPrivateKeyString());

        $signer = new Signer($this->params, $privateKey);
        $signed = $signer->signMessage($this->message);
        $header = $signed->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame($expected, $header->getFieldValue());
    }

    public function testSignMessageHandlesStringableObjectBody(): void
    {
        $stringable = new class () {
            public function __toString(): string
            {
                return "Hello world!\r\nHello Again!\r\n";
            }
        };
        $this->message->setBody($stringable);

        $signer = new Signer($this->params, $this->privateKey);
        $signed = $signer->signMessage($this->message);
        $header = $signed->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame(self::DEFALT_DKIM, $header->getFieldValue());
    }

    public function testSignMessageNormalisesNewLines(): void
    {
        $this->message->setBody("Hello world!\nHello Again!\n");

        $signer = new Signer($this->params, $this->privateKey);
        $signed = $signer->signMessage($this->message);
        $header = $signed->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame(self::DEFALT_DKIM, $header->getFieldValue());
    }

    public function testSignMessageRemovesEmptyLinesFromEndOfMessage(): void
    {
        $this->message->setBody("Hello world!\r\nHello Again!\r\n\r\n");

        $signer = new Signer($this->params, $this->privateKey);
        $signed = $signer->signMessage($this->message);
        $header = $signed->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame(self::DEFALT_DKIM, $header->getFieldValue());
    }

    public function testSignMessageAddsCrLfToEmptyBody(): void
    {
        // phpcs:disable Generic.Files.LineLength.TooLong
        $expected = 'v=1; a=rsa-sha256; bh=frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=; c=relaxed/simple; d=example.com; h=from:to:subject; s=202209; b=CysxP633CzFFVJrNB0euqonA993c+cbSobhf+cdCAEwTgDbkQT7LUfU2opIMUf4H59T8Kx7PC MaaNgnrXbIE7sI3PvaM5nXtiGxCon6vjMLqRGl/bvoNycksDYETfCxAiQPoDBMRmGaccDsD1d d8AC2bZX6qTB8GXl6OCH2jvRA=';
        // phpcs:enable
        $this->message->setBody("");

        $signer = new Signer($this->params, $this->privateKey);
        $signed = $signer->signMessage($this->message);
        $header = $signed->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame($expected, $header->getFieldValue());
    }

    /**
     * @dataProvider headerProvider
     */
    public function testSignMessageCanonicalizesHeaders(string $subject): void
    {
        $this->message->setSubject($subject);

        $signer = new Signer($this->params, $this->privateKey);
        $signed = $signer->signMessage($this->message);
        $header = $signed->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame(self::DEFALT_DKIM, $header->getFieldValue());
    }

    public function headerProvider(): array
    {
        return [
            'internal_whitespace' => ["Subject   Subject"],
            'leading_whitespace'  => ["   Subject Subject"],
            'trailing_whitespace' => ["Subject Subject   "],
        ];
    }

    public function testSignMessagesCanonicalizesFoldedHeader(): void
    {
        // phpcs:disable Generic.Files.LineLength.TooLong
        $expected = 'v=1; a=rsa-sha256; bh=36+kqoyJsuwP2NJR3Fl95HuripBg2zfO++jH/8Df2LM=; c=relaxed/simple; d=example.com; h=from:to:subject; s=202209; b=ltIZz2CnS0EXyfNfjbCLZx58um55Uq2SvHUj3VCBrF/MH5CVRQQy7/CxcL260k6ddodOaRKjw QLW9kRWD/CuXz9AWpjYQbDg5qPNVsFHcNzKPJHIbytpYktC6e55nealcY/qpK7mcociop3S/S xzPHrhJtKI8ZaqQLFd+0x2P6s=';
        // phpcs:enable

        // 80-char subject will be wrapped at 70 chars
        $this->message->setSubject(str_repeat("Subject ", 10));

        $signer = new Signer($this->params, $this->privateKey);
        $signed = $signer->signMessage($this->message);
        $header = $signed->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame($expected, $header->getFieldValue());
    }

    public function testSignMultipleMessages(): void
    {
        $signer = new Signer($this->params, $this->privateKey);
        $first  = clone $this->message;
        $second = clone $this->message;

        $first  = $signer->signMessage($first);
        $header = $first->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame(self::DEFALT_DKIM, $header->getFieldValue());

        $second = $signer->signMessage($second);
        $header = $second->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame(self::DEFALT_DKIM, $header->getFieldValue());
    }

    public function testSignMessageReturnsClone(): void
    {
        $expectedBody = new MimeMessage();
        $expectedBody->addPart(new Part("Hello world"));
        $this->message->setBody($expectedBody);
        $expectedHeaders = $this->message->getHeaders();

        $signer = new Signer($this->params, $this->privateKey);
        $signed = $signer->signMessage($this->message);
        self::assertNotSame($this->message, $signed);
        self::assertNotSame($expectedBody, $signed->getBody());
        self::assertSame($expectedBody, $this->message->getBody());
        self::assertSame($expectedHeaders, $this->message->getHeaders());
    }
}
