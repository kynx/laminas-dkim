<?php

declare(strict_types=1);

namespace DkimTest\Signer;

use Dkim\Header\Dkim;
use Dkim\Signer\Signer;
use Exception;
use Laminas\Mail\Message;
use Laminas\Mime\Message as MimeMessage;
use Laminas\Mime\Part;
use PHPUnit\Framework\TestCase;

use function file_get_contents;
use function str_repeat;
use function str_replace;

/**
 * @covers \Dkim\Signer\Signer
 * @uses \Dkim\Header\Dkim
 */
final class SignerTest extends TestCase
{
    // phpcs:disable Generic.Files.LineLength.TooLong
    private const DEFALT_DKIM = 'v=1; a=rsa-sha256; bh=36+kqoyJsuwP2NJR3Fl95HuripBg2zfO++jH/8Df2LM=; c=relaxed/simple; d=example.com; h=from:to:subject; s=202209; b=TpDEopkzCtJzchi1ZoXG1jg3aPNFEA0/WSfW6ysfJtBbjge1YuKacxRe/873WCN/3VdhU8hBZ 1+ZnoYWzJIAO3LHNooA66AU/Jq0ghiJcHONBU50IZdccvPoy8e0180pMLwJtYDF7KQUo65vkk PHIYClotwT29OjxFUdMl1mTEY=';
    // phpcs:enable

    /** @var Message */
    private $message;
    /** @var string */
    private $privateKey;
    /** @var array */
    private $params;

    protected function setUp(): void
    {
        $this->message = new Message();
        $this->message->setEncoding('ASCII');
        $this->message->setFrom('from@example.com');
        $this->message->addTo('to@example.com');
        $this->message->addCc('cc@example.com');
        $this->message->setSubject('Subject Subject');
        $this->message->setBody("Hello world!\r\nHello Again!\r\n");

        $this->privateKey = trim(str_replace(
            ['-----BEGIN RSA PRIVATE KEY-----', '-----END RSA PRIVATE KEY-----'],
            '',
            file_get_contents(__DIR__ . '/../assets/private_key.pem')
        ));
        $this->params = [
            'd' => 'example.com',
            'h' => 'from:to:subject',
            's' => '202209',
        ];
    }

    public function testConstructorSetsPrivateKeyAndParams(): void
    {
        $signer = new Signer(['private_key' => $this->privateKey, 'params' => $this->params]);

        $signer->signMessage($this->message);
        $header = $this->message->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame(self::DEFALT_DKIM, $header->getFieldValue());
    }

    /**
     * @dataProvider paramProvider
     */
    public function testSetParam(string $param, string $value, string $expected): void
    {
        $signer = new Signer(['private_key' => $this->privateKey, 'params' => $this->params]);
        $signer->setParam($param, $value);

        $signer->signMessage($this->message);
        $header = $this->message->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame($expected, $header->getFieldValue());
    }

    public function paramProvider(): array
    {
        return [
            // phpcs:disable Generic.Files.LineLength.TooLong
            'domain'   => ['d', 'example.org', 'v=1; a=rsa-sha256; bh=36+kqoyJsuwP2NJR3Fl95HuripBg2zfO++jH/8Df2LM=; c=relaxed/simple; d=example.org; h=from:to:subject; s=202209; b=jZlbMcYSrFH70zxi1Z9/EIX/B+VA54GZ9BFaMofx7P/mqcQFxaZ7pPwRwyLMHCXjfQC3whsXC OI4YkbG/n3l7g+V9L4BCyJ4ANBO9ZOCYeujXPmxp9J/p13No/O2TmAjJITEKRY7PkGu8fAOmG /czQYxvPZk8+taAc431L2EDkQ='],
            'headers'  => ['h', 'from:to:cc', 'v=1; a=rsa-sha256; bh=36+kqoyJsuwP2NJR3Fl95HuripBg2zfO++jH/8Df2LM=; c=relaxed/simple; d=example.com; h=from:to:cc; s=202209; b=lKFpHlViWca4UVRYOyVhvLyjqoPH1XkWbIp7Pkw/wpRdb9c+hmix2uJludOQyXQyB39JGaQQe HJH7LxH7Q48nO83nxlh52RrNNScwX+5O+N16n+yjp7Dg7feidPrVluQUqvYcR9pUHGPm2cD5N XnUFqHWRAX98CuxjDHTWX+kGo='],
            'selector' => ['s', 'foo', 'v=1; a=rsa-sha256; bh=36+kqoyJsuwP2NJR3Fl95HuripBg2zfO++jH/8Df2LM=; c=relaxed/simple; d=example.com; h=from:to:subject; s=foo; b=XV496nVuq62XEpZ7G/DxJiPy30uyTvFgcsrfaHmHsTImgdVjuAHvMl0yDBW23Vpd2Eksll1qd seRHxFa8V5OLHteElZELoz4HqA0jGo3sGqTNjoLzeZodAdiZ/VHJcdU5ZKeB/qJDyonQhN4Wr z2eWmRIWdFPY5Ex9olzPVtrBw='],
            // phpcs:enable
        ];
    }

    /**
     * @dataProvider emptyParamProvider
     */
    public function testEmptyParamThrowsException(string $param): void
    {
        $signer = new Signer(['private_key' => $this->privateKey, 'params' => $this->params]);
        $signer->setParam($param, '');

        self::expectException(Exception::class);
        self::expectExceptionMessage('Unable to sign message: missing params');
        $signer->signMessage($this->message);
    }

    public function emptyParamProvider(): array
    {
        return [
            'domain'   => ['d'],
            'headers'  => ['h'],
            'selector' => ['s'],
        ];
    }

    public function testSetInvalidParamsThrowsException(): void
    {
        $signer = new Signer([]);
        self::expectException(Exception::class);
        self::expectExceptionMessage("Invalid param 'z' given.");
        $signer->setParam('z', 'foo');
    }

    public function testSetParams(): void
    {
        $signer = new Signer(['private_key' => $this->privateKey]);
        $signer->setParams($this->params);

        $signer->signMessage($this->message);
        $header = $this->message->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame(self::DEFALT_DKIM, $header->getFieldValue());
    }

    public function testSetPrivateKeyInvalidThrowsException(): void
    {
        $signer = new Signer([]);
        self::expectException(Exception::class);
        self::expectExceptionMessage("Invalid private key given.");
        $signer->setPrivateKey('');
    }

    public function testSignMessageHandlesMimeMessage(): void
    {
        // phpcs:disable Generic.Files.LineLength.TooLong
        $expected = 'v=1; a=rsa-sha256; bh=yGIXoM91E1DiKjvCBcC8NlWyw54TdfMQ08sdtwtOO4I=; c=relaxed/simple; d=example.com; h=from:to:subject; s=202209; b=k5ndIRQ0AJNEFtycHqN0FBye3WCyxHsy7vGITgMW7LyTL2fOhYXHdJhu7y2yK5CciuJ4Dd6Hy 7S+13U87VcYEc2b3fXOafH+lIGLsvlZPWMKBe8rkHuzdWehPeL6SnhhOWXStVOb8RyqbGZTTq poAUw/SFt8W3eI66y9nWFYMHs=';
        // phpcs:enable
        $mime = new MimeMessage();
        $mime->addPart(new Part("Hello world"));
        $this->message->setBody($mime);

        $signer = new Signer(['private_key' => $this->privateKey, 'params' => $this->params]);
        $signer->signMessage($this->message);
        $header = $this->message->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame($expected, $header->getFieldValue());
    }

    public function testSignMessageNormalisesNewLines(): void
    {
        $this->message->setBody("Hello world!\nHello Again!\n");

        $signer = new Signer(['private_key' => $this->privateKey, 'params' => $this->params]);
        $signer->signMessage($this->message);
        $header = $this->message->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame(self::DEFALT_DKIM, $header->getFieldValue());
    }

    public function testSignMessageRemovesEmptyLinesFromEndOfMessage(): void
    {
        $this->message->setBody("Hello world!\r\nHello Again!\r\n\r\n");

        $signer = new Signer(['private_key' => $this->privateKey, 'params' => $this->params]);
        $signer->signMessage($this->message);
        $header = $this->message->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame(self::DEFALT_DKIM, $header->getFieldValue());
    }

    public function testSignMessageAddsCrLfToEmptyBody(): void
    {
        // phpcs:disable Generic.Files.LineLength.TooLong
        $expected = 'v=1; a=rsa-sha256; bh=frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=; c=relaxed/simple; d=example.com; h=from:to:subject; s=202209; b=CysxP633CzFFVJrNB0euqonA993c+cbSobhf+cdCAEwTgDbkQT7LUfU2opIMUf4H59T8Kx7PC MaaNgnrXbIE7sI3PvaM5nXtiGxCon6vjMLqRGl/bvoNycksDYETfCxAiQPoDBMRmGaccDsD1d d8AC2bZX6qTB8GXl6OCH2jvRA=';
        // phpcs:enable
        $this->message->setBody("");

        $signer = new Signer(['private_key' => $this->privateKey, 'params' => $this->params]);
        $signer->signMessage($this->message);
        $header = $this->message->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame($expected, $header->getFieldValue());
    }

    /**
     * @dataProvider headerProvider
     */
    public function testSignMessageCanonicalizesHeaders(string $subject): void
    {
        $this->message->setSubject($subject);

        $signer = new Signer(['private_key' => $this->privateKey, 'params' => $this->params]);
        $signer->signMessage($this->message);
        $header = $this->message->getHeaders()->get('dkim-signature');
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

        $signer = new Signer(['private_key' => $this->privateKey, 'params' => $this->params]);
        $signer->signMessage($this->message);
        $header = $this->message->getHeaders()->get('dkim-signature');
        self::assertInstanceOf(Dkim::class, $header);
        self::assertSame($expected, $header->getFieldValue());
    }

    public function testSignMessageNoPrivateKeyThrowsException(): void
    {
        $signer = new Signer(['params' => $this->params]);

        self::expectException(Exception::class);
        self::expectExceptionMessage('No private key given.');
        $signer->signMessage($this->message);
    }
}