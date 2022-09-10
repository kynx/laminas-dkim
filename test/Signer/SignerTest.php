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
    private const DEFALT_DKIM = 'v=1; a=rsa-sha256; bh=36+kqoyJsuwP2NJR3Fl95HuripBg2zfO++jH/8Df2LM=; c=relaxed; d=example.com; h=from:to:subject; s=202209; b=ZIveNTJs3JUE1s2P3DO/wIyftb+bQLDiv7uWXwwMs96r3SaLAbYs2UOF0t/RGPTz+YgeNMHL6 2LE0DeuegAOm2K7qzbsW2pi6b4nCAK9UnN0NDTLlW4vSEI512/MHK50qbe/EhK9dNX6phwBhT DCanUuZ0GADddCX7k7uw3vf6g=';
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
            'domain'   => ['d', 'example.org', 'v=1; a=rsa-sha256; bh=36+kqoyJsuwP2NJR3Fl95HuripBg2zfO++jH/8Df2LM=; c=relaxed; d=example.org; h=from:to:subject; s=202209; b=bUVWqeZYk051s8cYgnbs63IwnLQhZkmnrHpaPaRNLZigfMbp9aFTimzJNjD3y8tefA3avESWF XCCDPr4kYDxBOHnA+OlWWqKExjZMqww7Kwu1cpeEDYFlt2FNGnBSFwSPtVcrxRMsGSLjXo0IR YY+zLsD0fjwfrdu6BJbtN0Gug='],
            'headers'  => ['h', 'from:to:cc', 'v=1; a=rsa-sha256; bh=36+kqoyJsuwP2NJR3Fl95HuripBg2zfO++jH/8Df2LM=; c=relaxed; d=example.com; h=from:to:cc; s=202209; b=CfZoSx4/4934tkPbdGty5Jtx0FMMRyAAfUpSFkVWJr/cKBE9m3Qc+0Biofpr8IJwbEsm0ZKi+ pf0UMIUf0Ex1i5a8eap/6IOGNG1pOTYLa76C7HriCBCcUlqByZP5ZyIS/53kPXNzdSq99zGZb S/hp7sEu9jUMtwuP+ox1ta/rM='],
            'selector' => ['s', 'foo', 'v=1; a=rsa-sha256; bh=36+kqoyJsuwP2NJR3Fl95HuripBg2zfO++jH/8Df2LM=; c=relaxed; d=example.com; h=from:to:subject; s=foo; b=MPILDWMo+yuZKtMUgPymmxADwChhycfezMZcOWyjZuloRp06Osmc/5Ah7Yo14G47OzwvLskeE gIvmUxWo5oryMQmiPhtDHDXTlCoFRIY2eqwgZjHt//E2cXXNwH6VLyeKEikEfgzkddcj85x0u nKmILo8UDQitFkl+yYq1HIJj0='],
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
        $expected = 'v=1; a=rsa-sha256; bh=yGIXoM91E1DiKjvCBcC8NlWyw54TdfMQ08sdtwtOO4I=; c=relaxed; d=example.com; h=from:to:subject; s=202209; b=TqQ6vRv/tQzalihYo38Um9CYdVavndOX+TQLvw5Da13bLxVWaz4aRmtYmwA1J/BSuJmejssPL oFxTxoh1ThPuTZmgh6HYbS6sdVXULIO5l0Yt8Jn9OGUWJ6+Pe9rf1Nd2kEtfZgasRXpWvL+xJ OQH3g12uTwdAKSCDelD7QEHek=';
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
        $expected = 'v=1; a=rsa-sha256; bh=frcCV1k9oG9oKj3dpUqdJg1PxRT2RSN/XKdLCPjaYaY=; c=relaxed; d=example.com; h=from:to:subject; s=202209; b=iZ80xj9GbrxFqTJxijRYYTVolk9Y7zI+96NBJmn+tJ5e7uDXX0BNEcih2buMBB71d3/KTYQg3 nhZJvCzHbFX1ASvShjoW2fo+IRNKTbsarYPUBQAN7+E1idMKbdmWRrbRA+ZsVrCRqfQB5XE+/ s6xWuek5Fb3XAprsoEhCWXgU8=';
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
        $expected = 'v=1; a=rsa-sha256; bh=36+kqoyJsuwP2NJR3Fl95HuripBg2zfO++jH/8Df2LM=; c=relaxed; d=example.com; h=from:to:subject; s=202209; b=lBekusV7wbwMhkeS8CI6YvtIe8nLP6KmI7vjtobXWc3o69wq21tiPJfiliNp46oQZSf33CTnb l1MDI3nSzAfJNBGga/sZIhzjGXFRzfozGPCIPSiwRskX5+pQrKEMYNsPS5Uu3ZPhmtyDKrHsW EbBgo37MwR38emFM5NNCfynEo=';
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