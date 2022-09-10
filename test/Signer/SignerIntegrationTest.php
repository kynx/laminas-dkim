<?php

declare(strict_types=1);

namespace KynxTest\Laminas\Dkim\Signer;

use Kynx\Laminas\Dkim\Signer\Signer;
use Laminas\Mail\Message;
use Laminas\Mime\Message as MimeMessage;
use Laminas\Mime\Part;
use PHPMailer\DKIMValidator\Validator;
use PHPUnit\Framework\TestCase;

use function file_get_contents;
use function str_repeat;
use function str_replace;
use function trim;

/**
 * @coversNothing
 */
final class SignerIntegrationTest extends TestCase
{
    /** @var Message */
    private $message;
    /** @var string */
    private $privateKey;
    /** @var array */
    private $params;
    /** @var Signer */
    private $signer;

    protected function setUp(): void
    {
        parent::setUp();

        $this->message = new Message();
        $this->message->setEncoding('ASCII')
            ->setFrom('from@example.com')
            ->addTo('to@example.com')
            ->addCc('cc@example.com')
            ->setSubject('Subject Subject')
            ->setBody("Hello world!\r\nHello Again!\r\n");

        $this->privateKey = trim(str_replace(
            ['-----BEGIN RSA PRIVATE KEY-----', '-----END RSA PRIVATE KEY-----'],
            '',
            file_get_contents(__DIR__ . '/../assets/private_key.pem')
        ));
        $this->params     = [
            'd' => 'example.com',
            'h' => 'from:to:subject',
            's' => '202209',
        ];
        $this->signer     = new Signer(['private_key' => $this->privateKey, 'params' => $this->params]);
    }

    public function testSignMessageIsValid(): void
    {
        $this->signer->signMessage($this->message);
        self::assertSignedMessageIsValid($this->message);
    }

    public function testSignMimeMessageIsValid(): void
    {
        $mime = new MimeMessage();
        $mime->addPart(new Part("Hello world"));
        $this->message->setBody($mime);

        $this->signer->signMessage($this->message);
        self::assertSignedMessageIsValid($this->message);
    }

    /**
     * @see https://www.rfc-editor.org/rfc/rfc6376.html#section-5.4
     */
    public function testSignMissingHeaderIsValid(): void
    {
        $this->signer->setParam('h', 'from:to:subject:reply-to');

        $this->signer->signMessage($this->message);
        self::assertSignedMessageIsValid($this->message);
    }

    public function testSignMessageNormalisedNewLinesIsValid(): void
    {
        $this->message->setBody("Hello world!\nHello Again!\n");

        $this->signer->signMessage($this->message);
        self::assertSignedMessageIsValid($this->message);
    }

    public function testSignMessageTrailingNewLinesIsValid(): void
    {
        $this->message->setBody("Hello world!\r\nHello Again!\r\n\r\n");

        $this->signer->signMessage($this->message);
        self::assertSignedMessageIsValid($this->message);
    }

    public function testSignMessageEmptyBodyIsValid(): void
    {
        $this->message->setBody('');

        $this->signer->signMessage($this->message);
        self::assertSignedMessageIsValid($this->message);
    }

    /**
     * @dataProvider headerProvider
     */
    public function testSignMessageCanonicalHeaderIsValid(string $subject): void
    {
        $this->message->setSubject($subject);

        $this->signer->signMessage($this->message);
        self::assertSignedMessageIsValid($this->message);
    }

    public function headerProvider(): array
    {
        return [
            'internal_whitespace' => ["Subject   Subject"],
            'leading_whitespace'  => ["   Subject Subject"],
            'trailing_whitespace' => ["Subject Subject   "],
        ];
    }

    public function testSignMessageFoldedHeaderIsValid(): void
    {
        // 80-char subject will be wrapped at 70 chars
        $this->message->setSubject(str_repeat("Subject ", 10));

        $this->signer->signMessage($this->message);
        self::assertSignedMessageIsValid($this->message);
    }

    public static function assertSignedMessageIsValid(Message $message): void
    {
        $validator = new Validator($message->toString());
        $actual    = $validator->validateBoolean();
        self::assertTrue($actual);
    }
}
