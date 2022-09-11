<?php

declare(strict_types=1);

namespace KynxTest\Laminas\Dkim\Signer;

use Kynx\Laminas\Dkim\Signer\Params;
use Kynx\Laminas\Dkim\Signer\Signer;
use KynxTest\Laminas\Dkim\PrivateKeyTrait;
use Laminas\Mail\Message;
use Laminas\Mime\Message as MimeMessage;
use Laminas\Mime\Part;
use PHPMailer\DKIMValidator\Validator;
use PHPUnit\Framework\TestCase;

use function str_repeat;

/**
 * @coversNothing
 */
final class SignerIntegrationTest extends TestCase
{
    use PrivateKeyTrait;

    private Message $message;
    private Signer $signer;

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

        $params       = new Params('example.com', ['From', 'To', 'Subject']);
        $this->signer = new Signer($params, $this->getPrivateKey());
    }

    public function testSignMessageIsValid(): void
    {
        $signed = $this->signer->signMessage($this->message);
        self::assertSignedMessageIsValid($signed);
    }

    public function testSignMimeMessageIsValid(): void
    {
        $mime = new MimeMessage();
        $mime->addPart(new Part("Hello world"));
        $this->message->setBody($mime);

        $signed = $this->signer->signMessage($this->message);
        self::assertSignedMessageIsValid($signed);
    }

    /**
     * @see https://www.rfc-editor.org/rfc/rfc6376.html#section-5.4
     */
    public function testSignMissingHeaderIsValid(): void
    {
        $params = new Params('example.com', ['From', 'To', 'Subject', 'Reply-To']);
        $signer = new Signer($params, $this->getPrivateKey());

        $signed = $signer->signMessage($this->message);
        self::assertSignedMessageIsValid($signed);
    }

    public function testSignMessageNormalisedNewLinesIsValid(): void
    {
        $this->message->setBody("Hello world!\nHello Again!\n");

        $signed = $this->signer->signMessage($this->message);
        self::assertSignedMessageIsValid($signed);
    }

    public function testSignMessageTrailingNewLinesIsValid(): void
    {
        $this->message->setBody("Hello world!\r\nHello Again!\r\n\r\n");

        $signed = $this->signer->signMessage($this->message);
        self::assertSignedMessageIsValid($signed);
    }

    public function testSignMessageEmptyBodyIsValid(): void
    {
        $this->message->setBody('');

        $signed = $this->signer->signMessage($this->message);
        self::assertSignedMessageIsValid($signed);
    }

    public function testSignMessageRelaxedBodyIsValid(): void
    {
        $params = new Params('example.com', ['From', 'To', 'Subject'], Params::RELAXED_RELAXED);
        $signer = new Signer($params, $this->getPrivateKey());

        $this->message->setBody("Hello world!\t \r\nHello \t Again!\r\n\r\n");

        $signed = $signer->signMessage($this->message);
        self::assertSignedMessageIsValid($signed);
    }

    /**
     * @dataProvider headerProvider
     */
    public function testSignMessageRelaxedHeaderIsValid(string $subject): void
    {
        $this->message->setSubject($subject);

        $signed = $this->signer->signMessage($this->message);
        self::assertSignedMessageIsValid($signed);
    }

    /**
     * @dataProvider headerProvider
     */
    public function testSignMessageSimpleHeaderIsValid(string $subject): void
    {
        if ($subject === "   Subject Subject") {
            self::markTestSkipped("See https://github.com/PHPMailer/DKIMValidator/issues/14");
        }
        if ($subject === str_repeat("Subject ", 10)) {
            self::markTestSkipped("See https://github.com/PHPMailer/DKIMValidator/issues/15");
        }

        $params = new Params('example.com', ['From', 'To', 'Subject'], Params::SIMPLE_SIMPLE);
        $signer = new Signer($params, $this->getPrivateKey());

        $this->message->setSubject($subject);

        $signed = $signer->signMessage($this->message);
        self::assertSignedMessageIsValid($signed);
    }

    public function headerProvider(): array
    {
        return [
            'internal_whitespace' => ["Subject   Subject"],
            'leading_whitespace'  => ["   Subject Subject"],
            'trailing_whitespace' => ["Subject Subject   "],
            'folded_header'       => [str_repeat("Subject ", 10)],
        ];
    }

    public static function assertSignedMessageIsValid(Message $message): void
    {
        $validator = new Validator($message->toString());
        $actual    = $validator->validateBoolean();
        self::assertTrue($actual);
    }
}
