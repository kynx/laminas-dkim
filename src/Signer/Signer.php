<?php

namespace Kynx\Laminas\Dkim\Signer;

use Kynx\Laminas\Dkim\Header\Dkim;
use Kynx\Laminas\Dkim\PrivateKey\PrivateKeyInterface;
use Laminas\Mail\Header;
use Laminas\Mail\Message;
use Laminas\Mime\Message as MimeMessage;

use function assert;
use function base64_encode;
use function explode;
use function hash;
use function implode;
use function in_array;
use function is_object;
use function is_string;
use function method_exists;
use function pack;
use function preg_replace;
use function strtolower;
use function substr;
use function trim;

/**
 * @see \KynxTest\Laminas\Dkim\Signer\SignerTest
 */
final class Signer implements SignerInterface
{
    private const SIMPLE  = 'simple';
    private const RELAXED = 'relaxed';

    private Params $params;
    private PrivateKeyInterface $privateKey;
    private string $headerC13n;
    private string $bodyC13n;

    public function __construct(Params $params, PrivateKeyInterface $privateKey)
    {
        $this->params     = $params;
        $this->privateKey = $privateKey;

        [$this->headerC13n, $this->bodyC13n] = explode('/', $params->getCanonicalization());
    }

    /**
     * Returns message with DKIM signature added
     */
    public function signMessage(Message $message): Message
    {
        $clone     = $this->cloneMessage($message);
        $formatted = $this->formatMessage($clone);
        $dkim      = $this->getEmptyDkimHeader($formatted);

        // add empty (unsigned) dkim header
        $formatted->getHeaders()->addHeader($dkim);

        $canonical = $this->getCanonicalHeaders($formatted);
        return $this->sign($formatted, $dkim, $canonical);
    }

    /**
     * Returns deap clone of message
     */
    private function cloneMessage(Message $message): Message
    {
        $clone = clone $message;
        $clone->setHeaders(clone $message->getHeaders());
        $body = $message->getBody();
        if ($body instanceof MimeMessage) {
            $clone->setBody(clone $body);
        }

        return $clone;
    }

    /**
     * Returns message formatted for singing.
     *
     * This _replaces_ the body of the message with the generated body - so MIME content is generated. We have to do
     * this so that the random MIME boundaries are created prior to the body hash being calculated.
     */
    private function formatMessage(Message $message): Message
    {
        $body = $message->getBody();

        if ($body instanceof MimeMessage) {
            $body = $body->generateMessage();
        } elseif (is_object($body)) {
            /** @see \Laminas\Mail\Message::setBody() */
            assert(method_exists($body, '__toString'));
            $body = (string) $body;
        }

        $body = $this->normalizeNewlines($body);

        $message->setBody($body);

        return $message;
    }

    /**
     * Normalize new lines to CRLF sequences.
     */
    private function normalizeNewlines(string $string): string
    {
        return trim(preg_replace('~\R~u', "\r\n", $string)) . "\r\n";
    }

    /**
     * Returns canonical headers for signing.
     */
    private function getCanonicalHeaders(Message $message): string
    {
        $canonical     = '';
        $headersToSign = $this->params->getHeaders();

        if (! in_array('dkim-signature', $headersToSign, true)) {
            $headersToSign[] = 'dkim-signature';
        }

        foreach ($headersToSign as $fieldName) {
            $header = $message->getHeaders()->get($fieldName);
            if ($header instanceof Header\HeaderInterface) {
                $canonical .= $this->getCanonicalHeader($header);
            }
        }

        return trim($canonical);
    }

    /**
     * @see https://www.rfc-editor.org/rfc/rfc6376#section-3.4.1 for "simple" header canonicalization
     * @see https://www.rfc-editor.org/rfc/rfc6376#section-3.4.2 for "relaxed" header canonicalization
     * @see https://www.rfc-editor.org/rfc/rfc6376#section-3.4.5 for slightly convoluted examples
     */
    private function getCanonicalHeader(Header\HeaderInterface $header): string
    {
        if ($this->headerC13n === self::SIMPLE) {
            return $header->toString() . "\r\n";
        }

        return strtolower($header->getFieldName()) . ':' . trim(preg_replace(
            '/\s+/',
            ' ',
            $header->getFieldValue(Header\HeaderInterface::FORMAT_ENCODED)
        )) . "\r\n";
    }

    /**
     * Returns empty DKIM header.
     */
    private function getEmptyDkimHeader(Message $message): Dkim
    {
        // final params
        $params = [
            'v'  => $this->params->getVersion(),
            'a'  => $this->privateKey->getAlgorithm(),
            'bh' => $this->getBodyHash($message),
            'c'  => $this->params->getCanonicalization(),
            'd'  => $this->params->getDomain(),
            'h'  => implode(':', $this->params->getHeaders()),
            's'  => $this->privateKey->getSelector(),
        ];
        if ($this->params->getIdentifier() !== '') {
            $params['i'] = $this->params->getIdentifier();
        }
        $params['b'] = '';

        $string = '';
        foreach ($params as $key => $value) {
            $string .= $key . '=' . $value . '; ';
        }

        return new Dkim(substr(trim($string), 0, -1));
    }

    /**
     * Sign message.
     */
    private function sign(Message $message, Dkim $emptyDkimHeader, string $canonicalHeaders): Message
    {
        // generate signature
        $signature = $this->privateKey->createSignature($canonicalHeaders);

        $headers = $message->getHeaders();

        // first remove the empty dkim header
        $headers->removeHeader('DKIM-Signature');

        // generate new header set starting with the dkim header
        $headerSet = [new Dkim($emptyDkimHeader->getFieldValue() . $signature)];

        // then append existing headers
        foreach ($headers as $header) {
            $headerSet[] = $header;
        }

        $headers
            // clear headers
            ->clearHeaders()
            // add the newly created header set with the dkim signature
            ->addHeaders($headerSet);

        return $message;
    }

    /**
     * Get Message body (sha256) hash.
     *
     * @see https://www.rfc-editor.org/rfc/rfc6376#section-3.4.3 for "simple" body canonicalization
     * @see https://www.rfc-editor.org/rfc/rfc6376#section-3.4.4 for "relaxed" body canonicalization
     * @see https://www.rfc-editor.org/rfc/rfc6376#section-3.4.5 for slightly convoluted examples
     */
    private function getBodyHash(Message $message): string
    {
        $body = $message->getBody();
        assert(is_string($body));

        if ($this->bodyC13n === self::RELAXED) {
            // Ignore all whitespace at the end of lines.  Implementations MUST NOT remove the CRLF at the end of line.
            $body = preg_replace('/\h+(\R)/', '$1', $body);
            // Reduce all sequences of WSP within a line to a single SP character.
            $body = preg_replace('/\h+/', ' ', $body);
        }

        return base64_encode(pack("H*", hash('sha256', $body)));
    }
}
