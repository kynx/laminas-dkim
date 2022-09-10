<?php

namespace Dkim\Signer;

use Dkim\Header\Dkim;
use Exception;
use Laminas\Mail\Header;
use Laminas\Mail\Message;
use Laminas\Mime\Message as MimeMessage;

use function array_key_exists;
use function base64_encode;
use function chunk_split;
use function explode;
use function hash;
use function in_array;
use function is_array;
use function is_resource;
use function openssl_pkey_get_private;
use function openssl_sign;
use function pack;
use function preg_replace;
use function strtolower;
use function substr;
use function trim;

use const OPENSSL_ALGO_SHA256;

/**
 * @see \DkimTest\Signer\SignerTest
 */
class Signer
{
    /**
     * All configurable params.
     *
     * @var array
     */
    private $params = [
        // optional params having a default value set
        'v' => '1',
        'a' => 'rsa-sha256',
        // required to set either in your config file or through the setParam method before signing (see
        // module.config.dist file)
        'd' => '', // domain
        'h' => '', // headers to sign
        's' => '', // domain key selector
    ];

    /**
     * Empty DKIM header.
     *
     * @var Dkim
     */
    private $emptyDkimHeader;

    /**
     * Canonized headers.
     *
     * @var string
     */
    private $canonizedHeaders;

    /**
     * The private key being used.
     *
     * @var bool|resource key
     */
    private $privateKey = false;

    /**
     * Set and validate DKIM options.
     *
     * @throws Exception
     */
    public function __construct(array $config)
    {
        if (isset($config['private_key']) && ! empty($config['private_key'])) {
            $this->setPrivateKey($config['private_key']);
        }

        if (isset($config['params']) && is_array($config['params']) && ! empty($config['params'])) {
            foreach ($config['params'] as $key => $value) {
                $this->setParam($key, $value);
            }
        }
    }

    /**
     * Sign message with a DKIM signature.
     */
    public function signMessage(Message $message): void
    {
        $this
            // format message
            ->formatMessage($message)
            // generate empty dkim header including the body hash
            ->generateEmptyDkimHeader($message);

        // add empty (unsigned) dkim header
        $message->getHeaders()->addHeader($this->getEmptyDkimHeader());

        $this
            // canonize headers for signing
            ->canonizeHeaders($message)
            // sign message
            ->sign($message);
    }

    /**
     * Set Dkim param.
     *
     * @param string $key
     * @param string $value
     * @throws Exception
     */
    public function setParam($key, $value): self
    {
        if (! array_key_exists($key, $this->getParams())) {
            throw new Exception("Invalid param '$key' given.");
        }

        $this->params[$key] = $value;

        return $this;
    }

    /**
     * Set multiple Dkim params.
     */
    public function setParams(array $params): self
    {
        if (! empty($params)) {
            foreach ($params as $key => $value) {
                $this->setParam($key, $value);
            }
        }

        return $this;
    }

    /**
     * Set (generate) OpenSSL key.
     *
     * @throws Exception
     */
    public function setPrivateKey(string $privateKey): self
    {
        $key = <<<PKEY
-----BEGIN RSA PRIVATE KEY-----
$privateKey
-----END RSA PRIVATE KEY-----
PKEY;

        $key = @openssl_pkey_get_private($key);

        if (! $key) {
            throw new Exception("Invalid private key given.");
        }

        $this->privateKey = $key;

        return $this;
    }

    /**
     * Format message for singing.
     */
    private function formatMessage(Message $message): self
    {
        $body = $message->getBody();

        if ($body instanceof MimeMessage) {
            $body = $body->generateMessage();
        }

        $body = $this->normalizeNewlines($body);

        $message->setBody($body);

        return $this;
    }

    /**
     * Normalize new lines to CRLF sequences.
     */
    private function normalizeNewlines(string $string): string
    {
        return trim(preg_replace('~\R~u', "\r\n", $string)) . "\r\n";
    }

    /**
     * Canonize headers for signing.
     */
    private function canonizeHeaders(Message $message): self
    {
        $params        = $this->getParams();
        $headersToSign = explode(':', $params['h']);

        if (! in_array('dkim-signature', $headersToSign, true)) {
            $headersToSign[] = 'dkim-signature';
        }

        foreach ($headersToSign as $fieldName) {
            $fieldName = strtolower($fieldName);
            $header    = $message->getHeaders()->get($fieldName);

            if ($header instanceof Header\HeaderInterface) {
                $this->appendCanonizedHeader(
                    $fieldName . ':' . trim(preg_replace(
                        '/\s+/',
                        ' ',
                        $header->getFieldValue(Header\HeaderInterface::FORMAT_ENCODED)
                    )) . "\r\n"
                );
            }
        }

        return $this;
    }

    /**
     * Generate empty DKIM header.
     *
     * @throws Exception
     */
    private function generateEmptyDkimHeader(Message $message): self
    {
        // fetch configurable params
        $configurableParams = $this->getParams();

        // check if the required params are set for singing.
        if (empty($configurableParams['d']) || empty($configurableParams['h']) || empty($configurableParams['s'])) {
            throw new Exception('Unable to sign message: missing params');
        }

        // final params
        $params = [
            'v'  => $configurableParams['v'],
            'a'  => $configurableParams['a'],
            'bh' => $this->getBodyHash($message),
            'c'  => 'relaxed/simple',
            'd'  => $configurableParams['d'],
            'h'  => $configurableParams['h'],
            's'  => $configurableParams['s'],
            'b'  => '',
        ];

        $string = '';
        foreach ($params as $key => $value) {
            $string .= $key . '=' . $value . '; ';
        }

        // set empty dkim header
        $this->setEmptyDkimHeader(new Dkim(substr(trim($string), 0, -1)));

        return $this;
    }

    /**
     * Generate signature.
     *
     * @throws Exception
     */
    private function generateSignature(): string
    {
        $privateKey = $this->getPrivateKey();
        if (! is_resource($privateKey)) {
            throw new Exception('No private key given.');
        }

        $signature = '';
        openssl_sign($this->getCanonizedHeaders(), $signature, $privateKey, OPENSSL_ALGO_SHA256);

        return trim(chunk_split(base64_encode($signature), 73, ' '));
    }

    /**
     * Sign message.
     */
    private function sign(Message $message): self
    {
        // generate signature
        $signature = $this->generateSignature();

        $headers = $message->getHeaders();

        // first remove the empty dkim header
        $headers->removeHeader('DKIM-Signature');

        // generate new header set starting with the dkim header
        $headerSet[] = new Dkim($this->getEmptyDkimHeader()->getFieldValue() . $signature);

        // then append existing headers
        foreach ($headers as $header) {
            $headerSet[] = $header;
        }

        $headers
            // clear headers
            ->clearHeaders()
            // add the newly created header set with the dkim signature
            ->addHeaders($headerSet);

        return $this;
    }

    /**
     * Get configurable params.
     */
    private function getParams(): array
    {
        return $this->params;
    }

    /**
     * Set empty DKIM header.
     */
    private function setEmptyDkimHeader(Dkim $emptyDkimHeader): self
    {
        $this->emptyDkimHeader = $emptyDkimHeader;

        return $this;
    }

    /**
     * Get empty DKIM header.
     */
    private function getEmptyDkimHeader(): Dkim
    {
        return $this->emptyDkimHeader;
    }

    /**
     * Append canonized header to raw canonized header set.
     */
    private function appendCanonizedHeader(string $canonizedHeader): self
    {
        $this->setCanonizedHeaders($this->canonizedHeaders . $canonizedHeader);

        return $this;
    }

    /**
     * Set canonized headers.
     */
    private function setCanonizedHeaders(string $canonizedHeaders): self
    {
        $this->canonizedHeaders = $canonizedHeaders;

        return $this;
    }

    /**
     * Get canonized headers.
     */
    private function getCanonizedHeaders(): string
    {
        return trim($this->canonizedHeaders);
    }

    /**
     * Get Message body (sha256) hash.
     */
    private function getBodyHash(Message $message): string
    {
        return base64_encode(pack("H*", hash('sha256', $message->getBody())));
    }

    /**
     * Return OpenSSL key resource.
     *
     * @return bool|resource key
     */
    private function getPrivateKey()
    {
        return $this->privateKey;
    }
}
