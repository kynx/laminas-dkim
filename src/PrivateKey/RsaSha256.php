<?php

declare(strict_types=1);

namespace Kynx\Laminas\Dkim\PrivateKey;

use Kynx\Laminas\Dkim\Exception\InvalidPrivateKeyException;
use OpenSSLAsymmetricKey;

use function base64_encode;
use function chunk_split;
use function is_resource;
use function openssl_pkey_get_private;
use function openssl_sign;
use function trim;

use const OPENSSL_ALGO_SHA256;

/**
 * @see \KynxTest\Laminas\Dkim\PrivateKey\RsaSha256Test
 */
final class RsaSha256 implements PrivateKeyInterface
{
    private string $selector;
    /**
     * @psalm-suppress UndefinedDocblockClass
     * @var resource|OpenSSLAsymmetricKey
     */
    private $key;

    public function __construct(string $selector, string $privateKey)
    {
        if ($selector === '') {
            throw new InvalidPrivateKeyException("Selector cannot be empty");
        }
        $this->selector = $selector;

        $key = <<<PKEY
-----BEGIN RSA PRIVATE KEY-----
$privateKey
-----END RSA PRIVATE KEY-----
PKEY;

        $key = @openssl_pkey_get_private($key);

        /**
         * Remove `is_resource()` check once php7.4 dropped
         *
         * @psalm-suppress TypeDoesNotContainType
         * @psalm-suppress UndefinedClass
         */
        if (! (is_resource($key) || $key instanceof OpenSSLAsymmetricKey)) {
            throw new InvalidPrivateKeyException('Invalid private key');
        }

        $this->key = $key;
    }

    /**
     * Returns base64 encoded signature of payload
     */
    public function createSignature(string $payload): string
    {
        $signature = '';
        /** @psalm-suppress PossiblyInvalidArgument This can be removed once php7.4 support is dropped */
        openssl_sign($payload, $signature, $this->key, OPENSSL_ALGO_SHA256);

        return trim(chunk_split(base64_encode($signature), 73, ' '));
    }

    /**
     * Returns algorithm name for use in DKIM signature
     */
    public function getAlgorithm(): string
    {
        return 'rsa-sha256';
    }

    /**
     * Returns selector (`s` in DKIM parlance) to use when looking up DNS TXT record
     */
    public function getSelector(): string
    {
        return $this->selector;
    }
}
