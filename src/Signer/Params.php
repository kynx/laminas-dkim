<?php

declare(strict_types=1);

namespace Kynx\Laminas\Dkim\Signer;

use Kynx\Laminas\Dkim\Exception\InvalidParamException;

use function array_map;
use function in_array;
use function sprintf;

/**
 * @see https://www.rfc-editor.org/rfc/rfc6376#section-3.5
 * @see \KynxTest\Laminas\Dkim\Signer\ParamsTest
 */
final class Params
{
    public const RELAXED_SIMPLE   = 'relaxed/simple';
    public const RELAXED_RELAXED  = 'relaxed/relaxed';
    private const DEFAULT_HEADERS = ['Date', 'From', 'Reply-To', 'Sender', 'Subject'];

    private int $version;
    private string $algorithm;
    private string $domain;
    /** @var list<string> */
    private array $headers;
    private string $identifier;
    private string $canonicalization;

    /**
     * @param list<string> $headers
     */
    public function __construct(
        string $domain,
        array $headers = self::DEFAULT_HEADERS,
        string $canonicalization = self::RELAXED_SIMPLE,
        string $identifier = ''
    ) {
        if ($domain === '') {
            throw new InvalidParamException("Domain cannot be empty");
        }

        /** @see https://github.com/kynx/laminas-dkim/issues/27 */
        if ($canonicalization !== self::RELAXED_SIMPLE) {
            throw new InvalidParamException(sprintf(
                "Only '%s' canonicalization supported",
                self::RELAXED_SIMPLE
            ));
        }

        $headers = array_map('strtolower', $headers);
        if (! in_array('from', $headers, true)) {
            $headers[] = 'from';
        }

        $this->domain           = $domain;
        $this->headers          = $headers;
        $this->canonicalization = $canonicalization;
        $this->identifier       = $identifier;

        $this->version   = 1;
        $this->algorithm = 'rsa-sha256';
    }

    public function getVersion(): int
    {
        return $this->version;
    }

    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    public function getDomain(): string
    {
        return $this->domain;
    }

    /**
     * @return list<string>
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getCanonicalization(): string
    {
        return $this->canonicalization;
    }
}
