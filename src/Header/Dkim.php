<?php

namespace Dkim\Header;

use Laminas\Mail\Header\Exception\InvalidArgumentException;
use Laminas\Mail\Header\GenericHeader;
use Laminas\Mail\Header\HeaderInterface;

use function strtolower;

/**
 * @see \DkimTest\Header\DkimTest
 */
class Dkim implements HeaderInterface
{
    /** @var string */
    protected $value;

    /**
     * @param string $headerLine
     * @return static
     * @throws InvalidArgumentException
     */
    public static function fromString($headerLine)
    {
        [$name, $value] = GenericHeader::splitHeaderLine($headerLine);

        // check to ensure proper header type for this factory
        if (strtolower($name) !== 'dkim-signature') {
            throw new InvalidArgumentException('Invalid header line for DKIM-Signature string');
        }

        return new static($value);
    }

    public function __construct(string $value)
    {
        $this->value = $value;
    }

    public function getFieldName(): string
    {
        return 'DKIM-Signature';
    }

    /**
     * @param bool $format
     */
    public function getFieldValue($format = HeaderInterface::FORMAT_RAW): string
    {
        return $this->value;
    }

    /**
     * @param string $encoding
     * @return $this
     */
    public function setEncoding($encoding): self
    {
        // This header must be always in US-ASCII
        return $this;
    }

    public function getEncoding(): string
    {
        return 'ASCII';
    }

    public function toString(): string
    {
        return 'DKIM-Signature: ' . $this->getFieldValue();
    }
}
