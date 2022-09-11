<?php

declare(strict_types=1);

namespace Kynx\Laminas\Dkim\Signer;

use Kynx\Laminas\Dkim\Exception\InvalidParamException;

use function array_map;
use function implode;
use function in_array;
use function sprintf;

/**
 * @see https://www.rfc-editor.org/rfc/rfc6376#section-3.5
 * @see \KynxTest\Laminas\Dkim\Signer\ParamsTest
 */
final class Params
{
    public const RELAXED_SIMPLE          = 'relaxed/simple';
    public const RELAXED_RELAXED         = 'relaxed/relaxed';
    public const SIMPLE_SIMPLE           = 'simple/simple';
    public const SIMPLE_RELAXED          = 'simple/relaxed';
    private const DEFAULT_HEADERS        = [
        'CC',
        'Content-Type',
        'Date',
        'From',
        'MIME-Version',
        'Reply-To',
        'Subject',
        'To',
    ];
    private const VALID_CANONICALIZATION = [
        self::RELAXED_SIMPLE,
        self::RELAXED_RELAXED,
        self::SIMPLE_SIMPLE,
        self::SIMPLE_RELAXED,
    ];

    private int $version;
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
        string $canonicalization = self::RELAXED_RELAXED,
        string $identifier = ''
    ) {
        if ($domain === '') {
            throw new InvalidParamException("Domain cannot be empty");
        }

        if (! in_array($canonicalization, self::VALID_CANONICALIZATION, true)) {
            throw new InvalidParamException(sprintf(
                "Invalid canonicalization '%s': must be one of '%s'",
                $canonicalization,
                implode("', '", self::VALID_CANONICALIZATION)
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

        $this->version = 1;
    }

    /**
     * v= Version (plain-text; REQUIRED).
     *
     * This tag defines the version of this specification that applies to the signature record.  It MUST have the value
     * "1" for implementations compliant with this version of DKIM.
     */
    public function getVersion(): int
    {
        return $this->version;
    }

    /**
     * d= The SDID claiming responsibility for an introduction of a message into the mail stream (plain-text; REQUIRED).
     *
     * Hence, the SDID value is used to form the query for the public key.  The SDID MUST correspond to a valid DNS name
     * under which the DKIM key record is published.
     */
    public function getDomain(): string
    {
        return $this->domain;
    }

    /**
     * h= Signed header fields (plain-text, but see description; REQUIRED).
     *
     * A colon-separated list of header field names that identify the header fields presented to the signing algorithm.
     * The field MUST contain the complete list of header fields in the order presented to the signing algorithm.  The
     * field MAY contain names of header fields that do not exist when signed; nonexistent header fields do not
     * contribute to the signature computation (that is, they are treated as the null input, including the header field
     * name, the separating colon, the header field value, and any CRLF terminator).  The field MAY contain multiple
     * instances of a header field name, meaning multiple occurrences of the corresponding header field are included in
     * the header hash.  The field MUST NOT include the DKIM-Signature header field that is being created or verified
     * but may include others.  Folding whitespace (FWS) MAY be included on either side of the colon separator.  Header
     * field names MUST be compared against actual header field names in a case-insensitive manner.  This list MUST NOT
     * be empty.
     *
     * @see https://www.rfc-editor.org/rfc/rfc6376#section-5.4 for a discussion of choosing header fields to sign
     * @see https://www.rfc-editor.org/rfc/rfc6376#section-5.4.2 for requirements when signing multiple instances of
     *                                                           a single field
     *
     * @return list<string>
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }

    /**
     * c= Message canonicalization (plain-text; OPTIONAL, default is "simple/simple").
     *
     * This tag informs the Verifier of the type of canonicalization used to prepare the message for signing.  It
     * consists of two names separated by a "slash" (%d47) character, corresponding to the header and body
     * canonicalization algorithms, respectively.  These algorithms are described in Section 3.4.  If only one algorithm
     * is named, that algorithm is used for the header and "simple" is used for the body.  For example, "c=relaxed" is
     * treated the same as "c=relaxed/simple".
     *
     * @see https://www.rfc-editor.org/rfc/rfc6376#section-3.4 for reasons to choose different canonicalizations
     */
    public function getCanonicalization(): string
    {
        return $this->canonicalization;
    }

    /**
     * i= The Agent or User Identifier (AUID) on behalf of which the SDID is taking responsibility
     *
     * (dkim-quoted-printable; OPTIONAL, default is an empty local-part followed by an "@" followed by the domain from
     * the "d=" tag).
     *
     * The syntax is a standard email address where the local-part MAY be omitted.  The domain part of the address MUST
     * be the same as, or a subdomain of, the value of the "d=" tag. Internationalized domain names MUST be encoded as
     * A-labels: @see https://www.rfc-editor.org/rfc/rfc5890#section-2.3
     */
    public function getIdentifier(): string
    {
        return $this->identifier;
    }
}
