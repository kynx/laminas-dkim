<?php

declare(strict_types=1);

namespace Kynx\Laminas\Dkim\PrivateKey;

interface PrivateKeyInterface
{
    /**
     * Returns base64 encoded signature for payload
     */
    public function createSignature(string $payload): string;

    /**
     * a= The algorithm used to generate the signature (plain-text; REQUIRED).
     *
     * Verifiers MUST support "rsa-sha1" and "rsa-sha256"; Signers SHOULD sign using "rsa-sha256".  See Section 3.3 for
     * a description of the algorithms.
     */
    public function getAlgorithm(): string;

    /**
     * s= The selector subdividing the namespace for the "d=" (domain) tag (plain-text; REQUIRED).
     *
     * Internationalized selector names MUST be encoded as A-labels:
     *
     * @see https://www.rfc-editor.org/rfc/rfc5890#section-2.3
     */
    public function getSelector(): string;
}
