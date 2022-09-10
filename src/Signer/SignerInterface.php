<?php

declare(strict_types=1);

namespace Kynx\Laminas\Dkim\Signer;

use Laminas\Mail\Message;

interface SignerInterface
{
    /**
     * Returns signed message with a DKIM signature.
     */
    public function signMessage(Message $message): Message;
}
