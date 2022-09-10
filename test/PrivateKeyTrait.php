<?php

declare(strict_types=1);

namespace KynxTest\Laminas\Dkim;

use Kynx\Laminas\Dkim\PrivateKey\PrivateKeyInterface;
use Kynx\Laminas\Dkim\PrivateKey\RsaSha256;

use function file_get_contents;
use function str_replace;
use function trim;

trait PrivateKeyTrait
{
    protected function getPrivateKeyString(): string
    {
        return trim(str_replace(
            ['-----BEGIN RSA PRIVATE KEY-----', '-----END RSA PRIVATE KEY-----'],
            '',
            file_get_contents(__DIR__ . '/assets/private_key.pem')
        ));
    }

    protected function getPrivateKey(): PrivateKeyInterface
    {
        return new RsaSha256('202209', $this->getPrivateKeyString());
    }
}
