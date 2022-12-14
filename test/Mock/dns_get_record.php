<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

use function file_get_contents;

use const DNS_ANY;

/**
 * Ugly hack to override builtin - called in `PHPMailer\DKIMValidator\Validator::fetchPublicKeys()`
 */
function dns_get_record(string $hostname, int $type = DNS_ANY): array
{
    return [
        [
            'host'  => $hostname,
            'class' => 'IN',
            'type'  => 'TXT',
            'ttl'   => 3600,
            'txt'   => file_get_contents(__DIR__ . '/../assets/dns_record.txt'),
        ],
    ];
}
