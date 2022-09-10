<?php

declare(strict_types=1);

namespace Kynx\Laminas\Dkim\Exception;

use InvalidArgumentException;

final class InvalidPrivateKeyException extends InvalidArgumentException implements ExceptionInterface
{
}
