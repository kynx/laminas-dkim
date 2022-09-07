<?php

declare(strict_types=1);

namespace Kynx\Laminas\Dkim\Exception;

use DomainException;

final class MissingParamException extends DomainException implements ExceptionInterface
{
}
