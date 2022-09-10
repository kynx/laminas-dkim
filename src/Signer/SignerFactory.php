<?php

namespace Kynx\Laminas\Dkim\Signer;

use Exception;
use Psr\Container\ContainerInterface;

/**
 * @see \KynxTest\Laminas\Dkim\Signer\SignerFactoryTest
 */
final class SignerFactory
{
    public function __invoke(ContainerInterface $container): Signer
    {
        $config = $container->get('config');

        if (! isset($config['dkim'])) {
            throw new Exception("No 'dkim' config option set.");
        }

        return new Signer($config['dkim']);
    }
}
