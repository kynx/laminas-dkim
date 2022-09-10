<?php

namespace Dkim\Signer;

use Exception;
use Interop\Container\ContainerInterface;
use Laminas\ServiceManager\Factory\FactoryInterface;

/**
 * @see \DkimTest\Signer\SignerFactoryTest
 */
class SignerFactory implements FactoryInterface
{
    public function __invoke(ContainerInterface $container, $requestedName, ?array $options = null): Signer
    {
        $config = $container->get('config');

        if (! isset($config['dkim'])) {
            throw new Exception("No 'dkim' config option set.");
        }

        return new Signer($config['dkim']);
    }
}
