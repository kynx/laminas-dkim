<?php

namespace Kynx\Laminas\Dkim\Signer;

use Exception;
use Kynx\Laminas\Dkim\PrivateKey\RsaSha256;
use Psr\Container\ContainerInterface;

use function assert;
use function is_array;

/**
 * @see \KynxTest\Laminas\Dkim\Signer\SignerFactoryTest
 */
final class SignerFactory
{
    public function __invoke(ContainerInterface $container): Signer
    {
        $config = $container->get('config');
        assert(is_array($config));

        if (! (isset($config['dkim']) && is_array($config['dkim']))) {
            throw new Exception("No 'dkim' config set");
        }

        /**
         * @var array{
         *          params: array{
         *              domain: string,
         *              headers: list<string>
         *          },
         *          keys: array<string, array{
         *              selector: string,
         *              private_key: string
         *          }>
         *      } $dkim
         */
        $dkim = $config['dkim'];

        if (! (isset($dkim['params']) && is_array($dkim['params']))) {
            throw new Exception("No dkim params config set");
        }

        if (! (isset($dkim['keys']) && is_array($dkim['keys']))) {
            throw new Exception("No keys set");
        }

        /** @var array{domain: string, selector: string, headers: list<string>, canonicalization: string, identifier: string} $params */
        $params = $dkim['params'];
        $keys   = $dkim['keys'];

        if (! isset($keys['rsa-sha256'])) {
            throw new Exception("No rsa-sha256 key set");
        }
        $rsaSha256 = $keys['rsa-sha256'];

        return new Signer(
            new Params($params['domain'], $params['headers'], $params['canonicalization'], $params['identifier']),
            new RsaSha256($rsaSha256['selector'], $rsaSha256['private_key'])
        );
    }
}
