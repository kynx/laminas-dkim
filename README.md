# kynx/laminas-dkim

[![Build Status](https://github.com/kynx/laminas-dkim/workflows/Continuous%20Integration/badge.svg)](https://github.com/kynx/laminas-dkim/actions?query=workflow%3A"Continuous+Integration")

Add DKIM signatures to [laminas-mail] messages.

[DKIM] signatures enable systems receiving your emails to verify that the email was sent was sent from who it says it was
and hasn't been tampered with en-route. Adding them lessens the chance of ending up in someones spam folder.

If you are sending mail via SMTP you probably do not need this library: most reputable providers add them already. Check
the full headers of an email your system has sent for a `DKIM-Signature` header. If it's there, find something else to 
do :wink:

Before using this library, be sure you can add `TXT` records to the DNS of the domains you are sending mails `From`. 
You will need to add specially formatted `TXT` records to those domains or your signed messages will get rejected.


## Installation

```
composer require kynx/laminas-dkim
```

If you are adding this to an existing Laminas or Mezzio project, you should be prompted to add the package as a module 
or to your `config/config.php`. 

Next copy the configuration to your autoload directory:

```
cp vendor/kynx/laminas-dkim/config/dkim.global.php.dist config/autoload/dkim.global.php
cp vendor/kynx/laminas-dkim/config/dkim.local.php.dist config/autoload/dkim.local.php
```

The `dkim.local.php` file will contain the private key used to sign messages: **DO NOT** check it into version control!

Create a private signing key - as described at [dkimcore.org] - and add it to the `dkim.local.php` file you copied 
above, _without_ the surrounding `-----BEGIN RSA PRIVATE KEY-----` / `-----END RSA PRIVATE KEY-----`. 

Finish the configuration by setting your `domain`, `selector` and the `headers` you want to sign in `dkim.global.php`.

You will now be able to sign messages. But you still will need to configure your DNS `TXT` record before receiving mail 
servers will be able to verify it: see [dkimcore.org] for details on the format for that.

## Usage

### Manual instantiation

```php
<?php 

require 'vendor/autoload.php';

use Kynx\Laminas\Dkim\PrivateKey\RsaSha256;
use Kynx\Laminas\Dkim\Signer\Params;
use Kynx\Laminas\Dkim\Signer\Signer;
use Laminas\Mail\Message;
use Laminas\Mail\Transport\Sendmail;

$mail = Message();
$mail->setBody("Hello world!")
    ->setFrom('from@example.com')
    ->addTo('to@example.com')
    ->setSubject('subject');

// Create signer
$privateKey = new RsaSha256('sel1', 'your private key');
$params = new Params('example.com', ['From', 'To', 'Subject']);
$signer = new Signer($params, $privateKey);

// Sign message
$signed = $signer->signMessage($mail);

// Send message
$transport = new Sendmail();
$transport->send($signed);
```

### Factory based instantiation

```php
<?php 

require 'vendor/autoload.php';

use Kynx\Laminas\Dkim\Signer\Signer;
use Laminas\Mail\Message;
use Laminas\Mail\Transport\TransportInterface;

// Get container (Mezzio example)
$container = require 'config/container.php';

$mail = Message();
$mail->setBody("Hello world!")
    ->setFrom('from@example.com')
    ->addTo('to@example.com')
    ->setSubject('subject');

// Get configured Signer
$signer = $container->get(Signer::class);

// Sign message
$signed = $signer->signMessage($mail);

// Send message
$transport = $container->get(TransportInterface::class);
$transport->send($signed);
```

## Configuration options

You can configure most (but not all, yet) of the tags that will be included in the DKIM signature. The most common ones
to customize are:

### `canonicalization`
This controls how whitespace is handled when signing the headers and body. The are two options for both: "simple" and 
"relaxed". Simple canonicalization changes very little, relaxed canonicalization collapses whitespace. The 
canonicalization format is written as a pair separated by a '/' - so `relaxed/simple` specifies that the headers will 
collapse whitespace, while the body will not.

Some email systems mess with white space of emails in transit, which would result in failed validation if you use 
"simple". Consequently most major providers use "relaxed/relaxed" and that is the default for this library too. See the 
[3.4 Canonicalization] section of the specification for a detailed discussion of the pros and cons.

### `headers`
This specifies which headers will be included in the signature. In general you want to include headers that affect the 
transmission or display of the email - for instance `To`, `CC`, `Subject` - but not those that might get modified 
en-route like `Return-Path`. `From` is included no matter what.

By default this library signs `CC`, `Content-Type`, `Date`, `From`, `MIME-Version`, `Reply-To`, `Subject` and `To`. See
the [5.4.1 Recommended Signature Content] section of the specification for more guidance.


## Upgrading

The API has undergone a number of changes since version 1.x:

* All classes are now under the `Kynx\Laminas\Dkim` namespace. It seemed a bit rude to hog the top-level `Dkim` 
  namespace, and could cause conflicts with other DKIM-related packages.
* All classes are now `final`.
* `Signer` is now stateless. This fixes problems with signing multiple messages and permits usage in long-running
  processes such as mezzio-swoole.
* `Signer` now consumes a `Params` instance and a `PrivateKeyInterface`. This provides a more friendly interface to 
  DKIM's options, and will permit other signing algorithms in future (see [RFC8463]).
* `Signer::signMessage()` now _returns_ the signed message, leaving the original unaltered.
* The configuration files now use human-readable keys for parameters instead of `d`, `s` and `h`. The private key is 
  now in a `keys` section which includes the `selector`. Again, this is for forward-compatibility with multiple signing
  algorithms.

### To upgrade

* Search for `use Dkim\` and replace with `use Kynx\Laminas\Dkim\`
* Update the parameters in your configuration files to use `domain`, `selector` and `headers` instead of `d`, `s` and 
  `h`. See [dkim.global.php.dist] and [dkim.local.php.dist] for the new format.
* Change your code to use the signed message returned from `Signer::signMessage()`:

Before (1.x):
```php
<?php

$signer->signMessage($message);
```

After (2.x):
```php
<?php

$message = $signer->signMessage($message);
```

If you are manually constructing the `Signer` instance, see the Manual Instatiation section above for and example of 
passing the new `Params` and `PrivateKeyInterface` to the constructor.

## History

This is an evolution of [metalinspired/laminas-dkim], with improvements, bug fixes, tests and modernised code. That
package was forked from [joepsyko/zf-dkim], which in turn was forked from [fastnloud/zf-dkim].


[laminas-mail]: https://docs.laminas.dev/laminas-mail/
[DKIM]: https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail
[metalinspired/laminas-dkim]: https://github.com/metalinspired/laminas-dkim
[joepsyko/zf-dkim]: https://github.com/joepsyko/zf-dkim
[fastnloud/zf-dkim]: https://github.com/fastnloud/zf-dkim
[dkimcore.org]: http://dkimcore.org/specification.html
[3.4 Canonicalization]: https://www.rfc-editor.org/rfc/rfc6376#section-3.4
[5.4.1 Recommended Signature Content]: https://www.rfc-editor.org/rfc/rfc6376#section-5.4.1
[RFC8463]: https://www.rfc-editor.org/rfc/rfc8463.html
[dkim.global.php.dist]: ./config/dkim.global.php.dist
[dkim.local.php.dist]: ./config/dkim.local.php.dist