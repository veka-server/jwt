# JWT
Un middleware minimaliste pour firebase/php-jwt
basée sur https://github.com/firebase/php-jwt

## Installation

Via composer
```
composer require veka-server/jwt
```

## Utilisation des tokens
```php

        $data = ['id_user' =>555];

        /** @var VekaServer\JWT\JWT $jwt */
        $jwt = Container::getInstance()->get('JWT');
        $jwtToken = $jwt->getToken($data);

        $decoded = $jwt->decode($jwtToken);

        $retour = [
                "message" => "Successful login",
                "jwt" => $jwtToken,
                "expireAt" => $decoded->exp
        ];

```

## Utiliser le router comme un middleware PSR-15
```php
// creation du dispatcher
$Dispatcher = new VekaServer\Dispatcher\Dispatcher();

// creer le jwt
$jwt = new \App\classe\JWT(
                  $private, // private_key
                  $public, // public_key
                  'localhost:8000', // iss
                  3600, // expire time token -- facultatif default = 3600
                  'RS256', // algorithm de chiffrement -- facultatif default = RS256
                  'localhost:8000', // aud -- facultatif default = iss
              );

// ajout le middlewares
$Dispatcher->pipe($jwt);
```
