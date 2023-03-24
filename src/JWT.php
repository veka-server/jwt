<?php

namespace VekaServer\JWT;

use Exception;
use Firebase\JWT\Key;
use Nyholm\Psr7\Response;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use stdClass;

class JWT implements MiddlewareInterface
{

    /**
     * @var String
     */
    private string $private_key;
    private string $public_key;
    private string $algorithm;
    private string $expireTimeToken;
    private string $iss; // créateur (issuer) du jeton
    private string $aud; // audience du jeton
    public const ATTRIBUTE = 'JWT_ATTRIBUTE';

    public function __construct(String $private_key
                                ,String $public_key
                                ,String $iss
                                ,int $expireTimeToken = 3600
                                ,String $algorithm = 'RS256'
                                ,String $aud = null) {
        $this->private_key = $private_key;
        $this->public_key = $public_key ;
        $this->iss = $iss;
        $this->algorithm = $algorithm;
        $this->expireTimeToken = $expireTimeToken;
        $this->aud = $aud ?? $iss;
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler) :ResponseInterface
    {
        $this->authorise($request);
        return $handler->handle($request);
    }

    public function getToken($data = []) :string
    {

        $time = time();
        $expireAt = $time + $this->expireTimeToken;

        $payload = [
            'iss' => $this->iss,
            'aud' => $this->aud,
            'iat' => time(), // time of token issued at
            'nbf' => $time + 1, //not before in seconds
            'exp' => $expireAt, // expire time of token in seconds
            'data' => $data
        ];

        return \Firebase\JWT\JWT::encode($payload, $this->private_key, $this->algorithm);
    }

    public function decode($jwt) :stdClass
    {
        \Firebase\JWT\JWT::$leeway = 10;
        return \Firebase\JWT\JWT::decode($jwt, new Key($this->public_key, $this->algorithm));
    }

    private function authorise(ServerRequestInterface &$request) :void
    {
        $attr = [
            'success' => true,
            "jwt" => '',
            "data" => null,
            'error' => [],
        ];

        try {
            $authHeader = $request->getServerParams()['HTTP_AUTHORIZATION'] ?? '';
            if(!empty($authHeader)){
                $temp_header = explode(" ", $authHeader);
                $jwt = $temp_header[1] ?? '';
            }

            $attr['jwt'] = $jwt;

            $decoded = $this->decode($jwt ?? '');

            $attr['data'] = $decoded->data ?? null;

        }catch (Exception $e){
            $attr['success'] = false;
            $attr['error'] = [
                'message' => $e->getMessage(),
                'help' => 'Token JWT incorrect or missing. Please add header => Authorization: Bearer [token]',
            ];
        }

        $request = $request->withAttribute(self::ATTRIBUTE, $attr);
    }

}
