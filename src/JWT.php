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
    private array $exclude_url = []; // list url not require token

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
        $authResponse = $this->authorise($request);

        if ($authResponse->getStatusCode() === 200) {
            return $handler->handle($request);
        }

        return $authResponse;
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

    public static function extractPage($request_uri, $script_name){

        $url = urldecode($request_uri );

        $pos = strpos($url, '?');
        return '/'. trim(
                $pos !== false
                    ?   substr($url, 0, $pos)
                    :   $url,
                '/');
    }

    private static function cleanPath($url){

        $len = strlen($url);
        if ($len <= 0) {
            return '';
        }

        // Fix missing begin-/
        if ($url[0] != '/') {
            $url = '/' . $url;
        }

        // Fix trailing /
        if ($len > 1 && $url[$len - 1] == '/') {
            $url = substr($url, 0, -1);
        }

        return $url;
    }

    private function authorise(ServerRequestInterface $request) :Response
    {
        $ServerParams = $request->getServerParams();
        $uri = self::extractPage($ServerParams['REQUEST_URI'], $ServerParams['SCRIPT_NAME']);

        foreach ($this->exclude_url as $url){
            if($this->checkURI($url, $uri)){
                return new Response(200);
            }
        }

        try {
            $authHeader = $request->getServerParams()['HTTP_AUTHORIZATION'] ?? '';
            if(!empty($authHeader)){
                $temp_header = explode(" ", $authHeader);
                $jwt = $temp_header[1] ?? '';
            }

            $this->decode($jwt ?? null);

            $errorCode = 200;

        }catch (Exception $e){

            $jsonBody = [
                'success' => false,
                "jwt" => $jwt ?? null,
                'error' => [
                    'message' => $e->getMessage(),
                    'help' => 'Token JWT incorrect or missing. Please add header => Authorization: Bearer [token]',
                ],
            ];

            $reason = 'Unauthorized';
            $jsonBody = json_encode($jsonBody);
            $errorCode = 401;
        }

        return new Response($errorCode, [], ($jsonBody ?? null), '1.1', ($reason ?? null) );
    }

    /**
     * @param string $regex
     * @param string $path
     * @return bool
     */
    public function checkURI(string $regex, string $path) :bool
    {
        $regex =self::cleanPath($regex);
        $path =self::cleanPath($path);

        if(empty($regex)){
            return false;
        }

        if($regex == $path) {
            return true;
        }

        // Prevent @ collision
        $regex = str_replace('@', '\\@', $regex);
        $test = preg_match('@^' . $regex . '$@', $path);

        return (bool)($test);
    }

    public function excludeUrl($url)
    {
        $this->exclude_url[] = $url;
    }
}
