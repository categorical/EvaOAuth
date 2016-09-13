<?php

namespace EvaOAuth\Adapter\OAuth2;

use EvaOAuth\Adapter\OAuth2\AbstractAdapter;
use EvaOAuth\Service\Token\Access as AccessToken;
use EvaOAuth\Service\Token\Access;
use EvaOAuth\Service\Token\Request;
use ZendOAuth\OAuth;

class Weixindirect extends Weixin
{

    protected $authorizeUrl = 'https://open.weixin.qq.com/connect/oauth2/authorize';
    
    public function getRequestTokenUrl()
    {
        $url = parent::getRequestTokenUrl();
        $args = parse_url($url, PHP_URL_QUERY);
        parse_str($args, $args);

        $args = array_merge([
            'appid' => null,
            'redirect_uri' => null,
            'scope' => null,
            'response_type' => null
        ], $args);

        return strtok($url, '?') . '?' . http_build_query($args);
    }

}
