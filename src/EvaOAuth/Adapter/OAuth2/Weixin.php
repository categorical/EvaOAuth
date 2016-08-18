<?php

namespace EvaOAuth\Adapter\OAuth2;

use EvaOAuth\Adapter\OAuth2\AbstractAdapter;
use EvaOAuth\Service\Token\Access as AccessToken;
use EvaOAuth\Service\Token\Access;
use EvaOAuth\Service\Token\Request;
use ZendOAuth\OAuth;

class Weixin extends AbstractAdapter
{
    protected $accessTokenFormat = 'json';

    protected $authorizeUrl = 'https://open.weixin.qq.com/connect/qrconnect';
    protected $accessTokenUrl = 'https://api.weixin.qq.com/sns/oauth2/access_token';
    const USERINFOURL = 'https://api.weixin.qq.com/sns/userinfo';

    protected $defaultOptions = array(
        'requestScheme' => OAuth::REQUEST_SCHEME_POSTBODY,
        'scope' => 'snsapi_login',
    );

    protected $openid;


    public function getAccessToken($a, $b, $c, $d)
    {
        if (!empty($this->_token)) {
            return $this->_token;
        }
        $args = func_get_args();
        $code = isset($args[0]['code']) ? $args[0]['code'] : null;

        $foo = new \EvaOAuth\Service\Http\AccessToken($this->getConsumer());

        $tokenargs = array(
            'grant_type' => 'authorization_code',
            'appid' => $this->getConsumer()->getConsumerKey(),
            'secret' => $this->getConsumer()->getConsumerSecret(),
            'code' => $code,
        );
        $res = $foo->startRequestCycle($tokenargs);
        $token = new Access($res, null, $this->getConsumer()->getAccessTokenFormat());

        return $this->_token = $token;
    }

    public function _getRequestToken()
    {
        $args = array(
            'response_type' => $this->getConsumer()->getResponseType(),
            'appid' => $this->getConsumer()->getConsumerKey(),
            'redirect_uri' => $this->getConsumer()->getCallbackUrl(),
            'state' => md5(uniqid(rand(), true)),
            'scope' => $this->getConsumer()->getScope(),
        );

        $req = new Request();
        $req->setParams($args);

        return $req;
    }

    public function getRequestTokenUrl()
    {
        $params = $this->getConsumer()->getRequestToken()->toArray();
        $params['appid'] = $params['client_id'];
        unset($params['client_id']);

        return $this->authorizeUrl . '?' . http_build_query($params);
    }


    public function accessTokenToArray(AccessToken $accessToken)
    {
        $token = parent::accessTokenToArray($accessToken);
        $token['openid'] = $accessToken->getParam('openid');
        $token['unionid'] = $accessToken->getParam('unionid');

        $userinfo = $this->getuserinfo($token['openid']);
        $token['remoteToken'] = isset($userinfo['openid']) ? $userinfo['openid'] : null;
        $token['remoteUserId'] = isset($userinfo['unionid']) ? $userinfo['unionid'] : null;
        $token['remoteUserName'] = isset($userinfo['nickname']) ? $userinfo['nickname'] : null;
        $token['remoteImageUrl'] = isset($userinfo['headimgurl']) ? $userinfo['headimgurl'] : null;
        $token['remoteExtra'] = $userinfo ? json_encode($userinfo) : null;

        return $token;
    }

    private function getuserinfo($openid)
    {
        if ($this->_userinfo || false === $this->_userinfo) {
            return $this->_userinfo;
        }

        $client = $this->getHttpClient();
        $client->setUri(self::USERINFOURL, $openid);
        $client->setParameterGet([
            'openid' => $openid
        ]);
        $response = $client->send();
        if ($response->getStatusCode() >= 300) {
            return $this->userinfo = false;
        }

        return $this->_userinfo = $this->parseJsonResponse($response);
    }

}
