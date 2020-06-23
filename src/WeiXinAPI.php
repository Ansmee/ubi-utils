<?php

namespace Ubi\Utils;

class WeiXinAPI
{
    private $corpId;
    private $corpSecret;
    private $httpClient;

    function __construct()
    {
        $this->httpClient = new HttpClient();
    }

    /**
     * 设置 corpId，corpSecret，用于获取 accessToken
     * @param $corpId
     * @param $corpSecret
     * @return $this
     */
    public function setCorp($corpId, $corpSecret)
    {
        $this->corpId     = $corpId;
        $this->corpSecret = $corpSecret;

        return $this;
    }

    /**
     * 获取 accessToken，开发者需要缓存 accessToken，用于后续接口的调用（注意：不能频繁调用 getAccessToken 接口，否则会受到频率拦截）。
     * 当 accessToken 失效或过期时，需要重新获取。
     * @return array|bool|string
     * [
     *      'accessToken' => '获取到的凭证，最长为512字节',
     *      'expiresIn' => '凭证的有效时间（秒）'
     * ]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getAccessToken()
    {
        if (empty($this->corpId)) {
            throw new \Exception('微信 API 接口调用失败: corpId 不能为空');
        }

        if (empty($this->corpSecret)) {
            throw new \Exception('微信 API 接口调用失败: corpSecret 不能为空');
        }

        $api = $this->getAPI('accessToken');
        if (empty($api)) {
            throw new \Exception('微信 API 接口调用失败: 无法获取 accessToken 接口请求地址');
        }

        $params = [
            'corpid'     => $this->corpId,
            'corpsecret' => $this->corpSecret
        ];

        $originResponse = $this->httpClient->get($api, $params);
        $response       = $this->handleResponse($originResponse);

        $data = [
            'accessToken' => $response->access_token,
            'expiresIn'   => $response->expires_in,
        ];

        return $data;
    }

    /**
     * 解密回调信息，并进行密文比对验证，通过才可以进行之后的调用
     * @param $params
     * @return mixed
     * @throws \Exception
     */
    public function decryptCallBackMsg($params)
    {
        if (strlen($params['encodingAesKey']) != 43) {
            throw new \Exception("微信 API 接口调用失败: encodingAesKey 不合法");
        }

        if (empty($params['token']) || empty($params['encodingAesKey']) || empty($params['msgSignature']) || empty($params['timestamp']) || empty($params['nonce']) || empty($params['encrypt'])) {
            throw new \Exception("微信 API 接口调用失败: 缺少必要的参数，token: {$params['token']}, encodingAesKey: {$params['encodingAesKey']}, msgSignature: {$params['msgSignature']}，timestamp: {$params['timestamp']}，nonce: {$params['nonce']}，encrypt: {$params['encrypt']}");
        }

        // 验证签名是否合法
        if (!$this->verifySignature($params)) {
            throw new \Exception("微信 API 接口调用失败: 回调消息签名验证失败");
        }

        // 解密加密之后的消息内容
        $decryptMsg = $this->decryptMsg($params['encodingAesKey'], $params['encrypt'], $this->corpId);
        return $decryptMsg;
    }

    public function decryptUserMsg($params)
    {
        if (strlen($params['encodingAesKey']) != 43) {
            throw new \Exception("微信 API 接口调用失败: encodingAesKey 不合法");
        }

        if (empty($params['token']) || empty($params['encodingAesKey']) || empty($params['msgSignature']) || empty($params['timestamp']) || empty($params['nonce']) || empty($params['data'])) {
            throw new \Exception("微信 API 接口调用失败: 缺少必要的参数，token: {$params['token']}, encodingAesKey: {$params['encodingAesKey']}, msgSignature: {$params['msgSignature']}，timestamp: {$params['timestamp']}，nonce: {$params['nonce']}，data: {$params['data']}");
        }

        $xmlparse = new \XMLParse();
        $result   = $xmlparse->extract($params['data']);

        if ($result[0] != 0) {
            throw new \Exception("微信 API 接口调用失败: 消息内容解析失败");
        }

        $params['encrypt'] = $result[1];

        // 验证签名是否合法
        if (!$this->verifySignature($params)) {
            throw new \Exception("微信 API 接口调用失败: 回调消息签名验证失败");
        }

        // 解密加密之后的消息内容
        $decryptMsg          = $this->decryptMsg($params['encodingAesKey'], $params['encrypt'], $this->corpId);
        $msgXml              = simplexml_load_string($decryptMsg);
        $message['userName'] = (string)$msgXml->FromUserName;
        $message['content']  = (string)$msgXml->Content;

        return $message;
    }

    /**
     * 获取企业微信服务器的ip段
     * @param $accessToken
     * @return mixed ["101.226.103.*", "101.226.62.*"]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getCallbackIP($accessToken)
    {
        return $this->getIP('getCallbackIP', $accessToken);
    }

    /**
     * 获取企业微信API域名IP段
     * @return mixed ["182.254.11.176", "182.254.78.66"]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getAPIDomainIP($accessToken)
    {
        return $this->getIP('getAPIDomainIP', $accessToken);
    }

    private function getIP($type = 'getAPIDomainIP', $accessToken)
    {
        if (empty($accessToken)) {
            throw new \Exception("微信 API 接口调用失败: 缺少必要的参数 accessToken");
        }

        $api = $this->getAPI($type);
        if (empty($api)) {
            throw new \Exception("微信 API 接口调用失败: 无法获取 {$type} 接口请求地址");
        }

        $params = [
            'access_token' => $accessToken
        ];

        $originResponse = $this->httpClient->get($api, $params);
        $response       = $this->handleResponse($originResponse);

        return $response->ip_list;
    }

    private function verifySignature($params)
    {
        $encryptArr = [$params['encrypt'], $params['token'], $params['timestamp'], $params['nonce']];

        sort($encryptArr, SORT_STRING);
        $encryptStr      = implode('', $encryptArr);
        $devMsgSignature = sha1($encryptStr);

        $msgSignature = $params['msgSignature'];
        return $msgSignature === $devMsgSignature;
    }

    private function decryptMsg($encodingAesKey, $encrypt, $receiveId)
    {
        $decrypter = new \Prpcrypt($encodingAesKey);

        $result = $decrypter->decrypt($encrypt, $receiveId);
        if ($result[0] != 0) {
            throw new \Exception("微信 API 接口调用失败: 消息解密失败");
        }

        return $result[1];
    }

    private function handleResponse($response)
    {
        if (isset($response->errcode) && 0 != $response->errcode) {
            throw new \Exception("微信 API 接口调用失败: {$response->errmsg}");
        }

        return $response;
    }

    private function getAPI($pathName)
    {
        if (empty($pathName)) {
            return false;
        }

        $apiArr = [
            'accessToken'    => 'cgi-bin/gettoken', // 获取 accessToken
            'getCallbackIP'  => 'cgi-bin/getcallbackip', // 获取企业微信服务器的 ip 段
            'getAPIDomainIP' => 'cgi-bin/get_api_domain_ip', // 获取企业微信API域名IP段
        ];

        $host = "https://qyapi.weixin.qq.com";

        $path = $apiArr[$pathName];
        if (empty($path)) {
            return false;
        }

        return "{$host}/{$path}";
    }
}
