<?php

namespace Ubi\Utils;

class WeiXinAPI
{
    private $agentId;
    private $corpId;
    private $corpSecret;
    private $accessToken;
    private $httpClient;

    function __construct()
    {
        $this->httpClient = new HttpClient();
    }

    /**
     * 设置一些必要的参数
     * @param $params
     * @return $this
     */
    public function setParams($params)
    {
        $this->agentId     = $params['agentId'] ? $params['agentId'] : $this->agentId;
        $this->corpId      = $params['corpId'] ? $params['corpId'] : $this->corpId;
        $this->corpSecret  = $params['corpSecret'] ? $params['corpSecret'] : $this->corpSecret;
        $this->accessToken = $params['accessToken'] ? $params['accessToken'] : $this->accessToken;

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
     * @return array ['code' => '0: failure, 1: success, 2: accessToken expired', 'msg' => 'msg', 'data' => 'data']
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

        if ($response === false) {
            return ['code' => 2, 'msg' => 'accessToken 已过期，请重新获取'];
        }
        $data = [
            'accessToken' => $response->access_token,
            'expiresIn'   => $response->expires_in,
        ];

        return ['code' => 1, 'msg' => 'ok', 'data' => $data];
    }

    /**
     * 解密回调信息，并进行密文比对验证，通过才可以进行之后的调用
     * @param $params ['token', 'encodingAesKey', 'msgSignature', 'timestamp', 'nonce', 'encrypt']
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

    /**
     * 解析用户发送的消息内容
     * @param $params ['token', 'encodingAesKey', 'msgSignature', 'timestamp', 'nonce', 'data']
     * @return mixed
     * @throws \Exception
     */
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
        $decryptMsg = $this->decryptMsg($params['encodingAesKey'], $params['encrypt'], $this->corpId);
        $xmlMsg     = simplexml_load_string($decryptMsg);

        $message = $this->getMessage($xmlMsg);
        return $message;
    }

    /**
     * 获取企业微信服务器的ip段
     * @return array ['code' => '0: failure, 1: success, 2: accessToken expired', 'msg' => 'msg', 'data' => ["101.226.103.*", "101.226.62.*"]]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getCallbackIP()
    {
        return $this->getIP('getCallbackIP');
    }

    /**
     * 获取企业微信API域名IP段
     * @return array ['code' => '0: failure, 1: success, 2: accessToken expired', 'msg' => 'msg', 'data' => ["182.254.11.176", "182.254.78.66"]]
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    public function getAPIDomainIP()
    {
        return $this->getIP('getAPIDomainIP');
    }

    public function mediaUpload($type, $media)
    {
        $accessToken = $this->accessToken;

    }

    /**
     * 向指定用户发送文本消息
     * @param $message
     * @param $users [user1, user2, user3] | @all
     * @param bool $isSafe
     * @return array
     * @throws \Exception
     */
    public function sendTextMessageToUsers($message, $users, $isSafe = false)
    {
        $messageInfo = $this->makeMessage($message, 'text', $users, [], [], $isSafe);
        $response    = $this->sendMessage($messageInfo);
        return $response;
    }

    /**
     * 向指定部门发送文本消息
     * @param $message
     * @param $parties [party1, party2]
     * @param bool $isSafe
     * @return array
     * @throws \Exception
     */
    public function sendTextMessageToParties($message, $parties, $isSafe = false)
    {
        $messageInfo = $this->makeMessage($message, 'text', [], $parties, [], $isSafe);
        $response    = $this->sendMessage($messageInfo);
        return $response;
    }

    /**
     * 向指定标签的成员发送文本消息
     * @param $message
     * @param $tags [tag1, tag2]
     * @param bool $isSafe
     * @return array
     * @throws \Exception
     */
    public function sendTextMessageToTags($message, $tags, $isSafe = false)
    {
        $messageInfo = $this->makeMessage($message, 'text', [], [], $tags, $isSafe);
        $response    = $this->sendMessage($messageInfo);
        return $response;
    }

    /**
     * 给指定用户发送 markdown 格式的消息
     * @param $message
     * @param $users [user1, user2, user3] | @all
     * @param bool $isSafe
     * @return array
     * @throws \Exception
     */
    public function sendMarkDownMessageToUsers($message, $users, $isSafe = false)
    {
        $messageInfo = $this->makeMessage($message, 'markdown', $users, [], [], $isSafe);
        $response    = $this->sendMessage($messageInfo);
        return ['invaliduser' => $response['invaliduser']];
    }

    /**
     * 给指定部门发送 markdown 格式的消息
     * @param $message
     * @param $parties [party1, party2]
     * @param bool $isSafe
     * @return array
     * @throws \Exception
     */
    public function sendMarkDownMessageToParties($message, $parties, $isSafe = false)
    {
        $messageInfo = $this->makeMessage($message, 'markdown', [], $parties, [], $isSafe);
        $response    = $this->sendMessage($messageInfo);
        return ['invalidparty' => $response['invalidparty']];
    }

    /**
     * 给指定标签的用户发送 markdown 格式的消息
     * @param $message
     * @param $tags [tag1, tag2]
     * @param bool $isSafe
     * @return array
     * @throws \Exception
     */
    public function sendMarkDownMessageToTags($message, $tags, $isSafe = false)
    {
        $messageInfo = $this->makeMessage($message, 'markdown', [], [], $tags, $isSafe);
        $response    = $this->sendMessage($messageInfo);
        return ['invalidtag' => $response['invalidtag']];
    }

    private function makeMessage($message, $type = 'text', $users, $parties, $tags, $isSafe)
    {
        $messageInfo = [
            'touser'  => is_array($users) ? explode('|', $users) : $users,
            'toparty' => explode('|', $parties),
            'totag'   => explode('|', $tags),
            'msgtype' => $type,
            'agentid' => $this->agentId,
            'safe'    => $isSafe ? 1 : 0
        ];

        if ($type == 'text') {
            $messageInfo['text'] = ['content' => $message];
        }

        if ($type == 'markdown') {
            $messageInfo['markdown'] = ['content' => $message];
        }

        return $messageInfo;
    }

    private function sendMessage($message)
    {
        $accessToken = $this->accessToken;
        if (empty($accessToken)) {
            throw new \Exception("微信 API 接口调用失败: accessToken 为空");
        }

        if (empty($message)) {
            throw new \Exception("微信 API 接口调用失败: 消息内容为空");
        }

        $api = $this->getAPI('sendMessage');
        if (empty($api)) {
            throw new \Exception("微信 API 接口调用失败: 无法获取发送消息接口请求地址");
        }

        $params         = [
            'access_token' => $accessToken
        ];
        $originResponse = $this->httpClient->post($api, $params, $message);
        $response       = $this->handleResponse($originResponse);

        if ($response === false) {
            return ['code' => 2, 'msg' => 'accessToken 已过期，请重新获取'];
        }

        $data = [
            'invaliduser'  => explode('|', $response->invaliduser),
            'invalidparty' => explode('|', $response->invalidparty),
            'invalidtag'   => explode('|', $response->invalidtag),
        ];

        return ['code' => 1, 'msg'=> 'ok', 'data' => $data];
    }

    /**
     * @param string $type
     * @return array ['code' => '0: failure, 1: success, 2: accessToken expired', 'msg' => 'msg', 'data' => 'data']
     * @throws \GuzzleHttp\Exception\GuzzleException
     */
    private function getIP($type = 'getAPIDomainIP')
    {
        $accessToken = $this->accessToken;
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

        if ($response === false) {
            return ['code' => 2, 'msg' => 'accessToken 已过期，请重新获取'];
        }

        return ['code' => 1, 'msg' => 'ok', 'data' => $response->ip_list];
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

            // accessToken 过期，需要重新获取
            if (40014 == $response->errcode) {
                return false;
            }

            throw new \Exception("微信 API 接口调用失败: {$response->errmsg}");
        }

        return $response;
    }

    private function getMessage($xmlMsg)
    {
        $message['userName']   = (string)$xmlMsg->FromUserName;
        $message['createTime'] = (string)$xmlMsg->CreateTime;
        $message['type']       = (string)$xmlMsg->MsgType;

        if ($message['type'] == 'text') {
            $message['text'] = (string)$xmlMsg->Content;
        }

        return $message;
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
            'sendMessage'    => 'cgi-bin/message/send', // 发送应用消息
            'mediaUpload'    => 'cgi-bin/media/upload', // 上传临时素材
        ];

        $host = "https://qyapi.weixin.qq.com";

        $path = $apiArr[$pathName];
        if (empty($path)) {
            return false;
        }

        return "{$host}/{$path}";
    }
}
