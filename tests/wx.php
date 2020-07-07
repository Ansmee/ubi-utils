<?php

require_once '../vendor/autoload.php';

use Ubi\Utils\WeiXinAPI;


$params = [
    'corpId'     => 'ww52f8d8da8cab19eb',
    'corpSecret' => 'uLawHvmmfWw_sebn8aTsL_YBQaBiXUm1PMT05Yskfs8',
    'agentId'    => 1000019
];

// 返回的url验证明文
$wxcpt = new WeiXinAPI();
$wxcpt->setParams($params);

$xml = "<xml><ToUserName><![CDATA[ww52f8d8da8cab19eb]]></ToUserName><Encrypt><![CDATA[CN+2nN4HpHOo9HnqQPteFsGz7/bvg8gmthEdk9T9ttMBw2E38Ttg4VMg4IjxN1G2NntOUEv23ZTshxXk3Jb1R/wJZv3JtIaxzrF+RIQIeRq3VieS6B73hDzRQiloVp4hMKxbLKPLb7Oo51h9LpF9KbUzU1p3kAkLBkwDdPlc6682MeTwoeE938uz+aWQOi8+ZIQ+Qi8MzQk6mKCLMUoJ1HTjgvsjxr/151smp+NKxsqwmj8LGGF0sTfWkvXhWCkNMskaX0TE3Yv61RWnzMZw8joi07XWUFIr8uNpKkO6HMkz0fhdRFnrQy5tnsO+TUEPp/9MsYAf6xVzkrHjqxTrhrDJOAfDZgZgxleu+PrdF3IdGTSofnD3+KWVU2Gq5wnGZgQN+KRfaLQFKGGVhxJaaAZZjP1u+MoC0s2abGRtO2s=]]></Encrypt><AgentID><![CDATA[1000019]]></AgentID></xml>";
$encodingAesKey                 = "abkJMUMW0317OWIhncQaWTx9cxUEFJCRz6cA1E7E6dm";
$token                          = "te1Xomu2YR";
$verifyParams['encodingAesKey'] = $encodingAesKey;
$verifyParams['token']          = $token;
$verifyParams['msgSignature']   = '8ea1ef7f164143925f56c9fbdc4d4d2720180f16';
$verifyParams['timestamp']      = '1594103091';
$verifyParams['nonce']          = '1594670948';
$verifyParams['data'] = $xml;

$res = $wxcpt->decryptUserMsg($verifyParams);

var_dump($res);
