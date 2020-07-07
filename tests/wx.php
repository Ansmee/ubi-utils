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

$encodingAesKey                 = "abkJMUMW0317OWIhncQaWTx9cxUEFJCRz6cA1E7E6dm";
$token                          = "te1Xomu2YR";
$verifyParams['encodingAesKey'] = $encodingAesKey;
$verifyParams['token']          = $token;
$verifyParams['msgSignature']   = 'a1a276a8cf7e5a6947925b71e5070aaeb5c981e7';
$verifyParams['timestamp']      = time();
$verifyParams['nonce']          = time();
$verifyParams['encrypt']        = 'WNTsJVgBQwyNdYKVtF9A1O7fJxqhLxDq1fPf7xvM8d9I+BcatbsPydIKh5az2cqSXdC8kwxt3ZBX3ijgTq3ccg==';

$errCode = $wxcpt->decryptCallBackMsg($verifyParams);

var_dump($errCode);
