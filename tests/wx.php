<?php

require_once '../vendor/autoload.php';

use Ubi\Utils\WeiXinAPI;


$wxapi = new WeiXinAPI();
getToken($wxapi);

$aaa = 'tests';
$user = ['ZhengWenJun'];
$res = $wxapi->sendTextMessageToUsers($aaa,$user);


var_dump($res);

function getToken(WeiXinAPI $wxapi)
{
    $params = [
        'corpId'=>'ww52f8d8da8cab19eb',
        'corpSecret'=>'uLawHvmmfWw_sebn8aTsL_YBQaBiXUm1PMT05Yskfs8',
        'agentId'=>1000019
    ];

    $wxapi->setParams($params);
    $token = $wxapi->getAccessToken();

    $wxapi->setAccessToken($token['data']['accessToken']);
}
