<?php

require_once '../vendor/autoload.php';

use Ubi\Utils\WeiXinAPI;

$id = 'ww52f8d8da8cab19eb';
$sec = 'Z2BVc5B_edjKEYiMy_io5iaw-xstbQCBWNmiMQtGCDQ';

$wxapi = new WeiXinAPI();
$wxapi->setCorp($id, $sec);
$res = $wxapi->getAccessToken();

$accessToken = $res['accessToken'];
$ip = $wxapi->getCallbackIP($accessToken);
var_dump($ip);

