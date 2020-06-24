<?php

require_once '../vendor/autoload.php';

use Ubi\Utils\WeiXinAPI;

$wxapi = new WeiXinAPI();
$file = '/tmp/1592969435_WechatIMG88.jpeg';
$res = $wxapi->uploadMedia('image', $file);

var_dump($res);
