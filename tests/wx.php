<?php

require_once '../vendor/autoload.php';

use Ubi\Utils\WeiXinAPI;

$id  = 'ww52f8d8da8cab19eb';
$sec = 'Z2BVc5B_edjKEYiMy_io5iaw-xstbQCBWNmiMQtGCDQ';

$wxapi = new WeiXinAPI();
$wxapi->setParams(['accessToken' => 'gSbnwmWbZthNHzjCB-9rCoVjf8Oc1fH73dkYEazoQHOs7G4dYmLcwMufntM11JCJWeUdMxyL2tuBetZQv25B-2ei6W104FgIqnO-eGJHt3QSJ5zsaMgOgQt1Hjg7SfCse8H6sMkM97SmCoRB6Uv9rQ01BRnYIbHNGFs9ELv-Kuu2zau8vlYTU7hgpu-CqyNQVm61KEeek1nLl-FP0XXReA']);
$mediaId = '3fYJpxlTEQK9TSXCBdLBT4AFQ1BZdoPphz9BtWz8BDB6uDkqvrXgjxKzR6L41vOuV';
$file = $wxapi->getMedia($mediaId);

var_dump($file);
