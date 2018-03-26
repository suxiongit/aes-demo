<?php
/**
 * 数据加解密示例
 * @author p_bearsu
 * @date 2018/2/28
 */

include_once "./AesCrypt.php";

$token = 'token_test'; // 签名校验Token
$encodingAesKey = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG'; // AES加解密Key
$text = '{create_time:1519725182,event_type:"readdr",content:{community_list:["a0d00e9108ff6bc3bfdbf8584ec81447","14754233563f6f9a21e93b7c95fe0a84",],}}'; // 需要加密的明文

$pc = new AesCrypt($token, $encodingAesKey);
$errCode = 0;

//
// 加密示例
//

$encryptText = $pc->encrypt($text,$errCode);
if ($errCode == 0) {
    print('加密后：'. $encryptText . "\n");
} else {
    print('加密失败：'. $errCode . "\n");
}

//
// 生成签名
//

$signature = $pc->getSignature($encryptText,$errCode);
if ($errCode == 0) {
    print('生成签名：'. $signature . "\n");
} else {
    print('签名失败：'. $errCode . "\n");
}

//
// 解密示例
//

$encryptText = $pc->decrypt($encryptText, $errCode);
if ($errCode == 0) {
    print('解密后：'. $encryptText . "\n");
} else {
    print('解密失败：'. $errCode . "\n");
}