/**
 * 数据加解密示例
 * @author p_bearsu
 * @date 2018/2/28
 */

const AesCrypt = require('./AesCrypt');

let token = 'token_test'; // 签名校验Token
let encodingAesKey = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG'; // AES加解密Key
let text = '{create_time:1519725182,event_type:"readdr",content:{community_list:["a0d00e9108ff6bc3bfdbf8584ec81447","14754233563f6f9a21e93b7c95fe0a84",],}}'; // 需要加密的明文

let pc = new AesCrypt(token, encodingAesKey);


//
// 加密示例
//

let encryptText = pc.encrypt(text);
console.log('加密后：' + encryptText);

//
// 生成签名
//

let signature = pc.getSignature(encryptText);
console.log('生成签名：' + signature);


//
// 解密示例
//

let decryptText = pc.decrypt(encryptText);
console.log('解密后：' + decryptText);

