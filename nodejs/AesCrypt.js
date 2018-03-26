/**
 * Nodejs版的加解密示例代码
 *
 */

'use strict';

const crypto = require('crypto');

/**
 * 提供基于PKCS7算法的加解密接口
 *
 */
let PKCS7Encoder = {};

/**
 * 删除解密后明文的补位字符
 *
 * @param {String} text 解密后的明文
 */
PKCS7Encoder.decode = function (text) {
    let pad = text[text.length - 1];
    if (pad < 1 || pad > 32) {
        pad = 0;
    }
    return text.slice(0, text.length - pad);
};

/**
 * 对需要加密的明文进行填充补位
 *
 * @param {String} text 需要进行填充补位操作的明文
 */
PKCS7Encoder.encode = function (text) {
    let blockSize = 32;
    let textLength = text.length;
    let amountToPad = blockSize - (textLength % blockSize);//计算需要填充的位数
    let result = new Buffer(amountToPad);
    result.fill(amountToPad);
    return Buffer.concat([text, result]);
};

/**
 * 提供基于AES-CBC算法的加解密接口
 *
 * @param {String} token 签名校验Token
 * @param {String} encodingAESKey AES加解密Key
 */
let AesCrypt = function (token, encodingAESKey) {
    if (!token || !encodingAESKey) {
        throw new Error('please check arguments');
    }
    if (encodingAESKey.length !== 43) {
        throw new Error('encodingAESKey invalid');
    }
    this.token = token;
    let AESKey = new Buffer(encodingAESKey + '=', 'base64');
    // if (AESKey.length !== 32) {
    //     throw new Error('encodingAESKey invalid');
    // }
    this.key = AESKey;
    this.iv = AESKey.slice(0, 16);
};

/**
 * 生成安全签名
 *
 * @param {String} encrypted 加密后的密文
 * @return {String}
 */
AesCrypt.prototype.getSignature = function(encrypted) {
    let shasum = crypto.createHash('sha1');
    let arr = [this.token, encrypted].sort();
    shasum.update(arr.join(''));
    return shasum.digest('hex');
};

/**
 * 对明文进行加密
 *
 * @param {String} text 待加密的明文
 * @return {String}
 */
AesCrypt.prototype.encrypt = function (text) {
    // 算法：AES_Encrypt[random(16B) + msgLen(4B) + msg]
    // 获取16B的随机字符串
    let randomStr = crypto.pseudoRandomBytes(16);
    let msg = new Buffer(text);
    // 获取4B的内容长度的网络字节序
    let msgLen = new Buffer(4);
    msgLen.writeUInt32BE(msg.length, 0);
    let collector = Buffer.concat([randomStr, msgLen, msg]);
    // 对明文进行补位操作
    let encoded = PKCS7Encoder.encode(collector);
    // 创建加密对象，AES采用CBC模式，数据采用PKCS#7填充；IV初始向量大小为16字节，取AESKey前16字节
    let cipher = crypto.createCipheriv('aes-256-cbc', this.key, this.iv);
    cipher.setAutoPadding(false);
    let cipheredMsg = Buffer.concat([cipher.update(encoded), cipher.final()]);
    // 返回加密数据的base64编码
    return cipheredMsg.toString('base64');
};

/**
 * 对密文进行解密
 *
 * @param {String} encrypted 待解密的密文
 * @return {String}
 */
AesCrypt.prototype.decrypt = function(encrypted) {
    let decipher = crypto.createDecipheriv('aes-256-cbc', this.key, this.iv);// 创建解密对象，AES采用CBC模式，数据采用PKCS#7填充；IV初始向量大小为16字节，取AESKey前16字节
    decipher.setAutoPadding(false);
    let deciphered = Buffer.concat([decipher.update(encrypted, 'base64'), decipher.final()]);
    deciphered = PKCS7Encoder.decode(deciphered);
    // 算法：AES_Encrypt[random(16B) + msg_len(4B) + msg]
    // 去除16位随机数
    let content = deciphered.slice(16);
    let length = content.slice(0, 4).readUInt32BE(0);
    let text = content.slice(4, length + 4).toString();
    return text;
};

module.exports = AesCrypt;
