<?php

/**
 * error code 说明.
 * <ul>
 *    <li>-40001: 签名验证错误</li>
 *    <li>-40002: sha加密生成签名失败</li>
 *    <li>-40003: encodingAesKey 非法</li>
 *    <li>-40004: aes 加密失败</li>
 *    <li>-40005: aes 解密失败</li>
 *    <li>-40006: 解密后得到的buffer非法</li>
 *    <li>-40007: base64加密失败</li>
 *    <li>-40008: base64解密失败</li>
 * </ul>
 */
class ErrorCode
{
    public static $OK = 0;
    public static $ValidateSignatureError = -40001;
    public static $ComputeSignatureError = -40002;
    public static $IllegalAesKey = -40003;
    public static $EncryptAESError = -40004;
    public static $DecryptAESError = -40005;
    public static $IllegalBuffer = -40006;
    public static $EncodeBase64Error = -40007;
    public static $DecodeBase64Error = -40008;
}

/**
 * PKCS7Encoder class
 *
 * 提供基于PKCS7算法的加解密接口
 */
class PKCS7Encoder
{
    public static $block_size = 32;

    /**
     * 对需要加密的明文进行填充补位
     * @param $text 需要进行填充补位操作的明文
     * @return 补齐明文字符串
     */
    function encode($text)
    {
        $text_length = strlen($text);
        //计算需要填充的位数
        $amount_to_pad = PKCS7Encoder::$block_size - ($text_length % PKCS7Encoder::$block_size);
        if ($amount_to_pad == 0) {
            $amount_to_pad = PKCS7Encoder::block_size;
        }
        //获得补位所用的字符
        $pad_chr = chr($amount_to_pad);
        $tmp = "";
        for ($index = 0; $index < $amount_to_pad; $index++) {
            $tmp .= $pad_chr;
        }
        return $text . $tmp;
    }

    /**
     * 对解密后的明文进行补位删除
     * @param decrypted 解密后的明文
     * @return 删除填充补位后的明文
     */
    function decode($text)
    {

        $pad = ord(substr($text, -1));
        if ($pad < 1 || $pad > 32) {
            $pad = 0;
        }
        return substr($text, 0, (strlen($text) - $pad));
    }

}

/**
 * AesCrypt class
 *
 * 提供基于AES-CBC算法的加解密接口
 */
class AesCrypt
{
    private $token;
    private $key;

    /**
     * AesCrypt constructor.
     * @param $token string 签名校验Token
     * @param $encodingAesKey string AES加解密Key
     */
    public function AesCrypt($token, $encodingAesKey)
    {
        if (strlen($encodingAesKey) != 43) {
            throw new Exception(ErrorCode::$IllegalAesKey);
        }
        $this->token = $token;
        $this->key = base64_decode($encodingAesKey . "=");
    }

    /**
     * 生成安全签名
     *
     * @param $encrypted string 加密后的密文
     * @param int &$errCode 错误码
     * @return null|string
     */
    public function getSignature($encrypted, &$errCode) {

        // 用SHA1算法生成安全签名
        try {
            $array = array($this->token, $encrypted);
            sort($array, SORT_STRING);
            $str = implode($array);
            $signature = sha1($str);
            $errCode = ErrorCode::$OK;
            return $signature;
        } catch (Exception $e) {
            //print $e . "\n";
            $errCode = ErrorCode::$ComputeSignatureError;
            return null;
        }
    }

    /**
     * 对明文进行加密
     * @param string $text 需要加密的明文
     * @param int &$errCode 错误码
     * @return string 加密后的密文
     */
    public function encrypt($text, &$errCode)
    {
        try {
            //获得16位随机字符串，填充到明文之前
            $randomStr = $this->getRandomStr();
            $collector = $randomStr . pack("N", strlen($text)) . $text;
            // 网络字节序
            $size = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
            $module = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
            $iv = substr($this->key, 0, 16);
            //使用自定义的填充方式对明文进行补位填充
            $pkc_encoder = new PKCS7Encoder;
            $encoded = $pkc_encoder->encode($collector);
            mcrypt_generic_init($module, $this->key, $iv);
            //加密
            $encrypted = mcrypt_generic($module, $encoded);
            mcrypt_generic_deinit($module);
            mcrypt_module_close($module);

            //print(base64_encode($encrypted));
            //使用BASE64对加密后的字符串进行编码
            $errCode = ErrorCode::$OK;
            return base64_encode($encrypted);
        } catch (Exception $e) {
            //print $e;
            $errCode = ErrorCode::$EncryptAESError;
            return null;
        }
    }

    /**
     * 对密文进行解密
     * @param string $encrypted 需要解密的密文
     * @param int &$errCode 错误码
     * @return string 解密得到的明文
     */
    public function decrypt($encrypted, &$errCode)
    {

        try {
            //使用BASE64对需要解密的字符串进行解码
            $ciphertext_dec = base64_decode($encrypted);
            $module = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_CBC, '');
            $iv = substr($this->key, 0, 16);
            mcrypt_generic_init($module, $this->key, $iv);

            //解密
            $decrypted = mdecrypt_generic($module, $ciphertext_dec);
            mcrypt_generic_deinit($module);
            mcrypt_module_close($module);
        } catch (Exception $e) {
            $errCode = ErrorCode::$DecryptAESError;
            return null;
        }

        try {
            //去除补位字符
            $pkc_encoder = new PKCS7Encoder;
            $result = $pkc_encoder->decode($decrypted);
            //去除16位随机字符串，网络字节序
            if (strlen($result) < 16) return '';
            $content = substr($result, 16, strlen($result));
            $len_list = unpack("N", substr($content, 0, 4));
            $length = $len_list[1];
            $text = substr($content, 4, $length);
            $errCode = ErrorCode::$OK;
            return $text;
        } catch (Exception $e) {
            //print $e;
            $errCode = ErrorCode::$IllegalBuffer;
            return null;
        }
    }

    /**
     * 随机生成16位字符串
     * @return string 生成的字符串
     */
    function getRandomStr()
    {

        $str = "";
        $str_pol = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
        $max = strlen($str_pol) - 1;
        for ($i = 0; $i < 16; $i++) {
            $str .= $str_pol[mt_rand(0, $max)];
        }
        return $str;
    }
}

