/**
 * 数据加解密示例
 * @author p_bearsu
 * @date 2018/2/28
 */

import com.aes.AesCrypt;

public class Demo {
    public static void main(String[] args) throws Exception {

        String token = "token_test"; // 签名校验Token
        String encodingAesKey = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"; // AES加解密Key
        String text = "{create_time:1519725182,event_type:\"readdr\",content:{community_list:[\"a0d00e9108ff6bc3bfdbf8584ec81447\",\"14754233563f6f9a21e93b7c95fe0a84\",],}}"; // 需要加密的明文

        //
        // 加密示例
        //

        AesCrypt pc = new AesCrypt(token, encodingAesKey);
        String encryptText = pc.encrypt(text);
        System.out.println("加密后: " + encryptText);

        //
        // 生成签名
        //

        String signature = pc.getSignature(encryptText);
        System.out.println("生成签名: " + signature);

        //
        // 解密示例
        //

        String decryptText = pc.decrypt(encryptText);
        System.out.println("解密后: " + decryptText);

    }
}
