//
//  NHCryptor.h
//  NHEnDecryptPro
//
//  Created by hu jiaju on 16/5/25.
//  Copyright © 2016年 hu jiaju. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef struct {
    
    /**
     * Cipher strength
     * 评估密码强度：0-100分
     */
    int (*score_passphrase)(const char *passphrase);
    
    /**
     * RSA Part
     * 客户端Bundle需要引入public_key.der RSA公钥文件
     * iOS客户端目前不支持C加密S解密、C加签S解签等操作
     */
    NSString* (*rsaEncrypt)(NSString *plainText);
    BOOL (*rsaVerify)(NSString *cipherData,NSString *signData);
    
    /**
     *  AES Part 
     *  目前大类：流式、分组两种加密方式
     *  流式常见：RC4，ChaCha20-Poly1305(Google新增加速套件)
     *  分组常见：AES-CBC，AES-GCM
     *  RC4由于存在严重安全漏洞，已经基本不再使用
     *  AES-CBC容易遭受BEAST和LUCKY13攻击，使用也逐渐减少
     *  AES-GCM是它们的安全替代，AES-GCM也是目前最为流行的对称加密算法
     *  AES-GCM解决了对称加密存在的安全问题，但带来了性能问题。
     *  为此，出现了AES-NI（Advanced Encryption Standard New Instruction）
     *  可设置模式：No Padding\CBC\ECB
     */
    NSString* (*aesGenerateKey)(void);
    NSString* (*aesEncrypt)(NSString *plainData,NSString *key);
    NSString* (*aesDecrypt)(NSString *cipherData,NSString *key);
    
}NHCryptor_m;

#define NHSSLKit ([NHCryptor initSetup])

@interface NHCryptor : NSObject

+ (NHCryptor_m *)initSetup;

@end
