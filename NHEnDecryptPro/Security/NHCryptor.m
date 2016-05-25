//
//  NHCryptor.m
//  NHEnDecryptPro
//
//  Created by hu jiaju on 16/5/25.
//  Copyright © 2016年 hu jiaju. All rights reserved.
//

#import "NHCryptor.h"
#import <Security/Security.h>
#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonDigest.h>
#import "GTMBase64.h"

//设置AES的分组向量
static const NSString * NH_AES_VECTOR = @"NHSSLAESCBCSMODE";

@interface NHCryptor (){
    SecKeyRef publicKey;
    SecCertificateRef certificate;
    SecPolicyRef policy;
    SecTrustRef trust;
    size_t maxPlainLen;
}

//cipher
- (int)score_passphrase:(const char *)passphrase;

//rsa
- (NSString *)rsaEncryptWithString:(NSString *)content;
- (BOOL)rsaVerifySHA1SignatureWithString:(NSString *)content withSign:(NSString *)sign;

//aes
- (NSString *)generateAESEncryptKeyForLength:(NSInteger)len;
- (NSString *)aesEncryptWithString:(NSString *)content withKey:(NSString *)key;
- (NSString *)aesDecryptWithString:(NSString *)content withKey:(NSString *)key;

@end

static NHCryptor_m *util = nil;
static NHCryptor *instance = nil;

static int _score_passphrase(const char *passphrase) {
    return [instance score_passphrase:passphrase];
}

static NSString* _rsaEncrypt(NSString *plainText) {
    return [instance rsaEncryptWithString:plainText];
}

static BOOL _rsaVerify(NSString *cipherData,NSString *signData) {
    return [instance rsaVerifySHA1SignatureWithString:cipherData withSign:signData];
}

static NSString* _aesGenerateKey(void) {
    return [instance generateAESEncryptKeyForLength:NH_AES_VECTOR.length];
}

static NSString* _aesEncrypt(NSString *plainData,NSString *key) {
    return [instance aesEncryptWithString:plainData withKey:key];
}

static NSString* _aesDecrypt(NSString *cipherData,NSString *key) {
    return [instance aesDecryptWithString:cipherData withKey:key];
}

@implementation NHCryptor

- (void)dealloc{
    CFRelease(certificate);
    CFRelease(trust);
    CFRelease(policy);
    CFRelease(publicKey);
    util?free(util):0;
    util = NULL;
#if !__has_feature(objc_arc)
    [super dealloc];
#endif
}

- (id)init {
    self = [super init];
    if (self) {
        NSString *publicKeyPath = [[NSBundle mainBundle] pathForResource:@"public_key"ofType:@"der"];
        if (publicKeyPath == nil) {
            NSLog(@"Can not find pub.der");
            return nil;
        }
        
        NSData *publicKeyFileContent = [NSData dataWithContentsOfFile:publicKeyPath];
        if (publicKeyFileContent == nil) {
            NSLog(@"Can not read from pub.der");
            return nil;
        }
        
        certificate = SecCertificateCreateWithData(kCFAllocatorDefault, ( __bridge CFDataRef)publicKeyFileContent);
        if (certificate == nil) {
            NSLog(@"Can not read certificate from pub.der");
            return nil;
        }
        
        policy = SecPolicyCreateBasicX509();
        OSStatus returnCode = SecTrustCreateWithCertificates(certificate, policy, &trust);
        if (returnCode != 0) {
            NSLog(@"SecTrustCreateWithCertificates fail. Error Code: %d", (int)returnCode);
            return nil;
        }
        
        SecTrustResultType trustResultType;
        returnCode = SecTrustEvaluate(trust, &trustResultType);
        if (returnCode != 0) {
            NSLog(@"SecTrustEvaluate fail. Error Code: %d", (int)returnCode);
            return nil;
        }
        
        publicKey = SecTrustCopyPublicKey(trust);
        if (publicKey == nil) {
            NSLog(@"SecTrustCopyPublicKey fail");
            return nil;
        }
        
        maxPlainLen = SecKeyGetBlockSize(publicKey) - 12;
    }
    return self;
}

+ (NHCryptor_m *)initSetup {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        
        if (instance == nil) {
            instance = [[self alloc] init];
        }
        
        util = malloc(sizeof(NHCryptor_m));
        util->score_passphrase = _score_passphrase;
        util->rsaEncrypt = _rsaEncrypt;
        util->rsaVerify = _rsaVerify;
        util->aesGenerateKey = _aesGenerateKey;
        util->aesEncrypt = _aesEncrypt;
        util->aesDecrypt = _aesDecrypt;
    });
    return util;
}

#pragma mark -- Public Methods --

int key_distance(char a, char b) {
    const char *qwerty_lc = "`1234567890-="
    "qwertyuiop[]\\"
    " asdfghjkl;' "
    "  zxcvbnm,./ ";
    const char *qwerty_uc = "~!@#$%^&*()_+"
    "QWERTYUIOP{}|"
    " ASDFGHJKL:\" "
    "  ZXCVBNM<>? ";
    int pos_a,pos_b,dist;
    
    if (strchr(qwerty_lc, a)) {
        pos_a = strchr(qwerty_lc, a) - qwerty_lc;
    }else if (strchr(qwerty_uc, a)){
        pos_a = strchr(qwerty_uc, a) - qwerty_uc;
    }else {
        return -2;
    }
    
    if (strchr(qwerty_lc, b)) {
        pos_b = strchr(qwerty_lc, b) - qwerty_lc;
    }else if (strchr(qwerty_uc, b)) {
        pos_b = strchr(qwerty_uc, b) - qwerty_uc;
    }else {
        return -1;
    }
    //行距离+列距离
    dist = abs((pos_a/13) - (pos_b/13))
    + abs((pos_a%13 - pos_a%13));
    return dist;
}
- (int)score_passphrase:(const char *)passphrase {
    int total_score = 0;
    int unit_score ;
    int distances[strlen(passphrase)];
    int i;
    
    //cipher length
    unit_score = strlen(passphrase) / 4;
    total_score += MIN(3, unit_score);
    
    // upword
    for (unit_score = i = 0; passphrase[i]; ++i) {
        if (isupper(passphrase[i])) {
            unit_score++;
        }
    }
    total_score += MIN(3, unit_score);
    
    // low charactor
    for (unit_score = i = 0; passphrase[i]; ++i) {
        if (islower(passphrase[i])) {
            unit_score++;
        }
    }
    total_score += MIN(3, unit_score);
    
    // number
    for (unit_score = i = 0; passphrase[i]; ++i) {
        if (isdigit(passphrase[i])) {
            unit_score++;
        }
    }
    total_score += MIN(3, unit_score);
    
    // special charactor
    for (unit_score = i = 0; passphrase[i]; ++i) {
        if (!isalnum(passphrase[i])) {
            unit_score++;
        }
    }
    total_score += MIN(3, unit_score);
    
    // key distance
    distances[0] = 0;
    for (unit_score = i = 0; passphrase[i]; ++i) {
        if (passphrase[i+1]) {
            int dist = key_distance(passphrase[i], passphrase[i+1]);
            if (dist > 1) {
                int j, exists = 0;
                for (j = 0; distances[j]; ++j) {
                    if (distances[j] == dist) {
                        exists = 1;
                    }
                }
                if (!exists) {
                    distances[j] = dist;
                    distances[j+1] = 0;
                    unit_score++;
                }
            }
        }
    }
    total_score += MIN(3, unit_score);
    
    return ((total_score/18.0f) * 100);
}

#pragma mark -- RSA part --

- (NSData *) encryptWithData:(NSData *)content {
    
    size_t plainLen = [content length];
    if (plainLen > maxPlainLen) {
        NSLog(@"content(%ld) is too long, must < %ld", plainLen, maxPlainLen);
        return nil;
    }
    
    void *plain = malloc(plainLen);
    [content getBytes:plain
               length:plainLen];
    
    size_t cipherLen = 128; // 当前RSA的密钥长度是128字节
    void *cipher = malloc(cipherLen);
    
    OSStatus returnCode = SecKeyEncrypt(publicKey, kSecPaddingPKCS1, plain,
                                        plainLen, cipher, &cipherLen);
    
    NSData *result = nil;
    if (returnCode != 0) {
        NSLog(@"SecKeyEncrypt fail. Error Code: %d", (int)returnCode);
    } else {
        result = [NSData dataWithBytes:cipher
                                length:cipherLen];
    }
    
    free(plain);
    free(cipher);
    
    return result;
}

- (NSString *)rsaEncryptWithString:(NSString *)content {
    NSData *encryptData = [self encryptWithData:[content dataUsingEncoding:NSUTF8StringEncoding]];
    return [GTMBase64 encodeBase64Data:encryptData];
}

// SHA-1消息摘要的数据位数
#define kChosenDigestLength CC_SHA1_DIGEST_LENGTH
- (BOOL)rsaVerifySHA1SignatureWithString:(NSString *)content withSign:(NSString *)sign{
    NSData *plainData = [content dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signatureData = [GTMBase64 decodeString:sign];
    
    size_t signedHashBytesSize = SecKeyGetBlockSize(publicKey);
    const void* signedHashBytes = [signatureData bytes];
    
    size_t hashBytesSize = CC_SHA1_DIGEST_LENGTH;
    uint8_t* hashBytes = malloc(hashBytesSize);
    if (!CC_SHA1([plainData bytes], (CC_LONG)[plainData length], hashBytes)) {
        return false;
    }
    
    OSStatus status = SecKeyRawVerify(publicKey,
                                      kSecPaddingPKCS1SHA1,
                                      hashBytes,
                                      hashBytesSize,
                                      signedHashBytes,
                                      signedHashBytesSize);
    
    return status == errSecSuccess;
}

-(NSString *)getSHA1HashBytes:(NSString *)plaintext{
    if (!plaintext) {
        return nil;
    }
    NSData *plainData = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    NSData *hashData = [self getHashBytes:plainData];
    //将解了密码的nsdata转化为nsstring
    NSString *hashString = [[NSString alloc] initWithData:hashData encoding:NSUTF8StringEncoding];
    return hashString;
}

- (NSData *)getHashBytes:(NSData *)plainText {
    CC_SHA1_CTX ctx;
    uint8_t * hashBytes = NULL;
    NSData * hash = nil;
    
    // Malloc a buffer to hold hash.
    hashBytes = malloc( kChosenDigestLength * sizeof(uint8_t) );
    memset((void *)hashBytes, 0x0, kChosenDigestLength);
    // Initialize the context.
    CC_SHA1_Init(&ctx);
    // Perform the hash.
    CC_SHA1_Update(&ctx, (void *)[plainText bytes], (CC_LONG)[plainText length]);
    // Finalize the output.
    CC_SHA1_Final(hashBytes, &ctx);
    
    // Build up the SHA1 blob.
    hash = [NSData dataWithBytes:(const void *)hashBytes length:(NSUInteger)kChosenDigestLength];
    if (hashBytes) free(hashBytes);
    
    return hash;
}

#pragma mark -- AES part --

- (NSString *)generateAESEncryptKeyForLength:(NSInteger)length{
    if (length<=0) {
        return nil;
    }
    NSString *sourceString = @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-*/_=[]|<>@!#:";
    NSMutableString *result = [[NSMutableString alloc] init] ;
    srand((unsigned)time(0));
    for (int i = 0; i < length; i++){
        unsigned index = rand() % [sourceString length];
        NSString *s = [sourceString substringWithRange:NSMakeRange(index, 1)];
        [result appendString:s];
    }
    return result;
}
- (NSString *)aesEncryptWithString:(NSString *)content withKey:(NSString *)key{
//    //将nsstring转化为nsdata
//    NSData *data = [content dataUsingEncoding:NSUTF8StringEncoding];
//    //使用密码对nsdata进行加密
//    NSData *encryptedData = [data AES128EncryptWithKey:key];
//    NSString *encryptString = [GTMBase64 encodeBase64Data:encryptedData];
//    //NSLog(@"AES encrypt string is:%@",encryptString);
//    
//    return encryptString;
    
    
    //设置加密key
    char keyPtr[kCCKeySizeAES128+1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    //设置加密向量
    char ivPtr[kCCBlockSizeAES128+1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [NH_AES_VECTOR getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    NSData* data = [content dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger dataLength = [data length];
    
    int diff = kCCKeySizeAES128 - (dataLength % kCCKeySizeAES128);
    int newSize = 0;
    
    if(diff > 0){
        newSize = (int)(dataLength + diff);
    }
    
    char dataPtr[newSize];
    memcpy(dataPtr, [data bytes], [data length]);
    for(int i = 0; i < diff; i++){
        //关键地方:补零，即No Padding模式
        dataPtr[i + dataLength] = 0x00;
    }
    
    size_t bufferSize = newSize + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    memset(buffer, 0, bufferSize);
    
    size_t numBytesCrypted = 0;
    
    //mode:kCCOptionPKCS7Padding:0x0001需要与Android、PHP、C#等平台设置一致
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES128,
                                          0x0000,               //No padding/0x0001:PKCS7/0x0002:ECB
                                          keyPtr,
                                          kCCKeySizeAES128,
                                          ivPtr,
                                          dataPtr,
                                          sizeof(dataPtr),
                                          buffer,
                                          bufferSize,
                                          &numBytesCrypted);
    
    if (cryptStatus == kCCSuccess) {
        NSData *resultData = [NSData dataWithBytesNoCopy:buffer length:numBytesCrypted];
        return [GTMBase64 stringByEncodingData:resultData];
    }
    free(buffer);
    return nil;
}
- (NSString *)aesDecryptWithString:(NSString *)content withKey:(NSString *)key{
//    NSData *EncryptData = [GTMBase64 decodeString:content];
//    //使用密码对data进行解密
//    NSData *decryData = [EncryptData AES128DecryptWithKey:key];
//    //将解了密码的nsdata转化为nsstring
//    NSString *t_info_origin = [[NSString alloc] initWithData:decryData encoding:NSUTF8StringEncoding];
//    //NSLog(@"AES decrypt string is:%@",str);
//    return t_info_origin;
    
    char keyPtr[kCCKeySizeAES128 + 1];
    memset(keyPtr, 0, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    char ivPtr[kCCBlockSizeAES128 + 1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [NH_AES_VECTOR getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    NSData *data = [GTMBase64 decodeData:[content dataUsingEncoding:NSUTF8StringEncoding]];
    NSUInteger dataLength = [data length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesCrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          0x0000,
                                          keyPtr,
                                          kCCBlockSizeAES128,
                                          ivPtr,
                                          [data bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesCrypted);
    if (cryptStatus == kCCSuccess) {
        NSData *resultData = [NSData dataWithBytesNoCopy:buffer length:numBytesCrypted];
        return [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
    }
    free(buffer);
    return nil;
}

@end

@interface NSData(AESEncrypt)

- (NSData *)AES128EncryptWithKey:(NSString *)key;   //加密
- (NSData *)AES128DecryptWithKey:(NSString *)key;   //解密

@end
@implementation NSData(AESEncrypt)

-(NSData *)AES128EncryptWithKey:(NSString *)key{
    char keyPtr[kCCKeySizeAES128+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    char ivPtr[kCCKeySizeAES128+1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [NH_AES_VECTOR getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [self length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyPtr,
                                          kCCBlockSizeAES128,
                                          ivPtr,
                                          [self bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    free(buffer);
    return nil;
}
-(NSData *)AES128DecryptWithKey:(NSString *)key{
    char keyPtr[kCCKeySizeAES128+1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    char ivPtr[kCCKeySizeAES128+1];
    memset(ivPtr, 0, sizeof(ivPtr));
    [NH_AES_VECTOR getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [self length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt,
                                          kCCAlgorithmAES128,
                                          kCCOptionPKCS7Padding,
                                          keyPtr,
                                          kCCBlockSizeAES128,
                                          ivPtr,
                                          [self bytes],
                                          dataLength,
                                          buffer,
                                          bufferSize,
                                          &numBytesDecrypted);
    if (cryptStatus == kCCSuccess) {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    free(buffer);
    return nil;
}
@end
