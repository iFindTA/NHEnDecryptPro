# NHEnDecryptPro
##客户端加密实现（for iOS）
###用法AES：
```
NSString *aeskey = NHSSLUtil->aesGenerateKey();
    NSString *aesRet = NHSSLUtil->aesEncrypt(info,aeskey);
```
###用法RSA：
```
NSString *rsaRet = NHSSLUtil->rsaEncrypt(info);
```