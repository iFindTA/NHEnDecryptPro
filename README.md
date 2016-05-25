# NHEnDecryptPro
##客户端加密实现（for iOS）

###评估密码强度：
```ObjectiveC
	int score = NHSSLKit->score_passphrase([info UTF8String]);
```
###AES(No Padding/ECB/CBC)示例：
```ObjectiveC
	NSString *aeskey = NHSSLKit->aesGenerateKey();
	NSString *aesRet = NHSSLKit->aesEncrypt(info,aeskey);
```
###RSA示例：
```ObjectiveC
	NSString *rsaRet = NHSSLKit->rsaEncrypt(info);
```