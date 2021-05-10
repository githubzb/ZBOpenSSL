//
//  ZBRSACrypto.m
//  ZBOpenSSL
//
//  Created by 张宝 on 2018/6/29.
//  Copyright © 2018年 zb. All rights reserved.
//  相关函数调用请参考：http://www.qmailer.net/archives/216.html

#import "ZBRSACrypto.h"
#import <openssl/rsa.h>
#import <openssl/pem.h>
#import <openssl/md5.h>
#include <openssl/bn.h>

static NSString *const ZBBEGIN_PUBLIC_PKCS1_KEY   = @"-----BEGIN RSA PUBLIC KEY-----";
static NSString *const ZBBEGIN_PUBLIC_PKCS8_KEY   = @"-----BEGIN PUBLIC KEY-----";
static NSString *const ZBEND_PUBLIC_PKCS1_KEY   = @"-----END RSA PUBLIC KEY-----";
static NSString *const ZBEND_PUBLIC_PKCS8_KEY   = @"-----END PUBLIC KEY-----";

static NSString *const ZBBEGIN_PRIVATE_PKCS1_KEY   = @"-----BEGIN RSA PRIVATE KEY-----";
static NSString *const ZBBEGIN_PRIVATE_PKCS8_KEY   = @"-----BEGIN PRIVATE KEY-----";
static NSString *const ZBEND_PRIVATE_PKCS1_KEY   = @"-----END RSA PRIVATE KEY-----";
static NSString *const ZBEND_PRIVATE_PKCS8_KEY   = @"-----END PRIVATE KEY-----";

@interface ZBRSACrypto (){
    RSA *_rsa;
    RSA *_rsaPublic;
    RSA *_rsaPrivate;
    
    RSA *_rsaCustomPublic;
    RSA *_rsaCustomPrivate;
}
@property (nonatomic, copy) NSString *rsaPath;
@property (nonatomic, copy) NSString *publicPemPath;
@property (nonatomic, copy) NSString *privatePemPath;

@end
@implementation ZBRSACrypto

- (instancetype)init{
    self = [super init];
    if (self) {
        NSString *path = [NSSearchPathForDirectoriesInDomains(NSLibraryDirectory, NSUserDomainMask, YES) lastObject];
        path = [path stringByAppendingPathComponent:@".rsa"];
        self.rsaPath = path;
        if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
            NSError *error;
            [[NSFileManager defaultManager] createDirectoryAtPath:path
                                      withIntermediateDirectories:YES
                                                       attributes:nil
                                                            error:&error];
            if (error) {
                NSLog(@"create .rsa directory:%@", error);
            }
        }
        NSLog(@"---path:%@", path);
        self.publicPemPath = [path stringByAppendingPathComponent:@"puk.pem"];
        self.privatePemPath = [path stringByAppendingPathComponent:@"prk.pem"];
    }
    return self;
}

+ (instancetype)share{
    static ZBRSACrypto *rsaCrypto = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        rsaCrypto = [[ZBRSACrypto alloc] init];
    });
    return rsaCrypto;
}

- (NSString *)publicKey{
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:self.publicPemPath]) {
        NSError *error = nil;
        NSString *str = [NSString stringWithContentsOfFile:self.publicPemPath
                                                  encoding:NSUTF8StringEncoding
                                                     error:&error];
        if (error) {
            NSLog(@"%@", error);
            return nil;
        }
        NSString *ss = [[str componentsSeparatedByString:@"-----"] objectAtIndex:2];
        return [ss stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    }
    return nil;
}

- (NSString *)privateKey{
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:self.privatePemPath]) {
        NSError *error = nil;
        NSString *str = [NSString stringWithContentsOfFile:self.privatePemPath
                                                  encoding:NSUTF8StringEncoding
                                                     error:&error];
        if (error) {
            NSLog(@"%@", error);
            return nil;
        }
        NSString *ss = [[str componentsSeparatedByString:@"-----"] objectAtIndex:2];
        return [ss stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    }
    return nil;
}

+ (NSString *)publicKey{
    return [ZBRSACrypto share].publicKey;
}

+ (NSString *)privateKey{
    return [ZBRSACrypto share].privateKey;
}

+ (void)setCustomPublicKey:(NSString *)pk pemType:(ZBPemType)type{
    [[ZBRSACrypto share] setCustomPublicKey:pk pemType:type];
}

+ (void)setCustomPrivateKey:(NSString *)prk pemType:(ZBPemType)type{
    [[ZBRSACrypto share] setCustomPrivateKey:prk pemType:type];
}

+ (BOOL)existPem{
    return [[ZBRSACrypto share] existPem];
}
+ (BOOL)createRSAWithSize:(int)size{
    return [[ZBRSACrypto share] createRSAWithSize:size];
}
+ (BOOL)exportPem:(ZBPemType)type{
    return [[ZBRSACrypto share] exportPem:type];
}
+ (BOOL)importPem:(ZBPemType)type{
    return [[ZBRSACrypto share] importPem:type];
}

+ (NSData *)encryptWithType:(ZBKeyType)type
                paddingType:(ZBRSAPaddingType)padding
                       data:(NSData *)data
{
    return [[ZBRSACrypto share] encryptWithType:type
                                    paddingType:padding
                                           data:data
                                         custom:NO];
}

+ (NSData *)decryptWithType:(ZBKeyType)type
                paddingType:(ZBRSAPaddingType)padding
                       data:(NSData *)data{
    return [[ZBRSACrypto share] decryptWithType:type
                                    paddingType:padding
                                           data:data
                                         custom:NO];
}

+ (NSData *)encryptByCustomType:(ZBKeyType)type
                    paddingType:(ZBRSAPaddingType)padding
                           data:(NSData *)data
{
    return [[ZBRSACrypto share] encryptWithType:type
                                    paddingType:padding
                                           data:data
                                         custom:YES];
}

+ (NSData *)decryptByCustomType:(ZBKeyType)type
                    paddingType:(ZBRSAPaddingType)padding
                           data:(NSData *)data
{
    return [[ZBRSACrypto share] decryptWithType:type
                                    paddingType:padding
                                           data:data
                                         custom:YES];
}

#pragma mark - RSA Sign
+ (NSData *)signBySHA128:(NSData *)data customPrivateKey:(BOOL)custom{
    return [[ZBRSACrypto share] signBySHA128:data customPrivateKey:custom];
}
+ (NSData *)signBySHA256:(NSData *)data customPrivateKey:(BOOL)custom{
    return [[ZBRSACrypto share] signBySHA256:data customPrivateKey:custom];
}
+ (NSData *)signByMD5:(NSData *)data customPrivateKey:(BOOL)custom{
    return [[ZBRSACrypto share] signByMD5:data customPrivateKey:custom];
}
+ (BOOL)verifySignBySHA128:(NSData *)sign
                      data:(NSData *)data customPublicKey:(BOOL)custom{
    return [[ZBRSACrypto share] verifySignBySHA128:sign
                                              data:data
                                   customPublicKey:custom];
}
+ (BOOL)verifySignBySHA256:(NSData *)sign
                      data:(NSData *)data customPublicKey:(BOOL)custom{
    return [[ZBRSACrypto share] verifySignBySHA256:sign
                                              data:data
                                   customPublicKey:custom];
}
+ (BOOL)verifySignByMD5:(NSData *)sign
                   data:(NSData *)data customPublicKey:(BOOL)custom{
    return [[ZBRSACrypto share] verifySignByMD5:sign
                                           data:data
                                customPublicKey:custom];
}

#pragma mark - private
- (NSString *)formatPemKey:(NSString *)key type:(ZBPemType)type public:(BOOL)public{
    if (![key isKindOfClass:[NSString class]] || key.length==0) {
        return nil;
    }
    NSString *begin,*end;
    if (type==ZBPemTypePKCS1) {
        begin = public?ZBBEGIN_PUBLIC_PKCS1_KEY:ZBBEGIN_PRIVATE_PKCS1_KEY;
        end = public?ZBEND_PUBLIC_PKCS1_KEY:ZBEND_PRIVATE_PKCS1_KEY;
    }else{
        begin = public?ZBBEGIN_PUBLIC_PKCS8_KEY:ZBBEGIN_PRIVATE_PKCS8_KEY;
        end = public?ZBEND_PUBLIC_PKCS8_KEY:ZBEND_PRIVATE_PKCS8_KEY;
    }
    if ([key containsString:begin] || [key containsString:end]) {
        return nil;
    }
    NSMutableString *str = [NSMutableString stringWithString:begin];
    [str appendString:@"\n"];
    int sp = 64;
    for (int i=0; i<key.length; i+=sp) {
        if (i+sp>=key.length) {
            [str appendString:[key substringFromIndex:i]];
            break;
        }
        [str appendString:[key substringWithRange:NSMakeRange(i, sp)]];
        [str appendString:@"\n"];
    }
    [str appendString:@"\n"];
    [str appendString:end];
    [str appendString:@"\n"];
    return [NSString stringWithString:str];
}
- (void)setCustomPublicKey:(NSString *)pk pemType:(ZBPemType)type{
    NSString *str = [self formatPemKey:pk type:type public:YES];
    if (str==nil) {
        return;
    }
    NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
    if (_rsaCustomPublic) {
        RSA_free(_rsaCustomPublic);
        _rsaCustomPublic = NULL;
    }
    BIO *publicBIO = BIO_new_mem_buf(data.bytes, (int)data.length);
    if (type==ZBPemTypePKCS1) {
        _rsaCustomPublic = PEM_read_bio_RSAPublicKey(publicBIO, NULL, NULL, NULL);
    }else{
        EVP_PKEY *pkey = EVP_PKEY_new();
        PEM_read_bio_PUBKEY(publicBIO, &pkey, NULL, NULL);
        _rsaCustomPublic = EVP_PKEY_get1_RSA(pkey);
        EVP_PKEY_free(pkey);
    }
    BIO_free_all(publicBIO);
}
- (void)setCustomPrivateKey:(NSString *)prk pemType:(ZBPemType)type{
    NSString *str = [self formatPemKey:prk type:type public:NO];
    if (str == nil) {
        return;
    }
    NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
    if (_rsaCustomPrivate) {
        RSA_free(_rsaCustomPrivate);
        _rsaCustomPrivate = NULL;
    }
    BIO *privateBIO = BIO_new_mem_buf(data.bytes, (int)data.length);
    if (type==ZBPemTypePKCS1) {
        _rsaCustomPrivate = PEM_read_bio_RSAPrivateKey(privateBIO, NULL, NULL, NULL);
    }else{
        EVP_PKEY *pkey = EVP_PKEY_new();
        PEM_read_bio_PrivateKey(privateBIO, &pkey, NULL, NULL);
        _rsaCustomPrivate = EVP_PKEY_get1_RSA(pkey);
        EVP_PKEY_free(pkey);
    }
    BIO_free_all(privateBIO);
}
- (BOOL)existPem{
    NSFileManager *fm = [NSFileManager defaultManager];
    return [fm fileExistsAtPath:self.publicPemPath] && [fm fileExistsAtPath:self.privatePemPath];
}
- (BOOL)createRSAWithSize:(int)size{
    if (size<ZBRSASize1024) {
        return NO;
    }
    if (_rsa!=NULL) {
        RSA_free(_rsa);
        _rsa = NULL;
    }
    RSA *rsa = RSA_new();
    int ret = 0;
    BIGNUM *e = BN_new();
    ret = BN_set_word(e, RSA_F4);
    if (ret>0) {
        ret = RSA_generate_key_ex(rsa, size, e, NULL);
    }
    BN_clear_free(e);
//    _rsa = RSA_generate_key(size, RSA_F4, NULL, NULL); //Deprecated
    if (ret>0) {
        _rsa = rsa;
    }
    return _rsa!=NULL;
}
- (BOOL)exportPem:(ZBPemType)type{
    if (_rsa!=NULL) {
        FILE *pukFile, *prkFile;
        pukFile = fopen([self.publicPemPath cStringUsingEncoding:NSASCIIStringEncoding], "w");
        prkFile = fopen([self.privatePemPath cStringUsingEncoding:NSASCIIStringEncoding], "w");
        if (pukFile!=NULL && prkFile!=NULL) {
            int pukRes=0, prkRes=0;
            RSA *puk = RSAPublicKey_dup(_rsa);
            if (puk!=NULL) {
                if (type==ZBPemTypePKCS1) {
                    pukRes = PEM_write_RSAPublicKey(pukFile, puk);
                }else{
                    EVP_PKEY *key = EVP_PKEY_new();
                    EVP_PKEY_assign_RSA(key, puk);
                    pukRes = PEM_write_PUBKEY(pukFile, key);
                    EVP_PKEY_free(key);
                }
                if (_rsaPublic!=NULL) {
                    RSA_free(_rsaPublic);
                    _rsaPublic = NULL;
                }
                _rsaPublic = puk;
            }
            RSA *prk = RSAPrivateKey_dup(_rsa);
            if (prk!=NULL) {
                int klen = RSA_size(prk);
                if (type==ZBPemTypePKCS1) {
                    prkRes = PEM_write_RSAPrivateKey(prkFile, prk, NULL, NULL, klen, NULL, NULL);
                }else{
                    EVP_PKEY *key = EVP_PKEY_new();
                    EVP_PKEY_assign_RSA(key, prk);
                    prkRes = PEM_write_PrivateKey(prkFile, key, NULL, NULL, klen, NULL, NULL);
                    EVP_PKEY_free(key);
                }
                if (_rsaPrivate!=NULL) {
                    RSA_free(_rsaPrivate);
                    _rsaPrivate = NULL;
                }
                _rsaPrivate = prk;
            }
            fclose(pukFile);
            fclose(prkFile);
            return (pukRes+prkRes)>1;
        }
    }
    return NO;
}
- (BOOL)importPem:(ZBPemType)type{
    FILE *pukFile, *prkFile;
    pukFile = fopen([self.publicPemPath cStringUsingEncoding:NSASCIIStringEncoding], "rb");
    prkFile = fopen([self.privatePemPath cStringUsingEncoding:NSASCIIStringEncoding], "rb");
    if (pukFile!=NULL) {
        if (type==ZBPemTypePKCS1) {
            _rsaPublic = PEM_read_RSAPublicKey(pukFile, NULL, NULL, NULL);
        }else{
            EVP_PKEY *pkey = EVP_PKEY_new();
            PEM_read_PUBKEY(pukFile, &pkey, NULL, NULL);
            _rsaPublic = EVP_PKEY_get1_RSA(pkey);
            EVP_PKEY_free(pkey);
        }
        //输出publicKey
//        PEM_write_RSAPublicKey(stdout, _rsaPublic);
    }
    if (prkFile!=NULL) {
        if (type==ZBPemTypePKCS1) {
            _rsaPrivate = PEM_read_RSAPrivateKey(prkFile, NULL, NULL, NULL);
        }else{
            EVP_PKEY *pkey = EVP_PKEY_new();
            PEM_read_PrivateKey(prkFile, &pkey, NULL, NULL);
            _rsaPrivate = EVP_PKEY_get1_RSA(pkey);
            EVP_PKEY_free(pkey);
        }
        //输出privateKey
//        PEM_write_RSAPrivateKey(stdout, _rsaPrivate, NULL, NULL, 0, NULL, NULL);
    }
    fclose(pukFile);
    fclose(prkFile);
    return _rsaPublic!=NULL && _rsaPrivate!=NULL;
}
- (NSData *)encryptWithType:(ZBKeyType)type
                paddingType:(ZBRSAPaddingType)padding
                       data:(NSData *)data
                     custom:(BOOL)custom
{
    RSA *rsa;
    if (custom) {
        rsa = (type == ZBKeyTypePublic)?_rsaCustomPublic:_rsaCustomPrivate;
    }else{
        rsa = (type == ZBKeyTypePublic)?_rsaPublic:_rsaPrivate;
    }
    if (rsa==NULL) {
        return nil;
    }
    if (data && data.length>0) {
        int flen = (int)data.length;
        unsigned char from[flen];
        bzero(from, sizeof(from));
        memcpy(from, data.bytes, sizeof(from));
        
        int klen = RSA_size(rsa);
        unsigned char to[klen];
        bzero(to, sizeof(to));
        int relen = 0;//最终加密后的长度
        if (type == ZBKeyTypePublic) {
            relen = RSA_public_encrypt(flen, from, to, rsa, padding);
        }else{
            relen = RSA_private_encrypt(flen, from, to, rsa, padding);
        }
        if (relen>0) {
            return [NSData dataWithBytes:to length:sizeof(to)];
        }
    }
    return nil;
}

- (NSData *)decryptWithType:(ZBKeyType)type
                paddingType:(ZBRSAPaddingType)padding
                       data:(NSData *)data
                     custom:(BOOL)custom
{
    RSA *rsa;
    if (custom) {
        rsa = (type == ZBKeyTypePublic)?_rsaCustomPublic:_rsaCustomPrivate;
    }else{
        rsa = (type == ZBKeyTypePublic)?_rsaPublic:_rsaPrivate;
    }
    if (rsa==NULL) {
        return nil;
    }
    if (data && data.length>0) {
        int flen = (int)data.length;
        unsigned char from[flen];
        bzero(from, sizeof(from));
        memcpy(from, data.bytes, sizeof(from));
        
        int klen = RSA_size(rsa);
        unsigned char to[klen];
        bzero(to, sizeof(to));
        int relen = 0;//最终解密后的长度
        if (type == ZBKeyTypePublic) {
            relen = RSA_public_decrypt(flen, from, to, rsa, padding);
        }else{
            relen = RSA_private_decrypt(flen, from, to, rsa, padding);
        }
        if (relen>0) {
            return [NSData dataWithBytes:to length:sizeof(to)];
        }
    }
    return nil;
}

- (NSData *)signBySHA128:(NSData *)data customPrivateKey:(BOOL)custom{
    RSA *rsa = custom?_rsaCustomPrivate:_rsaPrivate;
    if (rsa==NULL) {
        return nil;
    }
    if (data.length==0) {
        return nil;
    }
    SHA_CTX ctx;
    int dlen = (int)data.length;
    unsigned char dataDigest[SHA_DIGEST_LENGTH];
    if (SHA1_Init(&ctx)!=1) {
        return nil;
    }
    if (SHA1_Update(&ctx, data.bytes, dlen)!=1) {
        return nil;
    }
    if (SHA1_Final(dataDigest, &ctx)!=1) {
        return nil;
    }
    int outlen = RSA_size(rsa);
    unsigned int siglen = 0;
    unsigned char output[outlen];
    int ret = RSA_sign(NID_sha1, dataDigest, sizeof(dataDigest), output, &siglen, rsa);
    if (ret==1) {
        return [NSData dataWithBytes:output length:siglen];
    }
    return nil;
}

- (NSData *)signBySHA256:(NSData *)data customPrivateKey:(BOOL)custom{
    RSA *rsa = custom?_rsaCustomPrivate:_rsaPrivate;
    if (rsa==NULL) {
        return nil;
    }
    if (data.length==0) {
        return nil;
    }
    SHA256_CTX ctx;
    unsigned char dataDigest[SHA256_DIGEST_LENGTH];
    if (SHA256_Init(&ctx)!=1) {
        return nil;
    }
    if (SHA256_Update(&ctx, data.bytes, (int)data.length)!=1) {
        return nil;
    }
    if (SHA256_Final(dataDigest, &ctx)!=1) {
        return nil;
    }
    int outlen = RSA_size(rsa);
    unsigned char output[outlen];
    unsigned int signlen = 0;
    int ret = RSA_sign(NID_sha256, dataDigest, sizeof(dataDigest), output, &signlen, rsa);
    if (ret==1) {
        return [NSData dataWithBytes:output length:signlen];
    }
    return nil;
}

- (NSData *)signByMD5:(NSData *)data customPrivateKey:(BOOL)custom{
    RSA *rsa = custom?_rsaCustomPrivate:_rsaPrivate;
    if (rsa==NULL) {
        return nil;
    }
    if (data.length==0) {
        return nil;
    }
    MD5_CTX ctx;
    unsigned char dataDigest[MD5_DIGEST_LENGTH];
    if (MD5_Init(&ctx)!=1) {
        return nil;
    }
    if (MD5_Update(&ctx, data.bytes, (int)data.length)!=1) {
        return nil;
    }
    if (MD5_Final(dataDigest, &ctx)!=1) {
        return nil;
    }
    int outlen = RSA_size(rsa);
    unsigned char output[outlen];
    unsigned int signlen = 0;
    int ret = RSA_sign(NID_md5, dataDigest, sizeof(dataDigest), output, &signlen, rsa);
    if (ret==1) {
        return [NSData dataWithBytes:output length:signlen];
    }
    return nil;
}

- (BOOL)verifySignBySHA128:(NSData *)sign
                      data:(NSData *)data customPublicKey:(BOOL)custom{
    RSA *rsa = custom?_rsaCustomPublic:_rsaPublic;
    if (rsa==NULL) {
        return NO;
    }
    if (sign.length==0 || data.length==0) {
        return NO;
    }
    SHA_CTX ctx;
    unsigned char dataDigest[SHA_DIGEST_LENGTH];
    if (SHA1_Init(&ctx)!=1) {
        return NO;
    }
    if (SHA1_Update(&ctx, data.bytes,(int)data.length)!=1) {
        return NO;
    }
    if (SHA1_Final(dataDigest, &ctx)!=1) {
        return NO;
    }
    int ret = RSA_verify(NID_sha1, dataDigest, sizeof(dataDigest), sign.bytes, (int)sign.length, rsa);
    return ret==1;
}

- (BOOL)verifySignBySHA256:(NSData *)sign
                      data:(NSData *)data customPublicKey:(BOOL)custom{
    RSA *rsa = custom?_rsaCustomPublic:_rsaPublic;
    if (rsa==NULL) {
        return NO;
    }
    if (sign.length==0 || data.length==0) {
        return NO;
    }
    SHA256_CTX ctx;
    unsigned char dataDigest[SHA256_DIGEST_LENGTH];
    if (SHA256_Init(&ctx)!=1) {
        return NO;
    }
    if (SHA256_Update(&ctx, data.bytes,(int)data.length)!=1) {
        return NO;
    }
    if (SHA256_Final(dataDigest, &ctx)!=1) {
        return NO;
    }
    int ret = RSA_verify(NID_sha256, dataDigest, sizeof(dataDigest), sign.bytes, (int)sign.length, rsa);
    return ret==1;
}
- (BOOL)verifySignByMD5:(NSData *)sign
                   data:(NSData *)data customPublicKey:(BOOL)custom{
    RSA *rsa = custom?_rsaCustomPublic:_rsaPublic;
    if (rsa==NULL) {
        return NO;
    }
    if (sign.length==0 || data.length==0) {
        return NO;
    }
    MD5_CTX ctx;
    unsigned char dataDigest[MD5_DIGEST_LENGTH];
    if (MD5_Init(&ctx)!=1) {
        return NO;
    }
    if (MD5_Update(&ctx, data.bytes,(int)data.length)!=1) {
        return NO;
    }
    if (MD5_Final(dataDigest, &ctx)!=1) {
        return NO;
    }
    int ret = RSA_verify(NID_md5, dataDigest, sizeof(dataDigest), sign.bytes, (int)sign.length, rsa);
    return ret==1;
}

@end






void ZBRSA_CustomPUBKEY_init(NSString *key, ZBPemType type){
    [ZBRSACrypto setCustomPublicKey:key pemType:type];
}

void ZBRSA_CustomPrivate_init(NSString *key, ZBPemType type){
    [ZBRSACrypto setCustomPrivateKey:key pemType:type];
}

NSString * ZBRSA_encrypt(NSString *aString, ZBKeyType type, ZBRSAPaddingType padding){
    if (![aString isKindOfClass:[NSString class]] || aString.length==0) {
        return nil;
    }
    BOOL canEncrypt = NO;
    if ([ZBRSACrypto existPem]) {
        canEncrypt = [ZBRSACrypto importPem:ZBPemTypePKCS8];
    }else{
        //不存在公钥和私钥，创建一份
        if ([ZBRSACrypto createRSAWithSize:ZBRSASize2048]) {
            canEncrypt = [ZBRSACrypto exportPem:ZBPemTypePKCS8];
        }
    }
    if (canEncrypt) {
        NSData *d = [aString dataUsingEncoding:NSUTF8StringEncoding];
        NSData *data = [GTMBase64 webSafeEncodeData:d padded:NO];
        NSData *resData = [ZBRSACrypto encryptWithType:type
                                           paddingType:padding
                                                  data:data];
        if (resData) {
            return [GTMBase64 stringByWebSafeEncodingData:resData padded:NO];
        }
    }
    return nil;
}

NSString * ZBRSA_encrypt_custom(NSString *aString, ZBKeyType type, ZBRSAPaddingType padding){
    if (![aString isKindOfClass:[NSString class]] || aString.length==0) {
        return nil;
    }
    NSData *d = [aString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [GTMBase64 webSafeEncodeData:d padded:NO];
    NSData *resData = [ZBRSACrypto encryptByCustomType:type
                                           paddingType:padding
                                                  data:data];
    if (resData) {
        return [GTMBase64 stringByWebSafeEncodingData:resData padded:NO];
    }
    return nil;
}

NSString * ZBRSA_decrypt(NSString *websafeBase64, ZBKeyType type, ZBRSAPaddingType padding){
    if (![websafeBase64 isKindOfClass:[NSString class]] || websafeBase64.length==0) {
        return nil;
    }
    BOOL canDecrypt = NO;
    if ([ZBRSACrypto existPem]) {
        canDecrypt = [ZBRSACrypto importPem:ZBPemTypePKCS8];
    }else{
        //不存在公钥和私钥，创建一份
        if ([ZBRSACrypto createRSAWithSize:ZBRSASize2048]) {
            canDecrypt = [ZBRSACrypto exportPem:ZBPemTypePKCS8];
        }
    }
    if (canDecrypt) {
        NSData *data = [GTMBase64 webSafeDecodeString:websafeBase64];
        NSData *resData = [ZBRSACrypto decryptWithType:type
                                           paddingType:padding
                                                  data:data];
        if (resData) {
            resData = [GTMBase64 webSafeDecodeData:resData];
            return [[NSString alloc] initWithData:resData encoding:NSUTF8StringEncoding];
        }
    }
    return nil;
}

NSString * ZBRSA_decrypt_custom(NSString *websafeBase64, ZBKeyType type, ZBRSAPaddingType padding){
    if (![websafeBase64 isKindOfClass:[NSString class]] || websafeBase64.length==0) {
        return nil;
    }
    NSData *data = [GTMBase64 webSafeDecodeString:websafeBase64];
    NSData *resData = [ZBRSACrypto decryptByCustomType:type
                                           paddingType:padding
                                                  data:data];
    if (resData) {
        resData = [GTMBase64 webSafeDecodeData:resData];
        return [[NSString alloc] initWithData:resData encoding:NSUTF8StringEncoding];
    }
    return nil;
}





NSString *ZBRSA_sign_sha128(NSString *message){
    if (![message isKindOfClass:[NSString class]] || message.length==0) {
        return nil;
    }
    BOOL canSign = NO;
    if ([ZBRSACrypto existPem]) {
        canSign = [ZBRSACrypto importPem:ZBPemTypePKCS8];
    }else{
        //不存在公钥和私钥，创建一份
        if ([ZBRSACrypto createRSAWithSize:ZBRSASize2048]) {
            canSign = [ZBRSACrypto exportPem:ZBPemTypePKCS8];
        }
    }
    if (canSign) {
        NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
        NSData *signData = [ZBRSACrypto signBySHA128:data
                                    customPrivateKey:NO];
        return [GTMBase64 stringByWebSafeEncodingData:signData padded:NO];
    }
    return nil;
}
NSString *ZBRSA_sign_sha256(NSString *message){
    if (![message isKindOfClass:[NSString class]] || message.length==0) {
        return nil;
    }
    BOOL canSign = NO;
    if ([ZBRSACrypto existPem]) {
        canSign = [ZBRSACrypto importPem:ZBPemTypePKCS8];
    }else{
        //不存在公钥和私钥，创建一份
        if ([ZBRSACrypto createRSAWithSize:ZBRSASize2048]) {
            canSign = [ZBRSACrypto exportPem:ZBPemTypePKCS8];
        }
    }
    if (canSign) {
        NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
        NSData *signData = [ZBRSACrypto signBySHA256:data
                                    customPrivateKey:NO];
        return [GTMBase64 stringByWebSafeEncodingData:signData padded:NO];
    }
    return nil;
}
NSString *ZBRSA_sign_md5(NSString *message){
    if (![message isKindOfClass:[NSString class]] || message.length==0) {
        return nil;
    }
    BOOL canSign = NO;
    if ([ZBRSACrypto existPem]) {
        canSign = [ZBRSACrypto importPem:ZBPemTypePKCS8];
    }else{
        //不存在公钥和私钥，创建一份
        if ([ZBRSACrypto createRSAWithSize:ZBRSASize2048]) {
            canSign = [ZBRSACrypto exportPem:ZBPemTypePKCS8];
        }
    }
    if (canSign) {
        NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
        NSData *signData = [ZBRSACrypto signByMD5:data
                                 customPrivateKey:NO];
        return [GTMBase64 stringByWebSafeEncodingData:signData padded:NO];
    }
    return nil;
}

NSString *ZBRSA_sign_sha128_custom(NSString *message){
    if (![message isKindOfClass:[NSString class]] || message.length==0) {
        return nil;
    }
    NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signData = [ZBRSACrypto signBySHA128:data
                                customPrivateKey:YES];
    return [GTMBase64 stringByWebSafeEncodingData:signData padded:NO];
}
NSString *ZBRSA_sign_sha256_custom(NSString *message){
    if (![message isKindOfClass:[NSString class]] || message.length==0) {
        return nil;
    }
    NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signData = [ZBRSACrypto signBySHA256:data
                                customPrivateKey:YES];
    return [GTMBase64 stringByWebSafeEncodingData:signData padded:NO];
}
NSString *ZBRSA_sign_md5_custom(NSString *message){
    if (![message isKindOfClass:[NSString class]] || message.length==0) {
        return nil;
    }
    NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
    NSData *signData = [ZBRSACrypto signByMD5:data
                             customPrivateKey:YES];
    return [GTMBase64 stringByWebSafeEncodingData:signData padded:NO];
}


BOOL ZBRSA_verify_sha128(NSString *signWebSafeBase64, NSString *message){
    if ((![signWebSafeBase64 isKindOfClass:[NSString class]] || signWebSafeBase64.length==0) ||
        (![message isKindOfClass:[NSString class]] || message.length==0)) {
        return NO;
    }
    BOOL canSign = NO;
    if ([ZBRSACrypto existPem]) {
        canSign = [ZBRSACrypto importPem:ZBPemTypePKCS8];
    }else{
        //不存在公钥和私钥，创建一份
        if ([ZBRSACrypto createRSAWithSize:ZBRSASize2048]) {
            canSign = [ZBRSACrypto exportPem:ZBPemTypePKCS8];
        }
    }
    if (canSign) {
        NSData *signData = [GTMBase64 webSafeDecodeString:signWebSafeBase64];
        NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
        return [ZBRSACrypto verifySignBySHA128:signData
                                          data:data
                               customPublicKey:NO];
    }
    return NO;
}
BOOL ZBRSA_verify_sha256(NSString *signWebSafeBase64, NSString *message){
    if ((![signWebSafeBase64 isKindOfClass:[NSString class]] || signWebSafeBase64.length==0) ||
        (![message isKindOfClass:[NSString class]] || message.length==0)) {
        return NO;
    }
    BOOL canSign = NO;
    if ([ZBRSACrypto existPem]) {
        canSign = [ZBRSACrypto importPem:ZBPemTypePKCS8];
    }else{
        //不存在公钥和私钥，创建一份
        if ([ZBRSACrypto createRSAWithSize:ZBRSASize2048]) {
            canSign = [ZBRSACrypto exportPem:ZBPemTypePKCS8];
        }
    }
    if (canSign) {
        NSData *signData = [GTMBase64 webSafeDecodeString:signWebSafeBase64];
        NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
        return [ZBRSACrypto verifySignBySHA256:signData
                                          data:data
                               customPublicKey:NO];
    }
    return NO;
}
BOOL ZBRSA_verify_md5(NSString *signWebSafeBase64, NSString *message){
    if ((![signWebSafeBase64 isKindOfClass:[NSString class]] || signWebSafeBase64.length==0) ||
        (![message isKindOfClass:[NSString class]] || message.length==0)) {
        return NO;
    }
    BOOL canSign = NO;
    if ([ZBRSACrypto existPem]) {
        canSign = [ZBRSACrypto importPem:ZBPemTypePKCS8];
    }else{
        //不存在公钥和私钥，创建一份
        if ([ZBRSACrypto createRSAWithSize:ZBRSASize2048]) {
            canSign = [ZBRSACrypto exportPem:ZBPemTypePKCS8];
        }
    }
    if (canSign) {
        NSData *signData = [GTMBase64 webSafeDecodeString:signWebSafeBase64];
        NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
        return [ZBRSACrypto verifySignByMD5:signData
                                       data:data
                            customPublicKey:NO];
    }
    return NO;
}


BOOL ZBRSA_verify_sha128_custom(NSString *signWebSafeBase64, NSString *message){
    if ((![signWebSafeBase64 isKindOfClass:[NSString class]] || signWebSafeBase64.length==0) ||
        (![message isKindOfClass:[NSString class]] || message.length==0)) {
        return NO;
    }
    NSData *signData = [GTMBase64 webSafeDecodeString:signWebSafeBase64];
    NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
    return [ZBRSACrypto verifySignBySHA128:signData
                                      data:data
                           customPublicKey:YES];
}
BOOL ZBRSA_verify_sha256_custom(NSString *signWebSafeBase64, NSString *message){
    if ((![signWebSafeBase64 isKindOfClass:[NSString class]] || signWebSafeBase64.length==0) ||
        (![message isKindOfClass:[NSString class]] || message.length==0)) {
        return NO;
    }
    NSData *signData = [GTMBase64 webSafeDecodeString:signWebSafeBase64];
    NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
    return [ZBRSACrypto verifySignBySHA256:signData
                                      data:data
                           customPublicKey:YES];
}
BOOL ZBRSA_verify_md5_custom(NSString *signWebSafeBase64, NSString *message){
    if ((![signWebSafeBase64 isKindOfClass:[NSString class]] || signWebSafeBase64.length==0) ||
        (![message isKindOfClass:[NSString class]] || message.length==0)) {
        return NO;
    }
    NSData *signData = [GTMBase64 webSafeDecodeString:signWebSafeBase64];
    NSData *data = [message dataUsingEncoding:NSUTF8StringEncoding];
    return [ZBRSACrypto verifySignByMD5:signData
                                   data:data
                        customPublicKey:YES];
}
