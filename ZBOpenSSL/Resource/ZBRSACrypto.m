//
//  ZBRSACrypto.m
//  ZBOpenSSL
//
//  Created by 张宝 on 2018/6/29.
//  Copyright © 2018年 zb. All rights reserved.
//  相关函数调用请参考：http://www.qmailer.net/archives/216.html

#import "ZBRSACrypto.h"
#include <openssl/pem.h>

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

@property (nonatomic, copy) NSString *customPublicPemPath;
@property (nonatomic, copy) NSString *customPrivatePemPath;

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
        self.customPublicPemPath = [path stringByAppendingPathComponent:@"cpuk.pem"];
        self.customPrivatePemPath = [path stringByAppendingPathComponent:@"cprk.pem"];
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
        return [[str componentsSeparatedByString:@"-----"] objectAtIndex:2];
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
        return [[str componentsSeparatedByString:@"-----"] objectAtIndex:2];
    }
    return nil;
}

+ (NSString *)publicKey{
    return [ZBRSACrypto share].publicKey;
}

+ (NSString *)privateKey{
    return [ZBRSACrypto share].privateKey;
}

+ (void)setCustomPublicKey:(NSString *)pk{
    [[ZBRSACrypto share] setCustomPublicKey:pk];
}

+ (void)setCustomPrivateKey:(NSString *)prk{
    [[ZBRSACrypto share] setCustomPrivateKey:prk];
}

+ (void)clearCustomKey{
    [[ZBRSACrypto share] clearCustomKey];
}

+ (BOOL)existPem{
    return [[ZBRSACrypto share] existPem];
}
+ (BOOL)createRSAWithSize:(int)size{
    return [[ZBRSACrypto share] createRSAWithSize:size];
}
+ (BOOL)exportPem{
    return [[ZBRSACrypto share] exportPem];
}
+ (BOOL)importPem{
    return [[ZBRSACrypto share] importPem];
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

#pragma mark - private
- (void)setCustomPublicKey:(NSString *)pk{
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL res = YES;
    if (![fm fileExistsAtPath:self.customPublicPemPath]) {
        NSMutableString *str = [[NSMutableString alloc] init];
        if ([pk containsString:@"-----BEGIN RSA PUBLIC KEY-----"]) {
            [str appendString:pk];
        }else{
            [str appendString:@"-----BEGIN RSA PUBLIC KEY-----"];
            [str appendString:pk];
            [str appendString:@"-----END RSA PUBLIC KEY-----\n"];
        }
        NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
        res = [data writeToFile:self.customPublicPemPath atomically:YES];
    }
    if (res) {
        FILE *file = fopen([self.customPublicPemPath cStringUsingEncoding:NSASCIIStringEncoding], "rb");
        if (_rsaCustomPublic) {
            RSA_free(_rsaCustomPublic);
            _rsaCustomPublic = NULL;
        }
        _rsaCustomPublic = PEM_read_RSAPublicKey(file, NULL, NULL, NULL);
        fclose(file);
    }
}
- (void)setCustomPrivateKey:(NSString *)prk{
    NSFileManager *fm = [NSFileManager defaultManager];
    BOOL res = YES;
    if (![fm fileExistsAtPath:self.customPrivatePemPath]) {
        NSMutableString *str = [[NSMutableString alloc] init];
        if ([prk containsString:@"-----BEGIN RSA PRIVATE KEY-----"]) {
            [str appendString:prk];
        }else{
            [str appendString:@"-----BEGIN RSA PRIVATE KEY-----"];
            [str appendString:prk];
            [str appendString:@"-----END RSA PRIVATE KEY-----\n"];
        }
        NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
        res = [data writeToFile:self.customPrivatePemPath atomically:YES];
    }
    if (res) {
        FILE *file = fopen([self.customPrivatePemPath cStringUsingEncoding:NSASCIIStringEncoding], "rb");
        if (_rsaCustomPrivate) {
            RSA_free(_rsaCustomPrivate);
            _rsaCustomPrivate = NULL;
        }
        _rsaCustomPrivate = PEM_read_RSAPrivateKey(file, NULL, NULL, NULL);
        fclose(file);
    }
}
- (void)clearCustomKey{
    NSFileManager *fm = [NSFileManager defaultManager];
    if ([fm fileExistsAtPath:self.customPublicPemPath]) {
        [fm removeItemAtPath:self.customPublicPemPath error:nil];
    }
    if ([fm fileExistsAtPath:self.customPrivatePemPath]) {
        [fm removeItemAtPath:self.customPrivatePemPath error:nil];
    }
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
- (BOOL)exportPem{
    if (_rsa!=NULL) {
        FILE *pukFile, *prkFile;
        pukFile = fopen([self.publicPemPath cStringUsingEncoding:NSASCIIStringEncoding], "w");
        prkFile = fopen([self.privatePemPath cStringUsingEncoding:NSASCIIStringEncoding], "w");
        if (pukFile!=NULL && prkFile!=NULL) {
            int pukRes=0, prkRes=0;
            RSA *puk = RSAPublicKey_dup(_rsa);
            if (puk!=NULL) {
                pukRes = PEM_write_RSAPublicKey(pukFile, puk);
                if (_rsaPublic!=NULL) {
                    RSA_free(_rsaPublic);
                    _rsaPublic = NULL;
                }
                _rsaPublic = puk;
            }
            RSA *prk = RSAPrivateKey_dup(_rsa);
            if (prk!=NULL) {
                int klen = RSA_size(prk);
                prkRes = PEM_write_RSAPrivateKey(prkFile, prk, NULL, NULL, klen, NULL, NULL);
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
- (BOOL)importPem{
    FILE *pukFile, *prkFile;
    pukFile = fopen([self.publicPemPath cStringUsingEncoding:NSASCIIStringEncoding], "rb");
    prkFile = fopen([self.privatePemPath cStringUsingEncoding:NSASCIIStringEncoding], "rb");
    if (pukFile!=NULL) {
        _rsaPublic = PEM_read_RSAPublicKey(pukFile, NULL, NULL, NULL);
        //输出publicKey
//        PEM_write_RSAPublicKey(stdout, _rsaPublic);
    }
    if (prkFile!=NULL) {
        _rsaPrivate = PEM_read_RSAPrivateKey(prkFile, NULL, NULL, NULL);
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

@end

NSString * ZBRSA_encrypt(NSString *aString, ZBKeyType type, ZBRSAPaddingType padding){
    if (![aString isKindOfClass:[NSString class]] || aString.length==0) {
        return nil;
    }
    BOOL canEncrypt = NO;
    if ([ZBRSACrypto existPem]) {
        canEncrypt = [ZBRSACrypto importPem];
    }else{
        //不存在公钥和私钥，创建一份
        if ([ZBRSACrypto createRSAWithSize:ZBRSASize2048]) {
            canEncrypt = [ZBRSACrypto exportPem];
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
        canDecrypt = [ZBRSACrypto importPem];
    }else{
        //不存在公钥和私钥，创建一份
        if ([ZBRSACrypto createRSAWithSize:ZBRSASize2048]) {
            canDecrypt = [ZBRSACrypto exportPem];
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

