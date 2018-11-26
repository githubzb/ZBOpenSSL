//
//  ZBHmacCrypto.m
//  ZBOpenSSL
//
//  Created by 张宝 on 2018/7/10.
//  Copyright © 2018年 zb. All rights reserved.
//

#import "ZBHmacCrypto.h"
#import <openssl/hmac.h>
#import "ZBHexCrypto.h"

@implementation ZBHmacCrypto

+ (NSData *)hmacSHA:(NSData *)d password:(NSString *)pwd{
    return [self hmac:d password:pwd md:EVP_sha()];
}

+ (NSData *)hmacSHA1:(NSData *)d password:(NSString *)pwd{
    return [self hmac:d password:pwd md:EVP_sha1()];
}

+ (NSData *)hmacSHA224:(NSData *)d password:(NSString *)pwd{
    return [self hmac:d password:pwd md:EVP_sha224()];
}

+ (NSData *)hmacSHA256:(NSData *)d password:(NSString *)pwd{
    return [self hmac:d password:pwd md:EVP_sha256()];
}

+ (NSData *)hmacSHA384:(NSData *)d password:(NSString *)pwd{
    return [self hmac:d password:pwd md:EVP_sha384()];
}

+ (NSData *)hmacSHA512:(NSData *)d password:(NSString *)pwd{
    return [self hmac:d password:pwd md:EVP_sha512()];
}

+ (NSData *)hmacMD5:(NSData *)d password:(NSString *)pwd{
    return [self hmac:d password:pwd md:EVP_md5()];
}

#pragma mark - private
+ (NSData *)hmac:(NSData *)d password:(NSString *)pwd md:(const EVP_MD *)md{
    if (![d isKindOfClass:[NSData class]] || d.length==0) {
        return nil;
    }
    NSData *key = [pwd dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char dataDigest[HMAC_MAX_MD_CBLOCK];
    unsigned int len = 0;
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    if (HMAC_Init_ex(&ctx, key.bytes, (int)key.length, md, NULL)!=1) {
        return nil;
    }
    if (HMAC_Update(&ctx, d.bytes, (int)d.length)!=1) {
        return nil;
    }
    if (HMAC_Final(&ctx, dataDigest, &len)!=1) {
        return nil;
    }
    HMAC_CTX_cleanup(&ctx);
    return [NSData dataWithBytes:dataDigest length:len];
}

@end

NSString * ZBHmacSHA(NSString *str, NSString *pwd){
    NSData *d = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [ZBHmacCrypto hmacSHA:d password:pwd];
    return [ZBHexCrypto hexString:data];
}
NSString * ZBHmacSHA1(NSString *str, NSString *pwd){
    NSData *d = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [ZBHmacCrypto hmacSHA1:d password:pwd];
    return [ZBHexCrypto hexString:data];
}
NSString * ZBHmacSHA224(NSString *str, NSString *pwd){
    NSData *d = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [ZBHmacCrypto hmacSHA224:d password:pwd];
    return [ZBHexCrypto hexString:data];
}
NSString * ZBHmacSHA256(NSString *str, NSString *pwd){
    NSData *d = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [ZBHmacCrypto hmacSHA256:d password:pwd];
    return [ZBHexCrypto hexString:data];
}
NSString * ZBHmacSHA384(NSString *str, NSString *pwd){
    NSData *d = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [ZBHmacCrypto hmacSHA384:d password:pwd];
    return [ZBHexCrypto hexString:data];
}
NSString * ZBHmacSHA512(NSString *str, NSString *pwd){
    NSData *d = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [ZBHmacCrypto hmacSHA512:d password:pwd];
    return [ZBHexCrypto hexString:data];
}
NSString * ZBHmacMD5(NSString *str, NSString *pwd){
    NSData *d = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [ZBHmacCrypto hmacMD5:d password:pwd];
    return [ZBHexCrypto hexString:data];
}

