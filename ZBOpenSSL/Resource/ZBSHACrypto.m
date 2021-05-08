//
//  ZBSHACrypto.m
//  ZBOpenSSL
//
//  Created by 张宝 on 2018/7/10.
//  Copyright © 2018年 zb. All rights reserved.
//

#import "ZBSHACrypto.h"
#import <openssl/sha.h>
#import "ZBHexCrypto.h"

@implementation ZBSHACrypto

+ (NSData *)sha1:(NSData *)d{
    if (![d isKindOfClass:[NSData class]] || d.length==0) {
        return nil;
    }
    SHA_CTX ctx;
    int dlen = (int)d.length;
    unsigned char dataDigest[SHA_DIGEST_LENGTH];
    if (SHA1_Init(&ctx)!=1) {
        return nil;
    }
    if (SHA1_Update(&ctx, d.bytes, dlen)!=1) {
        return nil;
    }
    if (SHA1_Final(dataDigest, &ctx)!=1) {
        return nil;
    }
    return [NSData dataWithBytes:dataDigest length:sizeof(dataDigest)];
}

+ (NSData *)sha224:(NSData *)d{
    if (![d isKindOfClass:[NSData class]] || d.length==0) {
        return nil;
    }
    SHA256_CTX ctx;
    unsigned char dataDigest[SHA224_DIGEST_LENGTH];
    if (SHA224_Init(&ctx)!=1) {
        return nil;
    }
    if (SHA224_Update(&ctx, d.bytes, (int)d.length)!=1) {
        return nil;
    }
    if (SHA224_Final(dataDigest, &ctx)!=1) {
        return nil;
    }
    return [NSData dataWithBytes:dataDigest length:sizeof(dataDigest)];
}

+ (NSData *)sha256:(NSData *)d{
    if (![d isKindOfClass:[NSData class]] || d.length==0) {
        return nil;
    }
    SHA256_CTX ctx;
    unsigned char dataDigest[SHA256_DIGEST_LENGTH];
    if (SHA256_Init(&ctx)!=1) {
        return nil;
    }
    if (SHA256_Update(&ctx, d.bytes, (int)d.length)!=1) {
        return nil;
    }
    if (SHA256_Final(dataDigest, &ctx)!=1) {
        return nil;
    }
    return [NSData dataWithBytes:dataDigest length:sizeof(dataDigest)];
}

+ (NSData *)sha384:(NSData *)d{
    if (![d isKindOfClass:[NSData class]] || d.length==0) {
        return nil;
    }
    SHA512_CTX ctx;
    unsigned char dataDigest[SHA384_DIGEST_LENGTH];
    if (SHA384_Init(&ctx)!=1) {
        return nil;
    }
    if (SHA384_Update(&ctx, d.bytes, (int)d.length)!=1) {
        return nil;
    }
    if (SHA384_Final(dataDigest, &ctx)!=1) {
        return nil;
    }
    return [NSData dataWithBytes:dataDigest length:sizeof(dataDigest)];
}

+ (NSData *)sha512:(NSData *)d{
    if (![d isKindOfClass:[NSData class]] || d.length==0) {
        return nil;
    }
    SHA512_CTX ctx;
    unsigned char dataDigest[SHA512_DIGEST_LENGTH];
    if (SHA512_Init(&ctx)!=1) {
        return nil;
    }
    if (SHA512_Update(&ctx, d.bytes, (int)d.length)!=1) {
        return nil;
    }
    if (SHA512_Final(dataDigest, &ctx)!=1) {
        return nil;
    }
    return [NSData dataWithBytes:dataDigest length:sizeof(dataDigest)];
}

@end

NSString * ZBSha1(NSString *str){
    NSData *d = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [ZBSHACrypto sha1:d];
    return [ZBHexCrypto hexString:data];
}
NSString * ZBSha224(NSString *str){
    NSData *d = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [ZBSHACrypto sha224:d];
    return [ZBHexCrypto hexString:data];
}
NSString * ZBSha256(NSString *str){
    NSData *d = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [ZBSHACrypto sha256:d];
    return [ZBHexCrypto hexString:data];
}
NSString * ZBSha384(NSString *str){
    NSData *d = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [ZBSHACrypto sha384:d];
    return [ZBHexCrypto hexString:data];
}
NSString * ZBSha512(NSString *str){
    NSData *d = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [ZBSHACrypto sha512:d];
    return [ZBHexCrypto hexString:data];
}

