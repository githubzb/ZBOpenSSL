//
//  ZBMD5Crypto.m
//  ZBOpenSSL
//
//  Created by 张宝 on 2018/7/9.
//  Copyright © 2018年 zb. All rights reserved.
//

#import "ZBMD5Crypto.h"
#import "ZBHexCrypto.h"
#import <openssl/md5.h>

@implementation ZBMD5Crypto

+ (NSData *)md5:(NSData *)d{
    MD5_CTX ctx;
    unsigned char dataDigest[MD5_DIGEST_LENGTH];
    if (MD5_Init(&ctx)!=1) {
        return nil;
    }
    if (MD5_Update(&ctx, d.bytes,(int)d.length)!=1) {
        return nil;
    }
    if (MD5_Final(dataDigest, &ctx)!=1) {
        return nil;
    }
    return [NSData dataWithBytes:dataDigest length:sizeof(dataDigest)];
}

@end

NSString * ZBMD5(NSString *str){
    if (![str isKindOfClass:[NSString class]] || str.length==0) {
        return nil;
    }
    NSData *d = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData *data = [ZBMD5Crypto md5:d];
    return [ZBHexCrypto hexString:data];
}
