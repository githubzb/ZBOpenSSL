//
//  ZBAESCrypto.m
//  ZBOpenSSL
//
//  Created by 张宝 on 2018/7/4.
//  Copyright © 2018年 zb. All rights reserved.
//

#import "ZBAESCrypto.h"
#import <openssl/aes.h>

@implementation ZBAESCrypto

+ (NSData *)encrypt:(NSData *)data type:(const EVP_CIPHER *)type password:(NSString *)pwd{
    if (![pwd isKindOfClass:[NSString class]] ||
        pwd.length==0 ||
        data.length==0) {
        return nil;
    }
    NSData *kdata = [pwd dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char key[AES_BLOCK_SIZE];
    bzero(key, sizeof(key));
    memcpy(key, kdata.bytes, sizeof(key));
    int ivl = EVP_CIPHER_iv_length(type);
    unsigned char iv[ivl];
    bzero(iv, sizeof(iv));
    
    int ret = 0;
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    ret = EVP_EncryptInit_ex(&ctx, type, NULL, key, iv);
    if (ret==1) {
        int inlen = (int)data.length;
        int outlen = 0,enclen = 0;
        unsigned char input[inlen];
        unsigned char output[BUFSIZ+inlen];
        bzero(input, sizeof(input));
        memcpy(input, data.bytes, sizeof(input));
        ret = EVP_EncryptUpdate(&ctx, output, &outlen, input, inlen);
        if (ret==1) {
            enclen += outlen;
            ret = EVP_EncryptFinal_ex(&ctx, output+outlen, &outlen);
            if (ret==1) {
                enclen += outlen;
                EVP_CIPHER_CTX_cleanup(&ctx);
                return [NSData dataWithBytes:output length:enclen];
            }
        }
    }
    EVP_CIPHER_CTX_cleanup(&ctx);
    return nil;
}

+ (NSData *)decrypt:(NSData *)data type:(const EVP_CIPHER *)type password:(NSString *)pwd{
    if (![pwd isKindOfClass:[NSString class]] ||
        pwd.length==0 ||
        data.length==0) {
        return nil;
    }
    NSData *kdata = [pwd dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char key[AES_BLOCK_SIZE];
    bzero(key, sizeof(key));
    memcpy(key, kdata.bytes, sizeof(key));
    int ivl = EVP_CIPHER_iv_length(type);
    unsigned char iv[ivl];
    bzero(iv, sizeof(iv));
    
    int ret = 0;
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    ret = EVP_DecryptInit_ex(&ctx, type, NULL, key, iv);
    if (ret==1) {
        int inlen = (int)data.length;
        int outlen = 0,enclen = 0;
        unsigned char input[inlen];
        unsigned char output[BUFSIZ+inlen];
        bzero(input, sizeof(input));
        memcpy(input, data.bytes, sizeof(input));
        ret = EVP_DecryptUpdate(&ctx, output, &outlen, input, inlen);
        if (ret==1) {
            enclen = outlen;
            ret = EVP_DecryptFinal_ex(&ctx, output+outlen, &outlen);
            if (ret==1) {
                enclen += outlen;
                EVP_CIPHER_CTX_cleanup(&ctx);
                return [NSData dataWithBytes:output length:enclen];
            }
        }
    }
    EVP_CIPHER_CTX_cleanup(&ctx);
    return nil;
}

@end
