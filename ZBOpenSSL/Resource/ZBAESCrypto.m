//
//  ZBAESCrypto.m
//  ZBOpenSSL
//
//  Created by 张宝 on 2018/7/4.
//  Copyright © 2018年 zb. All rights reserved.
//

#import "ZBAESCrypto.h"
#import <openssl/aes.h>
#import <openssl/rand.h>
#import <openssl/evp.h>

NSString * const ZBAesErrorDomain = @"ZBAESDomain";

@implementation ZBAESCrypto

+ (NSData *)generateKey:(ZBAESKeySize)size error:(NSError *__autoreleasing *)error{
    if (![self validKeySize:size err:error]) {
        return nil;
    }
    unsigned char *buf = (unsigned char*)malloc(sizeof(unsigned char) * size);
    RAND_bytes(buf, (int)size);
    return [NSData dataWithBytesNoCopy:buf length:size];
}

+ (NSData *)generateIV{
    unsigned char *ivec = (unsigned char*)malloc(sizeof(unsigned char) * AES_BLOCK_SIZE);
    RAND_bytes(ivec, AES_BLOCK_SIZE);
    return [NSData dataWithBytesNoCopy:ivec length:AES_BLOCK_SIZE];
}

+ (NSData *)encrypt_mode:(ZBAESMode)mode
                    data:(NSData *)data
                    key:(NSData *)key
                keySize:(ZBAESKeySize)ksize
                     iv:(NSData *)iv
                  error:(NSError **)error{
    if (data.length==0) {
        return nil;
    }
    if (![self validKeySize:ksize err:error]) {
        return nil;
    }
    if (![self validKey:key size:ksize err:error]) {
        return nil;
    }
    size_t blockLength = 0;
    size_t cipherBytesLength = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *evp_cipher = [self evp_cipher_size:ksize mode:mode];
    unsigned char *cipherBytes = (unsigned char*)malloc(data.length+AES_BLOCK_SIZE);
    memset(cipherBytes, 0, data.length+AES_BLOCK_SIZE);
    if (!EVP_EncryptInit(ctx, evp_cipher, key.bytes, iv.bytes)) {
        free(cipherBytes);
        *error = [self EVPError];
        return nil;
    }
    if (!EVP_EncryptUpdate(ctx, cipherBytes, (int *)&blockLength, data.bytes, (int)data.length)) {
        free(cipherBytes);
        *error = [self EVPError];
        return nil;
    }
    cipherBytesLength += blockLength;
    if (!EVP_EncryptFinal(ctx, cipherBytes+cipherBytesLength, (int *)&blockLength)) {
        free(cipherBytes);
        *error = [self EVPError];
        return nil;
    }
    cipherBytesLength += blockLength;
    EVP_CIPHER_CTX_free(ctx);
    return [NSData dataWithBytesNoCopy:cipherBytes length:cipherBytesLength];
}
+ (NSData *)decrypt_mode:(ZBAESMode)mode
                    data:(NSData *)data
                    key:(NSData *)key
                keySize:(ZBAESKeySize)ksize
                     iv:(NSData *)iv
                  error:(NSError *__autoreleasing *)error{
    if (data.length==0) {
        return nil;
    }
    if (![self validKeySize:ksize err:error]) {
        return nil;
    }
    if (![self validKey:key size:ksize err:error]) {
        return nil;
    }
    size_t messageBytesLength = 0;
    size_t blockLength = 0;
    unsigned char *messageBytes = (unsigned char*)malloc(data.length);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *evp_cipher = [self evp_cipher_size:ksize mode:mode];
    if (!EVP_DecryptInit(ctx, evp_cipher, key.bytes, iv.bytes)) {
        free(messageBytes);
        *error = [self EVPError];
        return nil;
    }
    if (!EVP_DecryptUpdate(ctx, messageBytes, (int *)&blockLength, data.bytes, (int)data.length)) {
        free(messageBytes);
        *error = [self EVPError];
        return nil;
    }
    messageBytesLength += blockLength;
    if (!EVP_DecryptFinal(ctx, messageBytes+messageBytesLength, (int *)&blockLength)) {
        free(messageBytes);
        *error = [self EVPError];
        return nil;
    }
    messageBytesLength += blockLength;
    EVP_CIPHER_CTX_free(ctx);
    return [NSData dataWithBytesNoCopy:messageBytes length:messageBytesLength];
}

#pragma mark - private
+ (BOOL)validKeySize:(ZBAESKeySize)size err:(NSError **)err{
    if (size!=ZBAESKeySize128 &&
        size!=ZBAESKeySize192 &&
        size!=ZBAESKeySize256) {
        NSString *s = [NSString stringWithFormat:@"AES key size invalid, %lu",size];
        *err = [NSError errorWithDomain:ZBAesErrorDomain
                                   code:ZBAESErrorCodeKeySize
                               userInfo:@{NSLocalizedDescriptionKey:s}];
        return NO;
    }
    return YES;
}
+ (BOOL)validKey:(NSData *)key size:(ZBAESKeySize)size err:(NSError **)err{
    if (key.length!=size) {
        NSString *s = [NSString stringWithFormat:@"AES key.length != %lu", size];
        *err = [NSError errorWithDomain:ZBAesErrorDomain
                                   code:ZBAESErrorCodeKeySize
                               userInfo:@{NSLocalizedDescriptionKey:s}];
        return NO;
    }
    return YES;
}
+ (const EVP_CIPHER *)evp_cipher_size:(ZBAESKeySize)size mode:(ZBAESMode)mode{
    const EVP_CIPHER *evp_cipher = nil;
    if (mode==ZBAESModeECB) {
        switch (size) {
            case ZBAESKeySize128:
                evp_cipher = EVP_aes_128_ecb();
                break;
            case ZBAESKeySize192:
                evp_cipher = EVP_aes_192_ecb();
                break;
            case ZBAESKeySize256:
                evp_cipher = EVP_aes_256_ecb();
                break;
            default:
                break;
        }
    }
    if (mode==ZBAESModeCBC) {
        switch (size) {
            case ZBAESKeySize128:
                evp_cipher = EVP_aes_128_cbc();
                break;
            case ZBAESKeySize192:
                evp_cipher = EVP_aes_192_cbc();
                break;
            case ZBAESKeySize256:
                evp_cipher = EVP_aes_256_cbc();
                break;
            default:
                break;
        }
    }
    if (mode==ZBAESModeCTR) {
        switch (size) {
            case ZBAESKeySize128:
                evp_cipher = EVP_aes_128_ctr();
                break;
            case ZBAESKeySize192:
                evp_cipher = EVP_aes_192_ctr();
                break;
            case ZBAESKeySize256:
                evp_cipher = EVP_aes_256_ctr();
                break;
            default:
                break;
        }
    }
    if (mode==ZBAESModeOFB) {
        switch (size) {
            case ZBAESKeySize128:
                evp_cipher = EVP_aes_128_ofb();
                break;
            case ZBAESKeySize192:
                evp_cipher = EVP_aes_192_ofb();
                break;
            case ZBAESKeySize256:
                evp_cipher = EVP_aes_256_ofb();
                break;
            default:
                break;
        }
    }
    if (mode==ZBAESModeCFB) {
        switch (size) {
            case ZBAESKeySize128:
                evp_cipher = EVP_aes_128_cfb();
                break;
            case ZBAESKeySize192:
                evp_cipher = EVP_aes_192_cfb();
                break;
            case ZBAESKeySize256:
                evp_cipher = EVP_aes_256_cfb();
                break;
            default:
                break;
        }
    }
    return evp_cipher;
}
+ (NSError *)EVPError{
    return [NSError errorWithDomain:ZBAesErrorDomain
                               code:ZBAESErrorCodeEVP
                           userInfo:@{NSLocalizedDescriptionKey:@"EVP error."}];
}

@end
