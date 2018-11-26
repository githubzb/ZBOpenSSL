//
//  ZBAESCrypto.h
//  ZBOpenSSL
//
//  Created by 张宝 on 2018/7/4.
//  Copyright © 2018年 zb. All rights reserved.
//

#import <Foundation/Foundation.h>

typedef NS_ENUM(NSUInteger, ZBAESKeySize) {
    ZBAESKeySize128 = 16,
    ZBAESKeySize192 = 24,
    ZBAESKeySize256 = 32
};

typedef NS_ENUM(NSInteger, ZBAESErrorCode) {
    ZBAESErrorCodeKeySize = 1,
    ZBAESErrorCodeEVP = 2
};

typedef NS_ENUM(NSInteger, ZBAESMode) {
    ZBAESModeECB = 0,
    ZBAESModeCBC,
    ZBAESModeCTR,
    ZBAESModeOFB,
    ZBAESModeCFB
};

FOUNDATION_EXPORT NSString * const ZBAesErrorDomain;

//所有加密解密Padding方式为PKCS padding
@interface ZBAESCrypto : NSObject

/**
 生成AES加解密的Key

 @param size    key的长度
 @param error   错误
 @return        data
 */
+ (NSData *)generateKey:(ZBAESKeySize)size error:(NSError **)error;

/**
 生成AES加解密的IV

 @return data
 */
+ (NSData *)generateIV;


/**
 加密

 @param mode    加密模式
 @param data    明文数据
 @param key     秘钥
 @param ksize   秘钥长度
 @param iv      iv向量
 @param error   错误
 @return        data
 */
+ (NSData *)encrypt_mode:(ZBAESMode)mode
                    data:(NSData *)data
                    key:(NSData *)key
                keySize:(ZBAESKeySize)ksize
                     iv:(NSData *)iv
                  error:(NSError **)error;

/**
 解密

 @param mode    解密模式
 @param data    密文数据
 @param key     秘钥
 @param ksize   秘钥长度
 @param iv      iv向量
 @param error   错误
 @return        data
 */
+ (NSData *)decrypt_mode:(ZBAESMode)mode
                    data:(NSData *)data
                    key:(NSData *)key
                keySize:(ZBAESKeySize)ksize
                     iv:(NSData *)iv
                  error:(NSError **)error;

@end
