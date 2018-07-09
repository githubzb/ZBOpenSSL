//
//  ZBAESCrypto.h
//  ZBOpenSSL
//
//  Created by 张宝 on 2018/7/4.
//  Copyright © 2018年 zb. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <GTMBase64/GTMBase64.h>
#import <openssl/evp.h>

@interface ZBAESCrypto : NSObject

/**
 AES加密

 @param data    明文数据
 @param type    加密类型
 @param pwd     秘钥
 @return        加密后的数据
 */
+ (NSData *)encrypt:(NSData *)data
               type:(const EVP_CIPHER *)type
           password:(NSString *)pwd;

/**
 AES解密

 @param data    加密后的数据
 @param type    解密类型（一定要与加密一致）
 @param pwd     秘钥
 @return        解密后的数据
 */
+ (NSData *)decrypt:(NSData *)data
               type:(const EVP_CIPHER *)type
           password:(NSString *)pwd;

@end
