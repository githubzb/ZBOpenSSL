//
//  ZBRSACrypto.h
//  ZBOpenSSL
//
//  Created by 张宝 on 2018/6/29.
//  Copyright © 2018年 zb. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <openssl/rsa.h>
#import <GTMBase64/GTMBase64.h>

typedef NS_ENUM(int , ZBRSASize) {
    ZBRSASize1024   = 1024,
    ZBRSASize2048   = 2048,
    ZBRSASize3072   = 3072
};

typedef NS_ENUM(NSInteger, ZBKeyType) {
    ZBKeyTypePublic     = 0,
    ZBKeyTypePrivate    = 1
};

typedef NS_ENUM(int, ZBRSAPaddingType) {
    ZBRSAPaddingTypeNone    = RSA_NO_PADDING,
    ZBRSAPaddingTypePKCS1   = RSA_PKCS1_PADDING,
    ZBRSAPaddingTypeSSLV23  = RSA_SSLV23_PADDING,
    ZBRSAPaddingTypePKCS1_OAEP  = RSA_PKCS1_OAEP_PADDING,
    ZBRSAPaddingTypeX931        = RSA_X931_PADDING
};

@interface ZBRSACrypto : NSObject

@property (nonatomic, readonly) NSString *publicKey;
@property (nonatomic, readonly) NSString *privateKey;
@property (class, readonly) NSString *publicKey;
@property (class, readonly) NSString *privateKey;

+ (instancetype)share;

/**
 设置自定义公钥

 @param pk  公钥字符串
 */
+ (void)setCustomPublicKey:(NSString *)pk;

/**
 设置自定义私钥

 @param prk 私钥字符串
 */
+ (void)setCustomPrivateKey:(NSString *)prk;

/**
 清空自定义秘钥
 */
+ (void)clearCustomKey;

/**
 判断publicKey.pem和privateKey.pem文件是否存在

 @return    YES：已存在
 */
+ (BOOL)existPem;

/**
 创建RSA对象

 @param size    秘钥长度（ZBRSASize）
 @return        YES：成功创建
 */
+ (BOOL)createRSAWithSize:(int)size;

/**
 导出publicKey.pem和privateKey.pem

 @return        YES：成功导出
 */
+ (BOOL)exportPem;

/**
 导入publicKey.pem和privateKey.pem

 @return        YES：成功导入
 */
+ (BOOL)importPem;

/**
 加密数据

 @param type    选择公钥还是私钥加密
 @param padding 选择padding类型
 @param data    需要加密的数据
 @return        加密后的数据
 */
+ (NSData *)encryptWithType:(ZBKeyType)type
                paddingType:(ZBRSAPaddingType)padding
                       data:(NSData *)data;

/**
 解密数据

 @param type    选择公钥还是私钥解密
 @param padding 选择padding类型
 @param data    需要解密的数据
 @return        解密后的数据
 */
+ (NSData *)decryptWithType:(ZBKeyType)type
                paddingType:(ZBRSAPaddingType)padding
                       data:(NSData *)data;

/**
 加密数据(自定义公钥或私钥)

 @param type    选择公钥还是私钥加密
 @param padding 选择padding类型
 @param data    需要加密的数据
 @return        加密后的数据
 */
+ (NSData *)encryptByCustomType:(ZBKeyType)type
                    paddingType:(ZBRSAPaddingType)padding
                           data:(NSData *)data;

/**
 解密数据(自定义公钥或私钥)

 @param type    选择公钥还是私钥解密
 @param padding 选择padding类型
 @param data    需要解密的数据
 @return        解密后的数据
 */
+ (NSData *)decryptByCustomType:(ZBKeyType)type
                    paddingType:(ZBRSAPaddingType)padding
                           data:(NSData *)data;

@end

/**
 RSA加密

 @param aString 需要加密的字符串
 @param type    选择公钥还是私钥加密
 @param padding 选择padding类型
 @return        加密后的字符串（websafe Base64 encode and no padded）
 */
NSString * ZBRSA_encrypt(NSString *aString, ZBKeyType type, ZBRSAPaddingType padding);

/**
 RSA加密(自定义公钥或私钥)
 
 @param aString 需要加密的字符串
 @param type    选择公钥还是私钥加密
 @param padding 选择padding类型
 @return        加密后的字符串（websafe Base64 encode and no padded）
 */
NSString * ZBRSA_encrypt_custom(NSString *aString, ZBKeyType type, ZBRSAPaddingType padding);

/**
 RSA解密

 @param websafeBase64   需要解密的字符串（websafe Base64 encode and no padded）
 @param type            选择公钥还是私钥解密
 @param padding         选择padding类型
 @return                解密后的原字符串
 */
NSString * ZBRSA_decrypt(NSString *websafeBase64, ZBKeyType type, ZBRSAPaddingType padding);

/**
 RSA解密(自定义公钥或私钥)
 
 @param websafeBase64   需要解密的字符串（websafe Base64 encode and no padded）
 @param type            选择公钥还是私钥解密
 @param padding         选择padding类型
 @return                解密后的原字符串
 */
NSString * ZBRSA_decrypt_custom(NSString *websafeBase64, ZBKeyType type, ZBRSAPaddingType padding);

