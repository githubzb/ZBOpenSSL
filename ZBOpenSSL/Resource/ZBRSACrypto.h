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
    ZBRSAPaddingTypePKCS1       = RSA_PKCS1_PADDING,
    ZBRSAPaddingTypePKCS1_OAEP  = RSA_PKCS1_OAEP_PADDING
};

/**
 -----BEGIN PRIVATE KEY-----:PKCS#8
 -----BEGIN RSA PRIVATE KEY-----:PKCS#1
 参考：https://ask.helplib.com/java/post_787598
 */
typedef NS_ENUM(NSInteger, ZBPemType) {
    ZBPemTypePKCS1  = 0,
    ZBPemTypePKCS8  = 1
};

@interface ZBRSACrypto : NSObject

@property (nonatomic, readonly) NSString *publicKey;
@property (nonatomic, readonly) NSString *privateKey;
@property (class, readonly) NSString *publicKey;
@property (class, readonly) NSString *privateKey;

+ (instancetype)share;

/**
 设置自定义公钥

 @param pk      公钥字符串
 @param type    编码类型
 */
+ (void)setCustomPublicKey:(NSString *)pk pemType:(ZBPemType)type;

/**
 设置自定义私钥

 @param prk     私钥字符串
 @param type    编码类型
 */
+ (void)setCustomPrivateKey:(NSString *)prk pemType:(ZBPemType)type;

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

 @param type    编码类型
 @return        YES：成功导出
 */
+ (BOOL)exportPem:(ZBPemType)type;

/**
 导入publicKey.pem和privateKey.pem

 @param type    编码类型
 @return        YES：成功导入
 */
+ (BOOL)importPem:(ZBPemType)type;

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

#pragma mark - RSA Sign

/**
 RSA签名

 @param data    需要签名的数据
 @param custom  YES：采用自定义私钥签名
 @return        签名后的数据
 */
+ (NSData *)signBySHA128:(NSData *)data customPrivateKey:(BOOL)custom;

/**
 RSA签名

 @param data    需要签名的数据
 @param custom  YES：采用自定义私钥签名
 @return        签名后的数据
 */
+ (NSData *)signBySHA256:(NSData *)data customPrivateKey:(BOOL)custom;

/**
 RSA签名

 @param data    需要签名的数据
 @param custom  YES：采用自定义私钥签名
 @return        签名后的数据
 */
+ (NSData *)signByMD5:(NSData *)data customPrivateKey:(BOOL)custom;

/**
 RSA校验签名

 @param sign    签名数据
 @param data    原始数据
 @param custom  YES：采用自定义公钥签名
 @return        YES：签名校验通过
 */
+ (BOOL)verifySignBySHA128:(NSData *)sign
                      data:(NSData *)data
           customPublicKey:(BOOL)custom;

/**
 RSA校验签名

 @param sign    签名数据
 @param data    原始数据
 @param custom  YES：采用自定义公钥签名
 @return        YES：签名校验通过
 */
+ (BOOL)verifySignBySHA256:(NSData *)sign
                      data:(NSData *)data
           customPublicKey:(BOOL)custom;

/**
 RSA校验签名

 @param sign    签名数据
 @param data    原始数据
 @param custom  YES：采用自定义公钥签名
 @return        YES：签名校验通过
 */
+ (BOOL)verifySignByMD5:(NSData *)sign
                   data:(NSData *)data
        customPublicKey:(BOOL)custom;

@end






/**
 设置自定义RSA公钥

 @param key     公钥字符串
 @param type    编码类型
 */
void ZBRSA_CustomPUBKEY_init(NSString *key, ZBPemType type);
/**
 设置自定义RSA私钥
 
 @param key     私钥字符串
 @param type    编码类型
 */
void ZBRSA_CustomPrivate_init(NSString *key, ZBPemType type);
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

#pragma mark - RSA Sign

/**
 RSA签名

 @param message 签名原始字符串
 @return        签名后的字符串（websafe Base64 encode and no padded）
 */
NSString *ZBRSA_sign_sha128(NSString *message);
/**
 RSA签名
 
 @param message 签名原始字符串
 @return        签名后的字符串（websafe Base64 encode and no padded）
 */
NSString *ZBRSA_sign_sha256(NSString *message);
/**
 RSA签名
 
 @param message 签名原始字符串
 @return        签名后的字符串（websafe Base64 encode and no padded）
 */
NSString *ZBRSA_sign_md5(NSString *message);

/**
 RSA签名(自定义私钥)
 
 @param message 签名原始字符串
 @return        签名后的字符串（websafe Base64 encode and no padded）
 */
NSString *ZBRSA_sign_sha128_custom(NSString *message);
/**
 RSA签名(自定义私钥)
 
 @param message 签名原始字符串
 @return        签名后的字符串（websafe Base64 encode and no padded）
 */
NSString *ZBRSA_sign_sha256_custom(NSString *message);
/**
 RSA签名(自定义私钥)
 
 @param message 签名原始字符串
 @return        签名后的字符串（websafe Base64 encode and no padded）
 */
NSString *ZBRSA_sign_md5_custom(NSString *message);


/**
 RSA校验签名

 @param signWebSafeBase64   签名字符串（websafe Base64 encode and no padded）
 @param message             签名原始字符串
 @return                    YES：校验通过
 */
BOOL ZBRSA_verify_sha128(NSString *signWebSafeBase64, NSString *message);
/**
 RSA校验签名
 
 @param signWebSafeBase64   签名字符串（websafe Base64 encode and no padded）
 @param message             签名原始字符串
 @return                    YES：校验通过
 */
BOOL ZBRSA_verify_sha256(NSString *signWebSafeBase64, NSString *message);
/**
 RSA校验签名
 
 @param signWebSafeBase64   签名字符串（websafe Base64 encode and no padded）
 @param message             签名原始字符串
 @return                    YES：校验通过
 */
BOOL ZBRSA_verify_md5(NSString *signWebSafeBase64, NSString *message);


/**
 RSA校验签名(自定义公钥)
 
 @param signWebSafeBase64   签名字符串（websafe Base64 encode and no padded）
 @param message             签名原始字符串
 @return                    YES：校验通过
 */
BOOL ZBRSA_verify_sha128_custom(NSString *signWebSafeBase64, NSString *message);
/**
 RSA校验签名(自定义公钥)
 
 @param signWebSafeBase64   签名字符串（websafe Base64 encode and no padded）
 @param message             签名原始字符串
 @return                    YES：校验通过
 */
BOOL ZBRSA_verify_sha256_custom(NSString *signWebSafeBase64, NSString *message);
/**
 RSA校验签名(自定义公钥)
 
 @param signWebSafeBase64   签名字符串（websafe Base64 encode and no padded）
 @param message             签名原始字符串
 @return                    YES：校验通过
 */
BOOL ZBRSA_verify_md5_custom(NSString *signWebSafeBase64, NSString *message);

