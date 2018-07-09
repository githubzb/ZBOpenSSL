//
//  AppDelegate.m
//  ZBOpenSSL
//
//  Created by 张宝 on 2018/6/29.
//  Copyright © 2018年 zb. All rights reserved.
//

#import "AppDelegate.h"
#import "ZBRSACrypto.h"

@interface AppDelegate ()

@end

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    
    NSString *str = @"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
//    NSString *encodeStr = ZBRSA_encrypt(str, ZBKeyTypePublic, ZBRSAPaddingTypePKCS1);
//    NSLog(@"--------加密数据:%@", encodeStr);
//    NSString *decodeStr = ZBRSA_decrypt(encodeStr, ZBKeyTypePrivate, ZBRSAPaddingTypePKCS1);
//    NSLog(@"--------解密数据:%@", decodeStr);
    
    ZBRSA_CustomPUBKEY_init(ZBRSACrypto.publicKey, ZBPemTypePKCS8);
    ZBRSA_CustomPrivate_init(ZBRSACrypto.privateKey, ZBPemTypePKCS8);

//    NSString *encodeStr = ZBRSA_encrypt_custom(str, ZBKeyTypePublic, ZBRSAPaddingTypePKCS1);
//    NSLog(@"--------加密数据:%@", encodeStr);
//    NSString *decodeStr = ZBRSA_decrypt_custom(encodeStr, ZBKeyTypePrivate, ZBRSAPaddingTypePKCS1);
//    NSLog(@"--------解密数据:%@", decodeStr);
    
    NSString *sign = ZBRSA_sign_sha128_custom(str);
    NSLog(@"------sign:%@", sign);
    if (ZBRSA_verify_sha128_custom(sign, str)) {
        NSLog(@"----校验通过");
    }else{
        NSLog(@"----未通过");
    }
    
    return YES;
}



@end
