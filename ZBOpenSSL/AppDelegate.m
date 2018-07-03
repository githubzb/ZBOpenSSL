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
    
    NSString *str = @"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
//    NSString *encodeStr = ZBRSA_encrypt(str, ZBKeyTypePublic, ZBRSAPaddingTypePKCS1);
//    NSLog(@"--------加密数据:%@", encodeStr);
//    NSString *decodeStr = ZBRSA_decrypt(encodeStr, ZBKeyTypePrivate, ZBRSAPaddingTypePKCS1);
//    NSLog(@"--------解密数据:%@", decodeStr);
    
    [ZBRSACrypto setCustomPublicKey:ZBRSACrypto.publicKey];
    [ZBRSACrypto setCustomPrivateKey:ZBRSACrypto.privateKey];
    
    NSString *encodeStr = ZBRSA_encrypt_custom(str, ZBKeyTypePublic, ZBRSAPaddingTypePKCS1);
    NSLog(@"--------加密数据:%@", encodeStr);
    NSString *decodeStr = ZBRSA_decrypt_custom(encodeStr, ZBKeyTypePrivate, ZBRSAPaddingTypePKCS1);
    NSLog(@"--------解密数据:%@", decodeStr);
    
    return YES;
}



@end
