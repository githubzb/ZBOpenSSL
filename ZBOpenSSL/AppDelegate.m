//
//  AppDelegate.m
//  ZBOpenSSL
//
//  Created by 张宝 on 2018/6/29.
//  Copyright © 2018年 zb. All rights reserved.
//

#import "AppDelegate.h"
#import "ZBRSACrypto.h"
#import "ZBMD5Crypto.h"
#import "ZBHexCrypto.h"
#import "ZBSHACrypto.h"
#import "ZBHmacCrypto.h"
#import "ZBAESCrypto.h"
#import <GTMBase64/GTMBase64.h>

@interface AppDelegate ()

@end

@implementation AppDelegate


- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    
    NSString *str = @"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    NSString *encodeStr = ZBRSA_encrypt(str, ZBKeyTypePublic, ZBRSAPaddingTypePKCS1);
    NSLog(@"--------加密数据:%@", encodeStr);
    NSString *decodeStr = ZBRSA_decrypt(encodeStr, ZBKeyTypePrivate, ZBRSAPaddingTypePKCS1);
    NSLog(@"--------解密数据:%@", decodeStr);
    
//    ZBRSA_CustomPUBKEY_init(ZBRSACrypto.publicKey, ZBPemTypePKCS8);
//    ZBRSA_CustomPrivate_init(ZBRSACrypto.privateKey, ZBPemTypePKCS8);

//    NSString *encodeStr = ZBRSA_encrypt_custom(str, ZBKeyTypePublic, ZBRSAPaddingTypePKCS1);
//    NSLog(@"--------加密数据:%@", encodeStr);
//    NSString *decodeStr = ZBRSA_decrypt_custom(encodeStr, ZBKeyTypePrivate, ZBRSAPaddingTypePKCS1);
//    NSLog(@"--------解密数据:%@", decodeStr);
    
//    NSString *sign = ZBRSA_sign_sha128_custom(str);
//    NSLog(@"------sign:%@", sign);
//    if (ZBRSA_verify_sha128_custom(sign, str)) {
//        NSLog(@"----校验通过");
//    }else{
//        NSLog(@"----未通过");
//    }
    
//    NSString *s = @"zzzbcbcbcbdddjdjfjdjdjdjjdjdjdjdj";
//    NSString *sha = ZBSha(s);
//    NSLog(@"-------sha:%@", sha);
//    NSString *sha1 = ZBSha1(s);
//    NSLog(@"-----sha1:%@", sha1);
//    NSString *sha224 = ZBSha224(s);
//    NSLog(@"\n\n-----sha224:%@", sha224);
//    NSString *sha256 = ZBSha256(s);
//    NSLog(@"\n\n-----sha256:%@", sha256);
//    NSString *sha384 = ZBSha384(s);
//    NSLog(@"\n\n-----sha384:%@", sha384);
//
//    NSString *sha512 = ZBSha512(s);
//    NSLog(@"\n\n-----sha512:%@", sha512);
    
//    NSString *pwd = @"aaaaaaaaaaaaaaaaaaaaaaaa122";
    
//    NSString *hmacsha = ZBHmacSHA(s, pwd);
//    NSLog(@"\n\n-----hmacsha:%@", hmacsha);
    
//    NSString *hmacsha1 = ZBHmacSHA1(s, pwd);
//    NSLog(@"-----hmacsha1:%@", hmacsha1);
    
//    NSString *hmacsha224 = ZBHmacSHA224(s, pwd);
//    NSLog(@"\n\n-----hmacsha224:%@", hmacsha224);
    
//    NSString *hmacsha256 = ZBHmacSHA256(s, pwd);
//    NSLog(@"\n\n-----hmacsha256:%@", hmacsha256);
    
//    NSString *hmacsha384 = ZBHmacSHA384(s, pwd);
//    NSLog(@"\n\n-----hmacsha384:%@", hmacsha384);
    
//    NSString *hmacsha512 = ZBHmacSHA512(s, pwd);
//    NSLog(@"\n\n-----hmacsha512:%@", hmacsha512);
    
//    NSString *hmacMD5 = ZBHmacMD5(s, pwd);
//    NSLog(@"\n\n-----hmacMD5:%@", hmacMD5);
    [self testAes];
    return YES;
}



- (void)testAes{
    
    NSData *data = [@"aaaaaaaaaaaaaaaa" dataUsingEncoding:NSUTF8StringEncoding];
    NSData *key = [ZBAESCrypto generateKey:ZBAESKeySize128 error:nil];
    NSLog(@"-------key:%@", [ZBHexCrypto hexString:key]);
    NSData *iv = [ZBAESCrypto generateIV];
    NSLog(@"--------iv:%@", [ZBHexCrypto hexString:iv]);
    NSData *r = [ZBAESCrypto encrypt_mode:ZBAESModeCBC
                                     data:data
                                      key:key
                                  keySize:ZBAESKeySize128
                                       iv:iv
                                    error:nil];
    
    NSData *rd = [GTMBase64 webSafeEncodeData:r padded:YES];
    NSString *str = [GTMBase64 stringByWebSafeEncodingData:rd padded:YES];
    NSLog(@"----加密数据：%@", str);
    
    NSData *tD = [ZBAESCrypto decrypt_mode:ZBAESModeCBC
                                      data:r
                                       key:key
                                   keySize:ZBAESKeySize128
                                        iv:iv
                                     error:nil];
    NSString *ss = [[NSString alloc] initWithData:tD encoding:NSUTF8StringEncoding];
    NSLog(@"----解密数据：%@", ss);
    
    if (data.length==tD.length) {
        NSLog(@"----aes解密成功");
    }else{
        NSLog(@"----aes解密失败");
    }
}


@end
