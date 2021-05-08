//
//  ZBHmacCrypto.h
//  ZBOpenSSL
//
//  Created by 张宝 on 2018/7/10.
//  Copyright © 2018年 zb. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ZBHmacCrypto : NSObject

+ (NSData *)hmacSHA1:(NSData *)d password:(NSString *)pwd;
+ (NSData *)hmacSHA224:(NSData *)d password:(NSString *)pwd;
+ (NSData *)hmacSHA256:(NSData *)d password:(NSString *)pwd;
+ (NSData *)hmacSHA384:(NSData *)d password:(NSString *)pwd;
+ (NSData *)hmacSHA512:(NSData *)d password:(NSString *)pwd;
+ (NSData *)hmacMD5:(NSData *)d password:(NSString *)pwd;

@end

NSString * ZBHmacSHA1(NSString *str, NSString *pwd);
NSString * ZBHmacSHA224(NSString *str, NSString *pwd);
NSString * ZBHmacSHA256(NSString *str, NSString *pwd);
NSString * ZBHmacSHA384(NSString *str, NSString *pwd);
NSString * ZBHmacSHA512(NSString *str, NSString *pwd);
NSString * ZBHmacMD5(NSString *str, NSString *pwd);

