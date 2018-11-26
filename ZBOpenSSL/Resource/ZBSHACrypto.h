//
//  ZBSHACrypto.h
//  ZBOpenSSL
//
//  Created by 张宝 on 2018/7/10.
//  Copyright © 2018年 zb. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ZBSHACrypto : NSObject

+ (NSData *)sha:(NSData *)d;
+ (NSData *)sha1:(NSData *)d;
+ (NSData *)sha224:(NSData *)d;
+ (NSData *)sha256:(NSData *)d;
+ (NSData *)sha384:(NSData *)d;
+ (NSData *)sha512:(NSData *)d;

@end

NSString * ZBSha(NSString *str);
NSString * ZBSha1(NSString *str);
NSString * ZBSha224(NSString *str);
NSString * ZBSha256(NSString *str);
NSString * ZBSha384(NSString *str);
NSString * ZBSha512(NSString *str);

