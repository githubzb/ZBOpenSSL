//
//  ZBHexCrypto.h
//  ZBOpenSSL
//
//  Created by 张宝 on 2018/7/9.
//  Copyright © 2018年 zb. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ZBHexCrypto : NSObject

+ (NSString *)hexString:(NSData *)d;
+ (NSData *)dataHex:(NSString *)hex;
+ (BOOL)isHexString:(NSString *)str;

@end
