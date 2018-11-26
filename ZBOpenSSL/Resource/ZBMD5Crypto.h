//
//  ZBMD5Crypto.h
//  ZBOpenSSL
//
//  Created by 张宝 on 2018/7/9.
//  Copyright © 2018年 zb. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface ZBMD5Crypto : NSObject

+ (NSData *)md5:(NSData *)d;

@end

/**
 openssl MD5加密

 @param str 需要加密的字符串
 @return    加密后的字符串
 */
NSString * ZBMD5(NSString *str);
