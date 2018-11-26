//
//  ZBHexCrypto.m
//  ZBOpenSSL
//
//  Created by 张宝 on 2018/7/9.
//  Copyright © 2018年 zb. All rights reserved.
//

#import "ZBHexCrypto.h"

@implementation ZBHexCrypto

+ (NSString *)hexString:(NSData *)d{
    if (![d isKindOfClass:[NSData class]] || d.length==0) {
        return nil;
    }
    const unsigned char *dataBuffer = (const unsigned char *)[d bytes];
    NSUInteger  dataLength = d.length;
    NSMutableString *hexString = [NSMutableString stringWithCapacity:(dataLength * 2)];
    for (int i = 0; i < dataLength; ++i)
        [hexString appendString:[NSString stringWithFormat:@"%02lx", (unsigned long)dataBuffer[i]]];
    return [NSString stringWithString:hexString];
}

+ (NSData *)dataHex:(NSString *)hex{
    if (![hex isKindOfClass:[NSString class]] || hex.length==0) {
        return nil;
    }
    if (![self isHexString:hex]) {
        return nil;
    }
    NSMutableData *hexData = [[NSMutableData alloc] initWithCapacity:20];
    NSRange range;
    if ([hex length] % 2 == 0) {
        range = NSMakeRange(0, 2);
    } else {
        range = NSMakeRange(0, 1);
    }
    for (NSInteger i = range.location; i < [hex length]; i += 2) {
        unsigned int anInt;
        NSString *hexCharStr = [hex substringWithRange:range];
        NSScanner *scanner = [[NSScanner alloc] initWithString:hexCharStr];
        [scanner scanHexInt:&anInt];
        NSData *entity = [[NSData alloc] initWithBytes:&anInt length:1];
        [hexData appendData:entity];
        range.location += range.length;
        range.length = 2;
    }
    return [NSData dataWithData:hexData];
}

+ (BOOL)isHexString:(NSString *)str{
    NSString *rexStr = @"(^[0-9A-Fa-f][0-9A-Fa-f]*$)|(^0x([0-9A-Fa-f][0-9A-Fa-f])*$)";
    NSRegularExpression *rex =
    [NSRegularExpression regularExpressionWithPattern:rexStr
                                              options:NSRegularExpressionCaseInsensitive
                                                error:nil];
    NSRange range = [rex rangeOfFirstMatchInString:str
                                           options:NSMatchingReportProgress
                                             range:NSMakeRange(0, str.length)];
    return range.location==0&&range.length==str.length;
}


@end
