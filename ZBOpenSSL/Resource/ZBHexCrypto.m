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
    NSString *hexStr = [hex stringByReplacingOccurrencesOfString:@" " withString:@""];
    hexStr = [hexStr lowercaseString];
    NSUInteger len = hexStr.length;
    if (!len) return nil;
    unichar *buf = malloc(sizeof(unichar) * len);
    if (!buf) return nil;
    [hexStr getCharacters:buf range:NSMakeRange(0, len)];
    
    NSMutableData *result = [NSMutableData data];
    unsigned char bytes;
    char str[3] = { '\0', '\0', '\0' };
    int i;
    for (i = 0; i < len / 2; i++) {
        str[0] = buf[i * 2];
        str[1] = buf[i * 2 + 1];
        bytes = strtol(str, NULL, 16);
        [result appendBytes:&bytes length:1];
    }
    free(buf);
    return [NSData dataWithData:result];
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
