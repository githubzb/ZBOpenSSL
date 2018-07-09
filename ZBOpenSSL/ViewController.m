//
//  ViewController.m
//  ZBOpenSSL
//
//  Created by 张宝 on 2018/6/29.
//  Copyright © 2018年 zb. All rights reserved.
//

#import "ViewController.h"
#import "ZBAESCrypto.h"
#import <GTMBase64/GTMBase64.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    NSString *key = @"aaaaaaaaaaaaaaaa";
    NSString *sss = @"123";
    NSData *sssData = [sss dataUsingEncoding:NSUTF8StringEncoding];
    NSData *d = [ZBAESCrypto encrypt:sssData type:EVP_aes_192_ecb() password:key];
    
    NSString *s = [GTMBase64 stringByEncodingData:d];
    NSLog(@"------d:%@", s);
    
    NSData *data = [ZBAESCrypto decrypt:d type:EVP_aes_192_ecb() password:key];
    NSString *str = [[NSString alloc] initWithData:data
                                          encoding:NSUTF8StringEncoding];
    NSLog(@"------:%@", str);
    
}


@end
