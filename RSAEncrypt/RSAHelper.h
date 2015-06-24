//
//  RSAHelper.h
//  OpenWiFi
//
//  Created by LuoShihui on 15/6/15.
//  Copyright (c) 2015年 WiFi-Tech. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>

@interface RSAHelper : NSObject

+ (SecKeyRef)addPublicKey:(NSString *)key;

+ (NSString *)encryptString:(NSString *)str publicKeyRef:(SecKeyRef)pubKey;

+ (NSString *)decryptString:(NSString *)str publicKeyRef:(SecKeyRef)pubKey;
@end
