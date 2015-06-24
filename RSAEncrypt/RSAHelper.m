//
//  RSAHelper.m
//  OpenWiFi
//
//  Created by LuoShihui on 15/6/15.
//  Copyright (c) 2015年 WiFi-Tech. All rights reserved.
//

#import "RSAHelper.h"
#import "GTMBase64.h"

#define String_Block_Size  86.0
#define Data_Block_Size  128.0

@implementation RSAHelper

static NSString *base64_encode_data(NSData *data) {
	data = [data base64EncodedDataWithOptions:0];
	NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
	return ret;
}

static NSData *base64_decode(NSString *str) {
	NSData *data = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
	return data;
}

/**
 *  公共方法: 使用公钥加密字符串
 *
 *  @param str    待加密明文
 *  @param pubKey 公钥类
 *
 *  @return 密文
 */
+ (NSString *)encryptString:(NSString *)str publicKeyRef:(SecKeyRef)pubKey {
	NSMutableData *data = [[NSMutableData alloc] initWithCapacity:0];
	NSInteger totalLength = str.length;
	if (totalLength > 0) {
		double test = ceilf(totalLength / String_Block_Size);
		for (int i = 0; i < test; i++) {
			NSString *subStr = @"";
			if (i == test - 1) {
				subStr = [str substringFromIndex:i * String_Block_Size];
			}
			else {
				subStr = [str substringWithRange:NSMakeRange(i * String_Block_Size, String_Block_Size)];
			}

			NSData *subData = [RSAHelper encrypt:subStr publicKeyRef:pubKey];
			[data appendData:subData];
		}
	}

	return base64_encode_data(data);
}

/**
 *  公共方法: 解析公钥串
 *
 *  @param key 公钥串
 *
 *  @return 公钥类
 */
+ (SecKeyRef)addPublicKey:(NSString *)key {
	NSRange spos = [key rangeOfString:@"-----BEGIN PUBLIC KEY-----"];
	NSRange epos = [key rangeOfString:@"-----END PUBLIC KEY-----"];
	if (spos.location != NSNotFound && epos.location != NSNotFound) {
		NSUInteger s = spos.location + spos.length;
		NSUInteger e = epos.location;
		NSRange range = NSMakeRange(s, e - s);
		key = [key substringWithRange:range];
	}

	key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
	key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
	key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
	key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];

	// This will be base64 encoded, decode it.
	NSData *data = base64_decode(key);
	data = [RSAHelper stripPublicKeyHeader:data];
	if (!data) {
		return nil;
	}

	NSString *tag = @"what_the_fuck_is_this";
	NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];

	// Delete any old lingering key with the same tag
	NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
	[publicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
	[publicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	[publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
	SecItemDelete((__bridge CFDictionaryRef)publicKey);

	// Add persistent version of the key to system keychain
	[publicKey setObject:data forKey:(__bridge id)kSecValueData];
	[publicKey setObject:(__bridge id)kSecAttrKeyClassPublic forKey:(__bridge id)
	 kSecAttrKeyClass];
	[publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)
	 kSecReturnPersistentRef];

	CFTypeRef persistKey = nil;
	OSStatus status = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistKey);
	if (persistKey != nil) {
		CFRelease(persistKey);
	}
	if ((status != noErr) && (status != errSecDuplicateItem)) {
		return nil;
	}

	[publicKey removeObjectForKey:(__bridge id)kSecValueData];
	[publicKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
	[publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
	[publicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];

	// Now fetch the SecKeyRef version of the key
	SecKeyRef keyRef = nil;
	status = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&keyRef);
	if (status != noErr) {
		return nil;
	}
	return keyRef;
}

/**
 *  私有方法: 解析公钥
 *
 *  @param d_key key转data
 *
 *  @return 格式化后的key data
 */
+ (NSData *)stripPublicKeyHeader:(NSData *)d_key {
	// Skip ASN.1 public key header
	if (d_key == nil) return(nil);

	unsigned long len = [d_key length];
	if (!len) return(nil);

	unsigned char *c_key = (unsigned char *)[d_key bytes];
	unsigned int idx    = 0;

	if (c_key[idx++] != 0x30) return(nil);

	if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
	else idx++;

	// PKCS #1 rsaEncryption szOID_RSA_RSA
	static unsigned char seqiod[] =
	{ 0x30,   0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
	  0x01, 0x05, 0x00 };
	if (memcmp(&c_key[idx], seqiod, 15)) return(nil);

	idx += 15;

	if (c_key[idx++] != 0x03) return(nil);

	if (c_key[idx] > 0x80) idx += c_key[idx] - 0x80 + 1;
	else idx++;

	if (c_key[idx++] != '\0') return(nil);

	// Now make a new NSData from this buffer
	return([NSData dataWithBytes:&c_key[idx] length:len - idx]);
}

/**
 *  私有方法: 使用公钥加密data
 *
 *  @param data   明文转data
 *  @param pubKey 公钥类
 *
 *  @return 加密后字符串
 */
+ (NSData *)encrypt:(NSString *)str publicKeyRef:(SecKeyRef)pubKey {
	if (!str || !pubKey) {
		return nil;
	}
	NSData *data = [str dataUsingEncoding:NSUTF8StringEncoding];
	const uint8_t *srcbuf = (const uint8_t *)[data bytes];
	size_t srclen = (size_t)data.length;

	size_t outlen = SecKeyGetBlockSize(pubKey) * sizeof(uint8_t);
	if (srclen > outlen - 42) {
		return nil;
	}
	void *outbuf = malloc(outlen);

	OSStatus status = noErr;
	status = SecKeyEncrypt(pubKey,
	                       kSecPaddingOAEP,
	                       srcbuf,
	                       srclen,
	                       outbuf,
	                       &outlen
	                       );
	NSData *encryptData = nil;
	if (status != 0) {
		NSLog(@"SecKeyEncrypt fail. Error Code: %d", status);
	}
	else {
		encryptData = [NSData dataWithBytes:outbuf length:outlen];
	}
	free(outbuf);
	return encryptData;
}

/**
 *  公共方法: 解密
 *
 *  @param str    密文
 *  @param pubKey 公钥
 *
 *  @return
 */
+ (NSString *)decryptString:(NSString *)str publicKeyRef:(SecKeyRef)pubKey {
	if (!str || !pubKey) {
		return nil;
	}
	NSMutableString *decryptString = [NSMutableString stringWithCapacity:0];
	NSData *data = base64_decode(str);
    size_t blockSize = SecKeyGetBlockSize(pubKey);
    
	double totalLength = data.length;
	if (totalLength > 0) {
		double test = ceilf(totalLength / blockSize);
		for (int i = 0; i < test; i++) {
			NSData *subData;
			if (i == test - 1) {
				subData = [data subdataWithRange:NSMakeRange(i * blockSize, totalLength - i * blockSize)];
			}
			else {
				subData = [data subdataWithRange:NSMakeRange(i * blockSize, blockSize)];
			}

			NSString *subDecryptStr = [RSAHelper decrypt:subData publicKeyRef:pubKey];
			[decryptString appendString:subDecryptStr];
		}
	}

	return decryptString;
}

/**
 *  私有方法: 使用公钥解密Data
 *
 *  @param data   解密Data
 *  @param pubKey 公钥
 *
 *  @return
 */
+ (NSString *)decrypt:(NSData *)data publicKeyRef:(SecKeyRef)pubKey {
	if (!data || !pubKey) {
		return nil;
	}
    
    size_t cipherBufferSize = SecKeyGetBlockSize(pubKey);
    size_t plainBufferSize = data.length;
    
    uint8_t *plainBuffer = calloc(1, data.length);
//    NSMutableData *bits = [NSMutableData dataWithLength:plainBufferSize];
	OSStatus status = noErr;
	status = SecKeyDecrypt(pubKey,
	                       kSecPaddingOAEP,
	                       [data bytes],
	                       data.length,
	                       plainBuffer,
	                       &plainBufferSize
	                       );
	NSString *decryptString = @"";
	if (status != errSecSuccess) {
		NSLog(@"SecKeyDecrypt fail. Error Code: %zd", status);
	}
	else {
//		decryptString = [[NSString alloc] initWithData:bits encoding:NSASCIIStringEncoding];
	}
//	free(plainBuffer);
	return decryptString;
}

@end
