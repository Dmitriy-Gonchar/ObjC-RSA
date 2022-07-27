//
//  RSAKey.h
//  RSA
//
//  Created by Jesus++
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class RSAKey;

@interface RSAKeyPair : NSObject
@property RSAKey *private, *public;
- (NSData *)tag;
+ (nullable RSAKeyPair *)fromTag: (NSData *)tag;
@end

@interface RSAKey : NSObject
@property BOOL isPrivate;
@property BOOL isPublic;
@property long size;
@property NSData *tag;

- (NSString *)pem;
- (SecKeyRef)secKey;
- (NSData *)encrypt: (NSData *)data;
- (NSData *)decrypt: (NSData *)data;
- (NSData *)binary;
- (nullable instancetype)initWithData: (NSData *)data;
- (nullable instancetype)initWithPEM: (NSString *)pem;
- (nullable instancetype)initWithTag: (NSData *)tag;
- (instancetype)initWithSecKey: (SecKeyRef)key;
+ (BOOL)containInKeyChainPem: (NSString *)pem;
+ (RSAKeyPair *)generateKeyPairWithSize: (long)size;

//+ (SecKeyRef)getSecKeyFromKeyChainIfExist: (NSString *)pem;
@end

NS_ASSUME_NONNULL_END
