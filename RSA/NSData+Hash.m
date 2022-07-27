//
//  NSData+Hash.m
//  RSA
//
//  Created by Jesus++
//

#import "NSData+Hash.h"
#import <CommonCrypto/CommonCrypto.h>

@implementation NSData (Hash)
- (NSString *)sha256String
{
	unsigned char hash[CC_SHA256_DIGEST_LENGTH];
	CC_SHA256([self bytes], (CC_LONG)[self length], hash);

	NSMutableString *ret = [NSMutableString stringWithCapacity: CC_SHA256_DIGEST_LENGTH*2];
	for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++)
	{
		[ret appendFormat: @"%02x", hash[i]];
	}
	return ret;
}

- (NSData *)md5
{
	unsigned char hash[CC_MD5_DIGEST_LENGTH];
	CC_MD5([self bytes], (CC_LONG)[self length], hash);
	return [NSData dataWithBytes: hash length: CC_MD5_DIGEST_LENGTH];
}
@end
