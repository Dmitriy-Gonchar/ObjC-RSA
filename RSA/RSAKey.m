//
//  RSAKey.m
//  RSA
//
//  Created by Jesus++
//

#import "RSAKey.h"
#import "NSData+Hash.h"

#define let const __auto_type

@interface RSAKey ()
@property SecKeyRef __secKey;
@end

@implementation RSAKeyPair
- (NSData *)tag
{
	let md = NSMutableData.new;
	[md appendData: self.private.tag];
	[md appendData: self.public.tag];
	return md;
}

+ (nullable RSAKeyPair *)fromTag: (NSData *)tag
{
	if (tag.length != 32)
	{
		return nil;
	}
	let priT = [tag subdataWithRange: (NSRange){0, 16}];
	let pubT = [tag subdataWithRange: (NSRange){16, 16}];
	let private = [RSAKey.alloc initWithTag: priT];
	let public = [RSAKey.alloc initWithTag: pubT];
	RSAKeyPair *kp = [RSAKeyPair new];
	kp.private = private;
	kp.public = public;

	return private && public ? kp : nil;
}
@end

@implementation RSAKey

+ (SecKeyRef)secKeyFromTag: (NSData *)tag
{
	OSStatus sanityCheck = noErr;
	CFTypeRef secKey = NULL;

	let query = @{(__bridge id)kSecClass: (__bridge id)kSecClassKey,
				  (__bridge id)kSecAttrApplicationTag: tag,
				  (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
				  (__bridge id)kSecReturnRef: @YES};

	// Get the key bits.
	sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&secKey);

	if (sanityCheck != noErr)
	{
		secKey = NULL;
	}

	return (SecKeyRef)secKey;
}

+ (NSData *)dataSecKeyFromTag: (NSData *)tag
{
	OSStatus sanityCheck = noErr;
	CFTypeRef secKey = NULL;

	let query = @{(__bridge id)kSecClass: (__bridge id)kSecClassKey,
				  (__bridge id)kSecAttrApplicationTag: tag,
				  (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA,
				  (__bridge id)kSecReturnData: @YES};

	// Get the key bits.
	sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&secKey);

	if (sanityCheck != noErr)
	{
		secKey = NULL;
	}

	return (__bridge NSData *)secKey;
}

+ (NSString *)stripPEM: (NSString *)keyString
{
	NSError *error = nil;
	NSString *pattern = @"-{5}.*-{5}\n*";
	NSRegularExpression *regex = [NSRegularExpression regularExpressionWithPattern: pattern
																		   options: NSRegularExpressionCaseInsensitive
																			 error: &error];
	let pem = [regex stringByReplacingMatchesInString: keyString
											  options: 0
												range: NSMakeRange(0, keyString.length)
										 withTemplate: @""];
	return [pem stringByReplacingOccurrencesOfString: @"\n" withString: @""];
}

+ (NSString *)pemWithTag: (NSData *)tag
{
	NSData *keyBits = [self dataSecKeyFromTag: tag];
	static const unsigned char _encodedRSAEncryptionOID[15] =
	{
		/* Sequence of length 0xd made up of OID followed by NULL */
		0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
		0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
	};

	unsigned char builder[15];
	NSMutableData *encKey = NSMutableData.new;
	int bitstringEncLength;

	// When we get to the bitstring - how will we encode it?

	if  ([keyBits length ] + 1 < 128 )
		bitstringEncLength = 1;
	else
		bitstringEncLength = (int)(([keyBits length] + 1) / 256) + 2;

	// Overall we have a sequence of a certain length
	builder[0] = 0x30;    // ASN.1 encoding representing a SEQUENCE
	// Build up overall size made up of -
	// size of OID + size of bitstring encoding + size of actual key
	size_t i = sizeof(_encodedRSAEncryptionOID) + 2 + bitstringEncLength +
			   [keyBits length];
	size_t j = encodeLength(&builder[1], i);
	[encKey appendBytes: builder
				 length: j + 1];

	// First part of the sequence is the OID
	[encKey appendBytes: _encodedRSAEncryptionOID
				 length: sizeof(_encodedRSAEncryptionOID)];

	// Now add the bitstring
	builder[0] = 0x03;
	j = encodeLength(&builder[1], [keyBits length] + 1);
	builder[j + 1] = 0x00;
	[encKey appendBytes: builder
				 length: j + 2];

	// Now the actual key
	[encKey appendData: keyBits];

	// base64 encode encKey and return
	return [encKey base64EncodedStringWithOptions: 0];
}

- (NSString *)pem
{
	return [RSAKey pemWithTag: self.tag];
}

- (SecKeyRef)secKey
{
	if (!self.__secKey && self.tag)
	{
		self.__secKey = [RSAKey secKeyFromTag: self.tag];
	}
	return self.__secKey;
}

- (NSData *)encrypt: (NSData *)data
{
	let secKey = self.secKey;
	size_t cipherBufferSize = SecKeyGetBlockSize(secKey);
	uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
	memset((void *)cipherBuffer, 0*0, cipherBufferSize);

	NSData *plainTextBytes = data;
	size_t blockSize = cipherBufferSize - 11;
	size_t blockCount = (size_t)ceil([plainTextBytes length] / (double)blockSize);
	NSMutableData *encryptedData = [NSMutableData dataWithCapacity: 0];

	for (int i = 0; i < blockCount; ++i)
	{
		int bufferSize = (int)MIN(blockSize,[plainTextBytes length] - i * blockSize);
		NSData *buffer = [plainTextBytes subdataWithRange: NSMakeRange(i * blockSize, bufferSize)];

		OSStatus status = SecKeyEncrypt(secKey,
										kSecPaddingPKCS1,
										(const uint8_t *)[buffer bytes],
										[buffer length],
										cipherBuffer,
										&cipherBufferSize);

		if (status == noErr)
		{
			NSData *encryptedBytes = [NSData dataWithBytes: (const void *)cipherBuffer
													length: cipherBufferSize];
			[encryptedData appendData: encryptedBytes];
		}
		else
		{
			if (cipherBuffer)
			{
				free(cipherBuffer);
			}
			return nil;
		}
	}
	if (cipherBuffer)
		free(cipherBuffer);

	return encryptedData;
}

- (NSData *)decrypt: (NSData *)data
{
	let secKey = self.secKey;
	size_t cipherBufferSize = SecKeyGetBlockSize(secKey);
	size_t keyBufferSize = data.length;

	NSMutableData *result = NSMutableData.new;

	if (!secKey ||
		!cipherBufferSize ||
		!keyBufferSize ||
		!result)
	{
		return nil;
	}

	long iCount = data.length / cipherBufferSize;

	for (long index = 0; index < iCount; ++index)
	{
		long i = index * cipherBufferSize;
		NSData *subData = [data subdataWithRange: NSMakeRange(i, cipherBufferSize)];
		CFErrorRef err = nil;
		NSData *decryptedSubData = CFBridgingRelease(SecKeyCreateDecryptedData(secKey,
																			   kSecKeyAlgorithmRSAEncryptionPKCS1,
																			   (CFDataRef)subData,
																			   &err));
		if (err)
		{
			return nil;
		}
		[result appendData: decryptedSubData];
	}

	return result;
}

- (nullable instancetype)initWithData: (NSData *)data
{
	self = [self initWithPEM: [data base64EncodedStringWithOptions: 0]];
	return self;
}

- (NSData *)binary
{
	return [NSData.alloc initWithBase64EncodedString: self.pem options: 0];
}

- (instancetype)initWithSecKey: (SecKeyRef)key
{
	self = [super init];

	self.__secKey = key;
	NSDictionary *attr = CFBridgingRelease(SecKeyCopyAttributes(key));
	self.tag = attr[(__bridge id)kSecAttrApplicationTag];
	if (!self.tag)
	{
		self.tag = attr[(__bridge id)kSecAttrApplicationLabel];
	}
	self.size = [attr[(__bridge id)(kSecAttrKeySizeInBits)] longValue];

	switch ([attr[(__bridge id)kSecAttrKeyClass] intValue])
	{
		case 0:
			self.isPublic = YES;
			self.isPrivate = NO;
			break;
		case 1:
			self.isPublic = NO;
			self.isPrivate = YES;
			break;
	}
	return self;
}

+ (CFDictionaryRef)queryForClass: (CFStringRef)class tag: (id)tag type: (CFStringRef)type
{
	class = class ? class : kSecClassKey;
	type = type ? type : kSecAttrKeyTypeRSA;
	let dict = @{(__bridge id)kSecClass: (__bridge id)class,
				 (__bridge id)kSecAttrApplicationTag: tag,
				 (__bridge id)kSecAttrKeyType: (__bridge id)type,
				 (__bridge id)kSecReturnRef: @YES
	};

	return CFBridgingRetain(dict);
}

+ (CFDictionaryRef)queryForRSAKeyWithTag: (id)tag
{
	return [self queryForClass:kSecClassKey tag: tag type: kSecAttrKeyTypeRSA];
}

+ (CFDictionaryRef)parametersForKeyPairGeneratorSize: (long)keySize
{
	let date = NSDate.date;

	NSString *tagPriv = [NSJSONSerialization dataWithJSONObject: @{@"date": date.description,
																 @"add": @(date.hash),
																 @"type": @"pr"}
														options: 0
														  error: nil].sha256String;
	NSString *tagPub = [NSJSONSerialization dataWithJSONObject: @{@"date": date.description,
																@"add": @(date.hash),
																@"type": @"pu"}
													   options: 0
														 error: nil].sha256String;

	let privateAttributes = @{(__bridge id)kSecAttrIsPermanent: @YES,
							  (__bridge id)(kSecAttrKeyType): (__bridge id)kSecAttrKeyTypeRSA,
							  (__bridge id)kSecClass: (__bridge id)kSecClassKey,
							  (__bridge id)kSecAttrApplicationTag: tagPriv};
	let publicAttributes = @{(__bridge id)kSecAttrIsPermanent: @YES,
							 (__bridge id)(kSecAttrKeyType): (__bridge id)kSecAttrKeyTypeRSA,
							 (__bridge id)kSecClass: (__bridge id)kSecClassKey,
							 (__bridge id)(kSecAttrApplicationTag): tagPub};
	let pairAttributes = @{(__bridge id)(kSecAttrKeyType): (__bridge id)kSecAttrKeyTypeRSA,
						   (__bridge id)(kSecAttrKeySizeInBits): @(keySize),
						   (__bridge id)(kSecPublicKeyAttrs): publicAttributes,
						   (__bridge id)(kSecPrivateKeyAttrs): privateAttributes};

	return CFBridgingRetain(pairAttributes);
}

+ (id)privateTagFromGenaratorParams: (CFDictionaryRef)params
{
	NSDictionary *dict = (__bridge NSDictionary *)params;
	return dict[(__bridge id)(kSecPrivateKeyAttrs)][(__bridge id)kSecAttrApplicationTag];
}

+ (id)publicTagFromGenaratorParams: (CFDictionaryRef)params
{
	NSDictionary *dict = (__bridge NSDictionary *)params;
	return dict[(__bridge id)(kSecPublicKeyAttrs)][(__bridge id)kSecAttrApplicationTag];
}

+ (RSAKeyPair *)generateKeyPairWithSize: (long)keySize
{
	RSAKeyPair *pair = RSAKeyPair.new;

	SecKeyRef public = NULL;
	SecKeyRef private = NULL;

	let params = [self parametersForKeyPairGeneratorSize: keySize];
	id tagPriv = [self privateTagFromGenaratorParams: params];
	id tagPub = [self publicTagFromGenaratorParams: params];

	let status = SecKeyGeneratePair(params, &public, &private);
	CFRelease(params);

	let privateTag = [[[RSAKey pemWithTag: tagPriv] dataUsingEncoding: NSUTF8StringEncoding] md5];
	NSDictionary *query = @{(__bridge id)kSecAttrApplicationTag: tagPriv,
							(__bridge id)kSecClass: (__bridge id)kSecClassKey};

	OSStatus privateUpdateStatus = SecItemUpdate((CFDictionaryRef)query,
												 (CFDictionaryRef)@{(__bridge id)kSecAttrApplicationTag: privateTag});

	let publicTag = [[[RSAKey pemWithTag: tagPub] dataUsingEncoding: NSUTF8StringEncoding] md5];
	query = @{(__bridge id)kSecAttrApplicationTag: tagPub,
			  (__bridge id)kSecClass: (__bridge id)kSecClassKey};

	OSStatus publicUpdateStatus = SecItemUpdate((CFDictionaryRef)query,
												(CFDictionaryRef)@{(__bridge id)kSecAttrApplicationTag: publicTag});

	if (privateUpdateStatus || publicUpdateStatus)
	{
		return nil;
	}

	if (public && private && !status)
	{
		pair.private = [RSAKey.alloc initWithSecKey: private];
		pair.private.tag = privateTag;
		pair.public = [RSAKey.alloc initWithSecKey: public];
		pair.public.tag = publicTag;
	}

	return pair;
}

- (nullable instancetype)initWithTag: (NSData *)tag
{
	self.tag = tag;
	self.__secKey = [self.class secKeyFromTag: self.tag];
	let dict = ((__bridge NSDictionary *)SecKeyCopyAttributes(self.__secKey));
	self.size = [dict[(__bridge id)kSecAttrKeySizeInBits] longValue];
	self.isPublic = [dict[(__bridge id)kSecAttrKeyClassPublic] boolValue];
	self.isPrivate = [dict[(__bridge id)kSecAttrKeyClassPrivate] boolValue];

	if (self.__secKey)
	{
		return self;
	}
	else
	{
		return nil;
	}
}

- (nullable instancetype)initWithPEM: (NSString *)pem
{
	pem = [RSAKey stripPEM: pem];
	NSData *extractedKey = [NSData.alloc initWithBase64EncodedString: pem
															 options: 0];

	/* Load as a key ref */
	OSStatus error = noErr;
	CFTypeRef persistPeer = NULL;
	SecKeyRef secKey = [RSAKey getSecKeyFromKeyChainIfExist: pem];

	NSData *refTag = [[pem dataUsingEncoding: NSUTF8StringEncoding] md5];

	if (!secKey)
	{
		let dict = @{(__bridge id)kSecClass: (__bridge id)kSecClassKey,
					 (__bridge id)kSecAttrApplicationTag: refTag,
					 (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeRSA};

		NSMutableDictionary *keyAttr = NSMutableDictionary.new;

		[keyAttr addEntriesFromDictionary: dict];

		/* First we delete any current keys */
		error = SecItemDelete((__bridge CFDictionaryRef) keyAttr);

		[keyAttr addEntriesFromDictionary: @{(__bridge id)kSecValueData: extractedKey,
											 (__bridge id)kSecReturnPersistentRef: @YES}];

		error = SecItemAdd((__bridge CFDictionaryRef) keyAttr, (CFTypeRef *)&persistPeer);

		if (persistPeer == nil || (error != noErr && error != errSecDuplicateItem))
		{
			return nil;
		}

		CFRelease(persistPeer);

		[keyAttr removeAllObjects];
		[keyAttr addEntriesFromDictionary: dict];
		[keyAttr addEntriesFromDictionary: @{(__bridge id)kSecReturnRef: @YES}];

		error = SecItemCopyMatching((__bridge CFDictionaryRef)keyAttr,
									(CFTypeRef *)&secKey);

		return nil;
	}
	if (error == noErr)
	{
		let dict = ((__bridge NSDictionary *)SecKeyCopyAttributes(secKey));
		self.__secKey = secKey;
		// get key size:
		self.size = [dict[(__bridge id)kSecAttrKeySizeInBits] longValue];
		self.tag = refTag;

		switch ([dict[(__bridge id)kSecAttrKeyClass] intValue])
		{
			case 0:
				self.isPublic = YES;
				self.isPrivate = NO;
				break;
			case 1:
				self.isPublic = NO;
				self.isPrivate = YES;
				break;
		}
	}

	return self;
}

+ (BOOL)containInKeyChainPem: (NSString *)pem
{
	let secKey = [self getSecKeyFromKeyChainIfExist: pem];

	return !!secKey;
}

+ (SecKeyRef)getSecKeyFromKeyChainIfExist: (NSString *)pem
{
	pem = [RSAKey stripPEM: pem];
	NSData *refTag = [[pem dataUsingEncoding: NSUTF8StringEncoding] md5];
	return [self.class secKeyFromTag: refTag];
}

static size_t encodeLength(unsigned char *buf, size_t length)
{
	if (length < 128)
	{
		buf[0] = length;
		return 1;
	}

	size_t i = (length / 256) + 1;
	buf[0] = i + 0x80;
	for (size_t j = 0; j < i; ++j)
	{
		buf[i - j] = length & 0xFF;
		length = length >> 8;
	}

	return i + 1;
}

@end
