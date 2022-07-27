//
//  NSData+Hash.h
//  RSA
//
//  Created by Jesus++
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSData (Hash)
- (NSString *)sha256String;
- (NSData *)md5;
@end

NS_ASSUME_NONNULL_END
