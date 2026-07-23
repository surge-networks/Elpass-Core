//
//  NSObject+MIEncryption.h
//  Elpass
//
//  Copyright © 2019 Surge Networks. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface NSData (MIEncryption)

- (NSData *)secretboxOpenWithKey:(NSData *)key;
- (NSData *)secretboxOpenWithKey:(NSData *)key nonce:(NSData *)nonce;


- (NSData *)secretboxWithKey:(NSData *)key;
- (NSData *)secretboxWithKey:(NSData *)key nonce:(NSData *)nonce;

// New-format writer (random nonce prepended). Kept disabled in this release;
// see the implementation note in MIEncryption.m. Enable together with the
// write-path switch and migration in a later release.
//- (NSData *)secretboxWithRandomNonceAndKey:(NSData *)key;

+ (NSData *)securityRandomDataWithLength:(NSInteger)length;

@end

