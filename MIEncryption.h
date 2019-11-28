//
//  NSObject+MIEncryption.h
//  Elpass
//
//  Created by Blankwonder on 2019/11/28.
//  Copyright © 2019 Surge Networks. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface NSData (MIEncryption)

- (NSData *)secretboxOpenWithKey:(NSData *)key;
- (NSData *)secretboxOpenWithKey:(NSData *)key nonce:(NSData *)nonce;


- (NSData *)secretboxWithKey:(NSData *)key;
- (NSData *)secretboxWithKey:(NSData *)key nonce:(NSData *)nonce;

+ (NSData *)securityRandomDataWithLength:(NSInteger)length;

@end

