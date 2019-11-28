//
//  NSObject+MIEncryption.m
//  Elpass
//
//  Created by Blankwonder on 2019/11/28.
//  Copyright © 2019 Surge Networks. All rights reserved.
//

#import "MIEncryption.h"
#import <sodium.h>


@implementation NSData (MIEncryption)

- (NSData *)secretboxOpenWithKey:(NSData *)key {
    return [self secretboxOpenWithKey:key nonce:nil];
}

- (NSData *)secretboxOpenWithKey:(NSData *)key nonce:(NSData *)nonceData {
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    memset(nonce, 0, sizeof(nonce));
    
    if (nonceData) {
        if (nonceData.length != crypto_secretbox_NONCEBYTES) return nil;
        [nonceData getBytes:nonce length:nonceData.length];
    }
    
    if (key.length != crypto_secretbox_KEYBYTES) return nil;
    if (self.length <= crypto_secretbox_MACBYTES) return nil;

    NSMutableData *decryptedData = [NSMutableData dataWithLength:self.length - crypto_secretbox_MACBYTES];

    if (crypto_secretbox_open_easy(decryptedData.mutableBytes, self.bytes, self.length, nonce, key.bytes) != 0) {
        return nil;
    }

    return decryptedData;
}

- (NSData *)secretboxWithKey:(NSData *)key {
    return [self secretboxWithKey:key nonce:nil];

}

- (NSData *)secretboxWithKey:(NSData *)key nonce:(NSData *)nonceData {
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    memset(nonce, 0, sizeof(nonce));

    if (nonceData) {
        if (nonceData.length != crypto_secretbox_NONCEBYTES) return nil;
        [nonceData getBytes:nonce length:nonceData.length];
    }
    if (key.length != crypto_secretbox_KEYBYTES) return nil;

    
    NSMutableData *encryptedData = [NSMutableData dataWithLength:self.length + crypto_secretbox_MACBYTES];
    if (crypto_secretbox_easy(encryptedData.mutableBytes, self.bytes, self.length, nonce, key.bytes) != 0) {
        return nil;
    }

    return encryptedData;
}

+ (NSData *)securityRandomDataWithLength:(NSInteger)length {
    void *ptr = malloc(length);
    randombytes_buf(ptr, length);
    
    return [NSData dataWithBytesNoCopy:ptr length:length freeWhenDone:YES];
}

@end
