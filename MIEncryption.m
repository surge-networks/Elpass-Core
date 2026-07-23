//
//  NSObject+MIEncryption.m
//  Elpass
//
//  Copyright © 2019 Surge Networks. All rights reserved.
//

#import "MIEncryption.h"
#import <sodium.h>


@implementation NSData (MIEncryption)

// Transparently reads both on-disk formats:
//   * Legacy: <box>, encrypted with an all-zero nonce (no nonce stored on disk).
//   * New:    <nonce(24)><box>, a fresh random nonce prepended to the ciphertext.
// The new format is tried first. Because crypto_secretbox is authenticated,
// misinterpreting a legacy blob as new-format (treating its first 24 bytes as a
// nonce) fails the Poly1305 check with probability ~2^-128, so falling back to
// the legacy zero-nonce path is safe and unambiguous.
//
// NOTE: this release only READS the new format; it still WRITES the legacy
// format. Writing is deferred to a later release (see the commented-out
// secretboxWithRandomNonceAndKey: below) so that every client gains read
// capability before any client starts producing new-format blobs.
- (NSData *)secretboxOpenWithKey:(NSData *)key {
    if (self.length > crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES) {
        NSData *nonce = [self subdataWithRange:NSMakeRange(0, crypto_secretbox_NONCEBYTES)];
        NSData *box = [self subdataWithRange:NSMakeRange(crypto_secretbox_NONCEBYTES,
                                                         self.length - crypto_secretbox_NONCEBYTES)];

        NSData *decrypted = [box secretboxOpenWithKey:key nonce:nonce];
        if (decrypted) {
            return decrypted;
        }
    }

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

// New on-disk write format, paired with the dual-format reader in
// secretboxOpenWithKey:. Prepends a fresh random 24-byte nonce to the ciphertext
// so that re-encrypting the same logical object (Trunk / Metadata / Attachment)
// never reuses a (key, nonce) pair.
//
// DO NOT ENABLE in this release. Keep writing the legacy zero-nonce format until
// the dual-format reader has shipped to all clients. A later release will:
//   1. uncomment this method (and its declaration in MIEncryption.h),
//   2. switch the Trunk / Metadata / Attachment write paths to it, and
//   3. re-encrypt existing blobs during unlock migration (gated by an Index flag).
//- (NSData *)secretboxWithRandomNonceAndKey:(NSData *)key {
//    NSData *nonceData = [NSData securityRandomDataWithLength:crypto_secretbox_NONCEBYTES];
//    NSData *box = [self secretboxWithKey:key nonce:nonceData];
//    if (!box) return nil;
//
//    NSMutableData *result = [NSMutableData dataWithCapacity:nonceData.length + box.length];
//    [result appendData:nonceData];
//    [result appendData:box];
//    return result;
//}

+ (NSData *)securityRandomDataWithLength:(NSInteger)length {
    void *ptr = malloc(length);
    randombytes_buf(ptr, length);
    
    return [NSData dataWithBytesNoCopy:ptr length:length freeWhenDone:YES];
}

@end
