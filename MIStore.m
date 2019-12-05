//
//  MIStore.m
//  Elpass iOS
//
//  Created by Blankwonder on 2019/8/16.
//  Copyright © 2019 Surge Networks. All rights reserved.
//

#import "MIStore.h"
#import "MessagePack.h"
#import <sodium.h>
#import "NSURL+KKDomain.h"
#import "NSString+KKDomain.h"
#import "MIStore+Private.h"
#import "MIStore+Metadata.h"
#import "MIEncryption.h"

@implementation MIStore {
    KDGCDTimer *_trunkSaveTimer;
    
    MIStoreState _state;
}

- (instancetype)init {
    self = [super init];
    
    _queue = dispatch_queue_create(NSStringFromClass(self.class).UTF8String, DISPATCH_QUEUE_SERIAL);
    const void *key = (__bridge const void *)(_queue);
    dispatch_queue_set_specific (_queue, key, (void *)key, NULL);
    
    return self;
}

- (BOOL)loadDatabaseInPath:(NSString *)path error:(NSError **)errorPtr {
    KDAssert(errorPtr);
    
    __block NSError *error;

    BOOL success = [(NSNumber *)[self syncDispatchReturn:^id{
        BOOL isDirectory;
        if (![[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:&isDirectory]) {
            error = KDSimpleError(@"File doesn't exist.");
            [self setState:MIStoreStateDamaged];

            return @NO;
        }
        
        if (!isDirectory) {
            error = KDSimpleError(@"The vault isn't a directory.");
            [self setState:MIStoreStateDamaged];

            return @NO;
        }
        
        NSString *indexPath = [path stringByAppendingPathComponent:@"Index"];
        
        if (![[NSFileManager defaultManager] fileExistsAtPath:indexPath]) {
            error = KDSimpleError(@"The vault is damaged.");
            [self setState:MIStoreStateDamaged];

            return @NO;
        }
        
        NSData *data = [NSData dataWithContentsOfFile:indexPath];
        if (data.length == 0) {
            error = KDSimpleError(@"Failed to open database.");
            [self setState:MIStoreStateDamaged];

            return @NO;
        }
        _inMemoryIndexData = data;
        
        NSDictionary *index = [MessagePack unpackData:data];
        
        int version = [index[@"v"] intValue];
        
        _masterPasswordSalt = index[@"s"];
        _encryptedDescriptorData = index[@"d"];
        _encryptedDescriptorDataNonce = index[@"dn"];
        
        if (_masterPasswordSalt.length != crypto_pwhash_SALTBYTES ||
            _encryptedDescriptorDataNonce.length != crypto_secretbox_NONCEBYTES ||
            !_encryptedDescriptorData) {
            error = KDSimpleError(@"The vault is damaged.");
            [self setState:MIStoreStateDamaged];

            return @NO;
        }
        
        if (version != 1) {
            error = KDSimpleError(@"Unsupported vault version.");
            
            [self setState:MIStoreStateUnsupportedVersion];

            return @NO;
        }
        
        _databasePath = path;
        [self setState:MIStoreStateLocked];

        return @YES;
    }] boolValue];
    
    *errorPtr = error;
    
    return success;
}

- (NSData *)indexDataFromDisk {
    return [NSData dataWithContentsOfFile:[_databasePath stringByAppendingPathComponent:@"Index"]];
}

- (NSData *)textPasswordToData:(NSString *)password salt:(NSData *)salt {
    unsigned char key[crypto_secretbox_KEYBYTES];
    
    if (crypto_pwhash(key, sizeof key, password.UTF8String, password.length, salt.bytes,
                      crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_MODERATE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        KDClassLog(@"crypto_pwhash failed!");
        return nil;
    }

    return [NSData dataWithBytes:key length:crypto_secretbox_KEYBYTES];
}


- (MIStoreTrunkData *)loadTrunkDataFromDisk {
    NSData *encryptedTrunkData = [NSData dataWithContentsOfFile:[_databasePath stringByAppendingPathComponent:@"Trunk"]];
    
    if (!encryptedTrunkData) {
        return nil;
    }
    
    NSData *decryptedTrunk = [encryptedTrunkData secretboxOpenWithKey:[self deriveKeyWithSubkeyID:MIStoreSubkeyIDTrunk size:crypto_secretbox_KEYBYTES]];
        
    if (!decryptedTrunk) {
        KDClassLog(@"Failed to decrypt trunk data");
        return nil;
    }
    
    NSDictionary *trunk = [MessagePack unpackData:decryptedTrunk];
    
    NSMutableDictionary *itemMap = [NSMutableDictionary dictionary];
    
    for (NSDictionary *i in trunk[@"items"]) {
        MIItem *item = [MIItem deserializeFromDictionary:i];
        if (item) {
            itemMap[item.uuid] = item;
        } else {
            KDClassLog(@"Failed to deserialize obj: %@", i);
        }
    }

    MIStoreTrunkData *data = [[MIStoreTrunkData alloc] init];
    data.itemMap = itemMap;
    [data rebuildCategoryArray];
    
    return data;
}

- (void)unlockWithMasterKey:(NSData *)key completionHandler:(void (^)(BOOL success, BOOL damaged))completionHandler {
    [self syncDispatch:^{
        if (_state == MIStoreStateUnlocked) {
            completionHandler(YES, NO);
            return;
        }
        KDAssert(_state == MIStoreStateLocked);
        NSData *decrypted = [_encryptedDescriptorData secretboxOpenWithKey:key nonce:_encryptedDescriptorDataNonce];
        if (!decrypted) {
            KDClassLog(@"Datebase failed to unlocked");
            completionHandler(NO, NO);
            return ;
        }
        
        NSDictionary *dic = [MessagePack unpackData:decrypted];
        
        if (!dic) {
            KDClassLog(@"Failed to unpack data");
            [self setState:MIStoreStateDamaged];
            completionHandler(NO, YES);
            return;
        }
        
        MIModalDatabaseDescriptor *descriptor = [MIModalDatabaseDescriptor yy_modelWithDictionary:dic];
        
        _descriptor = descriptor;
        
        KDClassLog(@"Datebase unlocked: %@", descriptor.databaseUUID);
        
        MIStoreTrunkData *trunk = [self loadTrunkDataFromDisk];
        
        if (!trunk) {
            KDClassLog(@"Failed to load trunk data");
            [self setState:MIStoreStateDamaged];

            completionHandler(NO, YES);

            return;
        }
        
        _trunk = trunk;
        [self setState:MIStoreStateUnlocked];
        KDClassLog(@"Item count: %ld", _trunk.itemMap.count);
        
        completionHandler(YES, NO);

    }];
}

- (void)lock {
    [self syncDispatch:^{
        KDAssert(_state == MIStoreStateUnlocked);
        KDClassLog(@"Lock");
        
        _trunk = nil;
        _descriptor = nil;
        [self setState:MIStoreStateLocked];
    }];
}

- (void)unlockWithMasterPassword:(NSString *)password completionHandler:(void (^)(BOOL success, BOOL damaged, NSData *key))completionHandler{
    dispatch_async( dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{
        CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
        
        NSData *key = [self textPasswordToData:password salt:_masterPasswordSalt];
        KDClassLog(@"crypto_pwhash in %.0f ms", (CFAbsoluteTimeGetCurrent() - start) * 1000);
        [self unlockWithMasterKey:key completionHandler:^(BOOL success, BOOL damaged) {
            completionHandler(success, damaged, key);
        }];
    });
}

- (void)verifyMasterPassword:(NSString *)password completionHandler:(void (^)(BOOL success, NSData *key))completionHandler {
    dispatch_async( dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{
        CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
        NSData *key = [self textPasswordToData:password salt:_masterPasswordSalt];
        KDClassLog(@"crypto_pwhash in %.0f ms", (CFAbsoluteTimeGetCurrent() - start) * 1000);

        NSData *decrypted = [_encryptedDescriptorData secretboxOpenWithKey:key nonce:_encryptedDescriptorDataNonce];
        if (!decrypted) {
            completionHandler(NO, key);
        } else {
            completionHandler(YES, key);
        }
    });

}

- (NSData *)deriveKeyWithSubkeyID:(MIStoreSubkeyID)subkeyID size:(size_t)size {
    NSMutableData *data = [NSMutableData dataWithLength:size];
    crypto_kdf_derive_from_key(data.mutableBytes, size, subkeyID, "________", _descriptor.masterKey.bytes);
    
    return data;
}

- (NSData *)createNewDatabaseInPath:(NSString *)path error:(NSError **)errorPtr masterPassword:(NSString *)password dbuuid:(NSString *)dbuuid{
    KDAssert(errorPtr);
    
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
        *errorPtr = KDSimpleError(@"File already exists.");
        return nil;
    }
    
    [self.delegate store:self willWriteFile:path];
    if (![[NSFileManager defaultManager] createDirectoryAtPath:path withIntermediateDirectories:YES attributes:nil error:errorPtr]) {
        return nil;
    }
    [self.delegate store:self didWriteFile:path];

    MIModalDatabaseDescriptor *descriptor = [[MIModalDatabaseDescriptor alloc] init];
    
    descriptor.createdAt = NSDate.date;
    descriptor.databaseUUID = dbuuid;
    
    KDClassLog(@"Generating a new vault: %@", descriptor.databaseUUID);
    
    NSMutableData *masterKey = [NSMutableData dataWithLength:crypto_kdf_KEYBYTES];
    randombytes_buf(masterKey.mutableBytes, crypto_kdf_KEYBYTES);
    descriptor.masterKey = masterKey;
    
    _descriptor = descriptor;
    _databasePath = path;

    NSData *key = [self changeMasterPassword:password];
    
    [self setState:MIStoreStateUnlocked];

    _trunk = [[MIStoreTrunkData alloc] init];
    
    _trunk.logins = [NSMutableArray array];
    _trunk.bankCards = [NSMutableArray array];
    _trunk.secureNotes = [NSMutableArray array];
    _trunk.identifications = [NSMutableArray array];

    _trunk.itemMap = [NSMutableDictionary dictionary];
    
    [self saveTrunk];
    
    return key;
}


- (NSData *)changeMasterPassword:(NSString *)password {
    NSData *plainIndexData = [MessagePack packObject:[_descriptor yy_modelToJSONObject]];
    
    NSData *saltData = [NSData securityRandomDataWithLength:crypto_pwhash_SALTBYTES];
    NSData *key = [self textPasswordToData:password salt:saltData];
    NSData *nonceData = [NSData securityRandomDataWithLength:crypto_secretbox_NONCEBYTES];
    NSData *ciphertext = [plainIndexData secretboxWithKey:key nonce:nonceData];
    
    _encryptedDescriptorData = ciphertext;
    _encryptedDescriptorDataNonce = nonceData;
    _masterPasswordSalt = saltData;

    NSDictionary *indexPayload = @{@"d": ciphertext,
                                   @"dn": nonceData,
                                   @"s": saltData,
                                   @"v": @1
    };
    
    NSString *indexPath = [_databasePath stringByAppendingPathComponent:@"Index"];
    [self.delegate store:self willWriteFile:indexPath];
    _inMemoryIndexData = [MessagePack packObject:indexPayload];
    BOOL res = [_inMemoryIndexData writeToFile:indexPath atomically:YES];
    if (!res) {
        KDClassLog(@"Failed to write index file!");
    }
    [self.delegate store:self didWriteFile:indexPath];
    
    return key;
}

- (void)saveTrunk {
    [self syncDispatch:^{
        [_trunkSaveTimer invalidate];
        _trunkSaveTimer = nil;

        KDClassLog(@"saveTrunk");
        NSArray *items = [_trunk.itemMap.allValues KD_arrayUsingMapEnumerateBlock:^id(MIItem *obj, NSUInteger idx) {
            return [obj yy_modelToJSONObject];
        }];

        NSDictionary *trunk = @{@"items": items, @"trunkUpdatedAt": @(time(NULL))};
        
        NSData *unencryptedData = [MessagePack packObject:trunk];
        NSData *key = [self deriveKeyWithSubkeyID:MIStoreSubkeyIDTrunk size:crypto_secretbox_KEYBYTES];
        NSData *ciphertext = [unencryptedData secretboxWithKey:key];
        
        NSString *fullpath = [_databasePath stringByAppendingPathComponent:@"Trunk"];
        
        [self.delegate store:self willWriteFile:fullpath];
        [ciphertext writeToFile:fullpath atomically:YES];
        [self.delegate store:self didWriteFile:fullpath];
    }];
}

- (BOOL)saveTrunkIfNecessary {
    __block BOOL saved = NO;
    [self syncDispatch:^{
        [_trunkSaveTimer invalidate];
        _trunkSaveTimer = nil;

        MIStoreTrunkData *diskTrunkData = [self loadTrunkDataFromDisk];
        
        if (![diskTrunkData.itemMap isEqualToDictionary:_trunk.itemMap]) {
            KDClassLog(@"Trunk need updates");
            
#if DEBUG
            KDDebuggerPrintDictionaryDiff(diskTrunkData.itemMap, _trunk.itemMap);
#endif
            
            [self saveTrunk];
            saved = YES;
        } else {
            KDClassLog(@"Trunk on disk is up to date");
        }
        
    }];
    
    return saved;
}

- (BOOL)isStoreFilesExist {
    if (![[NSFileManager defaultManager] fileExistsAtPath:[_databasePath stringByAppendingPathComponent:@"Index"]]) return NO;
    if (![[NSFileManager defaultManager] fileExistsAtPath:[_databasePath stringByAppendingPathComponent:@"Trunk"]]) return NO;
    return YES;
}


- (void)scheduleSaveTrunk {
    KDClassLog(@"scheduleSaveTrunk");

    [_trunkSaveTimer invalidate];
    _trunkSaveTimer = [KDGCDTimer onetimeTimerWithQueue:_queue after:1 handler:^{
        [self saveTrunkIfNecessary];
    }];
}


- (BOOL)isOnSelfDispatchQueue {
    const void *key = (__bridge const void *)(_queue);
    void *res = dispatch_get_specific(key);
    return res == key;
}

- (void)syncDispatch:(void (^)(void))block {
    if ([self isOnSelfDispatchQueue]) {
        block();
    } else {
        dispatch_sync(_queue, ^{
            @autoreleasepool {
                block();
            }
        });
    }
}

- (id)syncDispatchReturn:(id (^)(void))block {
    if ([self isOnSelfDispatchQueue]) {
        return block();
    } else {
        __block id result = nil;
        dispatch_sync(_queue, ^{
            @autoreleasepool {
                result = block();
            }
        });
        return result;
    }
}


- (void)asyncDispatch:(void (^)(void))block {
    dispatch_async(_queue, ^{
        @autoreleasepool {
            block();
        }
    });
}

- (void)syncIfPossibleOrAsync:(void (^)(void))block {
    if ([self isOnSelfDispatchQueue]) {
        block();
    } else {
        dispatch_async(_queue, ^{
            @autoreleasepool {
                block();
            }
        });
    }
}


- (void)setState:(MIStoreState)state {
    KDClassLog(@"State changed: %d -> %d", _state, state);
    _state = state;
}

- (MIStoreState)state {
    __block MIStoreState state;
    
    [self syncDispatch:^{
        state = _state;
    }];
    
    return state;
}

@end


@implementation MIStoreTrunkData

- (void)rebuildCategoryArray {
    self.logins = [NSMutableArray array];
    self.bankCards = [NSMutableArray array];
    self.secureNotes = [NSMutableArray array];
    self.identifications = [NSMutableArray array];
    self.passwords = [NSMutableArray array];

    [self.itemMap enumerateKeysAndObjectsUsingBlock:^(NSString * _Nonnull key, MIItem * _Nonnull obj, BOOL * _Nonnull stop) {
        [[self itemArrayForClass:obj.class] addObject:obj];
    }];
}


- (NSMutableArray *)itemArrayForClass:(Class)class {
    if (class == MILoginItem.class) return self.logins;
    if (class == MIBankCardItem.class) return self.bankCards;
    if (class == MISecureNoteItem.class) return self.secureNotes;
    if (class == MIIdentificationItem.class) return self.identifications;
    if (class == MIPasswordItem.class) return self.passwords;

    KDUtilThrowNoImplementationException
}


@end


NSString *MIStoreDidUpdateList = @"MIStoreDidUpdateList";
NSString *MIStoreDidUpdateItems = @"MIStoreDidUpdateItems";
NSString *MIStoreDidUpdateFavorites = @"MIStoreDidUpdateFavorites";
NSString *MIStoreDidUpdateArchivedItems = @"MIStoreDidUpdateArchivedItems";
NSString *MIStoreDidAddItem = @"MIStoreDidAddItem";
