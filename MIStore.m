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

NSError *MIStoreError(NSString *message, NSInteger code) {
    return [NSError errorWithDomain:MIStoreErrorDomain code:code userInfo:@{NSLocalizedDescriptionKey: message}];
}

@implementation MIStore {
    KDGCDTimer *_trunkSaveTimer;
    
    MIStoreState _state;
}

- (instancetype)initWithPersistentStore:(MIPersistentStoreDriver *)driver {
    self = [super init];
    
    _driver = driver;
    
    _queue = dispatch_queue_create(NSStringFromClass(self.class).UTF8String, DISPATCH_QUEUE_SERIAL);
    const void *key = (__bridge const void *)(_queue);
    dispatch_queue_set_specific (_queue, key, (void *)key, NULL);
    
    return self;
}

- (BOOL)loadDatabaseWithError:(NSError **)errorPtr {
    KDAssert(errorPtr);
    
    __block NSError *error;

    BOOL success = [(NSNumber *)[self syncDispatchReturn:^id{
//        BOOL isDirectory;
//        if (![_driver fileExistsAtPath:path isDirectory:&isDirectory]) {
//            error = MIStoreError(@"File doesn't exist.", 1);
//            [self setState:MIStoreStateDamaged];
//
//            return @NO;
//        }
//
//        if (!isDirectory) {
//            error = MIStoreError(@"The vault isn't a directory.", 2);
//            [self setState:MIStoreStateDamaged];
//
//            return @NO;
//        }
        
        NSString *indexPath = @"Index";
        
        if (![_driver fileExistsAtPath:indexPath directory:nil]) {
            error = MIStoreError(@"The vault is damaged.", 3);
            [self setState:MIStoreStateDamaged];

            return @NO;
        }
        
        NSData *data = [_driver readDataAtPath:indexPath directory:nil];
        if (data.length == 0) {
            error = MIStoreError(@"Failed to open database.", 4);
            [self setState:MIStoreStateDamaged];

            return @NO;
        }
        _inMemoryIndexData = data;
        
        NSDictionary *index = [MessagePack unpackData:data];
        
        int version = [index[@"v"] intValue];
        
        _masterPasswordSalt = index[@"s"];
        _encryptedDescriptorData = index[@"d"];
        _encryptedDescriptorDataNonce = index[@"dn"];
        
        if (!index[@"amd"]) {
            _shouldUpgradeToAllMetaData = YES;
        }
        
        if (_masterPasswordSalt.length != crypto_pwhash_SALTBYTES ||
            _encryptedDescriptorDataNonce.length != crypto_secretbox_NONCEBYTES ||
            !_encryptedDescriptorData) {
            error = MIStoreError(@"The vault is damaged.", 5);
            [self setState:MIStoreStateDamaged];

            return @NO;
        }
        
        if (version != 1) {
            error = MIStoreError(@"Unsupported vault version.", 6);
            
            [self setState:MIStoreStateUnsupportedVersion];

            return @NO;
        }
        
        [self setState:MIStoreStateLocked];

        return @YES;
    }] boolValue];
    
    *errorPtr = error;
    
    return success;
}

- (NSData *)indexDataFromDisk {
    return [_driver readDataAtPath:@"Index" directory:nil];
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
    NSData *encryptedTrunkData = [_driver readDataAtPath:@"Trunk" directory:nil];
    
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
        item.store = self;

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

- (void)unlockWithMasterKey:(NSData *)key completionHandler:(void (^)(BOOL success, NSError *error))completionHandler {
    [self syncDispatch:^{
        if (_state == MIStoreStateUnlocked) {
            completionHandler(YES, nil);
            return;
        }

        NSData *decrypted = [_encryptedDescriptorData secretboxOpenWithKey:key nonce:_encryptedDescriptorDataNonce];
        if (!decrypted) {
            KDClassLog(@"Datebase failed to unlocked");
            completionHandler(NO, nil);
            return ;
        }
        
        NSDictionary *dic = [MessagePack unpackData:decrypted];
        
        if (!dic) {
            KDClassLog(@"Failed to unpack data");
            [self setState:MIStoreStateDamaged];
            completionHandler(NO, MIStoreError(@"Failed to unpack data", 31));
            return;
        }
        
        MIModalDatabaseDescriptor *descriptor = [MIModalDatabaseDescriptor yy_modelWithDictionary:dic];
        
        _descriptor = descriptor;
        
        KDClassLog(@"Datebase unlocked: %@", descriptor.databaseUUID);
        
        MIStoreTrunkData *trunk = [self loadTrunkDataFromDisk];
        
        if (!trunk) {
            KDClassLog(@"Failed to load trunk data");
            [self setState:MIStoreStateDamaged];

            completionHandler(NO, MIStoreError(@"Failed to load trunk data", 32));

            return;
        }
        
        _trunk = trunk;
        [self updateLastUpdateTimestampForTrunkItemMap];
        [self setState:MIStoreStateUnlocked];
        KDClassLog(@"Item count: %ld, last updated at: %@", _trunk.itemMap.count, [NSDate dateWithTimeIntervalSince1970:_lastUpdatedAt]);
        
        completionHandler(YES, nil);

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

- (void)unlockWithMasterPassword:(NSString *)password completionHandler:(void (^)(BOOL success, NSError *error, NSData *key))completionHandler{
    dispatch_async( dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{
        CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
        
        NSData *key = [self textPasswordToData:password salt:_masterPasswordSalt];
        KDClassLog(@"crypto_pwhash in %.0f ms", (CFAbsoluteTimeGetCurrent() - start) * 1000);
        [self unlockWithMasterKey:key completionHandler:^(BOOL success, NSError *error) {
            completionHandler(success, error, key);
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

- (NSData *)createNewDatabaseWithError:(NSError **)errorPtr masterPassword:(NSString *)password dbuuid:(NSString *)dbuuid {
    KDAssert(errorPtr);
    KDAssert(dbuuid);
    KDAssert(password);
//    KDAssert(path);

//    if ([_driver fileExistsAtPath:path]) {
//        *errorPtr = MIStoreError(@"File already exists.", 7);
//        return nil;
//    }
    
    [_driver createDirectory:nil error:nil];

    MIModalDatabaseDescriptor *descriptor = [[MIModalDatabaseDescriptor alloc] init];
    
    descriptor.createdAt = NSDate.date;
    descriptor.databaseUUID = dbuuid;
    
    KDClassLog(@"Generating a new vault: %@", descriptor.databaseUUID);
    
    NSMutableData *masterKey = [NSMutableData dataWithLength:crypto_kdf_KEYBYTES];
    randombytes_buf(masterKey.mutableBytes, crypto_kdf_KEYBYTES);
    descriptor.masterKey = masterKey;
    
    _descriptor = descriptor;

    NSData *key = [self changeMasterPassword:password];
    
    [self setState:MIStoreStateUnlocked];

    _trunk = [[MIStoreTrunkData alloc] init];
    
    _trunk.logins = [NSMutableArray array];
    _trunk.bankCards = [NSMutableArray array];
    _trunk.secureNotes = [NSMutableArray array];
    _trunk.identifications = [NSMutableArray array];

    _trunk.itemMap = [NSMutableDictionary dictionary];
    
    [self saveTrunk];
    [self rebuildAllMetadataFromTrunk];
    
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
                                   @"v": @1,
                                   @"amd": @YES
    };
    
    _inMemoryIndexData = [MessagePack packObject:indexPayload];
    
    if (_shouldUpgradeToAllMetaData) {
        KDClassLog(@"changeMasterPassword with _shouldUpgradeToAllMetaData set");
        _shouldUpgradeToAllMetaData = NO;
        [self rebuildAllMetadataFromTrunk];
    }
    
    BOOL res = [_driver writeData:_inMemoryIndexData toPath:@"Index" directory:nil error:nil];
    if (!res) {
        KDClassLog(@"Failed to write index file!");
    }
    
    return key;
}



- (void)_rewriteIndexPayloadWithAllMetadataFlag {
    NSMutableDictionary *indexPayload = [[MessagePack unpackData:_inMemoryIndexData] mutableCopy];
    KDAssert(indexPayload.count != 0);
    indexPayload[@"amd"] = @1;
    _inMemoryIndexData = [MessagePack packObject:indexPayload];
    
    BOOL res = [_driver writeData:_inMemoryIndexData toPath:@"Index" directory:nil error:nil];
    if (!res) {
        KDClassLog(@"Failed to write index file!");
    }
}


- (void)saveTrunk {
    [self syncDispatch:^{
        if (_preventWriting) {
            KDClassLog(@"Try to save trunk while _preventWriting = YES!");
            return;
        }
        
        [_trunkSaveTimer invalidate];
        _trunkSaveTimer = nil;

        KDClassLog(@"saveTrunk");
        NSArray *items = [_trunk.itemMap.allValues KD_arrayUsingMapEnumerateBlock:^id(MIItem *obj, NSUInteger idx) {
            return [obj jsonDictionaryForStore];
        }];

        NSDictionary *trunk = @{@"items": items, @"trunkUpdatedAt": @(time(NULL))};
        
        NSData *unencryptedData = [MessagePack packObject:trunk];
        NSData *key = [self deriveKeyWithSubkeyID:MIStoreSubkeyIDTrunk size:crypto_secretbox_KEYBYTES];
        NSData *ciphertext = [unencryptedData secretboxWithKey:key];
        

        NSError *error = nil;
        BOOL success = [_driver writeData:ciphertext toPath:@"Trunk" directory:nil error:&error];
        KDLoggerPrintError(error);
        
        if (!success) {
            MIEncounterPanicError(error);
        }
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
    if (![_driver fileExistsAtPath:@"Index" directory:nil]) return NO;
    if (![_driver fileExistsAtPath:@"Trunk" directory:nil]) return NO;
    return YES;
}


- (void)scheduleSaveTrunk {
    KDClassLog(@"scheduleSaveTrunk");

    [_trunkSaveTimer invalidate];
    _trunkSaveTimer = [KDGCDTimer onetimeTimerWithQueue:_queue after:0.5 handler:^{
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

//- (NSString *)attachmentPathWithUUID:(NSString *)uuid {
//    NSString *dirPath = @"Attachments";
//
//    [KDStorageHelper mkdirIfNecessary:dirPath];
//
//    return [dirPath stringByAppendingPathComponent:uuid];
//}

- (NSString *)iconFullPathWithUUID:(NSString *)uuid {
    return [[self.databasePath stringByAppendingPathComponent:@"Icons"] stringByAppendingPathComponent:uuid];
}

- (NSDate *)storeCreatedDate {
    return [_driver fileCreateDateAtPath:@"Index" directory:nil];
}

- (void)setPreventWriting:(BOOL)preventWriting {
    [self syncDispatch:^{
        _preventWriting = preventWriting;
    }];
}

- (NSString *)databasePath {
    return [(MIPersistentStoreDriverFilesystem *)_driver basePath];
}

- (void)updateLastUpdateTimestampForTrunkItemMap {
    __block MITimestamp lastTimestamp = 0;
    
    [_trunk.itemMap enumerateKeysAndObjectsUsingBlock:^(NSString * _Nonnull key, MIItem * _Nonnull obj, BOOL * _Nonnull stop) {
        if (obj.updatedAt > lastTimestamp) {
            lastTimestamp = obj.updatedAt;
        }
    }];
    
    _lastUpdatedAt = lastTimestamp;
}

@end


@implementation MIStoreTrunkData

- (void)rebuildCategoryArray {
    self.logins = [NSMutableArray array];
    self.bankCards = [NSMutableArray array];
    self.secureNotes = [NSMutableArray array];
    self.identifications = [NSMutableArray array];
    self.passwords = [NSMutableArray array];
    self.softwareLicenses = [NSMutableArray array];
    self.bankAccounts = [NSMutableArray array];

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
    if (class == MISoftwareLicenseItem.class) return self.softwareLicenses;
    if (class == MIBankAccountItem.class) return self.bankAccounts;

    if (class == MIPlaceholderItem.class) return nil;

    KDUtilThrowNoImplementationException
}


@end


NSString *const MIStoreDidUpdateList = @"MIStoreDidUpdateList";
NSString *const MIStoreDidUpdateItems = @"MIStoreDidUpdateItems";
NSString *const MIStoreDidAddItem = @"MIStoreDidAddItem";
NSString *const MIStoreDidCompleteMergingMetadata = @"MIStoreDidCompleteMergingMetadata";
NSString *const MIStoreDidUpdateTags = @"MIStoreDidUpdateTags";

NSString *const MIStoreErrorDomain = @"MIStoreErrorDomain";
