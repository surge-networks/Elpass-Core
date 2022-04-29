//
//  MIStore+Metadata.m
//  Elpass
//
//  Created by Blankwonder on 2019/9/11.
//  Copyright © 2019 Surge Networks. All rights reserved.
//

#import "MIStore+Metadata.h"
#import "MIStore+Private.h"
#import "MessagePack.h"
#import <sodium.h>
#import "NSURL+KKDomain.h"
#import "NSString+KKDomain.h"
#import "MIEncryption.h"

@implementation MIStore (Metadata)

- (void)writeMetadataBlock:(int)blockNumber items:(NSArray *)items  {
    [_driver createDirectory:kStorageDirectoryMetadata error:nil];
    
    NSData *key = [self deriveKeyWithSubkeyID:MIStoreSubkeyIDMetadataMask + blockNumber size:crypto_secretbox_KEYBYTES];

    NSArray *jsonArray = [items KD_arrayUsingMapEnumerateBlock:^id(MIItem *obj, NSUInteger idx) {
        return [obj jsonDictionaryForStore];
    }];
    
    NSData *plainData = [MessagePack packObject:jsonArray];
    NSData *ciphertext = [plainData secretboxWithKey:key];

//    NSString *path = [self metadataPathForBlock:blockNumber];
    KDClassLog(@"Write %ld metadata payloads to: block %d", items.count, blockNumber);
    
//#if DEBUG
//    KDClassLog(@"Payloads in metadata: %@", jsonArray);
//#endif

    NSError *error = nil;
    BOOL success = [_driver writeData:ciphertext toPath:[NSString stringWithFormat:@"%d", blockNumber] directory:kStorageDirectoryMetadata error:&error];
    KDLoggerPrintError(error);

    if (!success) {
        MIEncounterPanicError(error);
    }
}

- (void)rebuildAllMetadataFromTrunk {
    [self syncDispatch:^{
//        NSString *dirPath = self.metadataFolderPath;
        
//        [_driver removeItemAtPath:dirPath error:nil];
//        [_driver createDirectoryAtPath:dirPath withIntermediateDirectories:YES attributes:nil error:nil];
        
        NSMutableDictionary *map = [NSMutableDictionary dictionaryWithCapacity:64];
        
        for (MIItem *item in _trunk.itemMap.allValues) {
            int block = item.blockNumber;
            
            NSMutableArray *array = map[@(block)];
            if (!array) {
                array = [NSMutableArray array];
                map[@(block)] = array;
            }
            [array addObject:item];
        }
        
        for (int i = 0; i < 64; i++) {
            [self writeMetadataBlock:i items:map[@(i)] ?: @[]];
        }
        
//        [map enumerateKeysAndObjectsUsingBlock:^(NSNumber *key, NSMutableArray *array, BOOL * _Nonnull stop) {
//            [self writeMetadataBlock:key.intValue items:array];
//        }];

    }];
}

//- (NSString *)metadataPathForBlock:(int)blockNumber {
//    return [self.metadataFolderPath stringByAppendingPathComponent:[NSString stringWithFormat:@"%d", blockNumber]];
//}


- (void)writeItemMetadatasForBlock:(int)blockNumber {
    if (self.preventWriting) {
        KDClassLog(@"writeItemMetadatasForBlock while preventWriting = YES!!");
        return;
    }
    NSMutableArray *array = [NSMutableArray array];

    for (MIItem *item in _trunk.itemMap.allValues) {
        if (item.blockNumber == blockNumber) [array addObject:item];
    }

    [self writeMetadataBlock:blockNumber items:array];
}


- (BOOL)mergeMetadata {
    KDClassLog(@"mergeMetadata");
    __block BOOL changed = NO;
    [self syncDispatch:^{
        CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();

        NSArray *subpaths = [_driver contentsOfDirectory:kStorageDirectoryMetadata error:nil];
        
        NSMutableSet *remainingUUIDs = [NSMutableSet setWithArray:_trunk.itemMap.allKeys];
                
        NSMutableArray *updatedItems = [NSMutableArray array];
        NSMutableArray *insertedItems = [NSMutableArray array];

        NSMutableArray *metadataPayloads = [NSMutableArray arrayWithCapacity:_trunk.itemMap.count];
        
        for (NSString *filename in subpaths) {
            int block = filename.intValue;
            if (block == 0 && ![filename isEqualToString:@"0"]) continue;
            
            
            if (![filename isEqualToString:[NSString stringWithFormat:@"%d", block]]) {
                KDClassLog(@"Invalid metadata filename: %@ (%d), remove it", filename, block);
                NSError *error = nil;
                
                [_driver removeItemAtPath:filename directory:kStorageDirectoryMetadata error:&error];
                KDLoggerPrintError(error);
                
                continue;
            }
            
            NSData *blockData = [_driver readDataAtPath:filename directory:kStorageDirectoryMetadata];

            NSData *key = [self deriveKeyWithSubkeyID:MIStoreSubkeyIDMetadataMask + block size:crypto_secretbox_KEYBYTES];

            NSData *decrypted = [blockData secretboxOpenWithKey:key];
            if (!decrypted) {
                KDClassLog(@"Failed to decrypt metadata file: %@, abort!", filename);
                return;
            }
            
            NSArray *items = [MessagePack unpackData:decrypted];

            [metadataPayloads addObjectsFromArray:items];
        }

        for (NSDictionary *payload in metadataPayloads) {
            NSString *uuid = payload[@"uuid"];
            MIItem *trunkItem = _trunk.itemMap[uuid];
            
            MIItem *item = [MIItem deserializeFromDictionary:payload];
            
            if (!item) {
                continue;
            }

            if (!trunkItem) {
                item.store = self;
                _trunk.itemMap[uuid] = item;
                
                NSMutableArray *array = [_trunk itemArrayForClass:item.class];
                [array addObject:item];

                [insertedItems addObject:item];
            } else {
                [remainingUUIDs removeObject:uuid];
                
                if ([item isEqualToItem:trunkItem]) {
                    //KDClassLog(@"%@: Identical", uuid)
                } else {
                    [updatedItems addObject:trunkItem];
                    KDClassLog(@"Metadata object is different to trunk, merge: %@", uuid);

#if DEBUG
                    NSDictionary *trunkPayload = [trunkItem jsonDictionaryForStore];
                    KDDebuggerPrintDictionaryDiff(payload, trunkPayload);
                    KDClassLog(@"Original payload in metadata: %@", payload);
#endif

                    [trunkItem yy_mergeAllPropertiesFrom:item];
                }
            }
        }
        
        for (NSString *uuid in remainingUUIDs) {
            KDClassLog(@"Metadata object doesn't exist for trunk item, deleting: %@", uuid);
            
            MIItem *item = _trunk.itemMap[uuid];

            [_trunk.itemMap removeObjectForKey:uuid];
            
            NSMutableArray *array = [_trunk itemArrayForClass:item.class];
            [array removeObject:item];
        }

        KDClassLog(@"Metadata verification completed in %.0f ms, updated: %ld, deleted: %ld, inserted: %ld", (CFAbsoluteTimeGetCurrent() - start) * 1000, updatedItems.count, remainingUUIDs.count, insertedItems.count);
        
        if (remainingUUIDs.count + insertedItems.count > 0) {
            changed = YES;
            dispatch_async( dispatch_get_main_queue(),^{
                [[NSNotificationCenter defaultCenter] postNotificationName:MIStoreDidUpdateList object:self];
            });
        }
        
        if (updatedItems.count > 0) {
            changed = YES;
            dispatch_async( dispatch_get_main_queue(),^{
                [[NSNotificationCenter defaultCenter] postNotificationName:MIStoreDidUpdateItems object:self userInfo:@{@"items": updatedItems}];
            });
        }
        
        dispatch_async( dispatch_get_main_queue(),^{
            [[NSNotificationCenter defaultCenter] postNotificationName:MIStoreDidCompleteMergingMetadata object:self];
        });
    }];
    
    return changed;
}

- (void)metadataIsReadyToMerge {
    [self syncDispatch:^{
        if (self.preventWriting) return;
        
        if (![MIStore verifyStoreIntegrityInPath:self.databasePath]) {
            KDClassLog(@"Data integrity verification failed, refuse to merge metadata!");
            return;
        }
        
        BOOL changed = [self mergeMetadata];
        if (changed) {
            KDClassLog(@"Metadata merged to trunk");
            [self updateTags];
            [self saveTrunkIfNecessary];
            [self updateLastUpdateTimestampForTrunkItemMap];
        }
        
        if (_shouldUpgradeToAllMetaData) {
            KDClassLog(@"Upgrade to all metadata");
            
            [self rebuildAllMetadataFromTrunk];
            [self _rewriteIndexPayloadWithAllMetadataFlag];
            _shouldUpgradeToAllMetaData = NO;
        }
    }];
}

+ (BOOL)verifyStoreIntegrityInPath:(NSString *)path {
    NSData *data = [NSData dataWithContentsOfFile:[path stringByAppendingPathComponent:@"Index"]];

    NSDictionary *index = [MessagePack unpackData:data];

    if (!index) return NO;
    
    BOOL amd = (index[@"amd"] != nil);
    
    if (![[NSFileManager defaultManager] fileExistsAtPath:[path stringByAppendingPathComponent:@"Trunk"]]) {
        return NO;
    }
    
    if (amd) {
        NSMutableIndexSet *indexSet = [[NSMutableIndexSet alloc] init];
        for (NSString *filename in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:[path stringByAppendingPathComponent:kStorageDirectoryMetadata] error:nil]) {
            int block = filename.intValue;
            if (block == 0 && ![filename isEqualToString:@"0"]) continue;
            
            if (![filename isEqualToString:[NSString stringWithFormat:@"%d", block]]) {
                continue;
            }
            
            [indexSet addIndex:block];
        }
        
        if (![indexSet containsIndexesInRange:NSMakeRange(0, 64)]) {
            for (int i = 0; i < 64; i++) {
                if (![indexSet containsIndex:i]) {
                    KDClassLog(@"Missing metadata file: %d", i);
                }
            }
            
            return NO;
        }
    }
    
    return YES;
}

@end
