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

- (NSString *)metadataFolderPath {
    return [self.databasePath stringByAppendingPathComponent:@"Metadata"];
}

- (NSString *)writeMetadataBlock:(int)blockNumber items:(NSArray *)items  {
    [KDStorageHelper mkdirIfNecessary:self.metadataFolderPath];
    
    NSData *key = [self deriveKeyWithSubkeyID:MIStoreSubkeyIDMetadataMask + blockNumber size:crypto_secretbox_KEYBYTES];

    NSArray *jsonArray = [items KD_arrayUsingMapEnumerateBlock:^id(MIItem *obj, NSUInteger idx) {
        return [obj yy_modelToJSONObject];
    }];
    
    NSData *plainData = [MessagePack packObject:jsonArray];
    NSData *ciphertext = [plainData secretboxWithKey:key];

    NSString *path = [self metadataPathForBlock:blockNumber];
    KDClassLog(@"Write %ld metadata payloads to: %@", items.count, path);

    [self.delegate store:self willWriteFile:path];
    [ciphertext writeToFile:path atomically:YES];
    [self.delegate store:self didWriteFile:path];

    return path;
}

- (void)rebuildAllMetadataFromTrunk {
    [self syncDispatch:^{
        NSString *dirPath = self.metadataFolderPath;
        
        [[NSFileManager defaultManager] removeItemAtPath:dirPath error:nil];
        [[NSFileManager defaultManager] createDirectoryAtPath:dirPath withIntermediateDirectories:YES attributes:nil error:nil];
        
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
        
        [map enumerateKeysAndObjectsUsingBlock:^(NSNumber *key, NSMutableArray *array, BOOL * _Nonnull stop) {
            [self writeMetadataBlock:key.intValue items:array];
        }];
    }];
}

- (NSString *)metadataPathForBlock:(int)blockNumber {
    return [self.metadataFolderPath stringByAppendingPathComponent:[NSString stringWithFormat:@"%d", blockNumber]];
}


- (NSString *)writeItemMetadatasForBlock:(int)blockNumber {
    NSMutableArray *array = [NSMutableArray array];

    for (MIItem *item in _trunk.itemMap.allValues) {
        if (item.blockNumber == blockNumber) [array addObject:item];
    }

    return [self writeMetadataBlock:blockNumber items:array];
}


- (BOOL)mergeMetadata {
    KDClassLog(@"mergeMetadata");
    __block BOOL changed = NO;
    [self syncDispatch:^{
        CFAbsoluteTime start = CFAbsoluteTimeGetCurrent();
        

        NSString *dirPath = [self.databasePath stringByAppendingPathComponent:@"Metadata"];

        NSArray *subpaths = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dirPath error:NULL];
        
        NSMutableSet *remainingUUIDs = [NSMutableSet setWithArray:_trunk.itemMap.allKeys];
                
        NSMutableArray *updatedItems = [NSMutableArray array];
        NSMutableArray *insertedItems = [NSMutableArray array];

        NSMutableArray *metadataPayloads = [NSMutableArray arrayWithCapacity:_trunk.itemMap.count];
        
        for (NSString *filename in subpaths) {
            int block = filename.intValue;
            if (block == 0 && ![filename isEqualToString:@"0"]) continue;
            NSData *blockData = [NSData dataWithContentsOfFile:[dirPath stringByAppendingPathComponent:filename]];
            

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
            
            if (!trunkItem) {
                MIItem *item = [MIItem deserializeFromDictionary:payload];
                _trunk.itemMap[uuid] = item;
                
                NSMutableArray *array = [_trunk itemArrayForClass:item.class];
                [array addObject:item];

                [insertedItems addObject:item];
            } else {
                [remainingUUIDs removeObject:uuid];
                NSDictionary *trunkPayload = [trunkItem yy_modelToJSONObject];
                
                if ([payload isEqualToDictionary:trunkPayload]) {
                    //KDClassLog(@"%@: Identical", uuid)
                } else {
                    [updatedItems addObject:trunkItem];
                    [trunkItem yy_modelSetWithDictionary:payload];
                    KDClassLog(@"Metadata object is different to trunk, merge: %@", uuid)
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
    }];
    
    return changed;
}

- (void)metadataIsReadyToMerge {
    BOOL changed = [self mergeMetadata];
    if (changed) {
        KDClassLog(@"Metadata merged to trunk");
        [self saveTrunkIfNecessary];
    }
}

@end
