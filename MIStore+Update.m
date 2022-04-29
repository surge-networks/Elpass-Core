//
//  MIStore+Update.m
//  Elpass
//
//  Created by Blankwonder on 2019/10/12.
//  Copyright © 2019 Surge Networks. All rights reserved.
//

#import "MIStore+Update.h"
#import "MIStore+Private.h"
#import "MIStore+Metadata.h"
#import <sodium.h>
#import "MIEncryption.h"
#import "MILocalResourceCache.h"
#import "MIRecentlyUsedManager.h"

@implementation MIStore (Update)

- (void)markItemFavorited:(MIItem *)item {
    if (self.readonly) return;
    
    [self syncDispatch:^{
        if (item.favIdx != 0) return;
        
        NSArray *favItems = self.favoritedItems;
        
        int index = [(MIItem *)favItems.firstObject favIdx] + 1000;
        
        [self _internalUpdateItem:item block:^(MIItem *item) {
            item.favIdx = index;
            if (item.archived) {
                item.archived = NO;
            }
        }];
    }];
}

- (void)unmarkItemFavorited:(MIItem *)item {
    if (self.readonly) return;

    [self syncDispatch:^{
        if (item.favIdx == 0) return;
        
        [self _internalUpdateItem:item block:^(MIItem *item) {
            item.favIdx = 0;
        }];
    }];
}

- (void)archiveItem:(MIItem *)item {
    if (self.readonly) return;

    [self syncDispatch:^{
        if (item.archived) return;
        
        [self _internalUpdateItem:item block:^(MIItem *item) {
            item.archived = YES;
            if (item.favIdx != 0) item.favIdx = 0;
        }];
        
        [MIRecentlyUsedManager.sharedInstance removeUsedItem:item.uuid];
    }];
}

- (void)unarchiveItem:(MIItem *)item {
    if (self.readonly) return;

    [self syncDispatch:^{
        if (!item.archived) return;
        
        [self _internalUpdateItem:item block:^(MIItem *item) {
            item.archived = NO;
        }];
    }];
}

- (void)beginBatchOperations {
    KDClassLog(@"Enter batch operations mode");
    [self syncDispatch:^{
        KDAssert(_batchObjects == nil);
        _batchObjects = [NSMutableSet set];
    }];
}

- (void)endBatchOperations {
    KDClassLog(@"Exit batch operations mode");

    [self syncDispatch:^{
        if (_batchObjects.count > 0) {
            [self scheduleSaveTrunk];
            
            NSMutableSet *blocks = [NSMutableSet set];
            
            for (MIItem *item in _batchObjects) {
                [blocks addObject:@(item.blockNumber)];
            }
            
            for (NSNumber *b in blocks) {
                [self writeItemMetadatasForBlock:b.intValue];
            }
            
            [self updateTags];

            NSArray *allItems = _batchObjects.allObjects;
            dispatch_async( dispatch_get_main_queue(),^{
                [[NSNotificationCenter defaultCenter] postNotificationName:MIStoreDidUpdateList object:self];
                [[NSNotificationCenter defaultCenter] postNotificationName:MIStoreDidUpdateItems object:self userInfo:@{@"batch": @YES, @"items": allItems}];
            });
        }
        _batchObjects = nil;
    }];
}


- (void)addItem:(MIItem *)item {
    if (self.readonly) return;

    [self syncDispatch:^{
        item.store = self;
        if (!item.uuid) item.uuid = [NSUUID UUID].UUIDString;
        if (item.createdAt == 0) item.createdAt = MIGetTimestamp();
        if (item.updatedAt == 0) item.updatedAt = MIGetTimestamp();
        
        KDClassLog(@"Adding item: %@", item.uuid);
        
        NSMutableArray *array = [_trunk itemArrayForClass:item.class];
        [array addObject:item];
        
        _trunk.itemMap[item.uuid] = item;
                
        if (_batchObjects) {
            [_batchObjects addObject:item];
        } else {
            [self writeItemMetadatasForBlock:item.blockNumber];
            [self scheduleSaveTrunk];
            [self updateTags];

            dispatch_async( dispatch_get_main_queue(),^{
                [[NSNotificationCenter defaultCenter] postNotificationName:MIStoreDidUpdateList object:self];
                [[NSNotificationCenter defaultCenter] postNotificationName:MIStoreDidAddItem object:item];
            });
        }
    }];
}

- (void)deleteItem:(MIItem *)item {
    if (self.readonly) return;

    [self syncDispatch:^{
        NSString *uuid = item.uuid;
        KDClassLog(@"Removing item: %@", uuid);
        
        [item setDeleted:YES];
        [_trunk.itemMap removeObjectForKey:uuid];
        NSMutableArray *array = [_trunk itemArrayForClass:item.class];
        [array removeObject:item];
        
        for (MIAttachment *a in item.attachments) {
            [self removeAttachmentWithUUIDIfNecessary:a.uuid];
        }
        
        if (item.iconUUID) {
            // Item already removed from _trunk
            [self removeIconFileWithUUIDIfNecessary:item.iconUUID];
        }
                
        if (_batchObjects) {
            [_batchObjects addObject:item];
        } else {
            [self scheduleSaveTrunk];
            [self writeItemMetadatasForBlock:item.blockNumber];
            [self updateTags];

            dispatch_async( dispatch_get_main_queue(),^{
                [[NSNotificationCenter defaultCenter] postNotificationName:MIStoreDidUpdateList object:self];
            });
        }
        
        [MIRecentlyUsedManager.sharedInstance removeUsedItem:uuid];
    }];
}

- (void)_internalUpdateItem:(MIItem *)_item block:(void (^)(MIItem *item))block {
    if (self.readonly) return;
    
    [self syncDispatch:^{
        MIItem *item = _item;
        KDClassLog(@"Updating item: %@", item.uuid);
        
        MIItem *trunkItem = _trunk.itemMap[item.uuid];
        if (!trunkItem) {
            KDClassLog(@"Trunk item doesn't exist");
            return;
        }
        if (trunkItem != item) {
            KDClassLog(@"Trunk item != item");
            item = trunkItem;
        }
        
        NSMutableSet *oldAttachementUUIDs = [NSMutableSet set];
        for (MIAttachment *a in item.attachments) {
            [oldAttachementUUIDs addObject:a.uuid];
        }
        
#if DEBUG
        KDClassLog(@"Before %@", item);
        NSDictionary *before = [item jsonDictionaryForStore];
#endif
        block(item);
#if DEBUG
        KDClassLog(@"After %@", item);
        NSDictionary *after = [item jsonDictionaryForStore];

        KDDebuggerPrintDictionaryDiff(before, after);
#endif
        
        NSMutableSet *newAttachementUUIDs = [NSMutableSet set];
        for (MIAttachment *a in item.attachments) {
            [newAttachementUUIDs addObject:a.uuid];
        }

        [oldAttachementUUIDs minusSet:newAttachementUUIDs];
        
        if (oldAttachementUUIDs.count > 0) {
            [oldAttachementUUIDs enumerateObjectsUsingBlock:^(NSString *obj, BOOL * _Nonnull stop) {
                [self removeAttachmentWithUUIDIfNecessary:obj];
            }];
        }

        _lastUpdatedAt = MIGetTimestamp();

        if (_batchObjects) {
            [_batchObjects addObject:item];
        } else {
            [self scheduleSaveTrunk];
            [self writeItemMetadatasForBlock:item.blockNumber];
            [self updateTags];

            dispatch_async( dispatch_get_main_queue(),^{
                [[NSNotificationCenter defaultCenter] postNotificationName:MIStoreDidUpdateItems object:self userInfo:@{@"items": @[item]}];
            });
        }
    }];
}


- (void)updateItem:(MIItem *)item block:(void (^)(MIItem *item))block {
    if (self.readonly) return;

    [self _internalUpdateItem:item block:^(MIItem *item) {
        block(item);
        item.updatedAt = MIGetTimestamp();
        _lastUpdatedAt = item.updatedAt;
    }];
}

- (void)deleteTag:(NSString *)tag {
    [self syncDispatch:^{
        BOOL alreadyInBatch = _batchObjects != nil;
        
        if (!alreadyInBatch) {
            [self beginBatchOperations];
        }
        
        for (MIItem *item in self.allItemsIncludedArchived) {
            if ([item.tags containsObject:tag]) {
                [self updateItem:item block:^(MIItem *item) {
                    NSMutableArray *tags = item.tags.mutableCopy;
                    [tags removeObject:tag];
                    item.tags = tags;
                }];
            }
        }
        
        if (!alreadyInBatch) {
            [self endBatchOperations];
        }
    }];
}

- (void)addAttachment:(MIAttachment *)attachment completionHandler:(void (^)(NSError *error))completionHandler {
    KDAssert(attachment.sourcePath);
    dispatch_async( dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT,0),^{
        NSData *data = [NSData dataWithContentsOfFile:attachment.sourcePath];
        
        if (!data) {
            completionHandler(MIStoreError(@"The attachment file doesn't exist", 10));
            return;
        }
        
        NSData *key = [self deriveKeyWithSubkeyID:MIStoreSubkeyIDAttachment size:crypto_secretbox_KEYBYTES];
        NSData *ciphertext = [data secretboxWithKey:key];
        
        [_driver createDirectory:kStorageDirectoryAttachments error:nil];

        NSError *error = nil;
        [_driver writeData:ciphertext toPath:attachment.uuid directory:kStorageDirectoryAttachments error:&error];
        
        KDLoggerPrintError(error);

        [self asyncDispatch:^{
            completionHandler(error);
        }];
    });
}

- (void)removeAttachmentWithUUIDIfNecessary:(NSString *)uuid {
    if (self.readonly) return;
    
    [self syncDispatch:^{
        
        for (MIItem *item in _trunk.itemMap.allValues) {
            for (MIAttachment *a in item.attachments) {
                if ([a.uuid isEqualToString:uuid]) {
                    KDClassLog(@"Attachment %@ is still used by another item, skip deleting", uuid);
                    return;
                }
            }
            
        }
        KDClassLog(@"Delete attachment: %@", uuid);
        
        NSError *error = nil;
        [_driver removeItemAtPath:uuid directory:kStorageDirectoryAttachments error:&error];
        KDLoggerPrintError(error);
    }];
}

- (void)updateTags {
    NSMutableSet *set = [NSMutableSet set];
    
    for (MIItem *item in _trunk.itemMap.allValues) {
        if (!item.archived && item.tags.count > 0) {
            [set addObjectsFromArray:item.tags];
        }
    }
    
    NSArray *tags = [set.allObjects sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];

    if (![_allTags isEqualToArray:tags]) {
        _allTags = tags;
        
        dispatch_async( dispatch_get_main_queue(),^{
            [NSNotificationCenter.defaultCenter postNotificationName:MIStoreDidUpdateTags object:self];
        });
    }
}

- (void)renameTag:(NSString *)oldTag to:(NSString *)newTag {
    if ([oldTag isEqualToString:newTag]) return;
    [self syncDispatch:^{
        BOOL alreadyInBatch = _batchObjects != nil;
        
        if (!alreadyInBatch) {
            [self beginBatchOperations];
        }
        
        for (MIItem *item in self.allItemsIncludedArchived) {
            if ([item.tags containsObject:oldTag]) {
                [self updateItem:item block:^(MIItem *item) {
                    NSMutableArray *tags = item.tags.mutableCopy;
                    [tags removeObject:oldTag];
                    if (![tags containsObject:newTag]) {
                        [tags addObject:newTag];
                    }
                    item.tags = tags;
                }];
            }
        }
        
        if (!alreadyInBatch) {
            [self endBatchOperations];
        }

    }];

}

- (void)setIconForItem:(MIItem *)item iconData:(NSData *)data {
    [self updateItem:item block:^(MIItem *item) {
        NSString *hash = [data KD_MD5];
               
        NSString *previousIconHash = item.iconUUID;
        item.iconUUID = hash;
        
        [self mkdirIconFolder];
        [_driver writeData:data toPath:item.iconUUID directory:kStorageDirectoryIcons error:nil];

        [MILocalResourceCache.sharedInstance invalidCacheAtPath:item.iconUUID];
        if (previousIconHash && ![hash isEqualToString:previousIconHash]) {
            [self asyncDispatch:^{
                [self removeIconFileWithUUIDIfNecessary:previousIconHash];
            }];
        }
    }];
}

- (void)mkdirIconFolder {
    [_driver createDirectory:kStorageDirectoryIcons error:nil];
}

- (void)removeIconForItem:(MIItem *)item {
    if (!item.iconUUID) return;
    NSString *iconUUID = item.iconUUID;
    [self updateItem:item block:^(MIItem *item) {
        item.iconUUID = nil;
    }];
    [self removeIconFileWithUUIDIfNecessary:iconUUID];
}

- (void)removeIconFileWithUUIDIfNecessary:(NSString *)iconUUID {
    if (self.readonly) return;
    
    [self syncDispatch:^{
        for (MIItem *item in _trunk.itemMap.allValues) {
            if ([item.iconUUID isEqualToString:iconUUID]) {
                KDClassLog(@"Icon %@ is still used by another item, skip deleting", iconUUID);
                return;
            }
        }
        KDClassLog(@"Delete icon file: %@", iconUUID);
        
        NSError *error = nil;
        [_driver removeItemAtPath:iconUUID directory:kStorageDirectoryIcons error:&error];
        KDLoggerPrintError(error);
        
        [MILocalResourceCache.sharedInstance invalidCacheAtPath:iconUUID];
    }];
}

@end
