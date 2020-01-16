//
//  MIStore+Update.h
//  Elpass
//
//  Created by Blankwonder on 2019/10/12.
//  Copyright © 2019 Surge Networks. All rights reserved.
//

#import "MIStore.h"

@interface MIStore (Update)

- (void)beginBatchOperations;
- (void)endBatchOperations;

- (void)addItem:(MIItem *)item;
- (void)deleteItem:(MIItem *)item;
- (void)updateItem:(MIItem *)item block:(void (^)(MIItem *item))block;

- (void)markItemFavorited:(MIItem *)item;
- (void)unmarkItemFavorited:(MIItem *)item;

- (void)archiveItem:(MIItem *)item;
- (void)unarchiveItem:(MIItem *)item;

- (void)deleteTag:(NSString *)tag;
- (void)renameTag:(NSString *)oldTag to:(NSString *)newTag;

- (void)addAttachment:(MIAttachment *)attachment completionHandler:(void (^)(NSError *error))completionHandler;

- (void)updateTags;

@end
