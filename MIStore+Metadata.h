//
//  MIStore+Metadata.h
//  Elpass
//
//  Created by Blankwonder on 2019/9/11.
//  Copyright © 2019 Surge Networks. All rights reserved.
//


#import "MIStore.h"

@interface MIStore (Metadata)

- (NSString *)metadataFolderPath;

- (void)rebuildAllMetadataFromTrunk;
- (BOOL)mergeMetadata;

- (void)metadataIsReadyToMerge;

- (NSString *)writeItemMetadatasForBlock:(int)blockNumber;


@end
