//
//  MIStore+Metadata.h
//  Elpass
//
//  Copyright © 2019 Surge Networks. All rights reserved.
//


#import "MIStore.h"

@interface MIStore (Metadata)

- (void)rebuildAllMetadataFromTrunk;
- (BOOL)mergeMetadata;

- (void)metadataIsReadyToMerge;

- (void)writeItemMetadatasForBlock:(int)blockNumber;

+ (BOOL)verifyStoreIntegrityInPath:(NSString *)path;

@end
