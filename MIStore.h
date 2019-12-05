//
//  MIStore.h
//  Elpass iOS
//
//  Created by Blankwonder on 2019/8/16.
//  Copyright © 2019 Surge Networks. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MIModalDefines.h"
#import "KDOrderedDictionary.h"

typedef NS_ENUM(int, MIStoreState) {
    MIStoreStateNull,
    MIStoreStateLocked,
    MIStoreStateUnlocked,
    MIStoreStateDamaged,
    MIStoreStateUnsupportedVersion,

};

@class MIStore;
@protocol MIStoreDelegate <NSObject>

- (void)store:(MIStore *)store willWriteFile:(NSString *)fullpath;
- (void)store:(MIStore *)store didWriteFile:(NSString *)fullpath;

@end

@interface MIStoreTrunkData : NSObject

@property (nonatomic) NSMutableArray<MILoginItem *> *logins;
@property (nonatomic) NSMutableDictionary<NSString *, MIItem *> *itemMap;
@property (nonatomic) NSMutableArray<MIBankCardItem *> *bankCards;
@property (nonatomic) NSMutableArray<MISecureNoteItem *> *secureNotes;
@property (nonatomic) NSMutableArray<MIIdentificationItem *> *identifications;
@property (nonatomic) NSMutableArray<MIPasswordItem *> *passwords;

- (void)rebuildCategoryArray;
- (NSMutableArray *)itemArrayForClass:(Class)class;

@end


@interface MIStore : NSObject {
    MIModalDatabaseDescriptor *_descriptor;
    
    NSData *_encryptedDescriptorData;
    NSData *_encryptedDescriptorDataNonce;
    NSData *_masterPasswordSalt;

    MIStoreTrunkData *_trunk;
    
    dispatch_queue_t _queue;
    
    NSMutableSet *_batchObjects;
}

- (NSData *)createNewDatabaseInPath:(NSString *)path error:(NSError **)errorPtr masterPassword:(NSString *)password dbuuid:(NSString *)dbuuid;
- (NSData *)changeMasterPassword:(NSString *)password;

- (BOOL)loadDatabaseInPath:(NSString *)path error:(NSError **)errorPtr;

- (void)unlockWithMasterPassword:(NSString *)password completionHandler:(void (^)(BOOL success, BOOL damaged, NSData *key))completionHandler;
- (void)unlockWithMasterKey:(NSData *)key completionHandler:(void (^)(BOOL success, BOOL damaged))completionHandler;

- (void)verifyMasterPassword:(NSString *)password completionHandler:(void (^)(BOOL success, NSData *key))completionHandler;

- (BOOL)isStoreFilesExist;

@property (nonatomic, readonly) MIStoreState state;
@property (nonatomic) NSString *databasePath;

@property (nonatomic, readonly) long trunkUpdatedAt;

@property (nonatomic, weak) id <MIStoreDelegate> delegate;

@property (nonatomic) BOOL readonly;
@property (nonatomic) BOOL demo;

@property (nonatomic, readonly) MIModalDatabaseDescriptor *descriptor;

@property (nonatomic, readonly) NSData *inMemoryIndexData;

- (NSData *)indexDataFromDisk;

- (void)saveTrunk;
- (BOOL)saveTrunkIfNecessary;

- (void)lock;

- (void)syncDispatch:(void (^)(void))block;
- (void)asyncDispatch:(void (^)(void))block;
- (id)syncDispatchReturn:(id (^)(void))block;
- (void)syncIfPossibleOrAsync:(void (^)(void))block;



@end


extern NSString *MIStoreDidUpdateList;
extern NSString *MIStoreDidUpdateItems;
extern NSString *MIStoreDidAddItem;
