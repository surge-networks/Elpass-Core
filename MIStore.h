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
#import "MIPersistentStoreDriver.h"

extern NSString *const MIStoreErrorDomain;
extern NSError *MIStoreError(NSString *message, NSInteger code);

typedef NS_ENUM(int, MIStoreState) {
    MIStoreStateNull,
    MIStoreStateLocked,
    MIStoreStateUnlocked,
    MIStoreStateDamaged,
    MIStoreStateUnsupportedVersion,

};

@interface MIStoreTrunkData : NSObject

@property (nonatomic) NSMutableArray<MILoginItem *> *logins;
@property (nonatomic) NSMutableDictionary<NSString *, MIItem *> *itemMap;
@property (nonatomic) NSMutableArray<MIBankCardItem *> *bankCards;
@property (nonatomic) NSMutableArray<MISecureNoteItem *> *secureNotes;
@property (nonatomic) NSMutableArray<MIIdentificationItem *> *identifications;
@property (nonatomic) NSMutableArray<MIPasswordItem *> *passwords;
@property (nonatomic) NSMutableArray<MISoftwareLicenseItem *> *softwareLicenses;
@property (nonatomic) NSMutableArray<MIBankAccountItem *> *bankAccounts;

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
    
    NSArray *_allTags;
    
    MIPersistentStoreDriver *_driver;
    
    MITimestamp _lastUpdatedAt;
    BOOL _shouldUpgradeToAllMetaData;
}

- (instancetype)initWithPersistentStore:(MIPersistentStoreDriver *)driver NS_DESIGNATED_INITIALIZER;
- (instancetype)init NS_UNAVAILABLE;

- (NSData *)createNewDatabaseWithError:(NSError **)errorPtr masterPassword:(NSString *)password dbuuid:(NSString *)dbuuid;
- (NSData *)changeMasterPassword:(NSString *)password;

- (BOOL)loadDatabaseWithError:(NSError **)errorPtr;

- (void)unlockWithMasterPassword:(NSString *)password completionHandler:(void (^)(BOOL success, NSError *error, NSData *key))completionHandler;
- (void)unlockWithMasterKey:(NSData *)key completionHandler:(void (^)(BOOL success, NSError *error))completionHandler;

- (void)verifyMasterPassword:(NSString *)password completionHandler:(void (^)(BOOL success, NSData *key))completionHandler;

- (BOOL)isStoreFilesExist;

@property (nonatomic) MIPersistentStoreDriver *driver;
@property (nonatomic, readonly) MIStoreState state;
@property (nonatomic, readonly) NSString *databasePath;

@property (nonatomic, readonly) long trunkUpdatedAt;

@property (nonatomic, readonly) MITimestamp lastUpdatedAt;


@property (nonatomic) BOOL readonly;
@property (nonatomic) BOOL demo;

@property (nonatomic) BOOL preventWriting;


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

- (void)_rewriteIndexPayloadWithAllMetadataFlag;

//- (NSString *)attachmentPathWithUUID:(NSString *)uuid;
//- (NSString *)iconPathWithUUID:(NSString *)uuid;

- (NSString *)iconFullPathWithUUID:(NSString *)uuid;

- (NSDate *)storeCreatedDate;

@end


extern NSString *const MIStoreDidUpdateList;
extern NSString *const MIStoreDidUpdateItems;
extern NSString *const MIStoreDidAddItem;
extern NSString *const MIStoreDidCompleteMergingMetadata;
extern NSString *const MIStoreDidUpdateTags;


