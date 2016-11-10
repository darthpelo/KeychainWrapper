//
//  KeychainWrapper.h


#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Security/Security.h>
#import <CommonCrypto/CommonDigest.h>

@interface KeychainWrapper : NSObject

// Generic exposed method to search the keychain for a given value.  Limit one result per search.
+ (nullable NSData *)searchKeychainCopyMatchingIdentifier:(nullable NSString *)identifier;

// Calls searchKeychainCopyMatchingIdentifier: and converts to a string value.
+ (nullable NSString *)keychainStringFromMatchingIdentifier:(nullable NSString *)identifier;

// Simple method to compare a passed in Hash value with what is stored in the keychain.
+ (BOOL)compareKeychainValueForMatchingHashPIN:(NSUInteger)pinHash withIdentifier:(nullable NSString *)identifier;

+ (BOOL)compareKeychainValueForMatchingPIN:(nullable NSString *)pin withIdentifier:(nullable NSString *)identifier;

// Default initializer to store a value in the keychain.  
// Associated properties are handled for you (setting Data Protection Access, Company Identifer (to uniquely identify string, etc).
+ (BOOL)createKeychainValue:(nullable NSString *)value forIdentifier:(nullable NSString *)identifier;

// Updates a value in the keychain.  If you try to set the value with createKeychainValue: and it already exists
// this method is called instead to update the value in place.
+ (BOOL)updateKeychainValue:(nullable NSString *)value forIdentifier:(nullable NSString *)identifier;

// Delete a value in the keychain
+ (void)deleteItemFromKeychainWithIdentifier:(nullable NSString *)identifier;

// Generates an SHA256 (much more secure than MD5) Hash
+ (nullable NSString *)securedSHA256DigestHashForPIN:(NSUInteger)pinHash;
+ (nullable NSString*)computeSHA256DigestForString:(nullable NSString*)input;

@end
