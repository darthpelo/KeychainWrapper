//
//  NSMutableData+AES.h


#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@interface NSMutableData(AES)

/**
 *    Crypt NSMutableData using AES 128.
 *
 *    @param key The key.
 *
 *    @return The crypted object.
 */
- (NSMutableData *)encryptAES:(NSString *)key;

/**
 *    Decrypt NSMutableData using AES 128.
 *
 *    @param key              The key.
 *    @param objencryptedData The crypted object.
 *
 *    @return The decrypted object.
 */
- (NSMutableData *)decryptAES:(NSString*)key andForData:(NSMutableData *)objencryptedData;

@end
