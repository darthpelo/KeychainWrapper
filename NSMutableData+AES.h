//
//  NSMutableData+AES.h


#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

@interface NSMutableData(AES)

/**
 *    Metodo per criptare in AES 128 l'oggetto NSMutableData.
 *
 *    @param key La chiave con cui eseguire la criptazione.
 *
 *    @return L'oggetto criptato.
 */

- (NSMutableData *)encryptAES:(NSString *)key;
/**
 *    Metodo per decriptare un oggetto criptato con algoritmo AES 128.
 *
 *    @param key              La chiave con cui è stato criptato l'oggetto.
 *    @param objencryptedData L'oggetto criptato.
 *
 *    @return Il valore decriptato.
 */
- (NSMutableData *)decryptAES:(NSString*)key andForData:(NSMutableData *)objencryptedData;

@end
