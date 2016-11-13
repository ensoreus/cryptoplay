//
//  FirstViewController.m
//  cryptoplay
//
//  Created by Philipp Maluta on 11.11.16.
//  Copyright © 2016 com.ensoreus. All rights reserved.
//

#import "AesRsaViewController.h"
@import Security;

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#define BUFSIZE 1024

int envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len,
                  unsigned char **encrypted_key, int *encrypted_key_len, unsigned char *iv,
                  unsigned char *ciphertext);

@interface AesRsaViewController ()
@property(nonatomic, weak) IBOutlet UILabel* generatedLine;
@property(nonatomic, weak) IBOutlet UITextView* encryptedLine;
@end

@implementation AesRsaViewController{
    EVP_PKEY_CTX * kctx;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        [self initCrypto];
    }
    return self;
}

- (void) dealloc{
    [self freeCrypto];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.generatedLine.text = [self generateString];
    [self sealEnvelope:self.generatedLine.text];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (void) initCrypto{
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
}

- (void) freeCrypto{
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

- (void) sealEnvelope:(NSString*)str{
    EVP_PKEY* pub_key = [self generateRsaKeyPair];
    unsigned char* encrypted_key =  malloc(EVP_PKEY_size(pub_key));
    int encryptedKeySize = 0;
    unsigned char* iv = malloc(256);
    unsigned char* cipherText = malloc(2048);
    unsigned char cStr[BUFSIZE];
    strncpy((char*)cStr, [str cStringUsingEncoding:NSASCIIStringEncoding], str.length);
    
    int decrLength = envelope_seal(&pub_key, cStr, (int)str.length, &encrypted_key, &encryptedKeySize, iv, cipherText);
    NSMutableString* resStr = [NSMutableString stringWithCapacity:decrLength];
    for (int i = 0; i < decrLength; i++) {
        [resStr appendFormat:@"%02x", cipherText[i]];
    }
    [self storeKeys:pub_key initVector:iv];
    self.encryptedLine.text = resStr;
}

- (NSString*) generateString {
    return [[NSUUID UUID] UUIDString];
}

- (EVP_PKEY*) generateRsaKeyPair{
    if (kctx != NULL){
        EVP_PKEY_CTX_free(kctx);
    }
    kctx = NULL;
    
    int type = EVP_PKEY_RSA;
    if(!(kctx = EVP_PKEY_CTX_new_id(type, NULL))){
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    if(!EVP_PKEY_keygen_init(kctx)){
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    
    if(type == EVP_PKEY_RSA)
    {
        if(!EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048)){
            ERR_print_errors_fp(stderr);
            return NULL;
        }
    }
    
    EVP_PKEY * key;
    if (!EVP_PKEY_keygen(kctx, &key)){
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    return key;
}

- (void) storeKeys:(EVP_PKEY*)keyPair initVector:(unsigned char*)iv{
//    NSString* pubKey = [self extractPublicKey:keyPair];
//    NSString* secKey = [self extractPrivateKey:keyPair];
    
   // CFDataRef pubKeyData = (__bridge CFDataRef)([self extractPublicKeyData:keyPair]);
    NSData* secKeyData = [self extractPrivateKeyData:keyPair];
    CFErrorRef error = NULL;
    SecAccessControlRef acl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleAfterFirstUnlock, kNilOptions, &error);
    NSDictionary * attributes = @{
                                  (id)kSecUseItemList: @[secKeyData],
                                  (id)kSecClass: (id)kSecClassKey,
                                  (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate,
                                  (id)kSecAttrAccessControl: (__bridge id)acl};
    CFTypeRef result = NULL;
    OSStatus status = SecItemAdd((CFDictionaryRef)attributes, &result);
    if (status != errSecSuccess) {
        NSLog(@"Error!!!");
    }
}

- (NSString*) extractPublicKey:(EVP_PKEY*)keyPair{
    int pkeyLen;
    unsigned char *ucBuf, *uctempBuf;
    pkeyLen = i2d_PublicKey(keyPair, NULL);
    ucBuf = (unsigned char *)malloc(pkeyLen+1);
    uctempBuf = ucBuf;
    i2d_PublicKey(keyPair, &uctempBuf);
    NSMutableString* strPubKey = [NSMutableString stringWithCapacity:pkeyLen];
    for (int i = 0; i < pkeyLen; i++) {
        [strPubKey appendFormat:@"%02x", ucBuf[i]];
    }
    free(ucBuf);
    return [strPubKey copy];
}

- (NSString*) extractPrivateKey:(EVP_PKEY*)keyPair{
    int pkeyLen;
    unsigned char *ucBuf, *uctempBuf;
    pkeyLen = i2d_PrivateKey(keyPair, NULL);
    ucBuf = (unsigned char *)malloc(pkeyLen+1);
    uctempBuf = ucBuf;
    i2d_PrivateKey(keyPair, &uctempBuf);
    NSMutableString* strPubKey = [NSMutableString stringWithCapacity:pkeyLen];
    for (int i = 0; i < pkeyLen; i++) {
        [strPubKey appendFormat:@"%02x", ucBuf[i]];
    }
    free(ucBuf);
    return [strPubKey copy];
}

- (NSData*) extractPublicKeyData:(EVP_PKEY*) keyPair{
    int pkeyLen;
    unsigned char *ucBuf, *uctempBuf;
    pkeyLen = i2d_PublicKey(keyPair, NULL);
    ucBuf = (unsigned char *)malloc(pkeyLen+1);
    uctempBuf = ucBuf;
    i2d_PublicKey(keyPair, &uctempBuf);
    NSMutableData* dPubKey = [NSMutableData dataWithCapacity:pkeyLen];
    [dPubKey appendBytes:ucBuf length:pkeyLen];
    free(ucBuf);
    return dPubKey;
}

- (NSData*) extractPrivateKeyData:(EVP_PKEY*) keyPair{
    int pkeyLen;
    unsigned char *ucBuf, *uctempBuf;
    pkeyLen = i2d_PrivateKey(keyPair, NULL);
    ucBuf = (unsigned char *)malloc(pkeyLen+1);
    uctempBuf = ucBuf;
    i2d_PrivateKey(keyPair, &uctempBuf);
    NSMutableData* dPubKey = [NSMutableData dataWithCapacity:pkeyLen];
    [dPubKey appendBytes:ucBuf length:pkeyLen];
    free(ucBuf);
    return dPubKey;
}

@end

int envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len,
                  unsigned char **encrypted_key, int *encrypted_key_len, unsigned char *iv,
                  unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    
    int ciphertext_len;
    
    int len;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())){
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    /* Initialise the envelope seal operation. This operation generates
     * a key for the provided cipher, and then encrypts that key a number
     * of times (one for each public key provided in the pub_key array). In
     * this example the array size is just one. This operation also
     * generates an IV and places it in iv. */
    if(1 != EVP_SealInit(ctx, EVP_aes_256_cbc(), encrypted_key, encrypted_key_len, iv, pub_key, 1)){
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_SealUpdate can be called multiple times if necessary
     */
    if(1 != EVP_SealUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)){
        ERR_print_errors_fp(stderr);
        return 0;
    }
    ciphertext_len = len;
    
    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_SealFinal(ctx, ciphertext + len, &len)) {
        ERR_print_errors_fp(stderr);
        return 0;
    };
    ciphertext_len += len;
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertext_len;
}
