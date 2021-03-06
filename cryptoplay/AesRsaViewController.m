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


#define BUFSIZE 1024

int envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len,
                  unsigned char **encrypted_key, int *encrypted_key_len, unsigned char *iv,
                  unsigned char *ciphertext);
int envelope_open(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
                  unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv,
                  unsigned char *plaintext);
int aesEncrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
               unsigned char *iv, unsigned char *ciphertext);

@interface AesRsaViewController ()
@property(nonatomic, weak) IBOutlet UILabel* generatedLine;
@property (weak, nonatomic) IBOutlet UITextView *aesKey;

@property(nonatomic, weak) IBOutlet UITextView* encryptedLine;
@property (weak, nonatomic) IBOutlet UITextView *encryptedAesKey;
@property(nonatomic, weak) IBOutlet UILabel* decryptedLine;
@end

@implementation AesRsaViewController{
    //EVP_PKEY_CTX * kctx;
    unsigned char* iv;
    unsigned char* ekey;
    int ekeyLength;
    unsigned char* encryptedText;
    int encryptedTextLength;
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
    NSData* aesKey = [self generateAesKey];
    self.encryptedLine.text = [self aesEncryptText:self.generatedLine.text withAes:aesKey];
    NSMutableString* sAesKey = [NSMutableString stringWithCapacity:256];
    unsigned char* cAesKey = malloc(256);
    [aesKey getBytes:cAesKey range:NSMakeRange(0, 256)];
    for (int i = 0; i < 256; i++) {
        [sAesKey appendFormat:@"%02x", cAesKey[i]];
    }
    self.aesKey.text = sAesKey;
    EVP_PKEY* key_pair = [self generateRsaKeyPair];
    [self sealEnvelope:sAesKey keyPair:key_pair];
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

/*
 1 encrypt plaintext with AES
 2 encrypt AES key with RSA public key
 3 store AES key to keychain
 
 show AES & plaintext
 show encrypted AES and enctext
 
 */

- (void) sealEnvelope:(NSString*)str keyPair:(EVP_PKEY*)key_pair{
    
    unsigned char* encrypted_key =  malloc(EVP_PKEY_size(key_pair));
    int encryptedKeySize = 0;
    iv = malloc(256);
    unsigned char* cipherText = malloc(2048);
    unsigned char cStr[BUFSIZE];
    strncpy((char*)cStr, [str cStringUsingEncoding:NSASCIIStringEncoding], str.length);
    
    int decrLength = envelope_seal(&key_pair, cStr, (int)str.length, &encrypted_key, &encryptedKeySize, iv, cipherText);
    encryptedText = cipherText;
    encryptedTextLength = decrLength;
    NSMutableString* resStr = [NSMutableString stringWithCapacity:decrLength];
    for (int i = 0; i < decrLength; i++) {
        [resStr appendFormat:@"%02x", cipherText[i]];
    }
    ekeyLength = encryptedKeySize;
    ekey = encrypted_key;
    [self storeKeys:key_pair initVector:iv];
    self.encryptedAesKey.text = resStr;
    
}

- (NSData*) generateAesKey{
    
    uint8_t *aesKey = calloc(256, sizeof(uint8_t));
    int res = SecRandomCopyBytes(kSecRandomDefault, 256, aesKey);
    if (res != 0) {
        NSLog(@"Error aesKey: %d", errno);
        return 0;
    }else{
        NSData* dAesKey = [NSData dataWithBytes:aesKey length:256];
        return dAesKey;
    }
}

- (NSString*) aesEncryptText:(NSString*)plainText withAes:(NSData*)aesKey{
    unsigned char* plaintext = malloc(plainText.length + 1);
    uint16_t usedPlainTextLength = 0;
    strncpy(plaintext, [plainText cStringUsingEncoding:NSASCIIStringEncoding], plainText.length);
    
    unsigned char* generatedAesKey = malloc(256);
    [aesKey getBytes:generatedAesKey range:NSMakeRange(0, 256)];
    unsigned char* _iv = malloc(128);
    int ivGenRes = SecRandomCopyBytes(kSecRandomDefault, 128, _iv);
    unsigned char* ciphertext = malloc(512);
    int cipherSize = aesEncrypt(plaintext, usedPlainTextLength, generatedAesKey, _iv, ciphertext);
    NSMutableString* resStr = [NSMutableString stringWithCapacity:cipherSize];
    for (int i = 0; i < cipherSize; i++) {
        [resStr appendFormat:@"%02x", ciphertext[i]];
    }
    free(plaintext);
    
    return resStr;
}


//- (NSString*) encryptAesKey:(NSData*)aesKey{
//    
//}

- (NSString*) generateString {
    return [[NSUUID UUID] UUIDString];
}

- (EVP_PKEY*) generateRsaKeyPair{
    EVP_PKEY_CTX * kctx;
//    if (kctx != NULL){
//        EVP_PKEY_CTX_free(kctx);
//    }
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
    EVP_PKEY_CTX_free(kctx);
    return key;
}

// Task #2

- (void) createKeychain{
   
}

- (void) storeKeys:(EVP_PKEY*)keyPair initVector:(unsigned char*)iv{
    NSData* secKeyData = [self extractPrivateKeyData:keyPair];
    CFErrorRef error = NULL;
    SecAccessControlRef acl = SecAccessControlCreateWithFlags(kCFAllocatorDefault, kSecAttrAccessibleAfterFirstUnlock, kNilOptions, &error);
    SecAccessControlRef sacObject;
    
    sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                                                kSecAccessControlTouchIDAny | kSecAccessControlPrivateKeyUsage, &error);
    NSDictionary * attributes = @{
                                  (id)kSecUseItemList: @[secKeyData],
                                  (id)kSecClass: (id)kSecClassKey,
                                  (id)kSecAttrLabel: @"com.ensoreus.cryptoplay.skey",
                                  (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate,
                                  (id)kSecAttrAccessControl: (__bridge id)acl,
                                  (id)kSecAttrKeySizeInBits: @256,
                                  (id)kSecPrivateKeyAttrs: @{
                                          (id)kSecAttrAccessControl: (__bridge_transfer id)sacObject,
                                          (id)kSecAttrIsPermanent: @YES,
                                          },
                                  (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
                                  (id)kSecAttrIsPermanent: @YES};
    CFTypeRef result = NULL;
    OSStatus status = SecItemAdd((CFDictionaryRef)attributes, &result);
    if (status != errSecSuccess) {
        NSLog(@"Error!!!");
    }
}

- (void) decryptString:(NSString*)str keyPair:(EVP_PKEY*)keyPair initVector:(unsigned char*)initVector{
    EVP_PKEY* privateKey = EVP_PKEY_new();
    int pkeyLen;
    unsigned char *ucBuf, *uctempBuf;
    pkeyLen = i2d_PrivateKey(keyPair, NULL);
    ucBuf = (unsigned char *)malloc(pkeyLen+1);
    uctempBuf = ucBuf;
    i2d_PrivateKey(keyPair, &uctempBuf);
    EVP_PKEY_assign(privateKey, EVP_PKEY_RSA, ucBuf);
    
    unsigned char cStr[BUFSIZE];
    strncpy((char*)cStr, [str cStringUsingEncoding:NSASCIIStringEncoding], str.length);
    unsigned char *decrypted = malloc(2048);
    int decrlen = envelope_open(keyPair, encryptedText, encryptedTextLength, ekey, ekeyLength, initVector, decrypted);
    NSString* strDec = [NSString stringWithCString:decrypted encoding:NSASCIIStringEncoding];
    self.decryptedLine.text = strDec;
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

int envelope_open(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
                  unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv,
                  unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    
    int len;
    
    int plaintext_len;
    
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())){
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    /* Initialise the decryption operation. The asymmetric private key is
     * provided and priv_key, whilst the encrypted session key is held in
     * encrypted_key */
    if(1 != EVP_OpenInit(ctx, EVP_aes_256_cbc(), encrypted_key,
                         encrypted_key_len, iv, priv_key))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_OpenUpdate can be called multiple times if necessary
     */
    if(1 != EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    plaintext_len = len;
    
    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_OpenFinal(ctx, plaintext + len, &len)) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    plaintext_len += len;
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return plaintext_len;
}

int aesEncrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    
    int len;
    
    int ciphertext_len;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        ERR_print_errors_fp(stderr);
        return 0;
    }
    ciphertext_len = len;
    
    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)){
        ERR_print_errors_fp(stderr);
        return 0;
    }
    ciphertext_len += len;
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertext_len;
}
