//
//  FirstViewController.m
//  cryptoplay
//
//  Created by Philipp Maluta on 11.11.16.
//  Copyright © 2016 com.ensoreus. All rights reserved.
//

#import "AesRsaViewController.h"

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

@interface AesRsaViewController ()
@property(nonatomic, weak) IBOutlet UILabel* generatedLine;
@property(nonatomic, weak) IBOutlet UITextField* inputString;
@property(nonatomic, weak) IBOutlet UITextView* encryptedLine;
@end

@implementation AesRsaViewController{
    EVP_PKEY_CTX * kctx;
    EVP_PKEY* pubKey;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    
    // Do any additional setup after loading the view, typically from a nib.
    
}
- (void) viewDidAppear:(BOOL)animated{
    [super viewDidAppear:animated];
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
    
    if((pubKey = [self generateRsaKeyPair]) == NULL){
        self.encryptedLine.text = @"Key not generated";
    }else{
        NSString* strToEncrypt = [self generateString];
        NSString* iv = [self generateIV];
        unsigned char* cEncryptedStr = calloc(2048, 1);
        [self encrypt:[self.generatedLine.text cStringUsingEncoding:NSASCIIStringEncoding] plaintext_len:self.generatedLine.text.length key:pubKey iv:[iv cStringUsingEncoding:NSASCIIStringEncoding] ciphertext:cEncryptedStr];
        NSString* encryptedStr = [NSString stringWithCString:cEncryptedStr encoding:NSASCIIStringEncoding];
        self.encryptedLine.text = encryptedStr;
        self.generatedLine.text = strToEncrypt;
    }
}

- (void) viewDidDisappear:(BOOL)animated{
    [super viewDidDisappear:animated];
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
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

- (int) encrypt:(unsigned char *)plaintext plaintext_len:(int)plaintext_len key:(unsigned char *)key iv:(unsigned char *)iv ciphertext:(unsigned char *)ciphertext
{
    EVP_CIPHER_CTX *ctx;
    
    int len;
    
    int ciphertext_len;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        NSLog(@"error init context");
    }
    
    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    {
        NSLog(@"error init encryption");
    }
    
    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        NSLog(@"error encrypt");
    }
    ciphertext_len = len;
    
    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        NSLog(@"error encrypt final");
    }
    ciphertext_len += len;
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    
    return ciphertext_len;
}

- (NSString*) generateIV{
    NSString *alphabet  = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXZY0123456789";
    NSMutableString *s = [NSMutableString stringWithCapacity:20];
    for (NSUInteger i = 0U; i < 20; i++) {
        u_int32_t r = arc4random() % [alphabet length];
        unichar c = [alphabet characterAtIndex:r];
        [s appendFormat:@"%C", c];
    }
    return [s copy];
}

@end
