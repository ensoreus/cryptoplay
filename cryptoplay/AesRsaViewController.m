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

int envelope_seal(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len,
                  unsigned char **encrypted_key, int *encrypted_key_len, unsigned char *iv,
                  unsigned char *ciphertext);

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
    [self initCrypto];
    self.generatedLine.text = [self generateString];
    [self sealEnvelope:self.generatedLine.text];
}

- (void) viewDidDisappear:(BOOL)animated{
    [super viewDidDisappear:animated];
    [self freeCrypto];
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
    EVP_PKEY* pub_key[1];
    pub_key[0] = [self generateRsaKeyPair];
    unsigned char* encrypted_key[1];
    encrypted_key[0] = malloc(EVP_PKEY_size(pubKey));
    int encryptedKeySize = 0;
    unsigned char* iv = malloc(2048);
    unsigned short* cipherText = malloc(2048);
    cipherText = "\0";
    unsigned char* cStr = [str cStringUsingEncoding:NSUTF8StringEncoding];
    envelope_seal(pub_key, cStr, (int)str.length, encrypted_key, &encryptedKeySize, iv, cipherText);
    self.encryptedLine.text = [NSString stringWithCString:cipherText encoding:NSUTF8StringEncoding];
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
