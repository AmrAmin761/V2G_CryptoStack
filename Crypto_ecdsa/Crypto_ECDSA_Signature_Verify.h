#ifndef ECDSA_SIGNATURE_VERIFICATION_H
#define ECDSA_SIGNATURE_VERIFICATION_H


#include "Crypto_Types_General.h"

   
#define ECDSA_VERIFY_KEY_LEN                                (64)
#define ECDSA_VERIFY_KEY_HALF_LEN                           32
#define ECDSA_VERIFY_SIGNATURE_SIZE                             (64)
#define ECDSA_VERIFY_SIGNATURE_HALF_SIZE                        32
#define ECDSA_VERIFY_INDEX_TWO                                  2
#define ECDSA_VERIFY_MEMORY_ALLOC_HEAP_SIZE                     20
#define ECDSA_VERIFY_HASH_LENGTH                                (32)


Std_ReturnType Crypto_SignatureVerify_ECDSA_Start(
   Crypto_Signature_VerifyContextBufType contextBuffer,
   const Asym_Public_KeyType * keyPtr
);

Std_ReturnType Crypto_SignatureVerify_ECDSA_Update(
    Crypto_Signature_VerifyContextBufType contextBuffer,
    const uint8 * dataPtr,
    uint32 dataLength
);

Std_ReturnType  Crypto_SignatureVerify_ECDSA_Finish(
    Crypto_Signature_VerifyContextBufType contextBuffer,
    const uint8 * signaturePtr,
    uint32 signatureLength,
	Std_ReturnType * resultPtr
);
#endif
