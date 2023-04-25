#ifndef ECDSA_SIGNATURE_GENERATION_H
#define ECDSA_SIGNATURE_GENERATION_H

#include "Crypto_Types_General.h"




#define ECDSA_GEN_KEY_LEN                               32
#define ECDSA_GEN_MEMORY_ALLOC_HEAP_SIZE                20
#define ECDSA_GEN_HASH_LENGTH                           32
#define ECDSA_GEN_SIGNATURE_SIZE                        64
#define ECDSA_GEN_SIGNATURE_HALF_SIZE                   32



Std_ReturnType Crypto_SignatureGenerate_ECDSA_Start(
   CryptoDrv_SignatureGenerateCtxBufType contextBuffer,
   const Asym_Private_Key_Type * keyPtr
);

Std_ReturnType Crypto_SignatureGenerate_ECDSA_Update(
    CryptoDrv_SignatureGenerateCtxBufType contextBuffer,
    const uint8 * dataPtr,
    uint32 dataLength
);

Std_ReturnType Crypto_SignatureGenerate_ECDSA_Finish(
    CryptoDrv_SignatureGenerateCtxBufType contextBuffer,
    uint8 * resultPtr,
    uint32 * resultLengthPtr
);

 


#endif /* #ifdef ECDSA_SIGNATURE_GENERATION_H */
