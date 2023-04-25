
#ifndef TYPES_H
#define TYPES_H

#ifdef __cplusplus
extern "C"
{
#endif

typedef signed long         sint32;
typedef unsigned long       uint32;
typedef float               float32;
typedef double              float64;

#ifndef FALSE
#define FALSE                              0
#endif
#ifndef TRUE
#define TRUE                               1
#endif

typedef signed long         sint8_least;
typedef signed long         sint16_least;
typedef signed long         sint32_least;

typedef signed char         sint8;
typedef unsigned char       uint8;
typedef signed short        sint16;
typedef unsigned short      uint16;



typedef uint8  Std_ReturnType;

#define V2X_E_OK            ((Std_ReturnType)0x00U)      /* Function Return OK */
#define V2X_E_NOT_OK        ((Std_ReturnType)0x01U)      /* Function Return NOT OK */

typedef enum CryptoDrv_ReturnTag
{
   CRYPTO_V2X_E_OK = 0,
   CRYPTO_V2X_E_NOT_OK = 1
}CryptoDrv_ReturnType;


typedef unsigned long       uint8_least;
typedef unsigned long       uint16_least;
typedef unsigned long       uint32_least;

#define NULL_PTR    ((void *)0)

typedef unsigned char       boolean;

typedef uint32 Align_Type_Size;

/* The value of the below macrow shall be generated such that
 * "SIGNATUREGENERATE_CONTEXT_BUFFER_SIZE * Align_Type_Size" is ((greater or
 * equal "SignatureGenerateMaxCtxBufByteSize") + 1)
 * Ex: SIGNATURE_GENERATE_CONTEXT_BUFFER_SIZE = ((CalSignatureGenerateMaxCtxBufByteSize /Align_Type_Size) + 1)*/

#define SIGNATURE_GENERATE_CONTEXT_BUFFER_SIZE                 1800

typedef Align_Type_Size CryptoDrv_SignatureGenerateCtxBufType[SIGNATURE_GENERATE_CONTEXT_BUFFER_SIZE];


 /* The value of the below macro shall be generated such that
 * "ASYM_PRIV_KEY_MAX_SIZE * Align_Type_Size" is greater or
* equal "AsymDecryptMaxKeySize, SignatureGenerateMaxKeySize, AsymPrivateKeyExtractMaxKeySize, AsymPrivateKeyWrapSymMaxPrivKeySize and AsymPrivateKeyWrapAsymMaxPrivKeySize.".
 * Ex: ASYM_PRIV_KEY_MAX_SIZE = (AsymDecryptMaxKeySize /Align_Type_Size)
*/

#define ASYM_PRIVATE_KEY_MAX_SIZE                 433

 /*
 * Data structure for the private asymmetrical key.
*/
typedef struct Asym_Private_Key_T
{
  uint32 length;
  Align_Type_Size data[ASYM_PRIVATE_KEY_MAX_SIZE];
}Asym_Private_Key_Type;

/*
* The value of the below macro shall be generated such that
* "SIGNATURE_VERIFY_CONTEXT_BUFFER_SIZE * Align_Type_Size" is ((greater or
* equal "SignatureVerifyMaxCtxBufByteSize") + 1)
* Ex: SIGNATURE_VERIFY_CONTEXT_BUFFER_SIZE = ((SignatureVerifyMaxCtxBufByteSize /Align_Type_Size) + 1)
*/

#define SIGNATURE_VERIFY_CONTEXT_BUFFER_SIZE                 2000

/*
* Type definition of the context buffer of a SignatureVerify .
*/
typedef Align_Type_Size Crypto_Signature_VerifyContextBufType[SIGNATURE_VERIFY_CONTEXT_BUFFER_SIZE];


 /* The value of the below macrow shall be generated such that
 * "ASYM_PUBLIC_KEY_MAX_SIZE * Align_Type_Size" is greater or
 * equal "AsymEncryptMaxKeySize, SignatureVerifyMaxKeySize, AsymPublicKeyExtractMaxKeySize, SymKeyWrapAsymMaxPubKeySize and AsymPrivateKeyWrapAsymMaxPubKeySize.".
 * Ex: ASYM_PUBLIC_KEY_MAX_SIZE = (AsymDecryptMaxKeySize /Align_Type_Size)*/

#define ASYM_PUBLIC_KEY_MAX_SIZE                 97


 /* Data structure for the public asymmetrical key.*/
typedef struct Asym_Public_Key_T
{
  uint32 length;
  Align_Type_Size data[ASYM_PUBLIC_KEY_MAX_SIZE];
}Asym_Public_KeyType;

#endif  /*TYPES_H */
