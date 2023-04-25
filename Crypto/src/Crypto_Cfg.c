 /******************************************************************************
 *
 * Module: Crypto driver
 *
 * File Name: Crypto_cfg.c
 *
 * Description: configuration source file for crypto driver   - V2xM Driver
 *
 * Author: Mohamed AbdelAzeem
 ******************************************************************************/

#include "../inc/Crypto.h"
#include "../inc/Crypto_Cfg.h"

/* ECDSA Signature generate  driver object  */
CryptoDriverObjectType CryptoMbedTlsObject =
{
		CRYPTO_DRIVER_OBJECT_ID,
		CRYPTO_QUEUE_SIZE,
		&signatureGenerateCryptoPrimitive
};





/* struct for cryptoPrimitives used through signature process*/
 CryptoPrimitive signatureGenerateCryptoPrimitive =
{		CRYPTO_ALGOFAM_ECCSEC, /* Primitive algorithm family  */
		CRYPTO_ALGOMODE_NOT_SET,
		CRYPTO_ALGOFAM_NOT_SET,/* Secondary family */
		CRYPTO_SIGNATUREGENERATE,
		TRUE};

/* struct for cryptoPrimitives used through verification process*/
 CryptoPrimitive verifyGenerateCryptoPrimitive =
{
		CRYPTO_ALGOFAM_ECCSEC, /* Primitive algorithm family  */
		CRYPTO_ALGOMODE_NOT_SET,
		CRYPTO_ALGOFAM_NOT_SET, /* Secondary family */
		CRYPTO_SIGNATUREVERIFY,
		TRUE
};

/* struct for cryptoPrimitives used through HASH process*/
 CryptoPrimitive hashGenerateCryptoPrimitive =
{
		CRYPTO_ALGOFAM_SHA2_256,  /* Primitive algorithm family  */
		CRYPTO_ALGOMODE_NOT_SET,
		CRYPTO_ALGOFAM_NOT_SET, /* Secondary family */
		CRYPTO_HASH,TRUE
};


/*****************************************
 * Crypto key configurations structures.
 ****************************************/
/* Crypto key ECC curve  type is constant in ETSI standard */
/*!< Domain parameters for the 256-bit curve defined by FIPS 186-4 and SEC1. */

/* Eliptic key material  */
CryptoKeyElementType EcckeyMaterialElement =
{
		CRYPTO_KEY_ELEMENT_MATERIAL_ID,
		CRYPTO_KE_FORMAT_BIN_OCTET,
		FALSE,						/* Partial access is not allowed */
		CRYPTO_WA_ALLOWED,
		CRYPTO_KEY_ELEMENT_SIZE		/* 64 byte */
};


/* Eliptic key Element Index   */
CryptoKeyElementType EcckeyIndexElement =
{
		CRYPTO_KEY_ELEMENT_INDEX_ID,
		CRYPTO_KE_FORMAT_BIN_OCTET,
		FALSE,								/* Partial access is not allowed */
		CRYPTO_WA_ALLOWED,					/* Read Access */
		CRYPTO_KEY_ELEMENT_INDEX_SIZE		/* 1 byte */
};



/* Eliptic key type instance  */
CryptoKeyTypeType EccKeyType =
{
		{&EcckeyMaterialElement, &EcckeyIndexElement}
};


/* Eliptic key instance for signature generation  */
CryptoKeyType EccSignatureGenerateKey =
{
		CRYPTO_SIGNATURE_GENERATION_KEY_ID,
		&EccKeyType,
		&NvmBlock_StoredPrivateKeys
};



/* Eliptic key for signature Verification  */
CryptoKeyType EccSignatureVerifyey =
{
		CRYPTO_SIGNATURE_VERIFICATION_KEY_ID,		/* Key Id  */
		&EccKeyType	,								/* Key type reference  */
		NULL_PTR 									/* Verification key is not persist key so it will be stored in the driver's memory  */
};



const CryptoNvBlock storedKey ={ &NvmBlock_StoredPrivateKeys,CRYPTO_NV_BLOCK_IMMEDIATE};
