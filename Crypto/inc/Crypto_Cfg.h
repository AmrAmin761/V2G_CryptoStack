
#ifndef CRYPTO_CFG_H
#define CRYPTO_CFG_H
#include "../../NvM/inc/NvM.h"

/*
 * Module Version 1.0.0
 */
#define CRYPTO_CFG_SW_MAJOR_VERSION           (1U)
#define CRYPTO_CFG_SW_MINOR_VERSION           (0U)
#define CRYPTO_CFG_SW_PATCH_VERSION           (0U)

/*
 * AUTOSAR Version 4.7.0
 */
#define CRYPTO_CFG_AR_RELEASE_MAJOR_VERSION   (4U)
#define CRYPTO_CFG_AR_RELEASE_MINOR_VERSION   (7U)
#define CRYPTO_CFG_AR_RELEASE_PATCH_VERSION   (0U)

/**********  ECUC_Crypto_00002 CryptoGeneral Container   **********/

/* ECUC_Crypto_00006 :  Pre-compile option for Development Error Detect  */
#define CRYPTO_DEV_ERROR_DETECT                (STD_ON)

/* ECUC_Crypto_00007 : Pre-compile option for Version Info API */
#define CRYPTO_VERSION_INFO_API                (STD_ON)

/*ECUC_Crypto_00040 : Pre-compile option to specify instance id*/
#define CRYPTO_INSTANCE_ID                      (1U)

/* ECUC_Crypto_00038 : Specifies the period of main function Crypto_MainFunction in seconds */
#define CRYPTO_MAIN_FUNCTION_PERIOD				(0.05) //assumption


/* ECUC_Crypto_00042 : Reference to EcuC Partition  */
/* According to  SWS_Crypto_00212 this configuration is not supported by crypto driver*/
#define CRYPTO_ECUC_PARTITION_REF 				(NULL)


/************  ECUC_Crypto_00003 : CryptoDriverObject Container  ********/

/* ECUC_Crypto_00009 : Pre-compile configuration for Identifier of the Crypto Driver Object. */
#define CRYPTO_DRIVER_OBJECT_ID  				(0)//Symbolic name from crypto.h


/* ECUC_Crypto_00019 : Pre-compile configuration for Crypto Queue Size (MAx Number of jobs in the queue) */
#define CRYPTO_QUEUE_SIZE 						 (128)//Implementation specific

/* ECUC_Crypto_00045 : Reference to key used by crypto default*/
#define CRYPTO_DEFAULT_RANDOM_KEY_REF       
    
/************  ECUC_Crypto_00011 : CryptoKey Container  ********/

/* Configuration for Crypto ket signature generation Id */
#define CRYPTO_SIGNATURE_GENERATION_KEY_ID  						(0)		/* Key for signature generation   */

/* Configuration for Crypto ket signature verification  Id */
#define CRYPTO_SIGNATURE_VERIFICATION_KEY_ID						(1)		/* Key for signature Verification */

/* ECUC_Crypto_00022 : Pre-compile configuration for Maximum Size size of a CRYPTO key element in bytes  **/
#define  CRYPTO_KEY_ELEMENT_SIZE 									(64)

#define  CRYPTO_KEY_ELEMENT_INDEX_SIZE 								(1)

/* Number of key elements in the Key */
#define CRYPTO_KEY_ELEMENTS_NUMBER                                   2

#define CRYPTO_KEYS_NUMBER                                           2





/**********  ECUC_Crypto_00005 : Crypto Key Element container  **********/

/*  Pre-compile configuration for  Identifier of the CRYPTO Key */
#define CRYPTO_KEY_ELEMENT_MATERIAL_ID						(1)
#define CRYPTO_KEY_ELEMENT_INDEX_ID							(1000)


#define CRYPTO_SIGNATUREGENERATE 7
#define CRYPTO_SIGNATUREVERIFY 8
#define CRYPTO_ALGOFAM_NOT_SET 0
#define CRYPTO_ALGOMODE_ECB 1
#define CRYPTO_ALGOFAM_ECCSEC 31

/* Determines the algorithm family used for the crypto service */
typedef Crypto_AlgorithmFamilyType CryptoPrimitiveAlgorithmFamily;

/* Determines the algorithm mode used for the crypto service */
typedef Crypto_AlgorithmModeType CryptoPrimitiveAlgorithmMode;

/* Determines the algorithm secondary family used for the crypto service */
typedef CryptoPrimitiveAlgorithmFamily CryptoPrimitiveAlgorithmSecondaryFamily;

typedef Crypto_ServiceInfoType CryptoPrimitiveService;


extern   NvM_BlockDescriptorType NvmBlock_StoredPrivateKeys;

#endif /* CRYPTO_CFG_H */
