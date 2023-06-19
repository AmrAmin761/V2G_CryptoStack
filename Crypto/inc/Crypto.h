#ifndef CRYPTO_H
#define CRYPTO_H
#include "Crypto_Cbk.h"

/* Id for the company in the AUTOSAR */
#define CRYPTO_VENDOR_ID    (1000U)

/* Crypto Module Id */
#define CRYPTO_MODULE_ID    (065U)

/* Crypto Instance Id */
#define CRYPTO_INSTANCE_ID  (0U)

#include"../../General/Crypto_GeneralTypes.h"

/*
 * Module Version 1.0.0
 */
#define CRYPTO_SW_MAJOR_VERSION           (1U)
#define CRYPTO_SW_MINOR_VERSION           (0U)
#define CRYPTO_SW_PATCH_VERSION           (0U)

/*
 * AUTOSAR Version 4.7.0
 */
#define CRYPTO_AR_RELEASE_MAJOR_VERSION   (4U)
#define CRYPTO_AR_RELEASE_MINOR_VERSION   (7U)
#define CRYPTO_AR_RELEASE_PATCH_VERSION   (0U)

/* Standard AUTOSAR types */
#include "../../General/Std_Types.h"
/* AUTOSAR checking between Std Types and V2xM Module */
#if ((STD_TYPES_AR_RELEASE_MAJOR_VERSION != CRYPTO_AR_RELEASE_MAJOR_VERSION)\
 ||  (STD_TYPES_AR_RELEASE_MINOR_VERSION != CRYPTO_AR_RELEASE_MINOR_VERSION)\
 ||  (STD_TYPES_AR_RELEASE_PATCH_VERSION != CRYPTO_AR_RELEASE_PATCH_VERSION))
  #error "The AR version of Std_Types.h does not match the expected version"
#endif


/* Crypto Pre-Compile Configuration Header file */
#include "Crypto_Cfg.h"

/* AUTOSAR Version checking between crypto_Cfg.h and crypto.h files */
#if ((CRYPTO_CFG_AR_RELEASE_MAJOR_VERSION != CRYPTO_AR_RELEASE_MAJOR_VERSION)\
 ||  (CRYPTO_CFG_AR_RELEASE_MINOR_VERSION != CRYPTO_AR_RELEASE_MINOR_VERSION)\
 ||  (CRYPTO_CFG_AR_RELEASE_PATCH_VERSION != CRYPTO_AR_RELEASE_PATCH_VERSION))
  #error "The AR version of V2xM_Cfg.h does not match the expected version"
#endif
/* Software Version checking between Crypto_Cfg.h and crypto.h files */
#if ((CRYPTO_CFG_SW_MAJOR_VERSION != CRYPTO_SW_MAJOR_VERSION)\
 ||  (CRYPTO_CFG_SW_MINOR_VERSION != CRYPTO_SW_MINOR_VERSION)\
 ||  (CRYPTO_CFG_SW_PATCH_VERSION != CRYPTO_SW_PATCH_VERSION))
  #error "The SW version of V2xM_Cfg.h does not match the expected version"
#endif


#include "../../NvM/inc/NvM.h"

#include <string.h>

 /*
 * Macros for Crypto driver  Status
 */
#define Crypto_INITIALIZED                (1U)
#define Crypto_NOT_INITIALIZED            (0U)

#define CRYPTO_IDLE_STATE                          (0U)
#define CRYPTO_ACTIVE_STATE                        (1U)
#define KEY_VALID   (1U)
#define KEY_NOT_VALID (0U)


/******************************************************************************
 *                      API Service Id Macros                                 *
 ******************************************************************************/

/* Service ID for Crypto init service */
#define CRYPTO_INIT_SID                            (uint8)0x00

/* Service ID for crypto process job  */
#define CRYPTO_PROCESS_JOB_SID						(uint8)0x03

#define CRYPTO_CANCEL_JOB_SID					(uint8)0x0e
#define CRYPTO_KEY_EXCHANGE_CALC_PUB_VAL_SID 	(uint8)0x09
#define CRYPTO_KEY_EXCHANGE_CALC_SECRET_SID 	(uint8)0x0a
#define CRYPTO_MAIN_FUNCTION_SID 				(uint8)0x0c

#define  CRYPTO_KEYELEMENTSET_SID			(uint8)0x04

/*******************************************************************************
 *                      DET Error Codes                                        *
 *******************************************************************************/

/* Det error code to report API request called before initialization of Crypto Driver. */
#define CRYPTO_E_UNINIT_ID		(0x00)

/* Det error code to report Initialization of Crypto Driver failed */
#define CRYPTO_E_INIT_FAILED	(0x01)

/* Det error code to report API request called with invalid parameter (Nullpointer without redirection) */
#define CRYPTO_E_PARAM_POINTER_ID 	(0x02)

/* Det error code to report API request called with invalid parameter (out of range) */
#define CRYPTO_E_PARAM_HANDLE_ID	(0x04)

/*******************************************************************************
*                              Module Data Types                              *
 *******************************************************************************/

/* Configuration data structure of the Crypto driver module. Implementation specific */
typedef void Crypto_ConfigType;

/* Configuration of a CryptoPrimitive */
typedef struct
{
/* Determines the algorithm family used for the crypto service */
CryptoPrimitiveAlgorithmFamily algorithmUsed;
/* Determines the algorithm mode used for the crypto service */
CryptoPrimitiveAlgorithmMode modeUsed;
/* Determines the algorithm secondary family used for the crypto service */
CryptoPrimitiveAlgorithmSecondaryFamily secondAlgorithmUsed;
/* Determines the crypto service used for defining the capabilities */
CryptoPrimitiveService serviceUsed;
/* Configures if the crypto primitive supports to store or restore context data
of the workspace. Since this option is vulnerable to security, it shall only
set to TRUE if absolutely needed */
boolean CryptoPrimitiveSupportContext;

}CryptoPrimitive;
/* Selects the operation mode when an NV block shall be updated */
typedef  enum {CRYPTO_NV_BLOCK_DEFERRED=1, CRYPTO_NV_BLOCK_IMMEDIATE}CryptoNvBlockProcessing;


typedef struct {
/* Reference to an NvM block descriptor */
const NvM_BlockDescriptorType *CryptoNvBlockDescriptorRef;
/* Selects the operation mode when an NV block shall be updated */
CryptoNvBlockProcessing usedNvBlockProcessing;
}CryptoNvBlock;

typedef struct {
	Crypto_JobType * jobPtr;
	uint32 jobPriority;

}CryptoSavedJobInfoType;



/*********************************************************************
 * 					Crypto driver configurations datatypes
 *********************************************************************/
/* Crypto key configurations is similar to : " int x ; "
 *
 * "int"  is the crypto key type
 * crypto key type consists of one or more elements
 *
 * "x"  is the key
 * key container refer to the NV memory block that stores the actual key values
 *
 * */


typedef struct
{
	uint8 CryptoDriverObjectId;
	uint8 CryptoQueueSize;
	CryptoPrimitive *CryptoPrimitiveRef; /* Pointer to array of crypto primitive supported in the crypto driver object */

}CryptoDriverObjectType;

typedef enum
{
	CRYPTO_KE_FORMAT_BIN_OCTET = 0x01,
	CRYPTO_KE_FORMAT_BIN_SHEKEYS,
	CRYPTO_KE_FORMAT_BIN_IDENT_PRIVATEKEY_PKCS8,
	CRYPTO_KE_FORMAT_BIN_IDENT_PUBLICKEY,
	CRYPTO_KE_FORMAT_BIN_RSA_PRIVATEKEY,
	CRYPTO_KE_FORMAT_BIN_RSA_PUBLICKEY,

}CryptoKeyElementFormat;

/* Define the reading access rights of the key element through external API */
typedef enum
{
	CRYPTO_RA_ALLOWED,
	CRYPTO_RA_ENCRYPTED,
	CRYPTO_RA_INTERNAL_COPY,
	CRYPTO_RA_DENIED
}CryptoKeyElementReadAccess;

typedef enum
{
	CRYPTO_WA_ALLOWED,
	CRYPTO_WA_DENIED,
	CRYPTO_WA_ENCRYPTED
}CryptoKeyElementWriteAccess;

/* Crypto Key element configuration structure data type */
typedef struct
{
	uint32 CryptoKeyElementId;
	CryptoKeyElementFormat format;
	boolean CryptoKeyElementAllowPartialAcces;
	boolean CryptoKeyElementWriteAccess;
	uint32  CryptoKeyElementSize;


}CryptoKeyElementType;



/* Crypto key type configuration structure   data type  */
typedef struct
{
	CryptoKeyElementType* CryptoKeyELements[CRYPTO_KEY_ELEMENTS_NUMBER];

}CryptoKeyTypeType;



/* Crypto Key configuration structure data type */
typedef struct
{
	uint8 CryptoKeyId;
	CryptoKeyTypeType* CryptoKeyTypeRef;
	NvM_BlockDescriptorType *CryptoNvBlockDescriptorRef;

}CryptoKeyType;



typedef struct
{
	uint8  CurrentkeyIndex;
	uint8* PrivateKeys;
}GenerationKeyInfoType;




/*******************************************************************************
 *                      Function Prototypes                                    *
 *******************************************************************************/
void Crypto_Init (const Crypto_ConfigType* configPtr);

Std_ReturnType Crypto_ProcessJob ( uint32 objectId, Crypto_JobType* job);
Std_ReturnType Crypto_ProcessECDSA (CryptoSavedJobInfoType job);
void Crypto_MainFunction (void);
Std_ReturnType Crypto_CancelJob (uint32 objectId,Crypto_JobType* job);

Std_ReturnType Crypto_KeyExchangeCalcSecret (uint32 cryptoKeyId, uint8* partnerPublicValuePtr, uint32* partnerPublicValueLength);
Std_ReturnType Crypto_KeyExchangeCalcPubVal (uint32 cryptoKeyId, uint8* publicValuePtr, uint32* publicValueLengthPtr);


Std_ReturnType Crypto_KeyElementSet (uint32 cryptoKeyId, uint32 keyElementId, const uint8* keyPtr, uint32 keyLength);

/*******************************************************************************
 *                      external Variables                                    *
 *******************************************************************************/
extern const CryptoNvBlock storedKey;
extern  CryptoPrimitive verifyGenerateCryptoPrimitive;
extern  CryptoPrimitive signatureGenerateCryptoPrimitive;
extern  CryptoPrimitive hashGenerateCryptoPrimitive;

extern CryptoKeyType EccSignatureGenerateKey;
extern CryptoKeyType EccSignatureVerifyey;

#endif /* END Crypto.h */
