 /******************************************************************************
 *
 * Module: Non volatile memory
 *
 * File Name: NvM.h
 *
 * Description: Header file for NvM module - Non AUTOSAR module
 *
 * Author: Mohamed AbdelAzeem
 ******************************************************************************/

#ifndef NVM_H_
#define NVM_H_


#include "NvM_Cfg.h"
#include "../../General/Std_Types.h"
#include "../../General/Common_Macros.h"
 /*******************************************************************************
  *                              Module Data Types                              *
  *******************************************************************************/
//#define HashAlgorithm_sha256     (uint8)0x00


 /* Type definition for NvM_BlockIdType */
typedef uint16 NvM_BlockIdType;




typedef enum {
	NVM_BLOCK_NATIVE,
	NVM_BLOCK_REDUNDANT,
	NVM_BLOCK_DATASET
} NvM_BlockManagementTypeType;

typedef Std_ReturnType (*NvMReadRamBlockFromNvCallback) (const void* NvmBuffer);

/* Type definition for Nvm block descriptor  */
typedef struct {
	// Identification of a NVRAM block via a unique block identifier
	NvM_BlockIdType		NvramBlockIdentifier;
	/* Pointer to the stucture  */
	void*		NvmBlockPtr;

	/* Number of elements in the NvM block */
	uint8 		NvMNumberOfElements;

}NvM_BlockDescriptorType;




/* Type definition for key array  */
/*
 * Public key is 64 byte (X coordinates | y Coordinates)
 * private key is 32 byte
 *
 * */
typedef struct{
	 uint8* PublicKey;
	 uint8* PrivateKey;
}NvM_KeyPairType;


/* Type definition for certificate validity period in minutes */
typedef struct{
	uint16 duration;
	uint32 start;
}NvM_CertificateValidityPeriodType;





/* Type definiton for certificate type.  Certificate type: Explicit */
typedef struct{
	uint8  CertificateId;  /* Certificate ID */
	uint8* issuerHashId;   /* Issuer Identifier (hashedId8 of the root certificate) */
	 uint16 duration;	   /* Duration in mintues */
	uint32 start;		   /* Start of Validity period */
	 uint8* PublicKey;	   /* Public key used to verify signed messages */
	 uint8* CertHash;	   /* HashedId8 of the certificate */
	 uint8* IssuerSignature; /* Certificate Signature verified by the root certificate public key */

}NvM_CertificateType;


extern  uint8 public_keys[];
extern  uint8 private_keys[];
extern  NvM_BlockDescriptorType NvmBlock_StoredKeyPairs;
extern  NvM_BlockDescriptorType NvmBlock_Pesudonym_Cerficates ;
extern  NvM_BlockDescriptorType NvmBlock_LongTerm_Cerficates;




/*******************************************************************************
 *                      Function Prototypes                                    *
 *******************************************************************************/
void NvM_Init();

Std_ReturnType NvM_ReadBlock (
	NvM_BlockIdType BlockId,
	void* NvM_DstPtr
);

/*******************************************************************************
 *                     Extern Variables                                    *
 *******************************************************************************/
/* PSEUDONYM_CERTIFICATES */
extern  NvM_CertificateType Pesudonym_Cerficates[4];
extern NvM_CertificateType certficate_0;
extern NvM_CertificateType certficate_1;
extern NvM_CertificateType certficate_2;
extern NvM_CertificateType certficate_3;
extern NvM_CertificateType RootCertificate;



#endif /* NVM_H_ */
