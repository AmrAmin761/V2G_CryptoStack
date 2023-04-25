 /******************************************************************************
 *
 * Module: NvM_Cfg.c
 *
 * File Name: V2xM.h
 *
 * Description: Pre-compile configuration Header file for NvM module - Non AUTOSAR module
 *
 * Author: Mohamed AbdelAzeem
 ******************************************************************************/


#ifndef NVM_CFG_H_
#define NVM_CFG_H_


#define NUMBER_OF_PRIVATE_KEYS 	4
#define NVRAM_BLOCK_PRIVATE_KEYS_ID 1

#define NUMBER_OF_VERIFICATION_KEYS   1
#define NVRAM_BLOCK_VERIFICATION_KEY_ID     4

#define NUMBER_OF_PESUDONUM_CERTFIFCATE		 4
#define NVRAM_BLOCK_PESUDONUM_CERTFIFCATE_ID 2

#define NUMBER_OF_LONGTERM_CERTFIFCATE 		1
#define NVRAM_BLOCK_LONGTERM_CERTFIFCATE_ID 3

#define PUBLIC_KEY_SIZE  64

#define CERT_DURATION_MIN  65000
#define CERT_START         0
#define LONG_CERT_DURATION    65000
#define LONG_CERT_START       0






#endif /* NVM_CFG_H_ */
