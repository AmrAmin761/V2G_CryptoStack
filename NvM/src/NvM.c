 /******************************************************************************
 *
 * Module: Non Volatile Memory module
 *
 * File Name: NvM.c
 *
 * Description: Source file for NvM module - Non AUTOSAR module
 *
 * Author: Mohamed AbdelAzeem
 ******************************************************************************/



#include "../inc/NvM.h"
#include "../inc/NvM_Cfg.h"


void NvM_Init()
{


	/* Initialize array of  PSEUDONYM_CERTIFICATES */
	  Pesudonym_Cerficates[0] =  certficate_0;
	  Pesudonym_Cerficates[1] =  certficate_1;
	  Pesudonym_Cerficates[2] =  certficate_2;
	  Pesudonym_Cerficates[3] =  certficate_3;


}


Std_ReturnType NvM_ReadBlock (
	NvM_BlockIdType BlockId,
	void* NvM_DstPtr
)
{
	if(NvM_DstPtr != NULL_PTR)
	{
		return V2X_E_NOT_OK;
	}
	switch(BlockId)
	{
	case NVRAM_BLOCK_PRIVATE_KEYS_ID:
		NvM_DstPtr =  (uint8*)&private_keys;
		break;
	case NVRAM_BLOCK_PESUDONUM_CERTFIFCATE_ID:
		NvM_DstPtr =  (NvM_BlockDescriptorType*)&NvmBlock_Pesudonym_Cerficates;
		break;
	case NVRAM_BLOCK_LONGTERM_CERTFIFCATE_ID:
		NvM_DstPtr =(NvM_BlockDescriptorType*)&NvmBlock_LongTerm_Cerficates;
	}

	return  V2X_E_OK;

}
