
#include "Crypto_ECDSA_Signature_Generate.h"

#include "Crypto_Types_General.h"
#include "ecdsa.h"
#include "sha256.h"
#include "memory_buffer_alloc.h"


Std_ReturnType Crypto_SignatureGenerate_ECDSA_Start(
		CryptoDrv_SignatureGenerateCtxBufType contextBuffer,
		const Asym_Private_Key_Type *  keyPtr
)
{
	Std_ReturnType return_value = V2X_E_OK;
	mbedtls_ecdsa_context * ecdsa_context;

	/* Context Buffer Content : ECDSA_Context | Message Hash | heap  |  global heap  */

	/* allocate heap buffer needed for calculations with remaining size in the context buffer    */
	mbedtls_memory_buffer_alloc_init((uint8*)((uint8*)(void*)&contextBuffer[(((uint32)sizeof(mbedtls_ecdsa_context)) + ((uint32)ECDSA_GEN_MEMORY_ALLOC_HEAP_SIZE)+((uint32)ECDSA_GEN_HASH_LENGTH))/(uint32)sizeof(Align_Type_Size)]),
			((uint32) sizeof(CryptoDrv_SignatureGenerateCtxBufType) - (((uint32)sizeof(mbedtls_ecdsa_context)) + ((uint32)ECDSA_GEN_MEMORY_ALLOC_HEAP_SIZE)+((uint32)ECDSA_GEN_HASH_LENGTH))));

	ecdsa_context = (mbedtls_ecdsa_context*)(void*)&contextBuffer[0];

	mbedtls_ecdsa_init(ecdsa_context);

	if((0 == mbedtls_mpi_read_binary(&(ecdsa_context->d), (const uint8*)(const void*)&keyPtr->data[0],ECDSA_GEN_KEY_LEN))
			&& (0 == mbedtls_ecp_group_load(&(ecdsa_context->grp), MBEDTLS_ECP_DP_SECP256R1)))
	{
		/* Copy workspace data from context to heap data  */
		mbedtls_memory_buffer_alloc_exportHeapData((uint8*)(void*)&contextBuffer[(((uint32)sizeof(mbedtls_ecdsa_context))+((uint32)ECDSA_GEN_HASH_LENGTH))/((uint32)sizeof(Align_Type_Size))]);
	}
	else
	{
		return_value = V2X_E_NOT_OK;
	}

	return return_value;
}

/**========================================================================================**/

Std_ReturnType Crypto_SignatureGenerate_ECDSA_Update(
		CryptoDrv_SignatureGenerateCtxBufType contextBuffer,
		const uint8*  dataPtr,
		uint32 dataLength)
{

	uint8 * result_Message_Hash;
	mbedtls_sha256_context_s sha256_context;
	Std_ReturnType return_value = V2X_E_NOT_OK;

	/* Copy data from heap to context  */
	mbedtls_memory_buffer_alloc_loadHeapData((uint8*)(void*)&contextBuffer[(((uint32)sizeof(mbedtls_ecdsa_context))+((uint32)ECDSA_GEN_HASH_LENGTH))/((uint32)sizeof(Align_Type_Size))]);

	result_Message_Hash = (uint8*)((void*)&contextBuffer[(sizeof(mbedtls_ecdsa_context))/(uint32)sizeof(Align_Type_Size)]);

	mbedtls_sha256_init(&sha256_context);

	if( (0 == mbedtls_sha256_starts_ret(&sha256_context, 0))
			&& (0 == mbedtls_sha256_update_ret(&sha256_context, dataPtr, dataLength))
			&& ( 0 == mbedtls_sha256_finish_ret(&sha256_context, result_Message_Hash)))
	{
		/* Copy workspace data from context to heap data  */
		mbedtls_memory_buffer_alloc_exportHeapData((uint8*)(void*)&contextBuffer[(((uint32)sizeof(mbedtls_ecdsa_context))+((uint32)ECDSA_GEN_HASH_LENGTH))/((uint32)sizeof(Align_Type_Size))]);
		return_value = V2X_E_OK;
	}
	else
	{
		return_value = V2X_E_NOT_OK;
	}


	return return_value;
}


/*------------------------------------------------------------------------------*/

Std_ReturnType Crypto_SignatureGenerate_ECDSA_Finish(
		CryptoDrv_SignatureGenerateCtxBufType contextBuffer,
		uint8 * resultPtr,
		uint32 * resultLengthPtr)
{


	mbedtls_mpi first_signature_r;
	mbedtls_mpi  second_signature_s;
	sint32 mbedtls_signature_result;
	uint8 * result_Message_Hash;
	mbedtls_ecdsa_context * ecdsa_context;
	Std_ReturnType return_value = V2X_E_OK;

	{
		 mbedtls_mpi_init( &first_signature_r );
		 mbedtls_mpi_init( &second_signature_s );
		ecdsa_context = (mbedtls_ecdsa_context*)(void*)&contextBuffer[0];

		result_Message_Hash = (uint8*)((void*)&contextBuffer[(sizeof(mbedtls_ecdsa_context))/(uint32)sizeof(Align_Type_Size)]);

		mbedtls_memory_buffer_alloc_loadHeapData((uint8*)(void*)&contextBuffer[(((uint32)sizeof(mbedtls_ecdsa_context))+((uint32)ECDSA_GEN_HASH_LENGTH))/((uint32)sizeof(Align_Type_Size))]);

		mbedtls_signature_result = mbedtls_ecdsa_sign_det (&(ecdsa_context->grp), &first_signature_r, &second_signature_s, &(ecdsa_context->d), result_Message_Hash, ECDSA_GEN_HASH_LENGTH, MBEDTLS_MD_SHA256);

		if(0 != mbedtls_signature_result)
		{
			return_value = V2X_E_NOT_OK;
		}

		else
		{

			if ((0 != mbedtls_mpi_write_binary(&first_signature_r, &resultPtr[0], ECDSA_GEN_SIGNATURE_HALF_SIZE))
					|| (0 != mbedtls_mpi_write_binary(&second_signature_s, &resultPtr[ECDSA_GEN_SIGNATURE_HALF_SIZE], ECDSA_GEN_SIGNATURE_HALF_SIZE)))
			{
				return_value = V2X_E_NOT_OK;
			}
			else
			{
				*resultLengthPtr = ECDSA_GEN_SIGNATURE_SIZE;
			}
		}
	}

	return return_value;
}



