

#include "Crypto_Types_General.h"
#include "Crypto_ECDSA_Signature_Verify.h"
#include "ecdsa.h"
#include "sha256.h"
#include "memory_buffer_alloc.h"


/*------------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------*/

Std_ReturnType Crypto_SignatureVerify_ECDSA_Start(
		Crypto_Signature_VerifyContextBufType contextBuffer,
		const Asym_Public_KeyType * keyPtr)
{
	Std_ReturnType  return_value = V2X_E_NOT_OK;
	mbedtls_ecdsa_context * ecdsa_context;
	const uint8 Qz[ECDSA_VERIFY_KEY_HALF_LEN] =   /* This array is for serving library logic as it needs a public key consists of 3 points (Doesn't contribute in signature generation or verification) */
	{
			0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01
	};

	mbedtls_memory_buffer_alloc_init((uint8*)((uint8*)(void*)&contextBuffer[(((uint32)sizeof(mbedtls_ecdsa_context)) + ((uint32)ECDSA_VERIFY_MEMORY_ALLOC_HEAP_SIZE)+((uint32)ECDSA_VERIFY_HASH_LENGTH))/(uint32)sizeof(Align_Type_Size)]),
			((uint32) sizeof(Crypto_Signature_VerifyContextBufType) - (((uint32)sizeof(mbedtls_ecdsa_context)) + ((uint32)ECDSA_VERIFY_MEMORY_ALLOC_HEAP_SIZE)+((uint32)ECDSA_VERIFY_HASH_LENGTH))));

	ecdsa_context = (mbedtls_ecdsa_context*)(void*)&contextBuffer[0];

	mbedtls_ecdsa_init(ecdsa_context);


	if(0 == mbedtls_mpi_read_binary(&(ecdsa_context->Q.X), (const uint8*)(const void*)&keyPtr->data[0], ECDSA_VERIFY_KEY_HALF_LEN))
	{
		if(0 == mbedtls_mpi_read_binary(&(ecdsa_context->Q.Y), (const uint8*)(const void*)&keyPtr->data[ECDSA_VERIFY_KEY_HALF_LEN], ECDSA_VERIFY_KEY_HALF_LEN))
		{
			if(0 == mbedtls_mpi_read_binary(&(ecdsa_context->Q.Z), Qz, ECDSA_VERIFY_KEY_HALF_LEN))
			{
				if(0 == mbedtls_ecp_group_load(&(ecdsa_context->grp), MBEDTLS_ECP_DP_SECP256R1))
				{
					mbedtls_memory_buffer_alloc_exportHeapData((uint8*)(void*)&contextBuffer[(((uint32)sizeof(mbedtls_ecdsa_context))+((uint32)ECDSA_VERIFY_HASH_LENGTH))/((uint32)sizeof(Align_Type_Size))]);
					return_value = V2X_E_OK;
				}
			}
		}
	}
	else
	{
	}

	return return_value;
}

/*------------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------*/

Std_ReturnType Crypto_SignatureVerify_ECDSA_Update(
		Crypto_Signature_VerifyContextBufType contextBuffer,
		const uint8 * dataPtr,
		uint32 dataLength)
{
	Std_ReturnType return_value = V2X_E_NOT_OK;
	uint8 * result_Message_Hash;
	mbedtls_sha256_context_s  sha256_context;


	mbedtls_memory_buffer_alloc_loadHeapData((uint8*)(void*)&contextBuffer[(((uint32)sizeof(mbedtls_ecdsa_context))+((uint32)ECDSA_VERIFY_HASH_LENGTH))/((uint32)sizeof(Align_Type_Size))]);

	result_Message_Hash = (uint8*)((void*)&contextBuffer[(sizeof(mbedtls_ecdsa_context))/(uint32)sizeof(Align_Type_Size)]);

	mbedtls_sha256_init(&sha256_context);


	if( (0 == mbedtls_sha256_starts_ret(&sha256_context, 0))
			&& ( 0 == mbedtls_sha256_update_ret(&sha256_context, dataPtr, dataLength))
			&&( 0 == mbedtls_sha256_finish_ret(&sha256_context, result_Message_Hash)))
	{
		mbedtls_memory_buffer_alloc_exportHeapData((uint8*)(void*)&contextBuffer[(((uint32)sizeof(mbedtls_ecdsa_context))+((uint32)ECDSA_VERIFY_HASH_LENGTH))/((uint32)sizeof(Align_Type_Size))]);
		return_value = V2X_E_OK;
	}

	else
	{
		return_value = V2X_E_NOT_OK;
	}


	return return_value;
}

/*------------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------*/

Std_ReturnType  Crypto_SignatureVerify_ECDSA_Finish(
		Crypto_Signature_VerifyContextBufType contextBuffer,
		const uint8 * signaturePtr,
		uint32 signatureLength,
		Std_ReturnType * resultPtr)
{
	Std_ReturnType return_value = V2X_E_OK;
	uint8 * result_Message_Hash;
	mbedtls_ecdsa_context * ecdsa_context;
	mbedtls_mpi first_signature_r;
	mbedtls_mpi second_signature_s;
	sint32 mbedtls_signature_return;


	 mbedtls_mpi_init( &first_signature_r );
	 mbedtls_mpi_init( &second_signature_s);
	ecdsa_context = (mbedtls_ecdsa_context*)(void*)&contextBuffer[0];

	result_Message_Hash = (uint8*)((void*)&contextBuffer[(sizeof(mbedtls_ecdsa_context))/(uint32)sizeof(Align_Type_Size)]);

	mbedtls_memory_buffer_alloc_loadHeapData((uint8*)(void*)&contextBuffer[(((uint32)sizeof(mbedtls_ecdsa_context))+((uint32)ECDSA_VERIFY_HASH_LENGTH))/((uint32)sizeof(Align_Type_Size))]);


	if(0 == mbedtls_mpi_read_binary( &first_signature_r, (const uint8*)&signaturePtr[0], (signatureLength/(uint32)ECDSA_VERIFY_INDEX_TWO)))
	{
		if(0 == mbedtls_mpi_read_binary( &second_signature_s, (const uint8*)&signaturePtr[ECDSA_VERIFY_SIGNATURE_HALF_SIZE], (signatureLength/(uint32)ECDSA_VERIFY_INDEX_TWO)))
		{
			mbedtls_signature_return = mbedtls_ecdsa_verify(&(ecdsa_context->grp), result_Message_Hash, ECDSA_VERIFY_HASH_LENGTH, &(ecdsa_context->Q), &first_signature_r, &second_signature_s);
		}
		else
		{
			return_value = V2X_E_NOT_OK;
		}
	}
	else
	{
		return_value = V2X_E_NOT_OK;
	}

	if(0 != mbedtls_signature_return)
	{
		return_value = V2X_E_NOT_OK;
		*resultPtr = V2X_E_NOT_OK;
	}
	else
	{
		*resultPtr = V2X_E_OK;
	}

	return return_value;
}





