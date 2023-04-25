


#include "../inc/Crypto.h"
#include "../../DET/inc/Det.h"
#include "../../Crypto_ecdsa/sha256.h"
#include <stdio.h>
#include "../../CryIf/inc/CryIf.h"
#include "../../Crypto_ecdsa/Crypto_ECDSA_Signature_Generate.h"
#include "../../Crypto_ecdsa/Crypto_ECDSA_Signature_Verify.h"


#include "../../SPI/inc/PLL.h"

#include "time.h"

#define DEBUG_MODE       STD_OFF


/* Pointer to all private keys  */
GenerationKeyInfoType GenerationKey ;

/* pointer to verification key (set by keyElementSet) */
 uint8* VerificationKey;

#define HASH_256_LENGTH         32

/* Global variable to hold the state of  Crypto Driver . */
STATIC uint8 Crypto_Status = Crypto_NOT_INITIALIZED; 
/* the state of driver */
STATIC uint8 Crypto_State;
/*state of key (valid or invalid) */
STATIC uint8 Key_State;
/* current job state in process*/
STATIC uint8 current_Job_State;
/* current job id in process*/
STATIC uint8 current_Job_id = -1;

extern  uint8 public_keys[];
extern uint8 private_keys[];

#define QUEUE_MAX_SIZE 3

typedef struct 
{
  uint8 front, rear;
  uint8 size;
  CryptoSavedJobInfoType arr[QUEUE_MAX_SIZE];
}Queue;
STATIC Queue jobQueue;


STATIC sint8 getJob(uint32 jobId){
    if( jobQueue.size ==0)
            return -1;

    for(uint8 i=jobQueue.front;i <= (jobQueue.rear % QUEUE_MAX_SIZE);i++)
    {

        if(jobId == jobQueue.arr[i].jobPtr->jobId)
        {
            return i;
        }
    }
    return -1;

}

boolean insertJob(Crypto_JobType* job){


if(jobQueue.size < QUEUE_MAX_SIZE)
   {
	boolean inserted=0;
	jobQueue.rear +=1;
	CryptoSavedJobInfoType temp;
	uint8 pos;
       for(uint8 i=jobQueue.front;i<=jobQueue.size;i++)
       {
            if (job->jobInfo.jobPriority > jobQueue.arr[i].jobPriority )
            {
            	 temp= jobQueue.arr[i];
			    jobQueue.arr[i].jobPriority =job->jobInfo.jobPriority;
			    jobQueue.arr[i].jobPtr = job;
			    inserted =1;
			    pos = i;
			    break;

            }

        }

       if(inserted==0)
       {

			jobQueue.arr[jobQueue.rear % QUEUE_MAX_SIZE].jobPriority =job->jobInfo.jobPriority;
			jobQueue.arr[jobQueue.rear % QUEUE_MAX_SIZE].jobPtr = job;
       }
       else {
    	   for(int j=jobQueue.rear-1;j>=pos+1;j--)
			{

				jobQueue.arr[j+1].jobPriority =jobQueue.arr[j].jobPriority;
				jobQueue.arr[j+1].jobPtr = jobQueue.arr[j].jobPtr;
			}
		  jobQueue.arr[pos+1] = temp;
       }
       jobQueue.size +=1;

       return TRUE;

   }
   return FALSE;

}

void deleteNextJob()
{
	if(jobQueue.size > 0)
	{
		jobQueue.front += 1;
		jobQueue.front %= QUEUE_MAX_SIZE;
		jobQueue.size -= 1;
	}
}
/************************************************************************************
* Service Name: Crypto_Init
* Service ID[hex]: 0x00
* Sync/Async: Synchronous
* Reentrancy: Non reentrant
* Parameters (in): ConfigPtr - Pointer to a selected configuration structure
* Parameters (inout): None
* Parameters (out): None
* Return value: void
* Description:  Initializes the Crypto Driver
* Requirements: SWS_Crypto_00215, SWS_Crypto_00198, SWS_Crypto_00045
************************************************************************************/
void Crypto_Init(const Crypto_ConfigType* configPtr){
// configPtr shall always have a null pointer value
// retrieve the key from NvM
NvM_ReadBlock(EccSignatureGenerateKey.CryptoNvBlockDescriptorRef->NvramBlockIdentifier, (uint8*)GenerationKey.PrivateKeys);
Crypto_Status= Crypto_INITIALIZED;
Crypto_State = CRYPTO_IDEAL_STATE;
jobQueue.front=0;
jobQueue.rear=-1;
jobQueue.size =0;


}
/************************************************************************************
* Service Name: Crypto_<vi>_<ai>_NvBlock_ReadFrom_<NvBlock>
* Service ID[hex]: 0x17
* Sync/Async: Synchronous
* Reentrancy: Non reentrant
* Parameters (in): NvmBuffer The address of the buffer where the data can be read from.
* Parameters (inout): None
* Parameters (out): None
* Return value: Std_ReturnType
* Description:  This function is called by NVM to let the crypto driver copy the key data from the
                mirror of the NVM ram block to an internal RAM buffer of the crypto driver.
                The resulting function name shall be set to the container associated with the Nvm
                BlockDescriptor: {CryptoNvBlock/{CryptoNvBlockDescriptorRef} / NvMReadRam
                BlockFromNvCallback.
* Requirements: SRS_CryptoStack_00117, SRS_CryptoStack_00118
************************************************************************************/
Std_ReturnType Crypto_11_STM32F429_NvBlock_ReadFrom_storedKey(const void* NvmBuffer){

// check if NvmBuffer is not empty (SRS_CryptoStack_00117)
if(NvmBuffer!= NULL_PTR)
    {
        Key_State = KEY_VALID;
        return V2X_E_OK;
    }
else
{
    Key_State =CRYPTO_E_KEY_EMPTY ;
    return CRYPTO_E_KEY_EMPTY;
}

}

/************************************************************************************
* Service Name: Crypto_ProcessJob
* Service ID[hex]: 0x03
* Sync/Async: Asynchronous or Async, depends on the job configuration
* Reentrancy: reentrant
* Parameters (in): objectId Holds the identifier of the Crypto Driver Object.
* Parameters (inout): job Pointer to the configuration of the job.
                      Contains structures with job and primitive relevant information but also pointer to result buffers.
* Parameters (out): None
* Return value: Std_ReturnType
* Description:  Performs the crypto primitive, that is configured in the job parameter
* Requirements: SWS_Crypto_00057, SWS_Crypto_00058, SWS_Crypto_00059, SWS_Crypto_00064, SWS_Crypto_00067, SWS_Crypto_00070
************************************************************************************/
Std_ReturnType Crypto_ProcessJob (uint32 objectId,Crypto_JobType* job)
{

#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)
    if (Crypto_NOT_INITIALIZED == Crypto_Status)
    {
        Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, CRYPTO_PROCESS_JOB_SID, CRYPTO_E_UNINIT_ID);
        return V2X_E_NOT_OK;
    }
    if(objectId != CRYPTO_DRIVER_OBJECT_ID){

            Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, CRYPTO_PROCESS_JOB_SID, CRYPTO_E_PARAM_HANDLE_ID );
            return V2X_E_NOT_OK;
    }

    if(NULL_PTR == job)
    {

        Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, CRYPTO_PROCESS_JOB_SID, CRYPTO_E_PARAM_POINTER_ID );
        return V2X_E_NOT_OK;
     }

    if(job->jobPrimitiveInfo->primitiveInfo->service != verifyGenerateCryptoPrimitive.serviceUsed &&
    job->jobPrimitiveInfo->primitiveInfo->service != signatureGenerateCryptoPrimitive.serviceUsed
    &&job->jobPrimitiveInfo->primitiveInfo->service != hashGenerateCryptoPrimitive.serviceUsed  )
    {

        Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, CRYPTO_PROCESS_JOB_SID, CRYPTO_E_PARAM_HANDLE_ID );
        return V2X_E_NOT_OK;
    }
    if(job->jobPrimitiveInfo->primitiveInfo->service == signatureGenerateCryptoPrimitive.serviceUsed &&
    !(job->jobPrimitiveInfo->primitiveInfo->algorithm.family == signatureGenerateCryptoPrimitive.algorithmUsed &&
       job->jobPrimitiveInfo->primitiveInfo->algorithm.mode == signatureGenerateCryptoPrimitive.modeUsed &&
       job->jobPrimitiveInfo->primitiveInfo->algorithm.keyLength == CRYPTO_KEY_ELEMENT_SIZE))
    {
        Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, CRYPTO_PROCESS_JOB_SID, CRYPTO_E_PARAM_HANDLE_ID );
        return V2X_E_NOT_OK;

    }

    if(job->jobPrimitiveInfo->primitiveInfo->service == verifyGenerateCryptoPrimitive.serviceUsed &&
            !(job->jobPrimitiveInfo->primitiveInfo->algorithm.family == verifyGenerateCryptoPrimitive.algorithmUsed &&
        job->jobPrimitiveInfo->primitiveInfo->algorithm.mode == verifyGenerateCryptoPrimitive.modeUsed &&
        job->jobPrimitiveInfo->primitiveInfo->algorithm.keyLength == CRYPTO_KEY_ELEMENT_SIZE))
     {
         Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, CRYPTO_PROCESS_JOB_SID, CRYPTO_E_PARAM_HANDLE_ID );
         return V2X_E_NOT_OK;
     }
    if(job->jobPrimitiveInfo->primitiveInfo->service == hashGenerateCryptoPrimitive.serviceUsed &&
            !( job->jobPrimitiveInfo->primitiveInfo->algorithm.family == hashGenerateCryptoPrimitive.algorithmUsed &&
            job->jobPrimitiveInfo->primitiveInfo->algorithm.mode == hashGenerateCryptoPrimitive.modeUsed &&
            job->jobPrimitiveInfo->primitiveInfo->algorithm.keyLength == CRYPTO_KEY_ELEMENT_SIZE))
         {
             Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, CRYPTO_PROCESS_JOB_SID, CRYPTO_E_PARAM_HANDLE_ID );
             return V2X_E_NOT_OK;
         }
    if(job->jobPrimitiveInputOutput.inputPtr == NULL_PTR)
        {
            Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, CRYPTO_PROCESS_JOB_SID, CRYPTO_E_PARAM_POINTER_ID );
            return V2X_E_NOT_OK;
        }

    if(job->cryptoKeyId != EccSignatureGenerateKey.CryptoKeyId &&
    		job->cryptoKeyId != EccSignatureVerifyey.CryptoKeyId)
    {
        Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, CRYPTO_PROCESS_JOB_SID, CRYPTO_E_PARAM_HANDLE_ID );
        return V2X_E_NOT_OK;
    }



#endif

    // save current job id
    current_Job_id =job->jobId;
    // check if job already in array, and need to start again reset the previous one
    sint8 res = getJob(job->jobId);
    // already in queue
    if(res != -1 &&
                   (job->jobPrimitiveInputOutput.mode == CRYPTO_OPERATIONMODE_START ||
                    job->jobPrimitiveInputOutput.mode == CRYPTO_OPERATIONMODE_SINGLECALL))
    {
        // reset the info
        jobQueue.arr[res].jobPriority = job->jobInfo.jobPriority;
         jobQueue.arr[res].jobPtr = job;

    }


    // check if job state is idle and mode is not == start then V2X_E_NOT_OK
    if(job->jobState == CRYPTO_JOBSTATE_IDLE && job->jobPrimitiveInputOutput.mode != CRYPTO_OPERATIONMODE_SINGLECALL)
    {
        return V2X_E_NOT_OK;
    }

    // if sync
    if(job->jobPrimitiveInfo->processingType == CRYPTO_PROCESSING_SYNC)
    {
        //check if crypto is busy
        if(Crypto_State != CRYPTO_IDEAL_STATE )
        {
            return CRYPTO_E_BUSY;
        }
        else
        {
            // if not call Crypto_ProcessECDSA();->change states into this fn
            CryptoSavedJobInfoType jobInfo= {job, job->jobInfo.jobPriority};
             return Crypto_ProcessECDSA(jobInfo);

        }
    }

    else if (job->jobPrimitiveInfo->processingType == CRYPTO_PROCESSING_ASYNC)
    {
        // check if queue is full
        if (insertJob(job))
            return V2X_E_OK;
        else
            return CRYPTO_E_BUSY;
    }
    else
        return V2X_E_NOT_OK;

}

Std_ReturnType Crypto_ProcessECDSA (CryptoSavedJobInfoType jobInfo)
{

/************************************** Processing Hashing jobs  *************************************************************/
	if(jobInfo.jobPtr->jobPrimitiveInfo->primitiveInfo->service == hashGenerateCryptoPrimitive.serviceUsed){


		if(*(jobInfo.jobPtr->jobPrimitiveInputOutput.outputLengthPtr) <=  HASH_256_LENGTH )
		{
			mbedtls_sha256_context_s sha256_context;

			mbedtls_sha256_init(&sha256_context);

			if(0 !=  mbedtls_sha256_starts_ret(&sha256_context, 0))
			{
				return V2X_E_NOT_OK;
			}

			if(0 !=  mbedtls_sha256_update_ret(&sha256_context, jobInfo.jobPtr->jobPrimitiveInputOutput.inputPtr, jobInfo.jobPtr->jobPrimitiveInputOutput.inputLength))
			{
				return V2X_E_NOT_OK;
			}

			if(0 != mbedtls_sha256_finish_ret(&sha256_context, jobInfo.jobPtr->jobPrimitiveInputOutput.outputPtr))
			{
				return V2X_E_NOT_OK;
			}
		}


	}

/******************************** processing Signature generation jobs ****************************************************/
	else if(jobInfo.jobPtr->jobPrimitiveInfo->primitiveInfo->service == signatureGenerateCryptoPrimitive.serviceUsed){

		// at start turn  driver to busy
		Crypto_State = CRYPTO_ACTIVE_STATE;
		// start process
		current_Job_State = CRYPTO_OPERATIONMODE_START;

		/* Private Key  */
		Asym_Private_Key_Type keyPtr = {0,{0}};

		/* Array to hold signature generate result  */
		uint8 result_sign[ECDSA_GEN_SIGNATURE_SIZE];

		uint32 result_length = ECDSA_GEN_SIGNATURE_SIZE;

		/* Heap buffer */
		uint32 buff_heap[SIGNATURE_GENERATE_CONTEXT_BUFFER_SIZE];


		keyPtr.length = ECDSA_GEN_KEY_LEN;

		/* copying private key to keyPtr */
		memcpy(&keyPtr.data, &private_keys[GenerationKey.CurrentkeyIndex * 32], ECDSA_GEN_KEY_LEN);


		if(0 != Crypto_SignatureGenerate_ECDSA_Start(buff_heap,&keyPtr))
		{
			Crypto_State = CRYPTO_IDEAL_STATE;
			return V2X_E_NOT_OK;
		}

		current_Job_State = CRYPTO_OPERATIONMODE_UPDATE;

		if(0 != Crypto_SignatureGenerate_ECDSA_Update(buff_heap,jobInfo.jobPtr->jobPrimitiveInputOutput.inputPtr,jobInfo.jobPtr->jobPrimitiveInputOutput.inputLength))
		{
			Crypto_State = CRYPTO_IDEAL_STATE;
			return V2X_E_NOT_OK;
		}

		current_Job_State = CRYPTO_OPERATIONMODE_FINISH;



//
//		start_time = rdtsc();
//
//
//
//
//		end_time = rdtsc();
//		ecdsa_ cpu_time_used = (end_time - start_time) / (TICKS_OF_HW_IN_MICROSECINDS);





		if(0 != Crypto_SignatureGenerate_ECDSA_Finish(buff_heap,result_sign,&result_length) )
		{
			Crypto_State = CRYPTO_IDEAL_STATE;
			return V2X_E_NOT_OK;
		}

		if(*(jobInfo.jobPtr->jobPrimitiveInputOutput.outputLengthPtr) >= result_length )
		{

			*(jobInfo.jobPtr->jobPrimitiveInputOutput.outputLengthPtr) = result_length;
			/* Copying result signature the output pointer */
			memcpy(jobInfo.jobPtr->jobPrimitiveInputOutput.outputPtr, result_sign, result_length);

			*(jobInfo.jobPtr->jobPrimitiveInputOutput.verifyPtr) = CRYPTO_E_VER_OK;
		}
		else
		{
			/* output length pointer smaller than the result length  */
			return V2X_E_NOT_OK;
		}

#if(DEBUG_MODE == STD_ON)
		uint32 buff_heap_ver[SIGNATURE_VERIFY_CONTEXT_BUFFER_SIZE];
		Asym_Public_KeyType keyPtr_Ver = {0,{0}};
		keyPtr_Ver.length = ECDSA_VERIFY_KEY_LEN;
		boolean result_ECDSA_verify = TRUE;
		Std_ReturnType result_ECDSA_Ver;
		memcpy(keyPtr_Ver.data, &public_keys[GenerationKey.CurrentkeyIndex * 64], ECDSA_VERIFY_KEY_HALF_LEN);
		memcpy(&(keyPtr_Ver.data[32]), &public_keys[(GenerationKey.CurrentkeyIndex * 64) + 32], ECDSA_VERIFY_KEY_HALF_LEN);

		if(0 != Crypto_SignatureVerify_ECDSA_Start(buff_heap_ver,&keyPtr_Ver) )
		{
			Crypto_State = CRYPTO_IDEAL_STATE;
			return V2X_E_NOT_OK;
		}
		current_Job_State = CRYPTO_OPERATIONMODE_UPDATE;
		if(0 !=Crypto_SignatureVerify_ECDSA_Update(buff_heap_ver,jobInfo.jobPtr->jobPrimitiveInputOutput.inputPtr, jobInfo.jobPtr->jobPrimitiveInputOutput.inputLength))
		{
			Crypto_State = CRYPTO_IDEAL_STATE;
			return V2X_E_NOT_OK;
		}

		current_Job_State = CRYPTO_OPERATIONMODE_FINISH;
		if(0 != Crypto_SignatureVerify_ECDSA_Finish(buff_heap_ver, result_sign,ECDSA_GEN_SIGNATURE_SIZE,&result_ECDSA_Ver))
		{
			Crypto_State = CRYPTO_IDEAL_STATE;
			return V2X_E_NOT_OK;
		}

		if(result_ECDSA_Ver == 0)
		{
			result_ECDSA_verify &= TRUE;
		}
		else
		{
			assert(1);
			printf("*********** verification did not pass\n");
			result_ECDSA_verify &= FALSE;
		}
#endif



		// at end turn driver to idle
		Crypto_State = CRYPTO_IDEAL_STATE;

	}
/*************************************** processing signature verification  ******************************************************/
	else if(jobInfo.jobPtr->jobPrimitiveInfo->primitiveInfo->service == verifyGenerateCryptoPrimitive.serviceUsed){


			// at start turn  driver to busy
			Crypto_State = CRYPTO_ACTIVE_STATE;
			// start process
			current_Job_State = CRYPTO_OPERATIONMODE_START;

			/* Public key for verification */
			Asym_Public_KeyType keyPtr_Ver = {0,{0}};

			uint32 buff_heap_ver[SIGNATURE_VERIFY_CONTEXT_BUFFER_SIZE];

			keyPtr_Ver.length = ECDSA_VERIFY_KEY_LEN;

			Std_ReturnType result_ECDSA_Ver;



			//memcpy(keyPtr_Ver.data, VerificationKey, ECDSA_VERIFY_KEY_LEN);
			memcpy(keyPtr_Ver.data, &VerificationKey[0], ECDSA_VERIFY_KEY_HALF_LEN);
			memcpy(&(keyPtr_Ver.data[32]), &VerificationKey[32], ECDSA_VERIFY_KEY_HALF_LEN);

			if(0 != Crypto_SignatureVerify_ECDSA_Start(buff_heap_ver,&keyPtr_Ver) )
			{
				Crypto_State = CRYPTO_IDEAL_STATE;
				return V2X_E_NOT_OK;
			}
			current_Job_State = CRYPTO_OPERATIONMODE_UPDATE;
			if(0 !=Crypto_SignatureVerify_ECDSA_Update(buff_heap_ver,jobInfo.jobPtr->jobPrimitiveInputOutput.inputPtr, jobInfo.jobPtr->jobPrimitiveInputOutput.inputLength))
			{
				Crypto_State = CRYPTO_IDEAL_STATE;
				return V2X_E_NOT_OK;
			}

			current_Job_State = CRYPTO_OPERATIONMODE_FINISH;
			if(0 != Crypto_SignatureVerify_ECDSA_Finish(buff_heap_ver, jobInfo.jobPtr->jobPrimitiveInputOutput.secondaryInputPtr,ECDSA_GEN_SIGNATURE_SIZE,&result_ECDSA_Ver))
			{
				Crypto_State = CRYPTO_IDEAL_STATE;
				return V2X_E_NOT_OK;
			}

			*(jobInfo.jobPtr->jobPrimitiveInputOutput.verifyPtr)  = result_ECDSA_Ver;
			Crypto_State = CRYPTO_IDEAL_STATE;

	}


	return V2X_E_OK;
}

/************************************************************************************
* Service Name: Crypto_CancelJob
* Service ID[hex]: 0x0e
* Sync/Async: Synchronous
* Reentrancy: Reentrant but not for same Crypto Driver Object
* Parameters (in): objectId Holds the identifier of the Crypto Driver Object.
* Parameters (inout): job Pointer to the configuration of the job.
                      Contains structures with job and primitive relevant information but also pointer to result buffers.
* Parameters (out): None
* Return value: Std_ReturnType
* Description: This interface removes the provided job from the queue and cancels the processing of the job if possible
* Requirements:
************************************************************************************/
Std_ReturnType Crypto_CancelJob (uint32 objectId,Crypto_JobType* job)
{
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)
	/* Check if the Module is initialized before using this function */
	if (Crypto_NOT_INITIALIZED == Crypto_Status)
	{
		Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, CRYPTO_CANCEL_JOB_SID, CRYPTO_E_UNINIT_ID);
		return V2X_E_NOT_OK;
	}

	if(objectId != CRYPTO_DRIVER_OBJECT_ID)
	{
		Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, CRYPTO_CANCEL_JOB_SID, CRYPTO_E_PARAM_HANDLE_ID );
		return V2X_E_NOT_OK;
	}

	if(NULL_PTR == job)
	{
		Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, CRYPTO_PROCESS_JOB_SID, CRYPTO_E_PARAM_POINTER_ID );
		return V2X_E_NOT_OK;
	}
#endif

		//remove the job from the queue
		sint8 res=getJob(job->jobId);
		if(res!=-1 && job->jobPrimitiveInfo->processingType == CRYPTO_PROCESSING_ASYNC)
		{
			/* the main fn checks if priority is not equal -1 before process the job*/
			jobQueue.arr[res].jobPriority = -1;
			return V2X_E_OK;
		}
		else if( res==-1 && job->jobPrimitiveInfo->processingType == CRYPTO_PROCESSING_ASYNC)
			return V2X_E_NOT_OK;

		else if(current_Job_id != job->jobId && job->jobPrimitiveInfo->processingType == CRYPTO_PROCESSING_SYNC)
			//driver currently not process this job, the service Crypto_CancelJob() shall return V2X_E_OK without any processing
			return V2X_E_OK;

return 	V2X_E_NOT_OK;

}
/************************************************************************************
* Service Name: Crypto_MainFunction
* Service ID[hex]: 0x0c
* Sync/Async:
* Parameters (in): None
* Parameters (inout): None
* Parameters (out): None
* Return value: None
* Description: if asynchronous job processing is configured and there are job queues, the function
* 			   is called cyclically to process queued jobs
* Requirements:
************************************************************************************/

void Crypto_MainFunction (void)
{

	//PLL_init();
//invoke higher priority job to process which is the front process but need to check if it cancelled or no jobs in queue
 if(jobQueue.arr[jobQueue.front].jobPriority != -1 && jobQueue.size != 0)
 {

	 Std_ReturnType res= Crypto_ProcessECDSA(jobQueue.arr[jobQueue.front]);
 	 //PLL_DeInit();
	 CryIf_CallbackNotification(jobQueue.arr[jobQueue.front].jobPtr,res);
	 deleteNextJob();
 }
 else if(jobQueue.arr[jobQueue.front].jobPriority== -1)
 {
	 deleteNextJob();
 }


}




Std_ReturnType Crypto_KeyElementSet (
	uint32 cryptoKeyId,
	uint32 keyElementId,
	const uint8* keyPtr,
	uint32 keyLength
)
{
#if (CRYPTO_DEV_ERROR_DETECT == STD_ON)
	if (Crypto_NOT_INITIALIZED == Crypto_Status)
	{
		Det_ReportError(CRYPTO_MODULE_ID, CRYPTO_INSTANCE_ID, CRYPTO_KEYELEMENTSET_SID, CRYPTO_E_UNINIT_ID);
		return V2X_E_NOT_OK;
	}

#endif


	switch (cryptoKeyId)
	{
	case CRYPTO_SIGNATURE_GENERATION_KEY_ID:
		if(keyElementId == CRYPTO_KEY_ELEMENT_INDEX_ID)
		{
			/* KEY Index for Crypto Key used for signature generation */
			if(keyLength != EccSignatureGenerateKey.CryptoKeyTypeRef->CryptoKeyELements[1]->CryptoKeyElementSize )
			{
				/* KeyLength is bigger than the configured key element */
				return V2X_E_NOT_OK;
			}

			memcpy(&GenerationKey.CurrentkeyIndex, (uint8*)keyPtr, keyLength);
		}
		break;
	case CRYPTO_SIGNATURE_VERIFICATION_KEY_ID:
		if(keyElementId == EccSignatureVerifyey.CryptoKeyTypeRef->CryptoKeyELements[0]->CryptoKeyElementId)
		{
			if(keyLength > EccSignatureVerifyey.CryptoKeyTypeRef->CryptoKeyELements[0]->CryptoKeyElementSize)
			{
				/* key length is bigger than the key size configured */
				return V2X_E_NOT_OK;
			}
			else if(keyLength <  EccSignatureVerifyey.CryptoKeyTypeRef->CryptoKeyELements[0]->CryptoKeyElementSize)
			{
				if(EccSignatureVerifyey.CryptoKeyTypeRef->CryptoKeyELements[0]->CryptoKeyElementAllowPartialAcces == FALSE)
				{
					/*partial access is not allowed  */
					return V2X_E_NOT_OK;
				}
			}
			else
			{
				/* KeyLength is equal to the configured key length  */
				if(EccSignatureVerifyey.CryptoKeyTypeRef->CryptoKeyELements[1]->CryptoKeyElementWriteAccess != CRYPTO_WA_ALLOWED)
				{
					/* Write access to this key is not allowed  */
					return V2X_E_NOT_OK;
				}
			}
			/* copying  key from keyPtr to Verification key */
			VerificationKey = keyPtr;
		}
		break;

	}
	return V2X_E_OK;
}





