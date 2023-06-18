/*
 ============================================================================
 Name        : Csm_Cfg.c
 Author      : Omar AbdelSamea
 Version     :
 Description : Pre-Compile Configuration Source file.
 ============================================================================
 */

#include "../inc/Csm.h"
/*
 1- array (LUTs) CsmJobInfo, CsmPermitiveJob
 */

/*
 1. [SWS_Csm_91005] Each crypto primitive configuration shall be realized as a
 constant structure of type Crypto_PrimitiveInfoType.

 2. [SWS_Csm_91006] Each job primitive configuration shall be realized as a constant
 structure of type Crypto_JobPrimitiveInfoType.

 3. [SWS_Csm_00028] It shall be possible to create several configurations for each
 cryptographic primitive. One configuration per job per primitive is possible.

 4. [SWS_Csm_00029] When creating a primitive configuration, it shall be possible to
 configure all available and allowed schemes from the underlying Crypto Driver
 Object.

 5. [SWS_Csm_00032] If the asynchronous interface is chosen, each job primitive
 configuration shall contain a callback function.

 6. [SWS_Csm_00940] It shall be possible to queue CSM jobs in configured
 CsmQueues in the CSM.

 */
/*const CsmCallback CsmJobPrimitiveCallbackRef[3]=
		{&V2xM_GenerateCallbackNotification
		,&V2xM_VerifyCallbackNotification,
		&V2xM_HashCallbackNotification };*/

const CsmSignatureGenerateConfig CsmJobPrimitiveRef1=
{ CRYPTO_ALGOFAM_ECCSEC, CRYPTO_ALGOMODE_NOT_SET, CRYPTO_ALGOFAM_NOT_SET, KEY_LENGTH_USED };
const CsmSignatureVerifyConfig CsmJobPrimitiveRef2={ CRYPTO_ALGOFAM_ECCSEC, CRYPTO_ALGOMODE_NOT_SET, CRYPTO_ALGOFAM_NOT_SET, KEY_LENGTH_USED };
const CsmHashConfig CsmJobPrimitiveRef3= {CRYPTO_ALGOFAM_SHA2_256 , 0, 0, KEY_LENGTH_USED } ;
const CsmPrimitives primitive1=
{CsmJobPrimitiveRef1,CsmJobPrimitiveRef2,CsmJobPrimitiveRef3};
const CsmQueue csmQueue = { MAX_QUEUE_SIZE, &cryIfChannel1, { 0.1 } };


/*signature structs */
const Crypto_AlgorithmInfoType signature_algo_info =
{       CRYPTO_ALGOFAM_ECCSEC,
		CRYPTO_ALGOFAM_NOT_SET,
		KEY_LENGTH_USED,
		CRYPTO_ALGOMODE_NOT_SET
};

const Crypto_PrimitiveInfoType signature_primitiveInfo ={32,7,signature_algo_info};

const Crypto_JobPrimitiveInfoType signature_info={0,&signature_primitiveInfo,CRYIF_KEY_ID1,CRYPTO_PROCESSING_ASYNC,FALSE};

/*verify structs */

const Crypto_AlgorithmInfoType verify_algo_info =
{       CRYPTO_ALGOFAM_ECCSEC,
		CRYPTO_ALGOFAM_NOT_SET,
		KEY_LENGTH_USED,
		CRYPTO_ALGOMODE_NOT_SET};
const Crypto_PrimitiveInfoType verify_primitiveInfo ={32,CRYPTO_SIGNATUREVERIFY,verify_algo_info};

const Crypto_JobPrimitiveInfoType verify_info=
{1,&verify_primitiveInfo,CRYIF_KEY_ID2,CRYPTO_PROCESSING_ASYNC,FALSE};

/* Hash Structs */


const Crypto_AlgorithmInfoType hash_algo_info =
{       CRYPTO_ALGOFAM_SHA2_256,
		CRYPTO_ALGOFAM_NOT_SET,
		KEY_LENGTH_USED,
		CRYPTO_ALGOMODE_NOT_SET};
const Crypto_PrimitiveInfoType hash_primitiveInfo ={32,CRYPTO_HASH,hash_algo_info};

const Crypto_JobPrimitiveInfoType hash_info=
{2,&hash_primitiveInfo,CRYIF_KEY_ID3,CRYPTO_PROCESSING_ASYNC,FALSE};

/*Key Exchange Structs*/
const Crypto_AlgorithmInfoType ecdh_algo_info =
{       CRYPTO_ALGOFAM_ECDH,
		CRYPTO_ALGOFAM_NOT_SET,
		KEY_LENGTH_USED,//key-length = 192
		CRYPTO_ALGOMODE_NOT_SET};
const Crypto_PrimitiveInfoType ecdh_primitiveInfo ={32,CRYPTO_KEYEXCHANGECALCPUBVAL,ecdh_algo_info};

const Crypto_JobPrimitiveInfoType ecdh_info=
{2,&ecdh_primitiveInfo,CRYIF_KEY_ID3,CRYPTO_PROCESSING_ASYNC,FALSE};

/* Encrypt Structs*/
const Crypto_AlgorithmInfoType 3-des_algo_info =
{       CRYPTO_ALGOFAM_3DES,
		CRYPTO_ALGOFAM_NOT_SET,
		KEY_LENGTH_USED,//key-length = 192
		CRYPTO_ALGOMODE_ECB};

const Crypto_PrimitiveInfoType Encrypt_primitiveInfo ={64,CRYPTO_ENCRYPT,3-des_algo_info};
const Crypto_PrimitiveInfoType Decrypt_primitiveInfo ={64,CRYPTO_DECRYPT,3-des_algo_info};

const Crypto_JobPrimitiveInfoType Encrypt_info=
{2,&Encrypt_primitiveInfo,CRYIF_KEY_ID3,CRYPTO_PROCESSING_ASYNC,FALSE};
const Crypto_JobPrimitiveInfoType Decrypt_info=
{2,&Decrypt_primitiveInfo,CRYIF_KEY_ID4,CRYPTO_PROCESSING_ASYNC,FALSE};


const CsmJob generateSignatureCsmJob = {
CSM_JOB_ID1,
USE_FNC,
JOB_PRIORITY_SIGNATURE_GENERATE,
USE_FNC, CRYPTO_PROCESSING_ASYNC, &csmKey, &CsmJobPrimitiveCallbackRef1,
		&primitive1,
		&csmQueue };

const CsmJob verifySignatureCsmJob = {
CSM_JOB_ID2,
USE_FNC,
JOB_PRIORITY_SIGNATURE_VERIFY,
USE_FNC, CRYPTO_PROCESSING_ASYNC, &csmKey, &CsmJobPrimitiveCallbackRef2,
		&primitive1, &csmQueue };

const CsmJob hashCsmJob = {
CSM_JOB_ID3,
USE_FNC,
JOB_PRIORITY_HASH,
USE_FNC, CRYPTO_PROCESSING_ASYNC, &csmKey, &CsmJobPrimitiveCallbackRef3,
		&primitive1, &csmQueue };
const CsmJob *CsmJobs[] = { &generateSignatureCsmJob, &verifySignatureCsmJob,
		&hashCsmJob };

