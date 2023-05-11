#ifndef _CRPYTO_ECDH_CFG_H__
#define _CRYPTO_ECDH_CFG_H__


/* for size-annotated integer types: uint8_t, uint32_t etc. */
#include <stdint.h> 

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define NIST_B163  1
#define NIST_K163  2
#define NIST_B233  3
#define NIST_K233  4
#define NIST_B283  5
#define NIST_K283  6
#define NIST_B409  7
#define NIST_K409  8
#define NIST_B571  9
#define NIST_K571 10


/* Default to a (somewhat) constant-time mode?
   NOTE: The library is _not_ capable of operating in constant-time and leaks information via timing.
         Even if all operations are written const-time-style, it requires the hardware is able to multiply in constant time. 
         Multiplication on ARM Cortex-M processors takes a variable number of cycles depending on the operands...
*/
#ifndef CONST_TIME
  #define CONST_TIME 0
#endif



/* What is the default curve to use? */
#ifndef ECC_CURVE
 #define ECC_CURVE NIST_B163
#endif

#if defined(ECC_CURVE) && (ECC_CURVE != 0)
 #if   (ECC_CURVE == NIST_K163) || (ECC_CURVE == NIST_B163)
  #define CURVE_DEGREE       163
  #define ECC_PRV_KEY_SIZE   24
 #elif (ECC_CURVE == NIST_K233) || (ECC_CURVE == NIST_B233)
  #define CURVE_DEGREE       233
  #define ECC_PRV_KEY_SIZE   32
 #elif (ECC_CURVE == NIST_K283) || (ECC_CURVE == NIST_B283)
  #define CURVE_DEGREE       283
  #define ECC_PRV_KEY_SIZE   36
 #elif (ECC_CURVE == NIST_K409) || (ECC_CURVE == NIST_B409)
  #define CURVE_DEGREE       409
  #define ECC_PRV_KEY_SIZE   52
 #elif (ECC_CURVE == NIST_K571) || (ECC_CURVE == NIST_B571)
  #define CURVE_DEGREE       571
  #define ECC_PRV_KEY_SIZE   72
 #endif
#else
 #error Must define a curve to use
#endif



/* margin for overhead needed in intermediate calculations */
#define BITVEC_MARGIN     3
#define BITVEC_NBITS      (CURVE_DEGREE + BITVEC_MARGIN)
#define BITVEC_NWORDS     ((BITVEC_NBITS + 31) / 32)
#define BITVEC_NBYTES     (sizeof(uint32_t) * BITVEC_NWORDS)



/******************************************************************************/

/* Here the curve parameters are defined. */

#if defined (ECC_CURVE) && (ECC_CURVE != 0)
 #if (ECC_CURVE == NIST_K163)
  #define coeff_a  1
  #define cofactor 2
#endif

 #if (ECC_CURVE == NIST_B163)
  #define coeff_a  1
  #define cofactor 2
#endif

 #if (ECC_CURVE == NIST_K233)
  #define coeff_a  0
  #define cofactor 4
#endif

 #if (ECC_CURVE == NIST_B233)
  #define coeff_a  1
  #define cofactor 2
#endif

 #if (ECC_CURVE == NIST_K283)
  #define coeff_a  0
  #define cofactor 4
#endif

 #if (ECC_CURVE == NIST_B283)
  #define coeff_a  1
  #define cofactor 2
#endif

 #if (ECC_CURVE == NIST_K409)
  #define coeff_a  0
  #define cofactor 4
#endif

 #if (ECC_CURVE == NIST_B409)
  #define coeff_a  1
  #define cofactor 2
 #endif

 #if (ECC_CURVE == NIST_K571)
  #define coeff_a  0
  #define cofactor 4
 #endif

 #if (ECC_CURVE == NIST_B571)
  #define coeff_a  1
  #define cofactor 2
#endif
#endif




#define ECC_PUB_KEY_SIZE     (2 * ECC_PRV_KEY_SIZE)

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* #ifndef _ECDH_H__ */
