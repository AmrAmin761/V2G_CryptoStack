#ifndef ETH_GENERALTYPES_H_
#define ETH_GENERALTYPES_H_

#include "ComStack_Types.h"
#include "Std_Types.h"
typedef uint16 Eth_FrameType ;
typedef uint32 Eth_BufIdxType ;
typedef uint8 Eth_DataType;

#define ETH_GENERAL_TYPES_VENDOR_ID                                  (1000U)

/*
 * Module Version 1.0.0
 */
#define ETH_GENERAL_TYPES_SW_MAJOR_VERSION                           (1U)
#define ETH_GENERAL_TYPES_SW_MINOR_VERSION                           (0U)
#define ETH_GENERAL_TYPES_SW_PATCH_VERSION                           (0U)

/*
 * AUTOSAR Version 4.7.0
 */
#define ETH_GENERAL_TYPES_AR_RELEASE_MAJOR_VERSION                   (4U)
#define ETH_GENERAL_TYPES_AR_RELEASE_MINOR_VERSION                   (7U)
#define ETH_GENERAL_TYPES_AR_RELEASE_PATCH_VERSION                   (0U)


typedef enum {
     ETH_RECEIVED
    ,ETH_NOT_RECEIVED
    ,ETH_RECEIVED_MORE_DATA_AVAILABLE
    ,ETH_RECEIVED_FRAMES_LOST /* not available in 4.2.2 version on */
}Eth_RxStatusType;

typedef enum {
    ETH_MODE_DOWN,
    ETH_MODE_ACTIVE,
	ETH_MODE_TX_OFFLINE,
	ETH_MODE_ACTIVE_WITH_WAKEUP_REQUEST
}Eth_ModeType;


#endif /* ETH_GENERALTYPES_H_ */
