#ifndef __FOTA_H
#define __FOTA_H



#include "stm32f4xx.h"
#include <stdio.h>

/* FOTA error code */
typedef enum {
    FOTA_NO_ERR             =  0,
    FOTA_GENERAL_ERR        = -1,    /* general error */
    FOTA_CHECK_FAILED       = -2,    /* check failed */
    FOTA_ALGO_NOT_SUPPORTED = -3,    /* firmware algorithm not supported */
    FOTA_COPY_FAILED        = -4,    /* copy firmware to destination partition failed */
    FOTA_FW_VERIFY_FAILED   = -5,    /* firmware verify failed */
    FOTA_NO_MEM_ERR         = -6,    /* no memory */
    FOTA_PART_READ_ERR      = -7,    /* partition read error */
    FOTA_PART_WRITE_ERR     = -8,    /* partition write error */
    FOTA_PART_ERASE_ERR     = -9,    /* partition erase error */
} fota_err_t;

/**
 * FOTA firmware encryption algorithm and compression algorithm
 */
enum fota_algo
{
    FOTA_CRYPT_ALGO_NONE    = 0x0L,               /**< no encryption algorithm and no compression algorithm */
    FOTA_CRYPT_ALGO_XOR     = 0x1L,               /**< XOR encryption */
    FOTA_CRYPT_ALGO_AES256  = 0x2L,               /**< AES256 encryption */
    FOTA_CMPRS_ALGO_GZIP    = 0x1L << 8,          /**< Gzip: zh.wikipedia.org/wiki/Gzip */
    FOTA_CMPRS_ALGO_QUICKLZ = 0x2L << 8,          /**< QuickLZ: www.quicklz.com */
    FOTA_CMPRS_ALGO_FASTLZ  = 0x3L << 8,          /**< FastLZ: fastlz.org/ */

    FOTA_CRYPT_STAT_MASK    = 0xFL,
    FOTA_CMPRS_STAT_MASK    = 0xFL << 8,
};
typedef enum fota_algo fota_algo_t;


#define FOTA_SW_VERSION      "1.0.0"


/* FOTA application partition name */
#ifndef FOTA_APP_PART_NAME
#define FOTA_APP_PART_NAME   "application"
#endif

/* FOTA download partition name */
#ifndef FOTA_FM_PART_NAME
#define FOTA_FM_PART_NAME    "download"
#endif

/* FOTA default partition name */
#ifndef FOTA_DF_PART_NAME
#define FOTA_DF_PART_NAME    "default"
#endif

/* AES256 encryption algorithm option */
#define FOTA_ALGO_AES_IV  	"0123456789ABCDEF"
#define FOTA_ALGO_AES_KEY 	"0123456789ABCDEF0123456789ABCDEF"


#define FOTA_GET_CHAR_WAITTIGN		    5*1000
#define FOTA_BLOCK_HEADER_SIZE			4
#define FOTA_ALGO_BUFF_SIZE				4096
#define FOTA_CMPRS_BUFFER_SIZE			4096
#define FOTA_FASTLZ_BUFFER_PADDING 		FASTLZ_BUFFER_PADDING(FOTA_CMPRS_BUFFER_SIZE)
#define FOTA_QUICKLZ_BUFFER_PADDING		QLZ_BUFFER_PADDING
long Fota_Task_Init(void);

#endif
