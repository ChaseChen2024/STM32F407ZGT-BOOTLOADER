#include "user.h"
#include "bsp_usart3.h"

#include <string.h>


#include "FreeRTOS.h"
#include "task.h"

#ifdef USER_LEETTER_SHELL
#include "shell_port.h"
#endif
#ifdef USE_FAL_CODE
#include "fal.h"
#endif
#include "fota.h"
#include <tinycrypt.h>
#include <fastlz.h>
#include <quicklz.h>

static TaskHandle_t Fota_Task_Handle = NULL;

typedef struct {
	char type[4];
	uint16_t fota_algo;
	uint8_t fm_time[6];
	char app_part_name[16];
	char download_version[24];
	char current_version[24];
	uint32_t code_crc;
	uint32_t hash_val;
	uint32_t raw_size;
	uint32_t com_size;
	uint32_t head_crc;
} free_fota_part_head, *fota_part_head_t;

static free_fota_part_head fota_part_head;

typedef void (*fota_app_func)(void);	
static fota_app_func app_func = NULL;
static int fota_boot_verify(void)
{
	int fota_res = FOTA_NO_ERR;

	memset(&fota_part_head, 0x0, sizeof(free_fota_part_head));
	
	/* partition initial */
	#ifdef USE_FAL_CODE
    fal_init();
    #endif

	extern int fal_init_check(void);
	/* verify partition */
	if (fal_init_check() != 1)
    {
    	log_i("Partition initialized failed!");
		fota_res = FOTA_GENERAL_ERR;
		goto __exit_boot_verify;
    }

__exit_boot_verify:
	return fota_res;
}
extern SemaphoreHandle_t Usart1_BinarySem_Handle;
static int fota_get_shell_key(void)
{
	char ch;
	int res = 0;
	uint32_t timeout = FOTA_GET_CHAR_WAITTIGN;
	uint32_t tick_start, tick_stop;
	log_i("timeout:%d",timeout);
	//ASSERT(shell_dev !=NULL);
	//ASSERT(shell_sem !=NULL);
    
	tick_start = xTaskGetTickCount();
	while (1)
	{
        
        if(xSemaphoreTake(Usart1_BinarySem_Handle, timeout)==pdFALSE)
        {
            res = -1;
		 	goto __exit_get_shell_key;
			
			
        }
        if(READ_IT_FLAG == 1)
        {
			log_i("READ_IT_FLAG:%x",READ_IT_FLAG);
            READ_IT_FLAG = 0;
            if(strlen(SHELL_RX_BUF) >= 1)
            {
                ch = SHELL_RX_BUF[0];
            }
            memset(SHELL_RX_BUF, 0, USART1_BUFF_SIZE);
			log_i("ch:%x",ch);
			if (ch == 0x0d)
				goto __exit_get_shell_key;
        }	
		

		tick_stop = xTaskGetTickCount();
		if ((tick_stop - tick_start) > FOTA_GET_CHAR_WAITTIGN)
		{
			res = -1;
			goto __exit_get_shell_key;
			
		}

		timeout = FOTA_GET_CHAR_WAITTIGN*portTICK_PERIOD_MS - tick_stop + tick_start;
	}

__exit_get_shell_key:
	return res;
}

#if 1
int fota_part_fw_verify(const char *part_name)
{
#define FOTA_CRC_BUFF_SIZE		4096
#define FOTA_CRC_INIT_VAL		0xffffffff

	int fota_res = FOTA_NO_ERR;
	const struct fal_partition *part;
	free_fota_part_head part_head;
	uint8_t *body_buf = NULL;
	uint32_t body_crc = FOTA_CRC_INIT_VAL;
	uint32_t hdr_crc;

	if (part_name == NULL)
	{
		log_d("Invaild paramenter input!");
		fota_res = FOTA_GENERAL_ERR;
		goto __exit_partition_verify;
	}

	part = fal_partition_find(part_name);
	if (part == NULL)
	{		
		log_d("Partition[%s] not found.", part_name);
		fota_res =FOTA_GENERAL_ERR;
		goto __exit_partition_verify;
	}

	/* read the head of RBL files */
	if (fal_partition_read(part, 0, (uint8_t *)&part_head, sizeof(free_fota_part_head)) < 0)
	{
		log_d("Partition[%s] read error!", part->name);
		fota_res =FOTA_PART_READ_ERR;
		goto __exit_partition_verify;
	}

	extern uint32_t fota_crc(uint8_t *buf, uint32_t len);
	hdr_crc = fota_crc((uint8_t *)&part_head, sizeof(free_fota_part_head) - 4);
	if (hdr_crc != part_head.head_crc)
	{
		log_d("Partition[%s] head CRC32 error!", part->name);
		fota_res =FOTA_FW_VERIFY_FAILED;
		goto __exit_partition_verify;
	}
	
	if (strcmp(part_head.type, "RBL") != 0)
	{
		log_d("Partition[%s] type[%s] not surport.", part->name, part_head.type);
		fota_res =FOTA_CHECK_FAILED;
		goto __exit_partition_verify;
	}

	if (fal_partition_find(part_head.app_part_name) ==NULL)
	{
		log_d("Partition[%s] not found.", part_head.app_part_name);
		fota_res =FOTA_FW_VERIFY_FAILED;
		goto __exit_partition_verify;
	}

	body_buf = pvPortMalloc(FOTA_CRC_BUFF_SIZE);
	if (body_buf ==NULL)
	{
		log_d("Not enough memory for body CRC32 verify.");	
		fota_res =FOTA_NO_MEM_ERR;
		goto __exit_partition_verify;
	}

	for (int body_pos = 0; body_pos < part_head.com_size;)
	{	
		int body_read_len = fal_partition_read(part, sizeof(free_fota_part_head) + body_pos, body_buf,FOTA_CRC_BUFF_SIZE);      
		if (body_read_len > 0) 
		{
            if ((body_pos + body_read_len) > part_head.com_size)
            {
                body_read_len = part_head.com_size - body_pos;
            }
            
			extern uint32_t fota_step_crc(uint32_t crc,uint8_t *buf, uint32_t len);
			body_crc = fota_step_crc(body_crc, body_buf, body_read_len);	
			body_pos = body_pos + body_read_len;
		}
		else
		{
			log_d("Partition[%s] read error!", part->name);		
			fota_res =FOTA_PART_READ_ERR;
			goto __exit_partition_verify;
		}
	}
	body_crc = body_crc ^FOTA_CRC_INIT_VAL;
	
	if (body_crc != part_head.code_crc)
	{
		log_d("Partition[%s] firmware integrity verify failed.", part->name);		
		fota_res =FOTA_FW_VERIFY_FAILED;
		goto __exit_partition_verify;
	}

__exit_partition_verify:
	if (fota_res ==FOTA_NO_ERR)
	{
		vTaskSuspendAll();
		memcpy(&fota_part_head, &part_head, sizeof(free_fota_part_head));
		xTaskResumeAll();

		log_d("partition[%s] verify success!", part->name);
	}
	else
	{
		vTaskSuspendAll();
		memset(&fota_part_head, 0x0, sizeof(free_fota_part_head));
		xTaskResumeAll();
		
		log_d("Partition[%s] verify failed!", part->name);
	}

	if (body_buf)
		vPortFree(body_buf);
	
	return fota_res;
}


#endif
int fota_check_upgrade(void)
{
	int is_upgrade = 0;

	if (strcmp(fota_part_head.download_version, fota_part_head.current_version) != 0)
	{
		is_upgrade = 1;
		log_d("Application need upgrade.");
		goto __exit_check_upgrade;
	}

__exit_check_upgrade:
	return is_upgrade;
}


int fota_erase_app_part(void)
{
	int fota_res = FOTA_NO_ERR;
	const struct fal_partition *part;

	part = fal_partition_find(fota_part_head.app_part_name);
	if (part == NULL)
	{
		log_d("Erase partition[%s] not found.", fota_part_head.app_part_name);
		fota_res = FOTA_FW_VERIFY_FAILED;
		goto __exit_partition_erase;
	}
    
    log_i("Partition[%s] erase start:", part->name);
	if (fal_partition_erase(part, 0, fota_part_head.raw_size) < 0)
	{
		log_d("Partition[%s] erase failed!", part->name);
		fota_res = FOTA_PART_ERASE_ERR;
		goto __exit_partition_erase;
	}

__exit_partition_erase:
	if (fota_res == FOTA_NO_ERR)
	{
		log_d("Partition[%s] erase %d bytes success!", part->name, fota_part_head.raw_size);
	}
	return fota_res;
}
static int fota_read_part(const struct fal_partition *part, int read_pos, tiny_aes_context *aes_ctx, uint8_t *aes_iv, uint8_t *decrypt_buf, uint32_t decrypt_len)
{
	int fota_err = FOTA_NO_ERR;
	uint8_t *encrypt_buf = NULL;

	if ((part == NULL) || (decrypt_buf == NULL) 
		|| (decrypt_len % 16 != 0) || (decrypt_len > FOTA_ALGO_BUFF_SIZE))
	{
		fota_err = FOTA_GENERAL_ERR;
		goto __exit_read_decrypt;
	}

	memset(decrypt_buf, 0x0, decrypt_len);

	/* Not use AES256 algorithm */
	if (aes_ctx == NULL || aes_iv == NULL)
	{
		fota_err = fal_partition_read(part, sizeof(free_fota_part_head) + read_pos, decrypt_buf, decrypt_len);
		if (fota_err <= 0)
		{
			fota_err = FOTA_PART_READ_ERR;
		}
		goto __exit_read_decrypt;
	}

	encrypt_buf = pvPortMalloc(decrypt_len);
	if (encrypt_buf == NULL)
	{
		fota_err = FOTA_GENERAL_ERR;
		goto __exit_read_decrypt;
	}
	memset(encrypt_buf, 0x0, decrypt_len);

	fota_err = fal_partition_read(part, sizeof(free_fota_part_head) + read_pos, encrypt_buf, decrypt_len);
	if (fota_err <= 0 || fota_err % 16 != 0)
	{
		fota_err = FOTA_PART_READ_ERR;
		goto __exit_read_decrypt;
	}

	tiny_aes_crypt_cbc(aes_ctx, AES_DECRYPT, fota_err, aes_iv, encrypt_buf, decrypt_buf);
__exit_read_decrypt:
	if (encrypt_buf)
		vPortFree(encrypt_buf);
	
	return fota_err;
}

int fota_write_app_part(int fw_pos, uint8_t *fw_buf, int fw_len)
{
	int fota_res = FOTA_NO_ERR;
	const struct fal_partition *part;

	part = fal_partition_find(fota_part_head.app_part_name);
	if (part == NULL)
	{
		log_d("Erase partition[%s] not found.", fota_part_head.app_part_name);
		fota_res = FOTA_FW_VERIFY_FAILED;
		goto __partition_write_exit;
	}

	if (fal_partition_write(part, fw_pos, fw_buf, fw_len) < 0)
	{
		log_d("Partition[%s] write failed!", part->name);
		fota_res = FOTA_PART_WRITE_ERR;
		goto __partition_write_exit;
	}
__partition_write_exit:
	if (fota_res == FOTA_NO_ERR)
	{
		log_d("Partition[%s] write %d bytes success!", part->name, fw_len);
	}
	return fota_res;
}
int fota_upgrade(const char *part_name)
{
	int fota_err = FOTA_NO_ERR;
	
	const struct fal_partition *part;
	fota_part_head_t part_head = NULL;
	
	tiny_aes_context *aes_ctx = NULL;
	uint8_t *aes_iv = NULL;
	uint8_t *crypt_buf = NULL;
	
	int fw_raw_pos = 0;
	int fw_raw_len = 0;
	uint32_t total_copy_size = 0;

	uint8_t block_hdr_buf[FOTA_BLOCK_HEADER_SIZE];	
	uint32_t block_hdr_pos = FOTA_ALGO_BUFF_SIZE;
	uint32_t block_size = 0;
	uint32_t dcprs_size = 0;
	
	qlz_state_decompress *dcprs_state = NULL;
	uint8_t *cmprs_buff = NULL;
	uint8_t *dcprs_buff = NULL;
	uint32_t padding_size = 0;

	if (part_name == NULL)
	{
		log_d("Invaild paramenter input!");
		fota_err = FOTA_GENERAL_ERR;
		goto __exit_upgrade;
	}

	part = fal_partition_find(part_name);
	if (part == NULL)
	{		
		log_d("Upgrade partition[%s] not found.", part_name);
		fota_err = FOTA_GENERAL_ERR;
		goto __exit_upgrade;
	}
	
	/* Application partition erase */
	fota_err = fota_erase_app_part();
	if (fota_err != FOTA_NO_ERR)
	{
		goto __exit_upgrade;
	}

	/* fota_erase_app_part() has check fota_part_head vaild already */
	part_head = &fota_part_head;

	crypt_buf = pvPortMalloc(FOTA_ALGO_BUFF_SIZE);
	if (crypt_buf == NULL)
	{
		log_d("Not enough memory for firmware buffer.");
		fota_err = FOTA_NO_MEM_ERR;
		goto __exit_upgrade;
	}

	/* AES256 algorithm enable */
	if ((part_head->fota_algo & FOTA_CRYPT_STAT_MASK) == FOTA_CRYPT_ALGO_AES256)
	{
		aes_ctx = pvPortMalloc(sizeof(tiny_aes_context));	
		aes_iv = pvPortMalloc(strlen(FOTA_ALGO_AES_IV) + 1);		
		if (aes_ctx == NULL || aes_iv == NULL)
		{
			log_d("Not enough memory for firmware hash verify.");
			fota_err = FOTA_NO_MEM_ERR;
			goto __exit_upgrade;
		}

		memset(aes_iv, 0x0, strlen(FOTA_ALGO_AES_IV) + 1);
		memcpy(aes_iv, FOTA_ALGO_AES_IV, strlen(FOTA_ALGO_AES_IV));
		tiny_aes_setkey_dec(aes_ctx, (uint8_t *)FOTA_ALGO_AES_KEY, 256);
	}
	else if ((part_head->fota_algo & FOTA_CRYPT_STAT_MASK) == FOTA_CRYPT_ALGO_XOR)
	{
		log_i("Not surpport XOR.");
		fota_err = FOTA_GENERAL_ERR;
		goto __exit_upgrade;
	}
	
	/* If enable fastlz compress function */	
	if ((part_head->fota_algo & FOTA_CMPRS_STAT_MASK) == FOTA_CMPRS_ALGO_FASTLZ) 
	{
		cmprs_buff = pvPortMalloc(FOTA_CMPRS_BUFFER_SIZE + FOTA_FASTLZ_BUFFER_PADDING);
		dcprs_buff = pvPortMalloc(FOTA_CMPRS_BUFFER_SIZE);	
		if (cmprs_buff == NULL || dcprs_buff == NULL)
		{
			log_d("Not enough memory for firmware hash verify.");
			fota_err = FOTA_NO_MEM_ERR;
			goto __exit_upgrade;
		}

		padding_size = FOTA_FASTLZ_BUFFER_PADDING;
	}
	else if ((part_head->fota_algo & FOTA_CMPRS_STAT_MASK) == FOTA_CMPRS_ALGO_QUICKLZ) 
	{
		cmprs_buff = pvPortMalloc(FOTA_CMPRS_BUFFER_SIZE + FOTA_QUICKLZ_BUFFER_PADDING);
		dcprs_buff = pvPortMalloc(FOTA_CMPRS_BUFFER_SIZE);	
		dcprs_state = pvPortMalloc(sizeof(qlz_state_decompress));
		if (cmprs_buff == NULL || dcprs_buff == NULL || dcprs_state == NULL)
		{
			log_d("Not enough memory for firmware hash verify.");
			fota_err = FOTA_NO_MEM_ERR;
			goto __exit_upgrade;
		}

		padding_size = FOTA_QUICKLZ_BUFFER_PADDING;
		memset(dcprs_state, 0x0, sizeof(qlz_state_decompress));
	}
	else if ((part_head->fota_algo & FOTA_CMPRS_STAT_MASK) == FOTA_CMPRS_ALGO_GZIP) 
	{
		log_i("Not surpport GZIP.");
		fota_err = FOTA_GENERAL_ERR;
		goto __exit_upgrade;
	}

	log_i("Start to copy firmware from %s to %s partition:", part->name, part_head->app_part_name);
	while (fw_raw_pos < part_head->com_size)
	{
		if ((part_head->fota_algo & FOTA_CMPRS_STAT_MASK) != FOTA_CRYPT_ALGO_NONE) 
		{		
			if (block_hdr_pos >= FOTA_ALGO_BUFF_SIZE)
			{
				fw_raw_len = fota_read_part(part, fw_raw_pos, aes_ctx, aes_iv, crypt_buf, FOTA_ALGO_BUFF_SIZE);
				if (fw_raw_len < 0)
				{
					log_d("AES256 algorithm failed.");
					fota_err = FOTA_PART_READ_ERR;
					goto __exit_upgrade;
				}
				fw_raw_pos += fw_raw_len;

				memcpy(block_hdr_buf, crypt_buf,FOTA_BLOCK_HEADER_SIZE);
				block_size = block_hdr_buf[0] * (1 << 24) + block_hdr_buf[1] * (1 << 16) + block_hdr_buf[2] * (1 << 8) + block_hdr_buf[3];
				memset(cmprs_buff, 0x0, FOTA_CMPRS_BUFFER_SIZE + padding_size);
				memcpy(cmprs_buff, &crypt_buf[FOTA_BLOCK_HEADER_SIZE], block_size);

				block_hdr_pos = FOTA_BLOCK_HEADER_SIZE + block_size;
			}
			else
			{
				uint8_t hdr_tmp_pos = 0;
				while (block_hdr_pos < FOTA_ALGO_BUFF_SIZE)
				{
					if (hdr_tmp_pos < FOTA_BLOCK_HEADER_SIZE)
					{
						block_hdr_buf[hdr_tmp_pos++] = crypt_buf[block_hdr_pos++];
					}
					else
					{
						block_size = block_hdr_buf[0] * (1 << 24) + block_hdr_buf[1] * (1 << 16) + block_hdr_buf[2] * (1 << 8) + block_hdr_buf[3];
						
						memset(cmprs_buff, 0x0, FOTA_CMPRS_BUFFER_SIZE + padding_size);
						if (block_size > (FOTA_ALGO_BUFF_SIZE - block_hdr_pos))
						{								
							memcpy(cmprs_buff, &crypt_buf[block_hdr_pos], (FOTA_ALGO_BUFF_SIZE - block_hdr_pos));
							fw_raw_len = fota_read_part(part, fw_raw_pos, aes_ctx, aes_iv, crypt_buf, FOTA_ALGO_BUFF_SIZE);
							if (fw_raw_len < 0)
							{
								log_d("AES256 algorithm failed.");
								fota_err = FOTA_PART_READ_ERR;
								goto __exit_upgrade;
							}
							fw_raw_pos += fw_raw_len;

							memcpy(&cmprs_buff[FOTA_ALGO_BUFF_SIZE - block_hdr_pos], &crypt_buf[0], (block_size +  block_hdr_pos) - FOTA_ALGO_BUFF_SIZE);
							block_hdr_pos = (block_size +  block_hdr_pos) - FOTA_ALGO_BUFF_SIZE;
						}
						else
						{
							memcpy(cmprs_buff, &crypt_buf[block_hdr_pos], block_size);
							block_hdr_pos = block_hdr_pos + block_size;
						}						
						break;
					}
				}
				
				if (hdr_tmp_pos < FOTA_BLOCK_HEADER_SIZE)
				{				
					fw_raw_len = fota_read_part(part, fw_raw_pos, aes_ctx, aes_iv, crypt_buf, FOTA_ALGO_BUFF_SIZE);
					if (fw_raw_len < 0)
					{
						log_d("AES256 algorithm failed.");
						fota_err = FOTA_PART_READ_ERR;
						goto __exit_upgrade;
					}
					fw_raw_pos += fw_raw_len;

					block_hdr_pos = 0;
					while (hdr_tmp_pos < FOTA_BLOCK_HEADER_SIZE)
					{
						block_hdr_buf[hdr_tmp_pos++] = crypt_buf[block_hdr_pos++];
					}
					block_size = block_hdr_buf[0] * (1 << 24) + block_hdr_buf[1] * (1 << 16) + block_hdr_buf[2] * (1 << 8) + block_hdr_buf[3];

					memset(cmprs_buff, 0x0, FOTA_CMPRS_BUFFER_SIZE + padding_size);
					memcpy(cmprs_buff, &crypt_buf[block_hdr_pos], block_size);

					block_hdr_pos = (block_hdr_pos + block_size) % FOTA_ALGO_BUFF_SIZE;
				}
			}

			memset(dcprs_buff, 0x0, FOTA_CMPRS_BUFFER_SIZE);		
			if ((part_head->fota_algo & FOTA_CMPRS_STAT_MASK) == FOTA_CMPRS_ALGO_FASTLZ) 
			{
				dcprs_size = fastlz_decompress((const void *)&cmprs_buff[0], block_size, &dcprs_buff[0], FOTA_CMPRS_BUFFER_SIZE);
				log_d("1111Decompress failed: %d.", dcprs_size);
			}
			else if ((part_head->fota_algo & FOTA_CMPRS_STAT_MASK) == FOTA_CMPRS_ALGO_QUICKLZ) 
			{
				dcprs_size = qlz_decompress((const char *)&cmprs_buff[0], &dcprs_buff[0], dcprs_state);
				log_d("2222Decompress failed: %d.", dcprs_size);
			}
			
			if (dcprs_size <= 0)
			{
				log_d("Decompress failed: %d.", dcprs_size);
				fota_err = FOTA_GENERAL_ERR;
				goto __exit_upgrade;
			}

			if (fota_write_app_part(total_copy_size, dcprs_buff, dcprs_size) < 0)
			{
				fota_err = FOTA_COPY_FAILED;
				goto __exit_upgrade;
			}

			total_copy_size += dcprs_size;
			shellPrint(&shell,"#");
		}
		/* no compress option */
		else
		{
			fw_raw_len = fota_read_part(part, fw_raw_pos, aes_ctx, aes_iv, crypt_buf, FOTA_ALGO_BUFF_SIZE);
			if (fw_raw_len < 0)
			{
				log_d("AES256 algorithm failed.");
				fota_err = FOTA_PART_READ_ERR;
				goto __exit_upgrade;
			}		
			fw_raw_pos += fw_raw_len;

			if (fota_write_app_part(total_copy_size, crypt_buf, fw_raw_len) < 0)
			{
				fota_err = FOTA_COPY_FAILED;
				goto __exit_upgrade;
			}
			
			total_copy_size += fw_raw_len;
			shellPrint(&shell,"#");
		}
	}

	/* it has compress option */
	if ((part_head->fota_algo & FOTA_CMPRS_STAT_MASK) != FOTA_CRYPT_ALGO_NONE)
	{
        while (total_copy_size < part_head->raw_size)
        {
            if ((block_hdr_pos < fw_raw_len) && ((fw_raw_len - block_hdr_pos) > FOTA_BLOCK_HEADER_SIZE))
            {
                memcpy(block_hdr_buf, &crypt_buf[block_hdr_pos], FOTA_BLOCK_HEADER_SIZE);
                block_size = block_hdr_buf[0] * (1 << 24) + block_hdr_buf[1] * (1 << 16) + block_hdr_buf[2] * (1 << 8) + block_hdr_buf[3];
                if ((fw_raw_len - block_hdr_pos - FOTA_BLOCK_HEADER_SIZE) >= block_size)
                {
                    memset(cmprs_buff, 0x0, FOTA_CMPRS_BUFFER_SIZE + padding_size);				
                    memcpy(cmprs_buff, &crypt_buf[block_hdr_pos + FOTA_BLOCK_HEADER_SIZE], block_size);
                    memset(dcprs_buff, 0x0, FOTA_CMPRS_BUFFER_SIZE);
                    
                    block_hdr_pos += (block_size + FOTA_BLOCK_HEADER_SIZE);

                    if ((part_head->fota_algo & FOTA_CMPRS_STAT_MASK) == FOTA_CMPRS_ALGO_FASTLZ) 
                    {
                        dcprs_size = fastlz_decompress((const void *)&cmprs_buff[0], block_size, &dcprs_buff[0], FOTA_CMPRS_BUFFER_SIZE);
                    }
                    else if ((part_head->fota_algo & FOTA_CMPRS_STAT_MASK) == FOTA_CMPRS_ALGO_QUICKLZ) 
                    {
                        dcprs_size = qlz_decompress((const char *)&cmprs_buff[0], &dcprs_buff[0], dcprs_state);
                    }
                
                    if (dcprs_size <= 0)
                    {
                        log_d("Decompress failed: %d.", dcprs_size);
                        fota_err = FOTA_GENERAL_ERR;
                        goto __exit_upgrade;
                    }

                    if (fota_write_app_part(total_copy_size, dcprs_buff, dcprs_size) < 0)
                    {
                        fota_err = FOTA_COPY_FAILED;
                        goto __exit_upgrade;
                    }

                    total_copy_size += dcprs_size;
                    shellPrint(&shell,"#");
                }
                else
                {
                    break;
                }                                
            }
            else
            {
                break;
            }
        }
	}
    shellPrint(&shell,"\r\n");

	/* 有可能两个值不相等,因为AES需要填充16字节整数,但最后的解密解压值的代码数量必须是大于等于raw_size */
	/* 比较好的方法是做一个校验,目前打包软件的HASH_CODE算法不知道 */
	if (total_copy_size < part_head->raw_size)
	{
		log_d("Decompress check failed.");
		fota_err = FOTA_GENERAL_ERR;
	}

__exit_upgrade:
	if (aes_ctx)
		vPortFree(aes_ctx);

	if (aes_iv)
		vPortFree(aes_iv);

	if (crypt_buf)
		vPortFree(crypt_buf);

	if (cmprs_buff)
		vPortFree(cmprs_buff);

	if (dcprs_buff)
		vPortFree(dcprs_buff);

	if (dcprs_state)
		vPortFree(dcprs_state);

	if (fota_err == FOTA_NO_ERR)
	{
    	log_i("Upgrade success, total %d bytes.", total_copy_size);
	}
	return fota_err;
}

int fota_copy_version(const char *part_name)
{
#define THE_NOR_FLASH_GRANULARITY		4096

	int fota_res = FOTA_NO_ERR;
	const struct fal_partition *part;
    
    fota_part_head_t part_head = NULL;
    uint8_t *cache_buf = NULL;

	part = fal_partition_find(part_name);
	if (part == NULL)
	{
		log_d("Find partition[%s] not found.", part_name);
		fota_res = FOTA_FW_VERIFY_FAILED;
		goto __exit_copy_version;
	}
	    
    cache_buf = pvPortMalloc(THE_NOR_FLASH_GRANULARITY);
    if (cache_buf == NULL)
    {
        log_d("Not enough memory for head erase.");
        fota_res = FOTA_NO_MEM_ERR;
        goto __exit_copy_version;
    }
    part_head = (fota_part_head_t)cache_buf;
	
	if (fal_partition_read(part, 0, cache_buf, THE_NOR_FLASH_GRANULARITY) < 0)
	{
		log_i("Read partition[%s] failed.", part_name);
		fota_res = FOTA_PART_READ_ERR;
		goto __exit_copy_version;
	}
	
	memcpy(part_head->current_version, part_head->download_version, sizeof(part_head->current_version));
	extern uint32_t fota_crc(uint8_t *buf, uint32_t len);
	part_head->head_crc = fota_crc((uint8_t *)part_head, sizeof(free_fota_part_head) - 4);
	
    if (fal_partition_erase(part, 0, THE_NOR_FLASH_GRANULARITY) < 0)
    {
		log_d("Erase partition[%s] failed.", part_name);
		fota_res = FOTA_PART_ERASE_ERR;
		goto __exit_copy_version;
    }
	
	if (fal_partition_write(part, 0, (const uint8_t *)cache_buf, THE_NOR_FLASH_GRANULARITY) < 0)
	{
		log_i("Write partition[%s] failed.", part_name);
		fota_res = FOTA_PART_WRITE_ERR;
		goto __exit_copy_version;
	}
__exit_copy_version:
	if (cache_buf)
		vPortFree(cache_buf);
	
	if(fota_res != FOTA_NO_ERR)
	{
		log_i("Copy firmware version failed!");	
	}
	else
		log_i("Copy firmware version Success!");
	
	return fota_res;
}



void SYS_DeInit(void)
{
	GPIO_DeInit(GPIOA);
	EXTI_DeInit();
	CRC_ResetDR();
	USART_DeInit(USART1);
	USART_DeInit(USART3);
	SPI_DeInit(SPI1);
	SPI_DeInit(SPI2);
	SPI_DeInit(SPI3);
	SPI_DeInit(SPI4);

}
static int fota_start_application(void)
{
	int fota_res = FOTA_NO_ERR;
	const struct fal_partition *part;
	uint32_t app_addr;

	part = fal_partition_find(FOTA_APP_PART_NAME);
	if (part == NULL)
	{		
		log_i("Partition[%s] not found.", fota_part_head.app_part_name);
		fota_res = FOTA_GENERAL_ERR;
		goto __exit_start_application;
	}

	app_addr = part->offset + 0x08000000;
	//判断是否为0x08XXXXXX.
	if (((*(__IO uint32_t *)(app_addr + 4)) & 0xff000000) != 0x08000000)
	{
		log_i("Illegal Flash code.");
		fota_res = FOTA_GENERAL_ERR;
		goto __exit_start_application;
	}
	// 检查栈顶地址是否合法.
	if (((*(__IO uint32_t *)app_addr) & 0x2ffe0000) != 0x20000000)	
	{
		log_i("Illegal Stack code.");
		fota_res = FOTA_GENERAL_ERR;
		goto __exit_start_application;
	}

	log_i("Implement application now.");      
	vTaskDelay(200);
    __disable_irq();
    for (IRQn_Type irq = WWDG_IRQn; irq <= FPU_IRQn; irq++)
    {
        NVIC_DisableIRQ(irq);
        NVIC_ClearPendingIRQ(irq);
    }
    //Resets the RCC clock configuration to the default reset state.
    RCC_DeInit();
    
    SysTick->CTRL = 0;
    SysTick->LOAD = 0;
    SysTick->VAL = 0;
    SYS_DeInit();

	//用户代码区第二个字为程序开始地址(复位地址)
	app_func = (fota_app_func)*(__IO uint32_t *)(app_addr + 4);
	/* Configure main stack */ 
	__set_MSP(*(__IO uint32_t *)app_addr);       
           
	/* jump to application */
	app_func();
	
__exit_start_application:
	log_i("Implement application failed.");
	return fota_res;
}
static void Fota_Task(void* parameter)
{	
	log_i("Enter Fota Task");
    int fota_err = FOTA_NO_ERR;
	
	/* Partition initialized */
	fota_err = fota_boot_verify();
	if (fota_err != FOTA_NO_ERR)
	{
		log_i("Partition initialized failed.");
	}
    
    /* Shell initialized */
    shellPrint(&shell,  "\r\nPlease press [Enter] key into shell mode in %d secs:\r\n", FOTA_GET_CHAR_WAITTIGN/1000);
    if (fota_get_shell_key() == 0)
    {	
		log_i("fota_get_shell_key == 0");
        goto __exit_shell_entry;
    }

	/* Firmware partition verify */
	fota_err = fota_part_fw_verify(FOTA_FM_PART_NAME);
	if (fota_err != FOTA_NO_ERR)
		goto __exit_boot_entry;

	/* Check upgrade status */
	if (fota_check_upgrade() <= 0)
		goto __exit_boot_entry;


	/* Implement upgrade, copy firmware partition to app partition */
	fota_err = fota_upgrade(FOTA_FM_PART_NAME);
	if (fota_err != FOTA_NO_ERR)
		goto __exit_boot_entry;

	// /* Update new application verison in RBL file of firmware partition */
	fota_err = fota_copy_version(FOTA_FM_PART_NAME);	
	if (fota_err != FOTA_NO_ERR)
		goto __exit_boot_entry;
		
__exit_boot_entry:
	/* Implement application */
	fota_start_application();


	/* Implement upgrade, copy default partition to app partition */
	if (fota_part_fw_verify(FOTA_DF_PART_NAME) == FOTA_NO_ERR)
	{
		if (fota_upgrade(FOTA_DF_PART_NAME) == FOTA_NO_ERR)
		{		
			fota_start_application();
		}
	}
	log_i("Boot application failed, entry shell mode.");
	
__exit_shell_entry:	
	shellPrint(&shell, "enter shell\r\n");
	/* Implement shell */
	bootloade_shell_task_init();
    
	vTaskDelete(NULL); 
}

long Fota_Task_Init(void)
{
    log_i("Fota Task Init");
	fota_crc_init();
    BaseType_t xReturn = pdPASS;

    xReturn = xTaskCreate((TaskFunction_t )Fota_Task,  /* 任务入口函数 */
                        (const char*    )"Fota_Task",/* 任务名字 */
                        (uint16_t       )512,  /* 任务栈大小 */
                        (void*          )NULL,/* 任务入口函数参数 */
                        (UBaseType_t    )3, /* 任务的优先级 */
                        (TaskHandle_t*  )&Fota_Task_Handle);/* 任务控制块指针 */ 
    return xReturn;
}


