/**
  ******************************************************************************
  * @file    FMC_SDRAM/stm32f4xx_it.c 
  * @author  MCD Application Team
  * @version V1.0.1
  * @date    11-November-2013
  * @brief   Main Interrupt Service Routines.
  *         This file provides template for all exceptions handler and
  *         peripherals interrupt service routine.
  ******************************************************************************
  * @attention
  *
  * <h2><center>&copy; COPYRIGHT 2013 STMicroelectronics</center></h2>
  *
  * Licensed under MCD-ST Liberty SW License Agreement V2, (the "License");
  * You may not use this file except in compliance with the License.
  * You may obtain a copy of the License at:
  *
  *        http://www.st.com/software_license_agreement_liberty_v2
  *
  * Unless required by applicable law or agreed to in writing, software 
  * distributed under the License is distributed on an "AS IS" BASIS, 
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  *
  ******************************************************************************
  */

/* Includes ------------------------------------------------------------------*/
#include "stm32f4xx_it.h"

#include "FreeRTOS.h"					//FreeRTOSÊ¹ÓÃ		  
#include "task.h" 
#include "queue.h"
#include "semphr.h"

#include "bsp_usart3.h"
#include<string.h>


/** @addtogroup STM32F429I_DISCOVERY_Examples
  * @{
  */

/** @addtogroup FMC_SDRAM
  * @{
  */ 

/* Private typedef -----------------------------------------------------------*/
/* Private define ------------------------------------------------------------*/
/* Private macro -------------------------------------------------------------*/
/* Private variables ---------------------------------------------------------*/
/* Private function prototypes -----------------------------------------------*/
/* Private functions ---------------------------------------------------------*/

/******************************************************************************/
/*            Cortex-M4 Processor Exceptions Handlers                         */
/******************************************************************************/

/**
  * @brief  This function handles NMI exception.
  * @param  None
  * @retval None
  */
void NMI_Handler(void)
{
}

/**
  * @brief  This function handles Hard Fault exception.
  * @param  None
  * @retval None
  */
// void HardFault_Handler(void)
// {
// 	log_i("\r\n  HardFault_Handler");
//   /* Go to infinite loop when Hard Fault exception occurs */
//   while (1)
//   {}
// }

/**
  * @brief  This function handles Memory Manage exception.
  * @param  None
  * @retval None
  */
void MemManage_Handler(void)
{
  /* Go to infinite loop when Memory Manage exception occurs */
  while (1)
  {}
}

/**
  * @brief  This function handles Bus Fault exception.
  * @param  None
  * @retval None
  */
void BusFault_Handler(void)
{
  /* Go to infinite loop when Bus Fault exception occurs */
  while (1)
  {}
}

/**
  * @brief  This function handles Usage Fault exception.
  * @param  None
  * @retval None
  */
void UsageFault_Handler(void)
{
  /* Go to infinite loop when Usage Fault exception occurs */
  while (1)
  {}
}

/**
  * @brief  This function handles Debug Monitor exception.
  * @param  None
  * @retval None
  */
void DebugMon_Handler(void)
{}

#ifdef USER_LEETTER_SHELL
#include "bsp_usart1.h"
void USART1_IRQHandler(void)  
{
	uint32_t ulReturn;
  u8 rec_data;
  ulReturn = taskENTER_CRITICAL_FROM_ISR();

	if(USART_GetITStatus(USART1_SHELL,USART_IT_IDLE)!=RESET)
	{		
		Usart1_DMA_Rx_Data();
    READ_IT_FLAG = 1;
		rec_data = USART_ReceiveData(USART1_SHELL);
	}	 
  taskEXIT_CRITICAL_FROM_ISR( ulReturn );
} 
#endif // USER_LEETTER_SHELL


/**
  * @brief  This function handles SysTick Handler.
  * @param  None
  * @retval None
  */
extern void xPortSysTickHandler(void);
void SysTick_Handler(void)
{	
    #if (INCLUDE_xTaskGetSchedulerState  == 1 )
      if (xTaskGetSchedulerState() != taskSCHEDULER_NOT_STARTED)
      {
    #endif  /* INCLUDE_xTaskGetSchedulerState */  
        xPortSysTickHandler();
    #if (INCLUDE_xTaskGetSchedulerState  == 1 )
      }
    #endif  /* INCLUDE_xTaskGetSchedulerState */
}

#ifdef USE_GNSS_CODE
#include "bsp_usart6.h"
void USART6_IRQHandler(void)  
{
	uint32_t ulReturn;
  u8 rec_data;
  ulReturn = taskENTER_CRITICAL_FROM_ISR();

	if(USART_GetITStatus(USART6,USART_IT_IDLE)!=RESET)
	{		
		Uart6_DMA_Rx_Data();
		rec_data = USART_ReceiveData(USART6);
	}	 

  taskEXIT_CRITICAL_FROM_ISR( ulReturn );
} 

#endif // USE_GNSS_CODE


/************************ (C) COPYRIGHT STMicroelectronics *****END OF FILE****/
