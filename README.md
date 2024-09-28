STM32F407ZGT-BOOTLOADER-Makefile

项目工程介绍：

基于启明欣欣的STM32F407ZGT开发版实现的的一个bootloader工程，参考rt-fota源码实现（源码移植，学习源码，学习框架），将rtthread更改为freertos、shell更改为letter-shell、sfud和fal以及加密算法没有更改。应用代码和部分枚举为了代码风格统一，删除了rt_或RT_前缀
rt-fota源码路径：https://gitee.com/spunky_973/rt-fota 



开发板介绍：

项目芯片型号：STM32F407ZGT6
资源介绍：32位 cortex-M4  时钟最高168M, 板载192k ram  1024k flash, pin 144 , 3个12位AD,2个12位DA,16个DMA通道，17个定时器，3个i2c,6个串口，3个spi,2个can2.0,2个usb otg,1个SDIO
工程使用makefile进行管理，gcc进行编译。

资源分配

| 外设   | 	资源 	 |		管理	| 											GPIO 													|
| -------|----------|---------------|---------------------------------------------------------------------------------------------------|
| SPI1   | w25q128	| sfud+fal+fatfs| sck--PB3,miso--PB4,mosi--PB5,cs--PG8																|
| SPI2   | st7789   | LVGL          | rst--PB0,cs--PB12,dc--PB14,blk--PB1,miso--PB13,mosi--PB15											| 
| SDIO   | SD       | fatfs         | 暂留																								| 
| ETH    | LAN8720  | lwip          | MDIO--PA2,MDC--PC1,CLK--PA1,DV--PA7,RXD0--PC4,RXD1--PC5,TXEN--PB11,EXD0--PG13,TXD1--PG14,RST--VCC | 
| FSMC   | SRAM     | 暂定           | ...(太多了，我就不列了)																			  | 
| USART3 | DEBUG	| easylogger    | tx1--PA9,rx1--PA10																				| 
| USART1 | shell    | letter-shell  | tx3--PB10,rx3--PB11																				| 
| USART6 | gnss     | NMEAS0183     | tx6--PC6，rx6--PC7																				| 
| I2C    | AT24C02  | 暂定           | scl--PB8,sda--PB9																				| 
| GPIOG13| LED0	    | 暂定           | PG13																								| 
| GPIOG14| LED1     | 暂定           | PG14																								| 
| GPIOF6 | KEY0     | 暂定           | PF6																								| 
| GPIOF7 | KEY1     | 暂定           | PF7																								| 

为了上传github的数据精简，删除了TOOL中的编译环境文件和非fota用到的工具，
编译环境搭建工具和搭建教程请从https://github.com/ChaseChen2024/STM32F407ZGT中获取



如果为jLink、STLink、DAP等工具，在连接好设备后，如果使用dap调试器可以直接使用make download，兼容的命令如下，也可以自己定义，更多详情查看makefile文件

#烧录命令

make down 下载bootloader固件和app固件，make down_app 下载app固件

down:
	-openocd -f TOOL/debug/stlink.cfg -f TOOL/debug/stm32f4x.cfg -c init -c "reset halt;wait_halt;flash write_image erase build/$(TARGET).bin 0x08000000" -c reset -c shutdown 

	



# 分支描述




# 使用到的开源库


| 功能   | 	库地址 	 |
| -------|----------|
|letter-shell|https://github.com/NevermindZZT/letter-shell|
|cmbacktrace |https://gitee.com/Armink/CmBacktrace|
|easylogger|https://github.com/armink/EasyLogger|
|SFUD|https://github.com/armink/SFUD/tree/master|
|FAL |https://gitee.com/RT-Thread-Mirror/fal|
|rt-fota |https://gitee.com/spunky_973/rt-fota |


