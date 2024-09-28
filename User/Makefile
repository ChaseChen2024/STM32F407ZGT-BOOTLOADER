
# C sources

C_SOURCES +=  \
User/main.c \
User/stm32f4xx_it.c \
User/bsp/uart/bsp_usart3.c \
User/bsp/uart/bsp_usart1.c \
User/bsp/key/bsp_key.c \
User/bsp/rtc/bsp_rtc.c \


ifeq ($(BUILE_FOTA),y)
C_SOURCES +=  \
User/app/fota/fota.c \
User/app/fota/fota_crc.c \

C_INCLUDES +=  \
-IUser/app/fota \

endif


ifeq ($(BUILE_FATFS),y)
C_SOURCES +=  \
User/app/nv/nv.c \

C_INCLUDES +=  \
-IUser/app/nv \

endif


C_INCLUDES +=  \
-IUser \
-IUser/bsp/uart \
-IUser/bsp/key \
-IUser/bsp/led \
-IUser/bsp/rtc \
-IUser/bsp/sram \


CFLAGS += $(MCU) $(C_DEFS) $(C_INCLUDES) $(OPT) -Wall -fdata-sections -ffunction-sections


# list of objects
OBJECTS = $(addprefix $(BUILD_DIR)/,$(notdir $(C_SOURCES:.c=.o)))
vpath %.c $(sort $(dir $(C_SOURCES)))

$(BUILD_DIR)/%.o: %.c Makefile | $(BUILD_DIR) 
	$(CC) -c $(CFLAGS) -Wa,-a,-ad,-alms=$(BUILD_DIR)/$(notdir $(<:.c=.lst)) $< -o $@

ifeq ($(DEBUG), 1)
CFLAGS += -g -gdwarf-2
endif	


#######################################
# dependencies
#######################################
-include $(wildcard $(BUILD_DIR)/*.d)

# *** EOF ***
