


ifeq ($(BUILE_FATFS),y)
#fatfs
C_SOURCES +=  \
Component/FatFs/diskio.c \
Component/FatFs/ff.c \
Component/FatFs/option/cc936.c \
Component/FatFs/option/syscall.c \

#fatfs
C_INCLUDES +=  \
-IComponent/FatFs \

endif

ifeq ($(BUILE_TINYCRYPT),y)

C_SOURCES +=  \
Component/tinycrypt/src/tiny_aes.c \
Component/fastlz/fastlz.c \
Component/quicklz/quicklz.c \

C_INCLUDES +=  \
-IComponent/tinycrypt/include \
-IComponent/quicklz \
-IComponent/fastlz \

endif




ifeq ($(BUILE_LETTER_SHELL),y)
C_SOURCES +=  \
Component/LetterShell/src/shell.c \
Component/LetterShell/src/shell_cmd_list.c \
Component/LetterShell/src/shell_companion.c \
Component/LetterShell/src/shell_ext.c \
Component/LetterShell/stm32-freertos/shell_port.c \
# Component/LetterShell/extensions/fs_support/shell_fs.c \

endif

ifeq ($(BUILE_CMBACKTRACE),y)
C_SOURCES +=  \
Component/Cm_Backtrace/cm_backtrace.c \

endif


ifeq ($(BUILE_EASYLOGGER),y)
C_SOURCES +=  \
Component/Easy_Logger/src/elog.c \
Component/Easy_Logger/src/elog_utils.c \
Component/Easy_Logger/port/elog_port.c \

endif

ifeq ($(BUILE_SFUD),y)
C_SOURCES +=  \
Component/sfud/src/sfud.c \
Component/sfud/src/sfud_sfdp.c \
Component/sfud/port/sfud_port.c \

C_INCLUDES +=  \
-IComponent/sfud/inc \

endif

ifeq ($(BUILE_FAL),y)
C_SOURCES +=  \
Component/fal/src/fal.c \
Component/fal/src/fal_flash.c \
Component/fal/src/fal_partition.c \
Component/fal/porting/fal_flash_sfud_port.c \
Component/fal/porting/fal_flash_stm32f4_port.c \

C_INCLUDES +=  \
-IComponent/fal/porting \
-IComponent/fal/inc \

endif




ifeq ($(BUILE_LETTER_SHELL),y)
C_INCLUDES +=  \
-IComponent/LetterShell/src \
-IComponent/LetterShell/stm32-freertos \
# -IComponent/LetterShell/extensions/fs_support \

endif

ifeq ($(BUILE_CMBACKTRACE),y)
C_INCLUDES +=  \
-IComponent/Cm_Backtrace \

endif

ifeq ($(BUILE_EASYLOGGER),y)
C_INCLUDES +=  \
-IComponent/Easy_Logger/inc \

endif

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
