LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

ifeq ($(TARGET_ARCH_ABI),armeabi)
	LOCAL_ARM_MODE := arm
endif

LOCAL_CPPFLAGS	:= -Wno-narrowing -Wall -pie -fPIE -std=gnu++11 #-Werror 
LOCAL_CPPFLAGS  += -fno-strict-aliasing -Wno-unused-value -Wno-parentheses -Wno-write-strings

LOCAL_MODULE    := $(LOCAL_MODULE_NAME)

SUB_DIRS = $(LOCAL_PATH)

MY_FILES_SUFFIX := %.cpp %.c
rwildcard=$(wildcard $1$2) $(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2))

MY_ALL_FILES = $(foreach src_path,$(SUB_DIRS),$(call rwildcard,$(src_path),*.*))
My_All_Files := $(My_All_Files:$(MY_CPP_PATH)/./%=$(MY_CPP_PATH)%)

MY_SRC_LIST  := $(foreach src_file, $(MY_ALL_FILES), $(filter $(MY_FILES_SUFFIX),$(src_file)))
MY_SRC_LIST  := $(MY_SRC_LIST:$(LOCAL_PATH)/%=%)

LOCAL_SRC_FILES := $(MY_SRC_LIST)

$(warning $(foreach src_file,$(LOCAL_SRC_FILES), $(warning $(src_file))))

LOCAL_LDFLAGS += -Wl,--gc-sections -pie -fPIE
LOCAL_LDLIBS 	:= -llog #-lz

LOCAL_CPPFLAGS += -ffunction-sections -fdata-sections -fvisibility=hidden 

include $(BUILD_EXECUTABLE)
