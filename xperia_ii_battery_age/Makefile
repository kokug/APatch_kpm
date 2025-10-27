# 版本号（随便写）
MYKPM_VERSION := 1.0.0

# 默认 KernelPatch 目录（可覆盖）
KP_DIR ?= ../KernelPatch

# 自动检测 NDK
OS_NAME   := $(shell uname | tr A-Z a-z)
MACHINE   := $(shell uname -m)
HOST_TAG  := $(OS_NAME)-$(MACHINE)
ifeq ($(HOST_TAG),darwin-arm64)
  HOST_TAG := darwin-x86_64
endif
NDK_BIN_DIR := toolchains/llvm/prebuilt/$(HOST_TAG)/bin

ifdef ANDROID_NDK_LATEST_HOME
  NDK_PATH ?= $(ANDROID_NDK_LATEST_HOME)/$(NDK_BIN_DIR)
else ifdef ANDROID_NDK
  NDK_PATH ?= $(ANDROID_NDK)/$(NDK_BIN_DIR)
endif

# 工具链
CC := $(NDK_PATH)/aarch64-linux-android31-clang
LD := $(NDK_PATH)/ld.lld

# 源文件
objs := no_sig_verify.c

# 输出名
out := no_sig_verify_$(MYKPM_VERSION).kpm

# 编译 flags
CFLAGS := -Wall -O2 -fno-PIC -fno-asynchronous-unwind-tables \
          -fno-stack-protector -fno-common \
          -DMYKPM_VERSION=\"$(MYKPM_VERSION)\"

INCLUDE_DIRS := . include patch/include linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

# 默认目标
all: $(out)

$(out): $(objs)
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) $(objs) -r -o $@

clean:
	rm -f *.kpm

.PHONY: all clean
