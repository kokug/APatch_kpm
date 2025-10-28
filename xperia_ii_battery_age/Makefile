# 版本号（随意）
MYKPM_VERSION := 1.0.0

# KernelPatch 目录（与 GitHub CI 保持一致）
KP_DIR        := ../KernelPatch

# 自动检测 NDK（GitHub Actions 已有环境）
NDK_PATH      := $(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin
CC            := $(NDK_PATH)/aarch64-linux-android31-clang

# 源文件
objs          := no_sig_verify.c
out           := no_sig_verify_$(MYKPM_VERSION).kpm

# 头文件路径（直接抄 CI）
INCLUDE_FLAGS := -I$(KP_DIR)/kernel/. \
                 -I$(KP_DIR)/kernel/include \
                 -I$(KP_DIR)/kernel/patch/include \
                 -I$(KP_DIR)/kernel/linux/include \
                 -I$(KP_DIR)/kernel/linux/arch/arm64/include \
                 -I$(KP_DIR)/kernel/linux/tools/arch/arm64/include

# 编译 flags（与 CI 完全一致）
CFLAGS        := -Wall -O2 -fno-PIC -fno-asynchronous-unwind-tables \
                 -fno-stack-protector -fno-common \
                 -DMYKPM_VERSION=\"$(MYKPM_VERSION)\"

# 默认目标
all: $(out)

$(out): $(objs)
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -r -o $@ $^

clean:
	rm -f *.kpm

.PHONY: all clean
