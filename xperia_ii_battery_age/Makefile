MYKPM_VERSION := 1.0.1
KP_DIR        := ../KernelPatch

CC            := $(ANDROID_NDK)/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang
INCLUDE_FLAGS := -I$(KP_DIR)/kernel/. \
                 -I$(KP_DIR)/kernel/include \
                 -I$(KP_DIR)/kernel/patch/include \
                 -I$(KP_DIR)/kernel/linux/include \
                 -I$(KP_DIR)/kernel/linux/arch/arm64/include \
                 -I$(KP_DIR)/kernel/linux/tools/arch/arm64/include

CFLAGS        := -Wall -O2 -fno-PIC -fno-asynchronous-unwind-tables \
                 -fno-stack-protector -fno-common \
                 -DMYKPM_VERSION=\"$(MYKPM_VERSION)\"

objs          := no_sig_verify.c
out           := no_sig_verify_$(MYKPM_VERSION).kpm

all: $(out)
$(out): $(objs)
	$(CC) $(CFLAGS) $(INCLUDE_FLAGS) -r -o $@ $^

clean:
	rm -f *.kpm

.PHONY: all clean
