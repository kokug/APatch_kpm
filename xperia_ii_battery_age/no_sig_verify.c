/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Runtime bypass module signature verification
 * KernelPatch native utilities
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/version.h>

/* ---------- KPM 元信息 ---------- */
KPM_NAME("no_sig_verify");
KPM_VERSION("1.1");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("you");
KPM_DESCRIPTION("Runtime hook verify_module to bypass signature check");

/* ---------- 兼容性检查 ---------- */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
#warning "This module is primarily tested on Linux 4.0+ kernels"
#endif

#ifdef CONFIG_ANDROID
#define IS_ANDROID_ENV 1
#else
#define IS_ANDROID_ENV 0
#endif

/* ---------- 函数声明 ---------- */
static int (*original_verify_module)(struct module *mod) = NULL;

/* ---------- Hook函数 ---------- */
static int hooked_verify_module(struct module *mod)
{
    pr_info("no_sig_verify: bypassing signature verification for module: %s\n", 
            mod ? mod->name : "unknown");
    return 0; // 始终返回成功
}

/* ---------- KPM初始化函数 ---------- */
static long no_sig_verify_init(const char *args, const char *event, void *__user reserved)
{
    int ret;
    
    pr_info("no_sig_verify: initializing module signature bypass\n");
    
    // 兼容性信息
    pr_info("no_sig_verify: Linux version %u.%u.%u, Android environment: %d\n",
            LINUX_VERSION_CODE >> 16,
            (LINUX_VERSION_CODE >> 8) & 0xFF,
            LINUX_VERSION_CODE & 0xFF,
            IS_ANDROID_ENV);
    
    // 查找原始verify_module函数
    original_verify_module = (typeof(original_verify_module))kallsyms_lookup_name("verify_module");
    if (!original_verify_module) {
        pr_err("no_sig_verify: failed to find verify_module symbol\n");
        return -ENOENT;
    }
    
    pr_info("no_sig_verify: found verify_module at %p\n", original_verify_module);
    
    // Hook verify_module函数
    ret = hook_func((void *)original_verify_module, (void *)hooked_verify_module, NULL);
    if (ret) {
        pr_err("no_sig_verify: failed to hook verify_module, error: %d\n", ret);
        return ret;
    }
    
    pr_info("no_sig_verify: successfully hooked verify_module\n");
    return 0;
}

/* ---------- KPM控制函数 ---------- */
static long no_sig_verify_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("no_sig_verify: control0 called with args: %s\n", args);
    
    char response[64] = "no_sig_verify: active";
    compat_copy_to_user(out_msg, response, sizeof(response));
    
    return 0;
}

static long no_sig_verify_control1(void *a1, void *a2, void *a3)
{
    pr_info("no_sig_verify: control1 called\n");
    return 0;
}

/* ---------- KPM退出函数 ---------- */
static long no_sig_verify_exit(void *__user reserved)
{
    pr_info("no_sig_verify: exiting, restoring original verify_module\n");
    
    if (original_verify_module) {
        // 恢复原始函数
        unhook_func((void *)original_verify_module);
        pr_info("no_sig_verify: original verify_module restored\n");
    }
    
    return 0;
}

/* ---------- KPM入口点 ---------- */
KPM_INIT(no_sig_verify_init);
KPM_CTL0(no_sig_verify_control0);
KPM_CTL1(no_sig_verify_control1);
KPM_EXIT(no_sig_verify_exit);
