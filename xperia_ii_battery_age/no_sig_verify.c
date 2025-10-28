// SPDX-License-Identifier: GPL-2.0
/*
 *  Runtime bypass module signature verification
 *  KernelPatch native utilities
 */

#include "../kpm_utils.h"
#include <linux/kallsyms.h>

/* 函数指针保存 */
static int (*orig_verify_module)(const struct module *mod,
                                 const struct module_signature *sig,
                                 size_t sig_size);

/* 永远返回成功 */
static int fake_verify_module(const struct module *mod,
                              const struct module_signature *sig,
                              size_t sig_size)
{
    return 0; /* = 0 表示验证通过 */
}

static void *hook_stub;

static long no_sig_init(const char *args, const char *event, void *reserved)
{
    /* 1. 找符号（KernelPatch 官方宏） */
    lookup_name(orig_verify_module);

    /* 2. 安装 hook（KernelPatch 官方宏） */
    hook_func(orig_verify_module, NULL, fake_verify_module, NULL, NULL);

    pr_info("no_sig: verify_module hooked → always pass\n");
    return 0;
}

static long no_sig_exit(void *reserved)
{
    unhook_func(orig_verify_module);
    pr_info("no_sig: verify_module unhooked → back to normal\n");
    return 0;
}

/* ---------- KPM 元信息 ---------- */
#define KPM_NAME "no_sig_verify"
#define KPM_VERSION "1.0"
#define KPM_LICENSE "GPL"
#define KPM_AUTHOR "you"
#define KPM_DESCRIPTION "Runtime hook verify_module to bypass signature check"

KPM_INFO(name, KPM_NAME);
KPM_INFO(version, KPM_VERSION);
KPM_INFO(license, KPM_LICENSE);
KPM_INFO(author, KPM_AUTHOR);
KPM_INFO(description, KPM_DESCRIPTION);

KPM_INIT(no_sig_init);
KPM_EXIT(no_sig_exit);
