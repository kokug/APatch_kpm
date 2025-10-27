// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/module_signature.h>


/* 内核符号 */
static bool (*orig_mod_verify_sig)(const struct module *mod,
                                   const struct module_signature *sig,
                                   size_t sig_size);

/* 永远返回验证成功 */
static bool fake_mod_verify_sig(const struct module *mod,
                                const struct module_signature *sig,
                                size_t sig_size)
{
    return true;
}

/* 保存 hook 句柄 */
static void *hook_stub = NULL;

/* 外部 inline_hook 接口（KernelPatch 提供） */
extern int inline_hook(void *target, void *new, void **old);
extern int inline_unhook(void *stub);

/* 模块入口 */
static int __init no_sig_init(void)
{
    void *target;

    /* 1. 解析符号 */
    target = (void *)kallsyms_lookup_name("mod_verify_sig");
    if (!target) {
        /* 某些分支叫 module_sig_check */
        target = (void *)kallsyms_lookup_name("module_sig_check");
        if (!target) {
            pr_err("no_sig: symbol not found\n");
            return -ENOENT;
        }
    }

    /* 2. 安装 hook */
    if (inline_hook(target, fake_mod_verify_sig, &hook_stub)) {
        pr_err("no_sig: hook failed\n");
        return -EPERM;
    }

    pr_info("no_sig: module signature verify bypassed!\n");
    return 0;
}

/* 模块退出 */
static void __exit no_sig_exit(void)
{
    if (hook_stub)
        inline_unhook(hook_stub);
    pr_info("no_sig: unloaded\n");
}

/* KPM 元信息 */
#define KPM_NAME "no_sig_verify"
#define KPM_VERSION "1.0"
#define KPM_LICENSE "GPL"
#define KPM_AUTHOR "you"
#define KPM_DESCRIPTION "Bypass module signature verification on 4.19"

/* 强制放入 .kpm.info */
static const char __kpm_info_name[]       __attribute__((section(".kpm.info"))) = "name=" KPM_NAME;
static const char __kpm_info_version[]    __attribute__((section(".kpm.info"))) = "version=" KPM_VERSION;
static const char __kpm_info_license[]    __attribute__((section(".kpm.info"))) = "license=" KPM_LICENSE;
static const char __kpm_info_author[]     __attribute__((section(".kpm.info"))) = "author=" KPM_AUTHOR;
static const char __kpm_info_desc[]       __attribute__((section(".kpm.info"))) = "description=" KPM_DESCRIPTION;

/* 入口/出口 */
typedef long (*kpm_initcall_t)(const char *args, const char *event, void *reserved);
typedef long (*kpm_exitcall_t)(void *reserved);

static kpm_initcall_t __kpm_initcall_no_sig __attribute__((section(".kpm.init"))) = no_sig_init;
static kpm_exitcall_t __kpm_exitcall_no_sig __attribute__((section(".kpm.exit"))) = no_sig_exit;
