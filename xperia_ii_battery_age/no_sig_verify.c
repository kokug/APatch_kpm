// SPDX-License-Identifier: GPL-2.0
#include <linux/kallsyms.h>

/* 手动前置声明 */
struct module_signature {
    u8 algo;
    u8 hash;
    u8 id_type;
    u8 signer_len;
    u8 key_id_len;
    u8 __pad[3];
    u8 sig_len;
};

/* 常数 */
#define ENOENT  2
#define EPERM   1

/* 原始函数指针 */
static bool (*orig_mod_verify_sig)(const struct module *,
                                   const struct module_signature *,
                                   size_t);

/* 永远返回验证成功 */
static bool fake_mod_verify_sig(const struct module *mod,
                                const struct module_signature *sig,
                                size_t sig_size)
{
    return true;
}

/* hook 句柄 */
static void *hook_stub;

/* 外部接口（KernelPatch 提供） */
extern int inline_hook(void *target, void *new, void **old);
extern int inline_unhook(void *stub);

/* 模块入口：签名与 KPM 约定一致 */
static long no_sig_init(const char *args, const char *event, void *reserved)
{
    void *target;

    target = (void *)kallsyms_lookup_name("mod_verify_sig");
    if (!target)
        target = (void *)kallsyms_lookup_name("module_sig_check");
    if (!target)
        return -ENOENT;

    if (inline_hook(target, fake_mod_verify_sig, &hook_stub))
        return -EPERM;

    return 0;
}

/* 模块出口：签名与 KPM 约定一致 */
static long no_sig_exit(void *reserved)
{
    if (hook_stub)
        inline_unhook(hook_stub);
    return 0;
}

/* ---------- KPM 元信息 ---------- */
#define KPM_NAME "no_sig_verify"
#define KPM_VERSION "1.0"
#define KPM_LICENSE "GPL"
#define KPM_AUTHOR "you"
#define KPM_DESCRIPTION "Bypass module signature verification on 4.19"

__attribute__((section(".kpm.info"))) static const char __kpm_info_name[]       = "name=" KPM_NAME;
__attribute__((section(".kpm.info"))) static const char __kpm_info_version[]    = "version=" KPM_VERSION;
__attribute__((section(".kpm.info"))) static const char __kpm_info_license[]    = "license=" KPM_LICENSE;
__attribute__((section(".kpm.info"))) static const char __kpm_info_author[]     = "author=" KPM_AUTHOR;
__attribute__((section(".kpm.info"))) static const char __kpm_info_desc[]       = "description=" KPM_DESCRIPTION;

/* ---------- KPM 生命期 ---------- */
typedef long (*kpm_initcall_t)(const char *args, const char *event, void *reserved);
typedef long (*kpm_exitcall_t)(void *reserved);

__attribute__((section(".kpm.init"))) static kpm_initcall_t __kpm_initcall_no_sig = no_sig_init;
__attribute__((section(".kpm.exit"))) static kpm_exitcall_t __kpm_exitcall_no_sig = no_sig_exit;
