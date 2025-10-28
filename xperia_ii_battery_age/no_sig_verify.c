// SPDX-License-Identifier: GPL-2.0
#include <linux/kallsyms.h>

static bool *mod_signing_enabled;

static long no_sig_init(const char *a, const char *e, void *r)
{
    mod_signing_enabled = (bool *)kallsyms_lookup_name("mod_signing_enabled");
    if (!mod_signing_enabled)
        return -ENOENT;
    *mod_signing_enabled = false;
    return 0;
}

static long no_sig_exit(void *r)
{
    if (mod_signing_enabled)
        *mod_signing_enabled = true;
    return 0;
}

#define KPM_NAME "no_sig_verify"
#define KPM_VERSION "1.0"
#define KPM_LICENSE "GPL"
#define KPM_AUTHOR "you"
#define KPM_DESCRIPTION "Toggle mod_signing_enabled at runtime"

__attribute__((section(".kpm.info"))) static const char
    __kpm_info_name[]       = "name=" KPM_NAME,
    __kpm_info_version[]    = "version=" KPM_VERSION,
    __kpm_info_license[]    = "license=" KPM_LICENSE,
    __kpm_info_author[]     = "author=" KPM_AUTHOR,
    __kpm_info_desc[]       = "description=" KPM_DESCRIPTION;

typedef long (*kpm_initcall_t)(const char *, const char *, void *);
typedef long (*kpm_exitcall_t)(void *);

__attribute__((section(".kpm.init")))
static kpm_initcall_t __kpm_initcall_no_sig = no_sig_init;

__attribute__((section(".kpm.exit")))
static kpm_exitcall_t __kpm_exitcall_no_sig = no_sig_exit;
