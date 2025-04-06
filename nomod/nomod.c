#define _GNU_SOURCE

#include <linux/landlock.h>
#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include "nomod.h"
#include "landlocked.h"

static const uint64_t ACCESS_R = LANDLOCK_ACCESS_FS_READ_FILE;
DECL_STRINGS_ARRAY(TARGET_EXES, "/usr/bin/kmod");
DECL_STRINGS_ARRAY(ROOT_SKIP, ".", "..", "sys");
DECL_STRINGS_ARRAY(SYS_SKIP, ".", "..", "module");
DECL_STRINGS_ARRAY(MODULE_SKIP, ".", "..", "xor");

OUTCOME __nomod_generate_rules(const struct landlocked_ctx *ctx)
{
    OUTCOME outcome = FAILURE;
    I("called");
    IF_FAILURE(__landlocked_add_rules(ctx, "/", ROOT_SKIP, ACCESS_R))
    {
        E("__landlocked_add_rules failure!");
        goto end;
    }
    IF_FAILURE(__landlocked_add_rules(ctx, "/sys", SYS_SKIP, ACCESS_R))
    {
        E("__landlocked_add_rules failure!");
        goto end;
    }
    IF_FAILURE(__landlocked_add_rules(ctx, "/sys/module", MODULE_SKIP, ACCESS_R))
    {
        E("__landlocked_add_rules failure!");
        goto end;
    }
    outcome = SUCCESS;
end:
    return outcome;
}

void __nomod_destructor(void)
{
    I("called");
    return;
}

void __nomod_constructor(void)
{
    struct landlocked_ctx ctx;
    struct landlock_ruleset_attr attr = {0};
    I("called");
    I("version %d.%d", NOMOD_VERSION_MAJOR, NOMOD_VERSION_MINOR);
    IF_FAILURE(__landlocked_init(&ctx))
    {
        goto end;
    }
    IF_FAILURE(__landlocked_exe_match(&ctx, TARGET_EXES))
    {
        W("nomod exemption");
        goto end;
    }
    attr.handled_access_fs = ACCESS_R;
    IF_FAILURE(__landlocked_create_ruleset(&ctx, &attr))
    {
        E("__landlocked_create_ruleset failure!");
        goto end;
    }
    IF_FAILURE(__nomod_generate_rules(&ctx))
    {
        E("__nomod_generate_rules failure!");
        goto end;
    }
    IF_FAILURE(__landlocked_enforce(&ctx))
    {
        E("__landlocked_enforce failure!");
        goto end;
    }
end:
    __landlocked_free(&ctx);
    return;
}
