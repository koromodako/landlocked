#define _GNU_SOURCE

#include <linux/landlock.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "noexec.h"
#include "landlocked.h"

void __noexec_destructor(void)
{
    I("called");
    return;
}

void __noexec_constructor(void)
{
    struct landlocked_ctx ctx;
    struct landlock_ruleset_attr attr = {0};
    I("called");
    I("version %d.%d", NOEXEC_VERSION_MAJOR, NOEXEC_VERSION_MINOR);
#ifdef NOEXEC_RANDOM
    IF_SUCCESS(__landlocked_random(10))
    {
        I("random exemption");
        goto end;
    }
#endif
    IF_FAILURE(__landlocked_init(&ctx))
    {
        E("__landlocked_init failure!");
        goto end;
    }
    attr.handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE;
    IF_FAILURE(__landlocked_create_ruleset(&ctx, &attr))
    {
        E("__landlocked_create_ruleset failure!");
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
