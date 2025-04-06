#include <linux/landlock.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "noconnect.h"
#include "landlocked.h"


void __noconnect_destructor(void)
{
    I("called");
    return;
}

void __noconnect_constructor(void)
{
    struct landlocked_ctx ctx;
    struct landlock_ruleset_attr attr = {0};
    I("called");
    I("version %d.%d", NOCONNECT_VERSION_MAJOR, NOCONNECT_VERSION_MINOR);
#ifdef NOCONNECT_RANDOM
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
    attr.handled_access_net = LANDLOCK_ACCESS_NET_CONNECT_TCP;
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
