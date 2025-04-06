#include <linux/landlock.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "nobind.h"
#include "landlocked.h"

void __nobind_destructor(void)
{
    I("called");
    return;
}

void __nobind_constructor(void)
{
    int fd, ok;
    struct landlocked_ctx ctx;
    struct landlock_ruleset_attr attr = {0};
    I("called");
    I("version %d.%d", NOBIND_VERSION_MAJOR, NOBIND_VERSION_MINOR);
    IF_FAILURE(__landlocked_init(&ctx))
    {
        E("__landlocked_init failure!");
        goto end;
    }
    attr.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP;
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
