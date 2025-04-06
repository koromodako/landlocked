#define _GNU_SOURCE

#include <linux/landlock.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include "lockdown.h"
#include "landlocked.h"


static const uint64_t ACCESS_BC =
    LANDLOCK_ACCESS_NET_BIND_TCP |
    LANDLOCK_ACCESS_NET_CONNECT_TCP;
static const uint64_t ACCESS_R = LANDLOCK_ACCESS_FS_READ_FILE;
static const uint64_t ACCESS_W =
    LANDLOCK_ACCESS_FS_TRUNCATE |
    LANDLOCK_ACCESS_FS_WRITE_FILE |
    LANDLOCK_ACCESS_FS_REMOVE_FILE;
static const uint64_t ACCESS_X = LANDLOCK_ACCESS_FS_EXECUTE;
static const uint64_t ACCESS_RWX = ACCESS_R | ACCESS_W | ACCESS_X;
static const uint64_t ACCESS_RW = ACCESS_R | ACCESS_W;
static const uint64_t ACCESS_RX = ACCESS_R | ACCESS_X;
DECL_STRINGS_ARRAY(
    ROOT_SKIP,
    ".",
    "..",
    "dev",
    "etc",
    "opt",
    "proc",
    "run",
    "sys",
    "tmp",
    "usr",
    "var",
    "lockdown.so"
);
DECL_STRINGS_ARRAY(
    ETC_SKIP,
    ".",
    "..",
    "ld.so.preload"
);
DECL_STRINGS_ARRAY(
    DOT_SKIP,
    ".."
);
DECL_STRINGS_ARRAY(
    RX_DIRS,
    "/usr",
    "/opt"
);
DECL_STRINGS_ARRAY(
    RW_DIRS,
    "/dev",
    "/proc",
    "/run",
    "/sys",
    "/tmp",
    "/var",
    NULL
);


OUTCOME __lockdown_generate_rules(const struct landlocked_ctx *ctx)
{
    OUTCOME outcome = FAILURE;
    int i;
    I("called");
    IF_FAILURE(__landlocked_add_rules(ctx, "/", ROOT_SKIP, ACCESS_R))
    {
        E("__landlocked_add_rules failure!");
        goto end;
    }
    IF_FAILURE(__landlocked_add_rules(ctx, "/etc", ETC_SKIP, ACCESS_R))
    {
        E("__landlocked_add_rules failure!");
        goto end;
    }
    i = 0;
    while(RX_DIRS[i] != NULL)
    {
        IF_FAILURE(__landlocked_add_rules(ctx, RX_DIRS[i], DOT_SKIP, ACCESS_RX))
        {
            E("__landlocked_add_rules failure!");
            goto end;
        }
        i++;
    }
    i = 0;
    while(RW_DIRS[i] != NULL)
    {
        IF_FAILURE(__landlocked_add_rules(ctx, RW_DIRS[i], DOT_SKIP, ACCESS_RW))
        {
            E("__landlocked_add_rules failure!");
            goto end;
        }
        i++;
    }
    outcome = SUCCESS;
end:
    return outcome;
}

void __lockdown_banner(void)
{
    fprintf(stderr, "                                    ████████\n");
    fprintf(stderr, "                              ██████        ██████\n");
    fprintf(stderr, "                          ▓▓▓▓░░░░░░░░░░░░░░░░░░░░▓▓██\n");
    fprintf(stderr, "                        ██  ░░░░░░░░▒▒▒▒▒▒▒▒░░░░░░    ██\n");
    fprintf(stderr, "                      ██░░░░░░░░▒▒▒▒████████▒▒▒▒░░░░░░░░██\n");
    fprintf(stderr, "                    ██  ░░░░▒▒▒▒████        ████▒▒▒▒░░░░  ██\n");
    fprintf(stderr, "                  ▓▓░░░░░░▒▒████                ████▒▒░░░░░░▓▓\n");
    fprintf(stderr, "                  ██░░░░▒▒██                        ██▒▒░░░░██\n");
    fprintf(stderr, "                ██░░░░▒▒██                            ██▒▒░░░░██\n");
    fprintf(stderr, "                ██░░▒▒██                                ██▒▒░░██\n");
    fprintf(stderr, "              ▒▒░░░░▒▒██                                ██▒▒░░░░▒▒\n");
    fprintf(stderr, "              ██░░░░▒▒██                                ██▒▒░░░░██\n");
    fprintf(stderr, "            ██  ░░▒▒██                                    ██▒▒░░  ██\n");
    fprintf(stderr, "            ██░░░░▒▒██                                    ██▒▒░░░░██\n");
    fprintf(stderr, "            ██░░░░▒▒██                                    ██▒▒░░░░██\n");
    fprintf(stderr, "            ██░░░░▒▒██                                    ██▒▒░░░░██\n");
    fprintf(stderr, "            ██░░░░▒▒██                                    ██▒▒░░░░██\n");
    fprintf(stderr, "            ██░░░░▒▒██                                    ██▒▒░░░░██\n");
    fprintf(stderr, "      ▒▒▒▒▒▒██░░░░▒▒██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██▒▒░░░░██▒▒▒▒▒▒\n");
    fprintf(stderr, "    ██░░░░░░██▒▒▒▒▒▒██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██▒▒▒▒▒▒██░░░░░░██\n");
    fprintf(stderr, "  ██░░░░░░░░░░██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██████░░░░░░░░░░██\n");
    fprintf(stderr, "  ██░░░░██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░██\n");
    fprintf(stderr, "  ██░░░░░░████████████████████████████████████████████████████████████░░░░░░██\n");
    fprintf(stderr, "  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██\n");
    fprintf(stderr, "  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██\n");
    fprintf(stderr, "  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██\n");
    fprintf(stderr, "  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██\n");
    fprintf(stderr, "  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██\n");
    fprintf(stderr, "  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██\n");
    fprintf(stderr, "  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██\n");
    fprintf(stderr, "  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██\n");
    fprintf(stderr, "  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██\n");
    fprintf(stderr, "  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██\n");
    fprintf(stderr, "  ██░░░░▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒░░░░██\n");
    fprintf(stderr, "  ██░░░░▒▒░░░░░░░░░░░░░░░░░░░░░░░░░ LOCKDOWN ░░░░░░░░░░░░░░░░░░░░░░░░░▒▒░░░░██\n");
    fprintf(stderr, "  ██▒▒░░▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒░░▒▒██\n");
    fprintf(stderr, "  ██▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▒▒▒▒▒▒▒██\n");
    fprintf(stderr, "  ██▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒▒▒▒▒▒▒▒██\n");
    fprintf(stderr, "  ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██\n");
    fprintf(stderr, "    ██▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒██\n");
    fprintf(stderr, "      ████████████████████████████████████████████████████████████████████\n");
}

void __lockdown_destructor(void)
{
    I("called");
    return;
}

void __lockdown_constructor(void)
{
    struct landlocked_ctx ctx;
    struct landlock_ruleset_attr attr = {0};
    I("called");
    I("version %d.%d", LOCKDOWN_VERSION_MAJOR, LOCKDOWN_VERSION_MINOR);
    IF_FAILURE(__landlocked_init(&ctx))
    {
        E("__landlocked_init failure!");
        goto end;
    }
    attr.handled_access_fs = ACCESS_RWX;
    attr.handled_access_net = ACCESS_BC;
    IF_FAILURE(__landlocked_create_ruleset(&ctx, &attr))
    {
        E("__landlocked_create_ruleset failure!");
        goto end;
    }
    IF_FAILURE(__lockdown_generate_rules(&ctx))
    {
        E("__lockdown_generate_rules failure!");
        goto end;
    }
    IF_FAILURE(__landlocked_enforce(&ctx))
    {
        E("__landlocked_enforce failure!");
        goto end;
    }
    __lockdown_banner();
end:
    __landlocked_free(&ctx);
    return;
}
