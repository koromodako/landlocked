#define _GNU_SOURCE

#include <linux/landlock.h>
#include <sys/syscall.h>
#include <sys/random.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include "landlocked.h"

/*****************************************************************************/
OUTCOME __landlocked_init(struct landlocked_ctx *ctx)
{
    OUTCOME outcome = FAILURE;
    int abi;
    I("called");
    abi = syscall(
        SYS_landlock_create_ruleset,
        NULL,
        0,
        LANDLOCK_CREATE_RULESET_VERSION
    );
    I("landlock abi version is %d", abi);
    if(abi < 4)
    {
        W("landlock abi version is too low!");
        goto end;
    }
    ctx->uid = getuid();
    ctx->pid = getpid();
    ctx->ppid = getppid();
    ctx->exe = realpath("/proc/self/exe", NULL);
    if(ctx->exe == NULL)
    {
        E("realpath failure! (%s)", strerror(errno));
        goto end;
    }
    ctx->ruleset_fd = -1;
    I("uid=%d pid=%d ppid=%d exe=%s", ctx->uid, ctx->pid, ctx->ppid, ctx->exe);
    outcome = SUCCESS;
end:
    return outcome;
}
/*****************************************************************************/
OUTCOME __landlocked_enforce(const struct landlocked_ctx *ctx)
{
    OUTCOME outcome = FAILURE;
    int ok;
    I("called");
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    ok = syscall(SYS_landlock_restrict_self, ctx->ruleset_fd, 0);
    if(ok != 0)
    {
        E("landlock_restrict_self failure! (%s)", strerror(errno));
        goto end;
    }
    outcome = SUCCESS;
    I("landlock policy enforced for %s", ctx->exe);
end:
    return outcome;
}
/*****************************************************************************/
OUTCOME __landlocked_random(uint8_t threshold)
{
    OUTCOME outcome = FAILURE;
    char random[4];
    I("called");
    if(getrandom(random, 4, 0) != 4)
    {
        E("getrandom failure! (%s)", strerror(errno));
        goto end;
    }
    outcome = random[0] < threshold ? SUCCESS : FAILURE;
end:
    return outcome;
}
/*****************************************************************************/
OUTCOME __landlocked_create_ruleset(
    struct landlocked_ctx *ctx,
    const struct landlock_ruleset_attr *attr
)
{
    OUTCOME outcome = FAILURE;
    I("called");
    ctx->ruleset_fd = syscall(
        SYS_landlock_create_ruleset,
        attr,
        sizeof(struct landlock_ruleset_attr),
        0
    );
    if(ctx->ruleset_fd < 0)
    {
        E("landlock_create_ruleset failure! (%s)", strerror(errno));
        goto end;
    }
    outcome = SUCCESS;
end:
    return outcome;
}
/*****************************************************************************/
OUTCOME __landlocked_uid_match(
    const struct landlocked_ctx *ctx,
    const uid_t *uids
)
{
    OUTCOME outcome = FAILURE;
    int i = 0;
    I("called");
    while(uids[i] < EOA_UIDS)
    {
        if(ctx->uid == uids[i])
        {
            I("matched i=%d ctx->uid=%d uids[i]=%d", i, ctx->uid, uids[i]);
            outcome = SUCCESS;
            goto end;
        }
        i++;
    }
end:
    return outcome;
}
/*****************************************************************************/
OUTCOME __landlocked_pid_match(
    const struct landlocked_ctx *ctx,
    const pid_t *pids
)
{
    OUTCOME outcome = FAILURE;
    int i = 0;
    I("called");
    while(pids[i] < EOA_PIDS)
    {
        if(ctx->pid == pids[i])
        {
            I("matched i=%d ctx->pid=%d pids[i]=%d", i, ctx->pid, pids[i]);
            outcome = SUCCESS;
            goto end;
        }
        i++;
    }
end:
    return outcome;
}
/*****************************************************************************/
OUTCOME __landlocked_ppid_match(
    const struct landlocked_ctx *ctx,
    const pid_t *ppids
)
{
    OUTCOME outcome = FAILURE;
    int i = 0;
    I("called");
    while(ppids[i] < EOA_PIDS)
    {
        if(ctx->ppid == ppids[i])
        {
            I("matched i=%d ctx->ppid=%d ppids[i]=%d", i, ctx->ppid, ppids[i]);
            outcome = SUCCESS;
            goto end;
        }
        i++;
    }
end:
    return outcome;
}
/*****************************************************************************/
OUTCOME __landlocked_exe_match(
    const struct landlocked_ctx *ctx,
    const char **exes
)
{
    OUTCOME outcome = FAILURE;
    int i = 0;
    I("called");
    while(exes[i] != EOA_STRINGS)
    {
        if(strcmp(ctx->exe, exes[i]) == 0)
        {
            I("matched i=%d ctx->exe=%s exes[i]=%s", i, ctx->exe, exes[i]);
            outcome = SUCCESS;
            goto end;
        }
        i++;
    }
end:
    return outcome;
}
/*****************************************************************************/
OUTCOME __landlocked_add_rule(
    const struct landlocked_ctx *ctx,
    const char *root,
    const char *name,
    uint64_t access
)
{
    OUTCOME outcome = FAILURE;
    int ok, sep, rootl, namel;
    char *fpath;
    struct stat fstat;
    struct landlock_path_beneath_attr path_beneath = {
        .allowed_access = access,
    };
    sep = strcmp(root, "/");
    rootl = strlen(root);
    namel = strlen(name);
    fpath = calloc(rootl + (sep ? 1 : 0) + namel + 1, sizeof(char));
    strcat(strcat(strcat(fpath, root), (sep ? "/" : "")), name);
    stat(fpath, &fstat);
    if(!(S_ISREG(fstat.st_mode) || S_ISDIR(fstat.st_mode)))
    {
        outcome = SUCCESS;
        goto free_end;
    }
    if(S_ISREG(fstat.st_mode))
    {
        path_beneath.allowed_access &= ~(
            LANDLOCK_ACCESS_FS_REMOVE_FILE |
            LANDLOCK_ACCESS_FS_REMOVE_DIR |
            LANDLOCK_ACCESS_FS_MAKE_DIR |
            LANDLOCK_ACCESS_FS_MAKE_REG |
            LANDLOCK_ACCESS_FS_MAKE_SYM |
            LANDLOCK_ACCESS_FS_REFER
        );
    }
    path_beneath.parent_fd = open(fpath, O_PATH | O_CLOEXEC);
    if(path_beneath.parent_fd < 0)
    {
        W("open failure! (%s)", strerror(errno));
        outcome = SUCCESS;
        goto free_end;
    }
    ok = syscall(
        SYS_landlock_add_rule,
        ctx->ruleset_fd,
        LANDLOCK_RULE_PATH_BENEATH,
        &path_beneath,
        0
    );
    if(ok != 0)
    {
        E("landlock_add_rule failure! (%s)", strerror(errno));
        goto close_end;
    }
    outcome = SUCCESS;
close_end:
    close(path_beneath.parent_fd);
free_end:
    free(fpath);
end:
    return outcome;
}
/*****************************************************************************/
OUTCOME __landlocked_add_rules(
    const struct landlocked_ctx *ctx,
    const char *root,
    const char **skip,
    uint64_t access
)
{
    OUTCOME outcome = FAILURE;
    int i, skipped;
    DIR *dir;
    struct dirent *dirent = NULL;
    I("called for %s", root);
    dir = opendir(root);
    if (dir == NULL)
    {
        E("opendir failure! (%s)", strerror(errno));
        goto end;
    }
    while ((dirent = readdir(dir)) != NULL)
    {
        i = 0;
        skipped = 0;
        while(skip[i] != NULL)
        {
            if(strcmp(dirent->d_name, skip[i]) == 0)
            {
                skipped = 1;
                break;
            }
            i++;
        }
        if(skipped)
        {
            W("skipped %s", dirent->d_name);
            continue;
        }
        IF_FAILURE(__landlocked_add_rule(ctx, root, dirent->d_name, access))
        {
            E("__landlocked_add_rule failure! (%s)", dirent->d_name);
            goto close_end;
        }
    }
    outcome = SUCCESS;
close_end:
    closedir(dir);
end:
    return outcome;
}
/*****************************************************************************/
void __landlocked_free(struct landlocked_ctx *ctx)
{
    if(ctx->exe != NULL)
    {
        free(ctx->exe);
        ctx->exe = NULL;
    }
    if(ctx->ruleset_fd >= 0)
    {
        close(ctx->ruleset_fd);
        ctx->ruleset_fd = -1;
    }
}
/*****************************************************************************/
void __landlocked_terminate(struct landlocked_ctx *ctx)
{
    pid_t pid;
    pid = ctx->pid;
    __landlocked_free(ctx);
    _exit(1);
}
