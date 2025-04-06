#ifndef LANDLOCKED_H
#define LANDLOCKED_H

#include <stdint.h>
#include <string.h>

#ifdef LANDLOCKED_DEBUG
#   define I(fmt, ...) do { fprintf(stderr, "[I](%s:%d:%s): " fmt "\n", strrchr(__FILE__, '/') + 1, __LINE__, __FUNCTION__ __VA_OPT__(,) __VA_ARGS__); } while(0)
#   define W(fmt, ...) do { fprintf(stderr, "[W](%s:%d:%s): " fmt "\n", strrchr(__FILE__, '/') + 1, __LINE__, __FUNCTION__ __VA_OPT__(,) __VA_ARGS__); } while(0)
#   define E(fmt, ...) do { fprintf(stderr, "[E](%s:%d:%s): " fmt "\n", strrchr(__FILE__, '/') + 1, __LINE__, __FUNCTION__ __VA_OPT__(,) __VA_ARGS__); } while(0)
#else
#   define I(fmt, ...)
#   define W(fmt, ...)
#   define E(fmt, ...)
#endif


#define OUTCOME               int
#define SUCCESS               0
#define FAILURE               1
#define IF_SUCCESS(operation) if((operation)==SUCCESS)
#define IF_FAILURE(operation) if((operation)!=SUCCESS)


#define EOA_UIDS                        32768
#define EOA_PIDS                        32768
#define EOA_STRINGS                     NULL
#define DECL_UIDS_ARRAY(name, ...)      static const uid_t name[] = {__VA_ARGS__, EOA_UIDS}
#define DECL_PIDS_ARRAY(name, ...)      static const pid_t name[] = {__VA_ARGS__, EOA_PIDS}
#define DECL_STRINGS_ARRAY(name, ...)   static const char *name[] = {__VA_ARGS__, EOA_STRINGS}


struct landlocked_ctx {
    uid_t uid;
    pid_t pid;
    pid_t ppid;
    char *exe;
    int ruleset_fd;
};

OUTCOME __landlocked_init(struct landlocked_ctx *ctx);
OUTCOME __landlocked_random(uint8_t threshold);
OUTCOME __landlocked_enforce(const struct landlocked_ctx *ctx);
OUTCOME __landlocked_create_ruleset(
    struct landlocked_ctx *ctx,
    const struct landlock_ruleset_attr *attr
);
OUTCOME __landlocked_add_rule(
    const struct landlocked_ctx *ctx,
    const char *root,
    const char *name,
    uint64_t access
);
OUTCOME __landlocked_add_rules(
    const struct landlocked_ctx *ctx,
    const char *root,
    const char **skip,
    uint64_t access
);
OUTCOME __landlocked_uid_match(
    const struct landlocked_ctx *ctx,
    const uid_t *uids
);
OUTCOME __landlocked_pid_match(
    const struct landlocked_ctx *ctx,
    const pid_t *pids
);
OUTCOME __landlocked_ppid_match(
    const struct landlocked_ctx *ctx,
    const pid_t *ppids
);
OUTCOME __landlocked_exe_match(
    const struct landlocked_ctx *ctx,
    const char **exes
);
void __landlocked_free(struct landlocked_ctx *ctx);
void __landlocked_terminate(struct landlocked_ctx *ctx);

#endif /* LANDLOCKED_H */
