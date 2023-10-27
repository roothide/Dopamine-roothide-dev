#include <CoreFoundation/CoreFoundation.h>
#include <spawn.h>
#include <sys/syslog.h>

#define SYSLOG(...) {openlog("systemhook",LOG_PID,LOG_AUTH);syslog(LOG_DEBUG, __VA_ARGS__);closelog();}

#define JB_ENV_REQUIRED_COUNT 5

extern char* JBRAND;
extern char* JBROOT;

extern char *JB_SandboxExtensions;
extern char *JB_SandboxExtensions2;
extern char *JB_RootPath;
extern bool swh_is_debugged;
#define JB_ROOT_PATH(path) ({ \
	char *outPath = alloca(PATH_MAX); \
	strlcpy(outPath, JB_RootPath, PATH_MAX); \
	strlcat(outPath, path, PATH_MAX); \
	(outPath); \
})

bool stringStartsWith(const char *str, const char* prefix);
bool stringEndsWith(const char* str, const char* suffix);

int64_t jbdswFixSetuid(void);
int64_t jbdswProcessBinary(const char *filePath);
int64_t jbdswProcessLibrary(const char *filePath);
int64_t jbdswDebugMe(void);
int64_t jbdswInterceptUserspacePanic(const char *messageString);

int64_t jbdswRebootUserspace();
int64_t jbdswPatchSpawn(int pid, bool resume);
int64_t jbdswPatchExecAdd(const char* execfile, bool resume);
int64_t jbdswPatchExecDel(const char* execfile);
int64_t jbdswLockDSCPage(uint64_t address, uint64_t size);

int resolvePath(const char *file, const char *searchPath, int (^attemptHandler)(char *path));
int spawn_hook_common(pid_t *restrict pid, const char *restrict path,
					   const posix_spawn_file_actions_t *restrict file_actions,
					   const posix_spawnattr_t *restrict attrp,
					   char *const argv[restrict],
					   char *const envp[restrict],
					   void *pspawn_org);