#import <spawn.h>
#import <Foundation/Foundation.h>
#import <libjailbreak/log.h>
#import <libjailbreak/libjailbreak.h>
#import "../systemhook/src/common.h"
#import "boomerang.h"
#import "substrate.h"
#include "crashreporter.h"
#import <mach-o/dyld.h>
#include <pthread.h>


#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"

NSString* getAppBundlePathForMachO(const char* path)
{
	if(!path) return nil;
	
	char rp[PATH_MAX];
	if(!realpath(path, rp)) return nil;

	if(strncmp(rp, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX)-1) != 0)
		return nil;

	char* p1 = rp + sizeof(APP_PATH_PREFIX)-1;
	char* p2 = strchr(p1, '/');
	if(!p2) return nil;

	//is normal app or jailbroken app/daemon? 
	if((p2 - p1) != (sizeof("xxxxxxxx-xxxx-xxxx-yxxx-xxxxxxxxxxxx")-1))
		return nil;

	char* p = strstr(p2,".app/");
	if(!p) return nil;
	
	p[sizeof(".app/")-1] = '\0';

	return [NSString stringWithUTF8String:rp];
}

//get main bundle identifier of app for (PlugIns's) executable path
NSString* getAppIdentifierForPath(const char* path)
{
	if(!path) return nil;

	NSString* bundlePath = getAppBundlePathForMachO(path);
	if(!bundlePath) return nil;

	NSDictionary* appInfo = [NSDictionary dictionaryWithContentsOfFile:[NSString stringWithFormat:@"%@/Info.plist",bundlePath]];
	if(!appInfo) return nil;

	NSString* identifier = appInfo[@"CFBundleIdentifier"];
	if(!identifier) return nil;

	JBLogDebug("spawn app [%s] %s", identifier.UTF8String, path);

	return identifier;
}

BOOL roothideBlacklistedApp(NSString* identifier)
{
	if(!identifier) return NO;

	NSString* configFilePath = jbrootPath(@"/var/mobile/Library/RootHide/RootHideConfig.plist");
	NSDictionary* roothideConfig = [NSDictionary dictionaryWithContentsOfFile:configFilePath];
	if(!roothideConfig) return NO;

	NSDictionary* appconfig = roothideConfig[@"appconfig"];
	if(!appconfig) return NO;

	NSNumber* blacklisted = appconfig[identifier];
	if(!blacklisted) return NO;

	return blacklisted.boolValue;
}

int (*posix_spawn_orig)(pid_t *restrict, const char *restrict, const posix_spawn_file_actions_t *restrict, posix_spawnattr_t *restrict, char *const[restrict], char *const[restrict]);

#include <os/lock.h>
static os_unfair_lock spinlock=OS_UNFAIR_LOCK_INIT; //do not use pthread mutext or nslock

int posix_spawn_orig_wrapper(pid_t *restrict pid, const char *restrict path,
					   const posix_spawn_file_actions_t *restrict file_actions,
					    posix_spawnattr_t *restrict attrp,
					   char *const argv[restrict],
					   char *const envp[restrict])
{
	// we need to disable the crash reporter during the orig call
	// otherwise the child process inherits the exception ports
	// and this would trip jailbreak detections
	
	// //posix_spawn run in multi-thread on launchd
	// os_unfair_lock_lock(&spinlock);
	// watch dog timeout???  may because of posix_spawn_with_filter in posix_spawn? should hook __posix_spawn

	crashreporter_pause();
	int r = posix_spawn_orig(pid, path, file_actions, attrp, argv, envp);
	crashreporter_resume();

	// os_unfair_lock_unlock(&spinlock);

	return r;
}

int posix_spawn_hook(pid_t *restrict pidp, const char *restrict path,
					   const posix_spawn_file_actions_t *restrict file_actions,
					   posix_spawnattr_t *restrict attrp,
					   char *const argv[restrict],
					   char *const envp[restrict])
{
	if (path) {
		const char *firstArg = "<none>";
		if (argv[0]) {
			if (argv[1]) {
				firstArg = argv[1];
			}
		}

		char executablePath[1024];
		uint32_t bufsize = sizeof(executablePath);
		_NSGetExecutablePath(&executablePath[0], &bufsize);
		if (!strcmp(path, executablePath)) {
			// This spawn will perform a userspace reboot...
			// Instead of the ordinary hook, we want to reinsert this dylib
			// This has already been done in envp so we only need to call the regular posix_spawn

			// But before, we want to pass the primitives to boomerang
			boomerang_userspaceRebootIncoming();

			//FILE *f = fopen("/var/mobile/launch_log.txt", "a");
			//fprintf(f, "==== USERSPACE REBOOT ====\n");
			//fclose(f);

			posix_spawnattr_t attr;
			if(!attrp) {
				attrp = &attr;
				posix_spawnattr_init(&attr);
			}

			short flags = 0;
			posix_spawnattr_getflags(attrp, &flags);
			posix_spawnattr_setflags(attrp, flags|POSIX_SPAWN_START_SUSPENDED); //!
			
			ksync_lock();
			// Say goodbye to this process
			return posix_spawn_orig_wrapper(pidp, path, file_actions, attrp, argv, envp);
		}
	}

	/*if (path) {
		const char *firstArg = "<none>";
		if (argv[0]) {
			if (argv[1]) {
				firstArg = argv[1];
			}
		}
		FILE *f = fopen("/var/mobile/launch_log.txt", "a");
		fprintf(f, "posix_spawn %s %s\n", path, firstArg);
		fclose(f);

		if (!strcmp(path, "/usr/libexec/xpcproxy")) {
			const char *tmpBlacklist[] = {
				"com.apple.logd"
			};
			size_t blacklistCount = sizeof(tmpBlacklist) / sizeof(tmpBlacklist[0]);
			for (size_t i = 0; i < blacklistCount; i++)
			{
				if (!strcmp(tmpBlacklist[i], firstArg)) {
					FILE *f = fopen("/var/mobile/launch_log.txt", "a");
					fprintf(f, "blocked injection %s\n", firstArg);
					fclose(f);
					int (*orig)(pid_t *restrict, const char *restrict, const posix_spawn_file_actions_t *restrict, const posix_spawnattr_t *restrict, char *const[restrict], char *const[restrict]) = posix_spawn_orig;
					return orig(pid, path, file_actions, attrp, argv, envp);
				}
			}
		}
	}*/

	NSString* appIdentifier = getAppIdentifierForPath(path);

	if(appIdentifier && roothideBlacklistedApp(appIdentifier)) {
		JBLogDebug("roothideBlacklistedApp:%s, %s", appIdentifier.UTF8String, path);
		return posix_spawn_orig_wrapper(pidp, path, file_actions, attrp, argv, envp);
	}

	posix_spawnattr_t attr=NULL;
	if(!attrp) {
		attrp = &attr;
		posix_spawnattr_init(&attr);
	}

	short flags = 0;
    posix_spawnattr_getflags(attrp, &flags);

	#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700
	int posix_spawnattr_getprocesstype_np(const posix_spawnattr_t * __restrict, int * __restrict) __API_AVAILABLE(macos(10.8), ios(6.0));

	int proctype = 0;
	posix_spawnattr_getprocesstype_np(attrp, &proctype);

	bool suspend = (proctype != POSIX_SPAWN_PROC_TYPE_DRIVER);
	bool should_resume=(flags&POSIX_SPAWN_START_SUSPENDED)==0;

	if(suspend) {
		posix_spawnattr_setflags(attrp, flags|POSIX_SPAWN_START_SUSPENDED);
	}

	JBLogDebug("launchd spawn path=%s flags=%x", path, flags);
	if(argv) for(int i=0; argv[i]; i++) JBLogDebug("\targs[%d] = %s", i, argv[i]);
	if(envp) for(int i=0; envp[i]; i++) JBLogDebug("\tenvp[%d] = %s", i, envp[i]);

	int pid=0;
	if(!pidp) pidp = &pid; //atomic with syscall
	int ret = spawn_hook_common(pidp, path, file_actions, attrp, argv, envp, posix_spawn_orig_wrapper);
	pid = *pidp;

	JBLogDebug("spawn ret=%d pid=%d", ret, pid);

	if(suspend && ret==0 && pid>0)
	{
		int patch_proc_csflags(int pid);

		patch_proc_csflags(pid);

		if(should_resume) kill(pid, SIGCONT);
	}


    // NSArray *csss = [NSThread callStackSymbols];
    // JBLogDebug("callstack=\n%s\n", [NSString stringWithFormat:@"%@", csss].UTF8String);

	if(attr) posix_spawnattr_destroy(&attr);
	
	return ret;
}


#include <sys/sysctl.h>
void logproclist()
{
	JBLogDebug("proclist start");
	static int maxArgumentSize = 0;
	if (maxArgumentSize == 0) {
		size_t size = sizeof(maxArgumentSize);
		if (sysctl((int[]){ CTL_KERN, KERN_ARGMAX }, 2, &maxArgumentSize, &size, NULL, 0) == -1) {
			perror("sysctl argument size");
			maxArgumentSize = 4096; // Default
		}
	}
	int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL};
	struct kinfo_proc *info;
	size_t length;
	int count;
	
	if (sysctl(mib, 3, NULL, &length, NULL, 0) < 0)
		return;
	if (!(info = malloc(length)))
		return;
	if (sysctl(mib, 3, info, &length, NULL, 0) < 0) {
		free(info);
		return;
	}
	count = length / sizeof(struct kinfo_proc);
	for (int i = 0; i < count; i++) {
		pid_t pid = info[i].kp_proc.p_pid;
		if (pid == 0) {
			continue;
		}
		size_t size = maxArgumentSize;
		char* buffer = (char *)malloc(length);
		if (sysctl((int[]){ CTL_KERN, KERN_PROCARGS2, pid }, 3, buffer, &size, NULL, 0) == 0) {
			char *executablePath = buffer + sizeof(int);
			JBLogDebug("pid=%d path=%s", pid, executablePath);
		}
		free(buffer);
	}
	free(info);

	JBLogDebug("proclist end");
}


#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <sys/syscall.h>
#define RB_QUICK        0x400   /* quick and ungraceful reboot with file system caches flushed*/
#define RB_PANIC        0x800   /* panic the kernel */

int	 __reboot(int how, int unk);
int	 (*reboot_orig)(int how, int unk);
int	 reboot_hook(int how, int unk)
{
	JBLogDebug("reboot...%d, %d", how, unk);
	
	sync();

	if(how==0 && unk==0) {

		logproclist();

		NSArray *csss = [NSThread callStackSymbols];
		JBLogDebug("callstack=\n%s\n", [NSString stringWithFormat:@"%@", csss].UTF8String);

		sync(); sleep(1);

		//make a panic log
		return syscall(SYS_reboot, RB_PANIC|RB_QUICK, "launchd force reboot");
	}

	return reboot_orig(how, unk);
}

void (*launchdlogfunc_orig)(uint64_t a1, uint64_t a2, char *format, va_list aptr, uint64_t a5);
void launchdlogfunc_hook(uint64_t a1, uint64_t a2, char *format, va_list aptr, uint64_t a5)
{
    char* buffer = NULL;
    vasprintf(&buffer, format, aptr);

	JBLogDebug("launchdlog: [%s] %s", a1, buffer);

	if(strstr(buffer, "exceeded sigkill timeout")) {

		logproclist();
		sync();
	}

    free(buffer);

	return launchdlogfunc_orig(a1,a2,format,aptr,a5);
}

#include <sys/sysctl.h>
int (*orig_sysctlbyname)(const char *, void *, size_t *, void *, size_t);
int new_sysctlbyname(const char *a1, void *a2, size_t *a3, void *a4, size_t a5)
{
	if(strcmp(a1, "vm.shared_region_pivot")==0) {
		return 0;
	}
	return orig_sysctlbyname(a1,a2,a3,a4,a5);
}

extern int gLaunchdImageIndex;
void initSpawnHooks(void)
{
	MSHookFunction(&posix_spawn, (void*)posix_spawn_hook, (void**)&posix_spawn_orig);
	MSHookFunction(&__reboot, (void*)reboot_hook, (void**)&reboot_orig);
 	MSHookFunction(&sysctlbyname, (void *)new_sysctlbyname, (void**)&orig_sysctlbyname);

	// uint64_t f1 = (uint64_t) _dyld_get_image_header(gLaunchdImageIndex) + 0x0361A8;
	// MSHookFunction((void*)f1, (void*)launchdlogfunc_hook, (void**)&launchdlogfunc_orig);

}