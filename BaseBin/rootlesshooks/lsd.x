#import <Foundation/Foundation.h>


#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"

BOOL isAppPath(const char* path)
{
    if(!path) return NO;
    
    char rp[PATH_MAX];
    if(!realpath(path, rp)) return NO;

    if(strncmp(rp, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX)-1) != 0)
        return NO;

    char* p1 = rp + sizeof(APP_PATH_PREFIX)-1;
    char* p2 = strchr(p1, '/');
    if(!p2) return NO;

    //is normal app or jailbroken app/daemon?
    if((p2 - p1) != (sizeof("xxxxxxxx-xxxx-xxxx-yxxx-xxxxxxxxxxxx")-1))
        return NO;

    return YES;
}

int proc_pidpath(int pid, void * buffer, uint32_t  buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);

%hook _LSCanOpenURLManager

- (BOOL)canOpenURL:(NSURL*)url publicSchemes:(BOOL)ispublic privateSchemes:(BOOL)isprivate XPCConnection:(NSXPCConnection*)xpc error:(NSError*)err
{
	char pathbuf[PATH_MAX]={0};
	if(xpc) {
		//lsd can get path for normal app
		proc_pidpath(xpc.processIdentifier, pathbuf, sizeof(pathbuf));
	}

	NSLog(@"canOpenURL:%@ publicSchemes:%d privateSchemes:%d XPCConnection:%@ proc:%d,%s", url, ispublic, isprivate, xpc, xpc.processIdentifier, pathbuf);
	//if(xpc) NSLog(@"canOpenURL:xpc=%@", xpc);

	NSArray* jbschemes = @[
		@"filza", 
		@"db-lmvo0l08204d0a0",
		@"boxsdk-810yk37nbrpwaee5907xc4iz8c1ay3my",
		@"com.googleusercontent.apps.802910049260-0hf6uv6nsj21itl94v66tphcqnfl172r",
		@"sileo",
		@"zbra", 
		@"santander", 
		@"icleaner", 
		@"xina", 
		@"ssh",
		@"apt-repo", 
		@"cydia",
		@"activator",
	];

	if(xpc && isAppPath(pathbuf))
	{
		if([jbschemes containsObject:url.scheme.lowercaseString]) {
			return NO;
		}
	}

	return %orig;
}

%end

void lsdInit(void)
{
	NSLog(@"lsdInit...");
	%init();
}
