#import <Foundation/Foundation.h>

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

	NSArray* jbschemes = @[@"filza", @"sileo", @"zbra", @"santander"];
#define NORMAL_APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"
	if(xpc && strncmp(pathbuf, NORMAL_APP_PATH_PREFIX, sizeof(NORMAL_APP_PATH_PREFIX)-1)==0)
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
