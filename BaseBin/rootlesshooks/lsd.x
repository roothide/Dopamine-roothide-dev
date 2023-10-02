#import <Foundation/Foundation.h>
#include <sys/mount.h>

#define APP_PATH_PREFIX "/private/var/containers/Bundle/Application/"

char* getAppUUIDOffset(const char* path)
{
    if(!path) return NULL;

    char rp[PATH_MAX];
    if(!realpath(path, rp)) return NULL;

    if(strncmp(rp, APP_PATH_PREFIX, sizeof(APP_PATH_PREFIX)-1) != 0)
        return NULL;

    char* p1 = rp + sizeof(APP_PATH_PREFIX)-1;
    char* p2 = strchr(p1, '/');
    if(!p2) return NULL;

    //is normal app or jailbroken app/daemon?
    if((p2 - p1) != (sizeof("xxxxxxxx-xxxx-xxxx-yxxx-xxxxxxxxxxxx")-1))
        return NULL;
	
	*p2 = '\0';

	return strdup(rp);
}

BOOL isJailbreakPath(const char* path)
{
    if(!path) return NO;

	struct statfs fs;
	if(statfs(path, &fs)==0)
	{
		if(strcmp(fs.f_mntonname, "/private/var") != 0)
			return NO;
	}

	char* p1 = getAppUUIDOffset(path);
	if(!p1) return YES; //reject by default

	char* p2=NULL;
	asprintf(&p2, "%s/_TrollStore", p1);

	int trollapp = access(p2, F_OK);

	free((void*)p1);
	free((void*)p2);

	if(trollapp==0) 
		return YES;

    return NO;
}

BOOL isNormalAppPath(const char* path)
{
    if(!path) return NO;
    
	char* p1 = getAppUUIDOffset(path);
	if(!p1) return NO; //allow by default

	char* p2=NULL;
	asprintf(&p2, "%s/_TrollStore", p1);

	int trollapp = access(p2, F_OK);

	free((void*)p1);
	free((void*)p2);

	if(trollapp==0) return NO;

    return YES;
}

int proc_pidpath(int pid, void * buffer, uint32_t  buffersize) __OSX_AVAILABLE_STARTING(__MAC_10_5, __IPHONE_2_0);

%hook _LSCanOpenURLManager

- (BOOL)canOpenURL:(NSURL*)url publicSchemes:(BOOL)ispublic privateSchemes:(BOOL)isprivate XPCConnection:(NSXPCConnection*)xpc error:(NSError*)err
{
	char pathbuf[PATH_MAX]={0};
	if(xpc) {
		//lsd can only get path for normal app
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

	if(xpc && isNormalAppPath(pathbuf))
	{
		if([jbschemes containsObject:url.scheme.lowercaseString]) {
			NSLog(@"block %@ for %s", url, pathbuf);
			return NO;
		}
	}

	return %orig;
}

%end


%hook _LSQueryContext

-(NSMutableDictionary*)_resolveQueries:(id)queries XPCConnection:(NSXPCConnection*)xpc error:(NSError*)err 
{
	NSMutableDictionary* result = %orig;

	char pathbuf[PATH_MAX]={0};
	if(xpc) {
		//lsd can only get path for normal app
		proc_pidpath(xpc.processIdentifier, pathbuf, sizeof(pathbuf));

		/* or 
			token
			xpc_connection_get_audit_token([xpc _xpcConnection], &token) //_LSCopyExecutableURLForXPCConnection
			proc_pidpath_audittoken(tokenarg, buffer, size) //_LSCopyExecutableURLForAuditToken
		*/
		
	}

	NSLog(@"_resolveQueries:%@ XPCConnection:%@ count=%ld proc:%d,%s", queries, xpc, result.count, xpc.processIdentifier, pathbuf);

	if(result)
	{
		NSLog(@"result=%@", result.class);
		//NSLog(@"result=%@, %@", result.allKeys, result.allValues);
		for(id key in result)
		{
			NSLog(@"result=%@, %@", [key class], [result[key] class]);
			if([key isKindOfClass:NSClassFromString(@"LSPlugInQueryWithUnits")])
			{
				//NSLog(@"_pluginUnits=%@", [key valueForKey:@"_pluginUnits"]);
				//NSLog(@"plugins=%@", result[key]);

				if(xpc && isNormalAppPath(pathbuf))
				{
					NSMutableIndexSet* removed = [[NSMutableIndexSet alloc] init];
					for (int i=0; i<[result[key] count]; i++) 
					{
						id plugin = result[key][i];
						id appbundle = [plugin performSelector:@selector(containingBundle)];
						//NSLog(@"plugin=%@, %@", plugin, appbundle);
						if(!appbundle) continue;

						NSURL* bundleURL = [appbundle performSelector:@selector(bundleURL)];
						if(isJailbreakPath(bundleURL.path.fileSystemRepresentation)) {
							NSLog(@"remove %@ for %s", plugin, pathbuf);
							[removed addIndex:i];
						}
					}

					[result[key] removeObjectsAtIndexes:removed];

					NSMutableArray* units = [[key valueForKey:@"_pluginUnits"] mutableCopy];
					[units removeObjectsAtIndexes:removed];
					[key setValue:[units copy] forKey:@"_pluginUnits"];
					
				}
			}
		}
		NSLog(@"result=%@", result);
	}

	return result;
}

%end

void lsdInit(void)
{
	NSLog(@"lsdInit...");
	%init();
}
