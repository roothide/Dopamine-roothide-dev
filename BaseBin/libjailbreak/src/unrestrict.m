#include <stdio.h>
#include <unistd.h>
#include <spawn.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/event.h>
#include <sys/syscall.h>

#include <libproc.h>
#include <libproc_private.h>

#import <Foundation/Foundation.h>
#import "libjailbreak.h"


/* Status values. */
#define SIDL    1               /* Process being created by fork. */
#define SRUN    2               /* Currently runnable. */
#define SSLEEP  3               /* Sleeping on an address. */
#define SSTOP   4               /* Process debugging or suspension. */
#define SZOMB   5               /* Awaiting collection by parent. */

int proc_paused(pid_t pid, bool* paused)
{
	*paused = false;

	struct proc_bsdinfo procInfo={0};
	int ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo));
	if(ret != sizeof(procInfo)) {
		JBLogDebug("bsdinfo failed, %d,%s\n", errno, strerror(errno));
		return -1;
	}

	//JBLogDebug("%d pstat=%x flag=%x xstat=%x sec=%lld %lld nice=%d\n", ret, procInfo.pbi_status, procInfo.pbi_flags, procInfo.pbi_xstatus, procInfo.pbi_start_tvsec, procInfo.pbi_start_tvusec, procInfo.pbi_nice);
	if(procInfo.pbi_status == SSTOP)
	{
		JBLogDebug("%d pstat=%x flag=%x xstat=%x\n", ret, procInfo.pbi_status, procInfo.pbi_flags, procInfo.pbi_xstatus);
		*paused = true;
	}
	else if(procInfo.pbi_status != SRUN) {
		JBLogDebug("unexcept %d pstat=%x\n", ret, procInfo.pbi_status);
		return -1;
	}

	return 0;
}

int unrestrict(pid_t pid, int (*callback)(pid_t pid), bool should_resume)
{
	int retries=0;
	while(true) {
		struct proc_bsdinfo procInfo={0};
		int ret = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo));
		if(ret != sizeof(procInfo)) {
			JBLogDebug("bsdinfo failed, %d,%s\n", errno, strerror(errno));
			return -1;
		}

		//JBLogDebug("%d pstat=%x flag=%x xstat=%x sec=%lld %lld nice=%d\n", ret, procInfo.pbi_status, procInfo.pbi_flags, procInfo.pbi_xstatus, procInfo.pbi_start_tvsec, procInfo.pbi_start_tvusec, procInfo.pbi_nice);
		if(procInfo.pbi_status == SSTOP)
		{
			JBLogDebug("%d pstat=%x flag=%x xstat=%x\n", ret, procInfo.pbi_status, procInfo.pbi_flags, procInfo.pbi_xstatus);
			break;
		}

		if(procInfo.pbi_status != SRUN) {
			JBLogDebug("unexcept %d pstat=%x\n", ret, procInfo.pbi_status);
			return -1;
		}
		retries++;
		usleep(10*1000);
	}

	JBLogDebug("unrestrict retries=%d\n", retries);
	
    int ret = callback(pid);

	if(should_resume) 
		kill(pid, SIGCONT);

	return ret;
}

int patch_proc_csflags(int pid)
{
	int ret = 0;

	ksync_start();

	bool proc_needs_release = false;
	uint64_t proc = proc_for_pid(pid, &proc_needs_release);
	if(proc) {
		uint32_t csflags = proc_get_csflags(proc);
		uint32_t new_csflags = csflags | 4; //CS_GET_TASK_ALLOW
		proc_set_csflags(proc, new_csflags);

		if (proc_needs_release) proc_rele(proc);
	} else {
		ret = -1;
	}

	ksync_finish();
	
	return ret;
}

// int patch_proc_dyld(pid_t pid, bool resume)
// {
// 	int ret=0;
//     kern_return_t kr = 0;
//     task_port_t task = MACH_PORT_NULL;

// 	kr = task_for_pid(mach_task_self(), pid, &task);
// 	if(kr != KERN_SUCCESS || !MACH_PORT_VALID(task)) {
//     	JBLogError("tfp failed %d (%d,%s)\n", task, kr, mach_error_string(kr));
// 		goto failed;
// 	}

// 	uint64_t dyld_address=0;

//     vm_address_t region_base = 0;
//     vm_size_t region_size = 0;
//     vm_region_basic_info_data_64_t info;
//     mach_msg_type_number_t info_count = VM_REGION_BASIC_INFO_COUNT_64;
//     mach_port_t object_name;
//     while (true) {
//         region_base += region_size;
//         kr = vm_region_64(task, &region_base, &region_size, VM_REGION_BASIC_INFO_64, (vm_region_info_t) &info, &info_count, &object_name);
//         if (kr != KERN_SUCCESS) {
// 				JBLogError("vm query failed on %lx %lx, %d %s", region_base, region_size, kr, mach_error_string(kr));
// 			break;
// 		}

// 		JBLogDebug("region = %lx %lx %x/%x %d\n", region_base, region_size, info.protection, info.max_protection, info.inheritance);
		
// 		if(info.protection==(VM_PROT_READ|VM_PROT_EXECUTE)) {
// 			struct mach_header_64 header={0};
// 			size_t readsize=0;
// 			kr = vm_read_overwrite(task, (vm_address_t)region_base, sizeof(header), (vm_address_t)&header, &readsize);
// 			if(kr != KERN_SUCCESS) {
// 				JBLogError("vm_read failed! %d %s", kr, mach_error_string(kr));
// 				break;
// 			}
// 			JBLogDebug("magic=%08x filetype=%d", header.magic, header.filetype);
// 			if(header.magic==MH_MAGIC_64 && header.filetype==MH_DYLINKER) {
// 				dyld_address = (uint64_t)region_base;
// 				break;
// 			}
// 		}
//     }

// 	if(!dyld_address) {
// 		JBLogError("can't find dyld address");
// 		goto failed;
// 	}

// 	uint64_t patch_addr = dyld_address + 0x01C3C0;

// 	int v=0; size_t outsize=0;
// 	kr = vm_read_overwrite(task, (vm_address_t)patch_addr, 4, (vm_address_t)&v, &outsize);
//     if(kr != KERN_SUCCESS) {
//     	JBLogError("read %d,%s %x\n", kr, mach_error_string(kr), v);
// 		goto failed;
// 	}

//     kr = vm_protect(task, patch_addr, 8, false, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_COPY);
//     if(kr != KERN_SUCCESS) {
//     	JBLogError("protect %d,%s\n", kr, mach_error_string(kr));
// 		goto failed;
// 	}

// 	kr = vm_write(task, (vm_address_t)patch_addr, (vm_offset_t)(0?"\x7F\x23\x03\xD5\xFF\x03\x01\xD1":"\xE0\x1F\x80\xD2\xC0\x03\x5F\xD6"), 8);
//     if(kr != KERN_SUCCESS) {
//     	JBLogError("write %d,%s\n", kr, mach_error_string(kr));
// 		goto failed;
// 	}

//     kr = vm_protect(task, patch_addr, 8, false, VM_PROT_READ|VM_PROT_EXECUTE);
//     if(kr != KERN_SUCCESS) {
//     	JBLogError("protect %d,%s\n", kr, mach_error_string(kr));
// 		goto failed;
// 	}

// 	kr = vm_read_overwrite(task, (vm_address_t)patch_addr, 4, (vm_address_t)&v, &outsize);
//     if(kr != KERN_SUCCESS) {
//     	JBLogError("read %d,%s %x\n", kr, mach_error_string(kr), v);
// 		goto failed;
// 	}
	
// 	ret = 0;
// 	goto final;

// failed:
// 	ret = -1;

// final:
//     if(MACH_PORT_VALID(task)) {
// 		if(resume) task_resume(task);
// 		mach_port_deallocate(mach_task_self(), task);
// 	}

// 	return ret;
// }
