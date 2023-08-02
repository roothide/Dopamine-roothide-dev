//
//  KernelPatchfinder.swift
//  KernelPatchfinder
//
//  Created by Linus Henze.
//  Copyright © 2022 Pinauten GmbH. All rights reserved.
//

import Foundation
import SwiftMachO
import PatchfinderUtils
import Darwin

open class KernelPatchfinder {
    public let kernel: MachO
    
    /// Virtual base address of the kernel image
    public let baseAddress: UInt64
    
    /// Kernel entry point
    public let entryPoint: UInt64
    
    /**
     * Whether or not the kernel is running under Piranha
     *
     * - Warning: Patchfinder results might be wrong when running under Piranha - You should dump the kernel from RAM in this case
     */
    public let runningUnderPiranha: Bool
    
    /// `__TEXT_EXEC,__text` section
    public let textExec: PatchfinderSegment
    
    /// `__TEXT,__cstring` section
    public let cStrSect: PatchfinderSegment

    /// `__TEXT,__oslog` section
    public let osLogSect: PatchfinderSegment
    
    /// `__DATA,__data` section
    public let dataSect: PatchfinderSegment
    
    /// `__DATA_CONST,__const` section
    public let constSect: PatchfinderSegment
    
    /// `__PPLTEXT,__text` section
    public let pplText: PatchfinderSegment

    
    public lazy var namecache: (UInt64,UInt64)? = {
        //MOV W10, #0x4C11DB7 in ncinit->(inline)init_crc32
        guard let crcflag = textExec.addrOf([0x5283B6EA,0x72A0982A]) else {
            return nil
        }
        NSLog("crcflag=\(crcflag)")
        for i in 1..<100 {
            let pc1 = crcflag + UInt64(i * 4)
            if let hashinit = AArch64Instr.Emulate.bl(textExec.instruction(at: pc1) ?? 0, pc: pc1) {
                NSLog("hashinit=\(pc1), \(hashinit)")
                
                var nchashtbl:UInt64 = 0;
                var nchashmask:UInt64 = 0;
                
                for j in 1..<10 {
                    let pc = pc1 + UInt64(j * 4)
                    let adrp = textExec.instruction(at: pc) ?? 0
                    let str  = textExec.instruction(at: pc + 4) ?? 0
                    
                    if let value = AArch64Instr.Emulate.adrpStr(adrp: adrp, str: str, pc: pc) {
                        if nchashtbl==0 {
                            nchashtbl = value
                            NSLog("nchashtbl=\(nchashtbl)")
                        } else if nchashmask==0 {
                            nchashmask = value
                            NSLog("nchashmask=\(nchashmask)")
                            
                            if nchashtbl != nchashmask-8 {
                                NSLog("invalid nc")
                                return nil
                            }
                            
                            return (nchashtbl, nchashmask)
                        }
                    }
                }
            }
        }
                
        return nil
    }()
    
    /// Address of allproc
    public lazy var allproc: UInt64? = {
        // First find ref to string "shutdownwait"
        guard let shutdownwait = cStrSect.addrOf("shutdownwait") else {
            return nil
        }
        
        // Get an xref to shutdownwait
        guard let reboot_kernel = textExec.findNextXref(to: shutdownwait, optimization: .noBranches) else {
            return nil
        }
        
        // allproc should be first adrp ldr
        for i in 1..<20 {
            let pc = reboot_kernel + UInt64(i * 4)
            let adrp = textExec.instruction(at: pc) ?? 0
            let ldr  = textExec.instruction(at: pc + 4) ?? 0
            if let target = AArch64Instr.Emulate.adrpLdr(adrp: adrp, ldr: ldr, pc: pc) {
                return target
            }
        }
        
        return nil
    }()
    
    /// Address of the kernel's root translation table
    public lazy var cpu_ttep: UInt64? = {
        // First follow the jump in start
        guard let start_first_cpu = AArch64Instr.Emulate.b(textExec.instruction(at: entryPoint) ?? 0, pc: entryPoint) else {
            return nil
        }
        
        // Find cbz x21, something
        guard let cpu_ttep_pre = textExec.addrOf([0xB40000B5], startAt: start_first_cpu) else {
            return nil
        }
        
        let adrp = textExec.instruction(at: cpu_ttep_pre + 4)
        let add  = textExec.instruction(at: cpu_ttep_pre + 8)
        
        return AArch64Instr.Emulate.adrpAdd(adrp: adrp ?? 0, add: add ?? 0, pc: cpu_ttep_pre + 4)
    }()
    
    /// Address of the `ppl_bootstrap_dispatch` function
    public lazy var ppl_bootstrap_dispatch: UInt64? = {
        guard let ppl_dispatch_failed = dataSect.addrOf("ppl_dispatch: failed") else {
            return nil
        }
        
        var ppl_bootstrap_dispatch: UInt64!
        var pc: UInt64! = nil
        while true {
            guard let found = textExec.findNextXref(to: ppl_dispatch_failed, startAt: pc, optimization: .noBranches) else {
                return nil
            }
            
            if AArch64Instr.isAutibsp(textExec.instruction(at: found - 4) ?? 0) {
                ppl_bootstrap_dispatch = found
                break
            }
            
            pc = found + 4
        }
        
        // Find the start of ppl_bootstrap_dispatch
        // Search up to 20 instructions
        var ppl_bootstrap_dispatch_start: UInt64?
        for i in 1..<50 {
            let pc = ppl_bootstrap_dispatch - UInt64(i * 4)
            let instr = textExec.instruction(at: pc) ?? 0
            if let args = AArch64Instr.Args.cmp(instr) {
                if args.regA == 15 {
                    ppl_bootstrap_dispatch_start = pc
                    break
                }
            }
        }
        
        return ppl_bootstrap_dispatch_start
    }()
    
    /// Address of the `gxf_ppl_enter` function
    public lazy var gxf_ppl_enter: UInt64? = {
        guard let ppl_bootstrap_dispatch = ppl_bootstrap_dispatch else {
            return nil
        }
        
        // Find gxf_ppl_enter
        guard let gxf_ppl_enter = textExec.findNextXref(to: ppl_bootstrap_dispatch, optimization: .onlyBranches) else {
            return nil
        }
        
        // Find start of gxf_ppl_enter
        // Search up to 20 instructions
        var gxf_ppl_enter_start: UInt64?
        for i in 1..<20 {
            let pc = gxf_ppl_enter - UInt64(i * 4)
            if AArch64Instr.isPacibsp(textExec.instruction(at: pc) ?? 0) {
                gxf_ppl_enter_start = pc
                break
            }
        }
        
        return gxf_ppl_enter_start
    }()
    
    /// Address of the `pmap_enter_options_addr` function
    public lazy var pmap_enter_options_addr: UInt64? = {
        guard let pmap_enter_options_ppl = pplDispatchFunc(forOperation: 0xA) else {
            return nil
        }
        
        // Now the hard part: xref pmap_enter_options_ppl and find out which one is pmap_enter_options_addr
        // pmap_enter_options does an 'or' and an 'and' before the call, but no left shift
        var candidate = textExec.findNextXref(to: pmap_enter_options_ppl, optimization: .onlyBranches)
        var pmap_enter_options_addr: UInt64!
        while candidate != nil {
            // Check 20 instructions before
            var foundOr  = false
            var foundAnd = false
            for i in 1..<20 {
                let inst = textExec.instruction(at: candidate! - UInt64(i * 4)) ?? 0
                if inst & 0x7F800000 == 0x12000000 {
                    foundAnd = true
                } else if inst & 0x7F800000 == 0x32000000 {
                    foundOr  = true
                } else if inst & 0x7F800000 == 0x53000000 {
                    // Nope, that's a lsl
                    foundAnd = false
                    foundOr  = false
                    break
                }
            }
            
            if foundOr && foundAnd {
                // Should be it
                pmap_enter_options_addr = candidate
                break
            }
            
            candidate = textExec.findNextXref(to: pmap_enter_options_ppl, startAt: candidate! + 4, optimization: .onlyBranches)
        }
        
        guard pmap_enter_options_addr != nil else {
            return nil
        }
        
        // Find the start of pmap_enter_options_addr
        while !AArch64Instr.isPacibsp(textExec.instruction(at: pmap_enter_options_addr.unsafelyUnwrapped) ?? 0) {
            pmap_enter_options_addr -= 4
        }
        
        return pmap_enter_options_addr
    }()

    /// Address of `cs_allow_invalid`
    public lazy var cs_allow_invalid: UInt64? = {
        guard let pmap_cs_allow_invalid_ppl = pplDispatchFunc(forOperation: 0x51) else {
            return nil
        }

        var candidate = textExec.findNextXref(to: pmap_cs_allow_invalid_ppl, optimization: .onlyBranches)
        var cs_allow_invalid_addr: UInt64!
        while candidate != nil {

            let inst = textExec.instruction(at: candidate!) ?? 0
            if (inst & 0x80000000) != 0 { // only BL to pmap_cs_allow_invalid_ppl is in cs_allow_invalid
                while true {
                    // find function start
                    if AArch64Instr.isPacibsp(textExec.instruction(at: candidate!) ?? 0) {
                        return candidate!
                    }
                    
                    candidate! -= 4
                }
            }

            candidate = textExec.findNextXref(to: pmap_cs_allow_invalid_ppl, startAt: candidate! + 4, optimization: .onlyBranches)
        }
        
        return nil
    }()
    
    /// Address of the signed part of the `hw_lck_ticket_reserve_orig_allow_invalid` function
    public lazy var hw_lck_ticket_reserve_orig_allow_invalid_signed: UInt64? = {
        var pc: UInt64?
        while true {
            guard let candidate = textExec.addrOf([0x52800000, 0xD65F03C0], startAt: pc) else {
                return nil
            }
            
            if let args = AArch64Instr.Args.str(textExec.instruction(at: candidate - 4) ?? 0) {
                if args.regSrc == 10 && args.regDst == 16 {
                    if textExec.instruction(at: candidate - 8) != 0xD503205F {
                        return candidate - 4
                    }
                }
            }
            
            pc = candidate + 4
        }
    }()
    
    /// Address of the `hw_lck_ticket_reserve_orig_allow_invalid` function
    public lazy var hw_lck_ticket_reserve_orig_allow_invalid: UInt64? = {
        guard let signed = hw_lck_ticket_reserve_orig_allow_invalid_signed else {
            return nil
        }
        
        for i in 0..<50 {
            let pc = signed - UInt64(i * 4)
            if AArch64Instr.Emulate.adr(textExec.instruction(at: pc) ?? 0, pc: pc) != nil {
                return pc
            }
        }
        
        return nil
    }()
    
    /// Address of a `br x22` gadget (first signs, then branches)
    public lazy var br_x22_gadget: UInt64? = {
        var pc: UInt64?
        while true {
            guard let candidate = textExec.addrOf([0xD71F0ADF], startAt: pc) else {
                return nil
            }
            
            for i in 0..<50 {
                let pc = candidate - UInt64(i * 4)
                if textExec.instruction(at: pc) == 0xDAC103F6 {
                    return pc
                }
            }
            
            pc = candidate + 4
        }
    }()
    
    /// Address of `thread_exception_return`
    public lazy var exception_return: UInt64? = {
        return textExec.addrOf([0xD5034FDF, 0xD538D083, 0x910002BF])
    }()
    
    /// Address of `thread_exception_return` after checking the signed state
    public lazy var exception_return_after_check: UInt64? = {
        guard let exception_return = exception_return else {
            return nil
        }
        
        return textExec.addrOf([0xAA0303FE, 0xAA1603E3, 0xAA1703E4, 0xAA1803E5], startAt: exception_return)
    }()
    
    /// Address of `thread_exception_return` after checking the signed state, without restoring lr and others
    public lazy var exception_return_after_check_no_restore: UInt64? = {
        guard let exception_return_after_check = exception_return_after_check else {
            return nil
        }
        
        return textExec.addrOf([0xD5184021], startAt: exception_return_after_check)
    }()
    
    /// Address of a `ldp x0, x1, [x8]` gadget
    public lazy var ldp_x0_x1_x8_gadget: UInt64? = {
        return textExec.addrOf([0xA9400500, 0xD65F03C0])
    }()
    
    /// Address of a `str x8, [x9]` gadget
    public lazy var str_x8_x9_gadget: UInt64? = {
        return textExec.addrOf([0xF9000128, 0xD65F03C0])
    }()

    /// Address of a `cmp x1, #0; pacda x1, x9; str x9, [x8]; csel x9, xzr, x1, eq; ret` gadget
    public lazy var pacda_gadget: UInt64? = {
        return textExec.addrOf([0xF100003F, 0xDAC10921, 0x9A8103E9, 0xF9000109, 0xD65F03C0])
    }()
    
    /// Address of a `str x0, [x19]; ldr x?, [x20, #?]` gadget
    public lazy var str_x0_x19_ldr_x20: UInt64? = {
        var pc: UInt64?
        while true {
            guard let candidate = textExec.addrOf([0xF9000260], startAt: pc) else {
                return nil
            }
            
            if let vals = AArch64Instr.Args.ldr(textExec.instruction(at: candidate + 4) ?? 0) {
                if vals.regSrc == 20 {
                    return candidate
                }
            }
            
            pc = candidate + 4
        }
    }()
    
    /// Address of the `pmap_set_nested` function
    public lazy var pmap_set_nested: UInt64? = {
        return pplDispatchFunc(forOperation: 0x1A)
    }()
    
    /// Address of the `pmap_nest` function
    public lazy var pmap_nest: UInt64? = {
        guard let pmap_nest_ppl = pplDispatchFunc(forOperation: 0x11) else {
            return nil
        }
        
        guard var pmap_nest = textExec.findNextXref(to: pmap_nest_ppl, optimization: .onlyBranches) else {
            return nil
        }
        
        while !AArch64Instr.isPacibsp(textExec.instruction(at: pmap_nest) ?? 0) {
            pmap_nest -= 4
        }
        
        return pmap_nest
    }()
    
    /// Address of the `pmap_remove_options` function
    public lazy var pmap_remove_options: UInt64? = {
        guard let pmap_remove_ppl = pplDispatchFunc(forOperation: 0x17) else {
            return nil
        }
        
        var pc: UInt64?
        while true {
            guard var candidate = textExec.findNextXref(to: pmap_remove_ppl, startAt: pc, optimization: .onlyBranches) else {
                return nil
            }
            
            if textExec.instruction(at: candidate - 4) != 0x52802003 {
                while !AArch64Instr.isPacibsp(textExec.instruction(at: candidate) ?? 0) {
                    candidate -= 4
                }
                
                return candidate
            }
            
            pc = candidate + 4
        }
    }()
    
    /// Address of the `pmap_mark_page_as_ppl_page` function
    public lazy var pmap_mark_page_as_ppl_page: UInt64? = {
        return pplDispatchFunc(forOperation: 0x10)
    }()
    
    /// Address of the `pmap_create_options` function
    public lazy var pmap_create_options: UInt64? = {
        guard let pmap_create_options_ppl = pplDispatchFunc(forOperation: 0x8) else {
            return nil
        }
        
        var pc: UInt64?
        while true {
            guard var candidate = textExec.findNextXref(to: pmap_create_options_ppl, startAt: pc, optimization: .onlyBranches) else {
                return nil
            }
            
            if textExec.instruction(at: candidate - 4) != 0x52800002 {
                if textExec.instruction(at: candidate - 4) != 0x52800102 {
                    while !AArch64Instr.isPacibsp(textExec.instruction(at: candidate) ?? 0) {
                        candidate -= 4
                    }
                    
                    return candidate
                }
            }
            
            pc = candidate + 4
        }
    }()
    
    /// Address of the `gIOCatalogue` object
    public lazy var gIOCatalogue: UInt64? = {
        guard let kConfigTablesStr = cStrSect.addrOf("KernelConfigTables syntax error: %s") else {
            return nil
        }
        
        // Xref that to find IOCatalogue::initialize
        guard let ioCatalogueInitialize = textExec.findNextXref(to: kConfigTablesStr, optimization: .noBranches) else {
            return nil
        }
        
        // Find the end of that function
        guard let ioCatalogueInitializeEnd = textExec.addrOf([0xD65F0FFF], startAt: ioCatalogueInitialize) else {
            return nil
        }
        
        // Go back to the first adrp ldr
        var gIOCatalogue: UInt64!
        for i in 1..<100 {
            let pos = ioCatalogueInitializeEnd - UInt64(i * 4)
            let instr1 = textExec.instruction(at: pos) ?? 0
            let instr2 = textExec.instruction(at: pos + 4) ?? 0
            let val = AArch64Instr.Emulate.adrpLdr(adrp: instr1, ldr: instr2, pc: pos)
            if val != nil {
                gIOCatalogue = val
                break
            }
        }
        
        return gIOCatalogue
    }()
    
    /// Address of the `IOCatalogue::terminateDriversForModule(const char * moduleName, bool unload)` function
    public lazy var terminateDriversForModule: UInt64? = {
        guard let cantRemoveKextStr = cStrSect.addrOf("Can't remove kext %s - not found.") else {
            return nil
        }
        
        // Xref str to find OSKext::removeKextWithIdentifier
        guard let removeKextWithIdentifier = textExec.findNextXref(to: cantRemoveKextStr, optimization: .noBranches) else {
            return nil
        }
        
        // Find the start of removeKextWithIdentifier
        var removeKextWithIdentifierStart: UInt64!
        for i in 1..<100 {
            let pos = removeKextWithIdentifier - UInt64(i * 4)
            if AArch64Instr.isPacibsp(textExec.instruction(at: pos) ?? 0) {
                removeKextWithIdentifierStart = pos
                break
            }
        }
        
        guard removeKextWithIdentifierStart != nil else {
            return nil
        }
        
        // Xref to find the function that does a bl
        var terminateOSString: UInt64! = textExec.findNextXref(to: removeKextWithIdentifierStart, optimization: .onlyBranches)
        while let pc = terminateOSString,
              AArch64Instr.Emulate.bl(textExec.instruction(at: pc) ?? 0, pc: pc) == nil {
            terminateOSString = textExec.findNextXref(to: removeKextWithIdentifierStart, startAt: pc + 4, optimization: .onlyBranches)
        }
        
        guard terminateOSString != nil else {
            return nil
        }
        
        // Now we just find the start of this...
        var terminateOSStringStart: UInt64!
        for i in 1..<300 {
            let pos = terminateOSString - UInt64(i * 4)
            if AArch64Instr.isPacibsp(textExec.instruction(at: pos) ?? 0, alsoAllowNop: false) {
                terminateOSStringStart = pos
                break
            }
        }
        
        guard terminateOSStringStart != nil else {
            return nil
        }
        
        // ...xref it...
        guard let terminateDriversForModuleBL = textExec.findNextXref(to: terminateOSStringStart, optimization: .onlyBranches) else {
            return nil
        }
        
        // ...and find start
        var terminateDriversForModule: UInt64!
        for i in 1..<300 {
            let pos = terminateDriversForModuleBL - UInt64(i * 4)
            if AArch64Instr.isPacibsp(textExec.instruction(at: pos) ?? 0) {
                terminateDriversForModule = pos
                break
            }
        }
        
        return terminateDriversForModule
    }()
    
    /// Address of the `kalloc_data_external` function
    public lazy var kalloc_data_external: UInt64? = {
        // For kalloc, find "AMFI: %s: Failed to allocate memory for fatal error message, cannot produce a crash reason."
        // The first bl in the function will be to kalloc_data_external
        guard let amfi_fatal_err_str = cStrSect.addrOf("AMFI: %s: Failed to allocate memory for fatal error message, cannot produce a crash reason.") else {
            return nil
        }
        
        guard var amfi_fatal_err_func = textExec.findNextXref(to: amfi_fatal_err_str, optimization: .noBranches) else {
            return nil
        }
        
        var amfi_fatal_err_func_start: UInt64!
        for i in 1..<300 {
            let pos = amfi_fatal_err_func - UInt64(i * 4)
            if AArch64Instr.isPacibsp(textExec.instruction(at: pos) ?? 0) {
                amfi_fatal_err_func_start = pos
                break
            }
        }
        
        guard amfi_fatal_err_func_start != nil else {
            return nil
        }
        
        var kalloc_external: UInt64!
        for i in 1..<20 {
            let pc = amfi_fatal_err_func_start + UInt64(i * 4)
            let target = AArch64Instr.Emulate.bl(textExec.instruction(at: pc) ?? 0, pc: pc)
            if target != nil {
                kalloc_external = target
                break
            }
        }
        
        return kalloc_external
    }()
    
    /// Address of the `kfree_data_external` function
    public lazy var kfree_data_external: UInt64? = {
        // For kfree, find "AMFI: %s: Failed to allocate memory for fatal error message, cannot produce a crash reason."
        // The second bl after this reference is kfree_data_external
        guard let amfi_fatal_err_str = cStrSect.addrOf("AMFI: %s: Failed to allocate memory for fatal error message, cannot produce a crash reason.") else {
            return nil
        }
        
        guard var amfi_fatal_err_func_string_xref = textExec.findNextXref(to: amfi_fatal_err_str, optimization: .noBranches) else {
            return nil
        }
        
        var kfree_data_external: UInt64!
        var blFoundCount: UInt64! = 0

        for i in 1..<20 {
            let pc = amfi_fatal_err_func_string_xref + UInt64(i * 4)
            let target = AArch64Instr.Emulate.bl(textExec.instruction(at: pc) ?? 0, pc: pc)
            if target != nil {
                blFoundCount += 1
                // Second bl after the xref is kfree_data_external
                if blFoundCount == 2 {
                    kfree_data_external = target
                    break
                }
            }
        }
        
        return kfree_data_external
    }()

    /// Address of the `ptrauth_utils_sign_blob_generic` function
    public lazy var ptrauth_utils_sign_blob_generic: UInt64? = {
        // ptrauth_utils_auth_blob_generic references this unique string, the first BL inside it is ptrauth_utils_sign_blob_generic
        guard let signature_mismatch_str = cStrSect.addrOf("signature mismatch for %lu bytes at %p, calculated %lx vs %lx @%s:%d") else {
            return nil
        }

        guard var ptrauth_utils_auth_blob_generic_func = textExec.findNextXref(to: signature_mismatch_str, optimization: .noBranches) else {
            return nil
        }

        var ptrauth_utils_auth_blob_generic_func_start: UInt64!
        for i in 1..<300 {
            let pos = ptrauth_utils_auth_blob_generic_func - UInt64(i * 4)
            if AArch64Instr.isPacibsp(textExec.instruction(at: pos) ?? 0) {
                ptrauth_utils_auth_blob_generic_func_start = pos
                break
            }
        }

        var ptrauth_utils_sign_blob_generic: UInt64!
        for i in 1..<20 {
            let pc = ptrauth_utils_auth_blob_generic_func_start + UInt64(i * 4)
            let target = AArch64Instr.Emulate.bl(textExec.instruction(at: pc) ?? 0, pc: pc)
            if target != nil {
                ptrauth_utils_sign_blob_generic = target
                break
            }
        }
        
        return ptrauth_utils_sign_blob_generic
    }()

    /// Address of the `mac_label_set` function
    public lazy var mac_label_set: UInt64? = {
        guard let sandbox_failed_revoke_str = osLogSect.addrOf("Sandbox failed to revoke host port (%d) for pid %d") else {
            return nil
        }

        guard var proc_apply_sandbox_func = textExec.findNextXref(to: sandbox_failed_revoke_str, optimization: .noBranches) else {
            return nil
        }

        var proc_apply_sandbox_func_start: UInt64!
        for i in 1..<500 {
            let pos = proc_apply_sandbox_func - UInt64(i * 4)
            if AArch64Instr.isPacibsp(textExec.instruction(at: pos) ?? 0, alsoAllowNop:false) {
                proc_apply_sandbox_func_start = pos
                break
            }
        }

        var mac_label_set: UInt64!
        var blFoundCount: UInt64! = 0
        for i in 1..<30 {
            let pc = proc_apply_sandbox_func_start + UInt64(i * 4)
            let target = AArch64Instr.Emulate.bl(textExec.instruction(at: pc) ?? 0, pc: pc)
            if target != nil {
                blFoundCount += 1
                if blFoundCount == 2 {
                    // second bl in proc_apply_sandbox is call to mac_label_set
                    mac_label_set = target
                    break
                }
            }
        }

        return mac_label_set
    }()

    /*public lazy var OSEntitlements_zone: UInt64? = {
        guard let OSEntitlementsString = cStrSect.addrOf("OSEntitlements") else {
            return nil
        }

        guard var OSEntitlementsZoneInitMid = textExec.findNextXref(to: OSEntitlementsString, optimization: .noBranches) else {
            return nil
        }

        for i in 1..<10 {
            let pc = OSEntitlementsZoneInitMid + UInt64(i * 4)
            let instr = textExec.instruction(at: pc) ?? 0
            if (instr & 0x00000004) != 0 /*???? (adrp) x4, ????*/ {
                return AArch64Instr.Emulate.adrpAdd(adrp: instr, add: textExec.instruction(at: pc+4) ?? 0, pc: pc)
            }
        }
        return nil
    }()

    public lazy var OSEntitlements_Destructor: UInt64? = {
        guard let OSEntitlements_zone = self.OSEntitlements_zone else {
            return nil
        }

        var pc: UInt64?
        while true {
            pc = textExec.findNextXref(to: OSEntitlements_zone, startAt: pc, optimization: .noBranches)
            if pc == nil {
                break
            }

            let isAlloc = (textExec.instruction(at: pc!-4) ?? 0 == 0xAA0003E8) /* mov x8, x0 */
            if !isAlloc {
                for i in 1..<20 {
                    let pos = pc! - UInt64(i * 4)
                    if AArch64Instr.isPacibsp(textExec.instruction(at: pos) ?? 0, alsoAllowNop:false) {
                        return pos
                    }
                }
            }

            pc = pc! + 4
        }

        return nil
    }()

    public lazy var OSEntitlements_MetaClass_alloc: UInt64? = {
        guard let OSEntitlements_zone = self.OSEntitlements_zone else {
            return nil
        }

        var pc: UInt64?
        while true {
            // Problem: Patchfinder is not able to find ADRP, LDR xrefs
            pc = textExec.findNextXref(to: OSEntitlements_zone, startAt: pc, optimization: .noBranches)
            
            if pc == nil {
                break
            }

            let isAlloc = (textExec.instruction(at: pc!-4) ?? 0 == 0xAA0003E8) /* mov x8, x0 */
            if isAlloc {
                for i in 1..<20 {
                    let pos = pc! - UInt64(i * 4)
                    if AArch64Instr.isPacibsp(textExec.instruction(at: pos) ?? 0, alsoAllowNop:false) {
                        return pos
                    }
                }
            }

            pc = pc! + 4
        }

        return nil
    }()*/

    /// Address of the `kernel_mount` function
    public lazy var kernel_mount: UInt64? = {
        
        // there are 3 references to this string in some function
        // we want the last one
        guard let basesystem_str = cStrSect.addrOf("/System/Volumes/BaseSystem") else {
            return nil
        }

        var last_xref: UInt64! = 0
        var spc: UInt64?
        for i in 1..<20 {
            spc = textExec.findNextXref(to: basesystem_str, startAt:spc, optimization: .noBranches)
            if (spc == nil) {
                break
            }
            last_xref = spc!
            spc! += 4
        }

        var kernel_mount: UInt64?

        // last BL before last xref is call to kernel_mount
        for i in 1..<20 {
            let pc = last_xref - UInt64(4 * i)
            let target = AArch64Instr.Emulate.bl(textExec.instruction(at: pc) ?? 0, pc: pc)
            if target != nil {
                kernel_mount = target
                break
            }
        }

        return kernel_mount
    }()

    public lazy var mount_common: UInt64? = {
        guard let panic_str = cStrSect.addrOf("mount_common(): mount of %s filesystem failed with %d, but vnode list is not empty. @%s:%d") else {
            return nil
        }

        guard let ref: UInt64? = textExec.findNextXref(to: panic_str, startAt:nil, optimization: .noBranches) else {
            return nil
        }

        var mount_common = ref!
        while !AArch64Instr.isPacibsp(textExec.instruction(at: mount_common) ?? 0) {
            mount_common -= 4
        }
        return mount_common
    }()

    public lazy var kerncontext: UInt64? = {
        
        // there are 3 references to this string in some function
        // we want the last one
        guard let basesystem_str = cStrSect.addrOf("/System/Volumes/BaseSystem") else {
            return nil
        }

        var last_xref: UInt64! = 0
        var spc: UInt64?
        for i in 1..<20 {
            spc = textExec.findNextXref(to: basesystem_str, startAt:spc, optimization: .noBranches)
            if (spc == nil) {
                break
            }
            last_xref = spc!
            spc! += 4
        }

        var kerncontext: UInt64?

        // next ADRL after last xref is kerncontext
        for i in 1..<5 {
            let pc = last_xref + UInt64(4 * i)
            let adrp = textExec.instruction(at: pc) ?? 0
            let ldr  = textExec.instruction(at: pc + 4) ?? 0
            let target = AArch64Instr.Emulate.adrpAdd(adrp: adrp, add: ldr, pc: pc)
            if target != nil {
                kerncontext = target
                break
            }
        }

        return kerncontext
    }()

    public lazy var safedounmount: UInt64? = {
        guard let entitlement_str = cStrSect.addrOf("com.apple.private.vfs.role-account-unmount") else {
            return nil
        }

        guard let ref: UInt64 = textExec.findNextXref(to: entitlement_str, startAt:nil, optimization: .noBranches) else {
            return nil
        }

        var safedounmount = ref
        while !AArch64Instr.isPacibsp(textExec.instruction(at: safedounmount) ?? 0, alsoAllowNop: false) {
            safedounmount -= 4
        }

        return safedounmount
    }()

    public lazy var namei: UInt64? = {
        guard let str = cStrSect.addrOf("We need to keep going on a continued lookup, but for vp type %d (tag %d) @%s:%d") else {
            return nil
        }

        guard let ref: UInt64 = textExec.findNextXref(to: str, startAt:nil, optimization: .noBranches) else {
            return nil
        }

        var namei = ref
        while !AArch64Instr.isPacibsp(textExec.instruction(at: namei) ?? 0, alsoAllowNop: false) {
            namei -= 4
        }
        return namei
    }()

    public lazy var vfs_context_current: UInt64? = {
        // Only exists on iOS 15.2 and up
        if #available(iOS 15.2, *) {}
        else { return nil }

        guard let mount_common_addr = mount_common else {
            return nil
        }

        guard let kernel_mount_addr = kernel_mount else {
            return nil
        }

        var pc: UInt64? = nil
        while true {
            guard var candidate = textExec.findNextXref(to: mount_common_addr, startAt: pc, optimization: .onlyBranches) else {
                return nil
            }

            var candidateStart = candidate
            while !AArch64Instr.isPacibsp(textExec.instruction(at: candidateStart) ?? 0) {
                candidateStart -= 4
            }
            
            if candidateStart != kernel_mount_addr {
                for i in 1..<20 {
                    let checkStart = candidateStart + UInt64(i * 4)
                    let target = AArch64Instr.Emulate.bl(textExec.instruction(at: checkStart) ?? 0, pc: checkStart)
                    if target != nil {
                        return target
                    }
                }
            }
            
            pc = candidate + 4
        }
    }()

    /// Address of the `ml_sign_thread_state` function
    public lazy var ml_sign_thread_state: UInt64? = {
        return textExec.addrOf([0x9AC03021, 0x9262F842, 0x9AC13041, 0x9AC13061, 0x9AC13081, 0x9AC130A1, 0xF9009401, 0xD65F03C0])
    }()

    // Address of the `proc_find` function
    public lazy var proc_find: UInt64? = {
        // all functions that reference this string call proc_find at the top
        guard let entitlement_str = cStrSect.addrOf("com.apple.private.process.suspend-resume.any") else {
            return nil
        }

        guard let ref: UInt64? = textExec.findNextXref(to: entitlement_str, startAt:nil, optimization: .noBranches) else {
            return nil
        }

        var funcStart = ref!
        while !AArch64Instr.isPacibsp(textExec.instruction(at: funcStart) ?? 0) {
            funcStart -= 4
        }

        var proc_find: UInt64!
        for i in 1..<50 {
            let pc = funcStart + UInt64(i * 4)
            let target = AArch64Instr.Emulate.bl(textExec.instruction(at: pc) ?? 0, pc: pc)
            if target != nil {
                proc_find = target
                break
            }
        }

        return proc_find
    }()

    // Address of the `proc_rele` function
    public lazy var proc_rele: UInt64? = {
        // all functions that reference this string call proc_find at the end
        guard let entitlement_str = cStrSect.addrOf("com.apple.private.process.suspend-resume.any") else {
            return nil
        }

        guard let ref: UInt64 = textExec.findNextXref(to: entitlement_str, startAt:nil, optimization: .noBranches) else {
            return nil
        }

        var funcEnd = ref
        while (textExec.instruction(at: funcEnd) ?? 0) != 0xD65F0FFF {
            funcEnd += 4
        }

        var proc_rele: UInt64!
        for i in 1..<50 {
            let pc = funcEnd - UInt64(i * 4)
            let target = AArch64Instr.Emulate.bl(textExec.instruction(at: pc) ?? 0, pc: pc)
            if target != nil {
                proc_rele = target
                break
            }
        }

        return proc_rele
    }()
    
    /// Address of the ppl handler table
    public lazy var ppl_handler_table: UInt64? = {
        guard let ppl_bootstrap_dispatch = ppl_bootstrap_dispatch else {
            return nil
        }
        
        var ppl_handler_table: UInt64?
        for i in 1..<20 {
            let pc = ppl_bootstrap_dispatch + UInt64(i * 4)
            let adrp = textExec.instruction(at: pc) ?? 0
            let ldr  = textExec.instruction(at: pc + 4) ?? 0
            let tbl = AArch64Instr.Emulate.adrpAdd(adrp: adrp, add: ldr, pc: pc)
            if tbl != nil {
                ppl_handler_table = tbl
                break
            }
        }
        
        return ppl_handler_table
    }()
    
    /// Address of `pmap_image4_trust_caches`
    public lazy var pmap_image4_trust_caches: UInt64? = {
        guard let ppl_handler_table = ppl_handler_table else {
            return nil
        }
        
        guard var pmap_lookup_in_loaded_trust_caches_internal = constSect.r64(at: ppl_handler_table + 0x148) else {
            return nil
        }
        
        if (pmap_lookup_in_loaded_trust_caches_internal >> 48) == 0x8011 {
            // Relocation, on-disk kernel
            pmap_lookup_in_loaded_trust_caches_internal &= 0xFFFFFFFFFFFF
            pmap_lookup_in_loaded_trust_caches_internal += 0xFFFFFFF007004000
        } else {
            // Probably live kernel
            // Strip pointer authentication code
            pmap_lookup_in_loaded_trust_caches_internal |= 0xFFFFFF8000000000
        }
        
        var pmap_image4_trust_caches: UInt64?
        for i in 1..<20 {
            let pc = pmap_lookup_in_loaded_trust_caches_internal + UInt64(i * 4)
            let emu = AArch64Instr.Emulate.ldr(pplText.instruction(at: pc) ?? 0, pc: pc)
            if emu != nil {
                pmap_image4_trust_caches = emu
                break
            }
        }
        
        return pmap_image4_trust_caches
    }()
    
    /// Get the EL level the kernel runs at
    public lazy var kernel_el: UInt64? = {
        // Get start
        guard let realStart = AArch64Instr.Emulate.b(textExec.instruction(at: entryPoint) ?? 0, pc: entryPoint) else {
            return nil
        }
        
        let targetInstructionAddr = realStart + 0x10
        let instr = textExec.instruction(at: targetInstructionAddr) ?? 0
        if instr == 0xD5384240 {
            return 2
        } else if AArch64Instr.Emulate.adrp(instr, pc: targetInstructionAddr) != nil {
            return 1
        } else {
            return nil
        }
    }()
    
    /// Offset of `TH_RECOVER` in thread struct
    public lazy var TH_RECOVER: UInt64? = {
        guard let lckFunc = hw_lck_ticket_reserve_orig_allow_invalid_signed else {
            return nil
        }
        
        guard let args = AArch64Instr.Args.str(textExec.instruction(at: lckFunc) ?? 0) else {
            return nil
        }
        
        return UInt64(args.imm)
    }()
    
    /// Offset of `TH_KSTACKPTR` in thread struct
    public lazy var TH_KSTACKPTR: UInt64? = {
        var pc: UInt64?
        while true {
            guard let candidate = textExec.addrOf([0xD538D08A], startAt: pc) else {
                return nil
            }
            
            if let args = AArch64Instr.Args.ldr(textExec.instruction(at: candidate + 4) ?? 0) {
                if (textExec.instruction(at: candidate + 8) ?? 0) == 0xD503233F {
                    return UInt64(args.imm)
                }
            }
            
            pc = candidate + 4
        }
    }()
    
    /// Offset of `ACT_CONTEXT` in thread struct
    public lazy var ACT_CONTEXT: UInt64? = {
        var pc: UInt64?
        while true {
            guard let candidate = textExec.addrOf([0xD5184100, 0xA8C107E0, 0xD50040BF], startAt: pc) else {
                return nil
            }
            
            if let args = AArch64Instr.Args.addImm(textExec.instruction(at: candidate - 12) ?? 0) {
                return UInt64(args.imm)
            }
            
            pc = candidate + 4
        }
    }()
    
    /// Offset of `ACT_CPUDATAP` in thread struct
    public lazy var ACT_CPUDATAP: UInt64? = {
        var pc: UInt64?
        while true {
            guard let candidate = textExec.addrOf([0xD50343DF], startAt: pc) else {
                return nil
            }
            
            if let args = AArch64Instr.Args.ldr(textExec.instruction(at: candidate + 4) ?? 0) {
                if args.regDst == 11 && args.regSrc == 10 {
                    return UInt64(args.imm)
                }
            }
            
            pc = candidate + 4
        }
    }()
    
    /// Offset of `ITK_SPACE` in task struct
    public lazy var ITK_SPACE: UInt64? = {
        guard let corpse_released_str = osLogSect.addrOf("Corpse released, count at %d\n") else {
            return nil
        }

        // find middle of task_crashinfo_release_ref
        var pc: UInt64! = nil
        var task_crashinfo_release_ref_mid = UInt64(0)
        while task_crashinfo_release_ref_mid == 0 {
            guard let candidate = textExec.findNextXref(to: corpse_released_str, startAt: pc, optimization: .noBranches) else {
                return nil
            }

            for i in 1..<20 {
                if textExec.instruction(at: candidate + UInt64(4*i)) == 0x52800000 {
                    task_crashinfo_release_ref_mid = candidate
                    break
                }
            }

            pc = candidate + 4
        }

        // find function start of task_crashinfo_release_ref
        var task_crashinfo_release_ref = task_crashinfo_release_ref_mid
        while true {
            if AArch64Instr.isPacibsp(textExec.instruction(at: task_crashinfo_release_ref) ?? 0, alsoAllowNop: false) {
                break
            }
            task_crashinfo_release_ref -= 4
        }

        // scan all xrefs of that until we find one that has "MOV W1, 0x4000" in the 20 instructions before it
        var task_collect_crash_info_mid = UInt64(0)
        pc = nil
        while task_collect_crash_info_mid == 0 {
            guard let candidate = textExec.findNextXref(to: task_crashinfo_release_ref, startAt: pc) else {
                return nil
            }

            for i in 1..<20 {
                if textExec.instruction(at: candidate - UInt64(4*i)) == 0x52880001 {
                    task_collect_crash_info_mid = candidate
                    break
                }
            }

            pc = candidate + 4
        }

        // find function start of that xref
        var task_collect_crash_info = task_collect_crash_info_mid
        while true {
            if AArch64Instr.isPacibsp(textExec.instruction(at: task_collect_crash_info) ?? 0) {
                break
            }
            task_collect_crash_info -= 4
        }

        // scan for xrefs of that until we find one that has a "MOV W2, #1" directly in front of it
        var before_add = UInt64(0)
        pc = nil
        while true {
            guard let candidate = textExec.findNextXref(to: task_collect_crash_info, startAt: pc) else {
                return nil
            }

            if textExec.instruction(at: candidate - UInt64(4)) == 0x52800022 {
                before_add = candidate
                break
            }

            pc = candidate + 4
        }

        // go down until the next ADD instruction, the immediate of that is our offset
        pc = before_add
        while true {
            if let args = AArch64Instr.Args.addImm(textExec.instruction(at: pc) ?? 0) {
                return UInt64(args.imm)
            }
            pc = pc + 4
        }
    }()
    
    /// Offset of `PMAP` in vm\_map struct
    public lazy var VM_MAP_PMAP: UInt64? = {
        guard let control_access_str = cStrSect.addrOf("userspace has control access to a kernel") else {
            return nil
        }
        
        guard var task_check_func = textExec.findNextXref(to: control_access_str, optimization: .noBranches) else {
            return nil
        }
        
        var pc = task_check_func
        while true {
            pc = pc - 4
            
            if let args = AArch64Instr.Args.ldr(textExec.instruction(at: pc) ?? 0) {
                if AArch64Instr.Emulate.compareBranch(textExec.instruction(at: pc + 4) ?? 0, pc: pc + 4) != nil {
                    if AArch64Instr.Emulate.adrp(textExec.instruction(at: pc - 4) ?? 0, pc: pc - 4) == nil {
                        return UInt64(args.imm)
                    }
                }
            }
        }
    }()
    
    /// Offset of `LABEL` in mach\_port struct
    public lazy var PORT_LABEL: UInt64? = {
        guard let label_check_str = cStrSect.addrOf("ipc_kobject_label_check: attempted receive right copyout for labeled kobject") else {
            return nil
        }
        
        guard var label_check_func = textExec.findNextXref(to: label_check_str, optimization: .noBranches) else {
            return nil
        }
        
        var pc = label_check_func
        while true {
            pc = pc - 4
            
            guard let br = textExec.findNextXref(to: pc, optimization: .onlyBranches) else {
                continue
            }
            
            pc = br
            
            while true {
                pc += 4
                if let args = AArch64Instr.Args.ldr(textExec.instruction(at: pc) ?? 0) {
                    return UInt64(args.imm)
                }
            }
        }
    }()

    /// Return patchfinder for the currently running kernel.
    public static var running: KernelPatchfinder? = {
        if let krnl = MachO.runningKernel {
            return KernelPatchfinder(kernel: krnl)
        }
        
        // Try libgrabkernel (if available)
        typealias grabKernelType = @convention(c) (_ path: UnsafePointer<CChar>?, _ isResearchDevice: Int32) -> Int32
        guard let grabKernelRaw = dlsym(dlopen(nil, 0), "grabkernel") else {
            return nil
        }
        
        let grabkernel = unsafeBitCast(grabKernelRaw, to: grabKernelType.self)
        
        let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0].path
        let kernel = documents + "/kernel.img4"
        if !FileManager.default.fileExists(atPath: kernel) {
            let status = grabkernel(kernel, 0)
            guard status == 0 else {
                return nil
            }
        }
        
        guard let k = loadImg4Kernel(path: kernel) else {
            return nil
        }
        
        guard let machO = try? MachO(fromData: k, okToLoadFAT: false) else {
            return nil
        }
        
        return KernelPatchfinder(kernel: machO)
    }()
    
    /// Initialize patchfinder for the given kernel.
    public required init?(kernel: MachO) {
        self.kernel = kernel
        
        guard let textExec = kernel.pfSection(segment: "__TEXT_EXEC", section: "__text") else {
            return nil
        }
        
        guard let cStrSect = kernel.pfSection(segment: "__TEXT", section: "__cstring") else {
            return nil
        }

        guard let osLogSect = kernel.pfSection(segment: "__TEXT", section: "__os_log") else {
            return nil
        }
        
        guard let dataSect = kernel.pfSection(segment: "__DATA", section: "__data") else {
            return nil
        }
        
        guard let constSect = kernel.pfSection(segment: "__DATA_CONST", section: "__const") else {
            return nil
        }
        
        guard let pplText = kernel.pfSection(segment: "__PPLTEXT", section: "__text") else {
            return nil
        }
        
        self.textExec  = textExec
        self.cStrSect  = cStrSect
        self.osLogSect = osLogSect
        self.dataSect  = dataSect
        self.constSect = constSect
        self.pplText   = pplText
        
        var baseAddress: UInt64 = UInt64.max
        var entryPoint: UInt64?
        var runningUnderPiranha = false
        for lc in kernel.cmds {
            if let seg = lc as? Segment64LoadCommand {
                if seg.vmAddr < baseAddress && seg.vmAddr > 0 {
                    baseAddress = seg.vmAddr
                }
            } else if let uCmd = lc as? UnixThreadLoadCommand {
                /*guard let state = uCmd.threadStates[0].state.tryGetGeneric(type: arm_thread_state64_t.self) else {
                    return nil
                }
                
                #if arch(arm64) && __DARWIN_OPAQUE_ARM_THREAD_STATE64
                let s = UInt64(UInt(bitPattern: state.__opaque_pc))
                #else
                let s = state.__pc
                #endif*/
                
                let state = uCmd.threadStates[0].state
                guard let s = state.tryGetGeneric(type: UInt64.self, offset: UInt(state.count - 0x10)) else {
                    return nil
                }
                
                entryPoint = s
                
                // Check the start instruction
                if AArch64Instr.Emulate.b(textExec.instruction(at: s) ?? 0, pc: s) == nil {
                    // Not a branch?
                    // Either a bad kernel or we're running under Piranha
                    // Piranha always adds three instructions
                    guard AArch64Instr.Emulate.b(textExec.instruction(at: s + 12) ?? 0, pc: s + 12) != nil else {
                        // Nope, bad kernel
                        return nil
                    }
                    
                    // Running under Piranha
                    // Kernel is probably patched, patchfinder results might be wrong
                    entryPoint = s + 12
                    runningUnderPiranha = true
                }
            }
        }
        
        guard baseAddress != UInt64.max else {
            return nil
        }
        
        guard let entryPoint = entryPoint else {
            return nil
        }
        
        self.baseAddress = baseAddress
        self.entryPoint = entryPoint
        self.runningUnderPiranha = runningUnderPiranha
    }
    
    public func pplDispatchFunc(forOperation op: UInt16) -> UInt64? {
        guard let gxf_ppl_enter = gxf_ppl_enter else {
            return nil
        }
        
        var pc: UInt64! = nil
        while true {
            guard let ref = textExec.findNextXref(to: gxf_ppl_enter, startAt: pc, optimization: .onlyBranches) else {
                return nil
            }
            
            if let args = AArch64Instr.Args.movz(textExec.instruction(at: ref - 4) ?? 0) {
                if args.regDst == 15 && args.imm == op {
                    return ref - 4
                }
            }
            
            pc = ref + 4
        }
    }

    public lazy var pmap_alloc_page_for_kern: UInt64? = {
        guard let func_str = cStrSect.addrOf("pmap_alloc_page_for_kern") else {
            return nil
        }
        
        guard var pc = textExec.findNextXref(to: func_str, optimization: .noBranches) else {
            return nil
        }
        
        while true {
            if AArch64Instr.isPacibsp(textExec.instruction(at: pc) ?? 0) {
                return pc
            }
            
            pc -= 4
        }
    }()
}
