//
//  AArch64Instr.swift
//  PatchfinderUtils
//
//  Created by Linus Henze.
//  Copyright © 2022 Pinauten GmbH. All rights reserved.
//

import Foundation

public struct AArch64Instr {
    public struct Emulate {
        public static func branch(_ instruction: UInt32, pc: UInt64) -> UInt64? {
            // Check that this is a branch instruction
            if ((instruction & 0x7C000000) != 0x14000000) {
                return nil
            }
            
            var imm = UInt64((instruction & 0x3FFFFFF) << 2)
            if (instruction & 0x2000000) != 0 {
                // Sign extend
                imm |= 0xFFFFFFFFFC000000
            }
            
            // Emulate
            return pc &+ imm
        }
        
        public static func b(_ instr: UInt32, pc: UInt64) -> UInt64? {
            // Make sure this is not a bl
            if (instr & 0x80000000) != 0 {
                return nil
            }
            
            // Checks that this is indeed a branch
            return branch(instr, pc: pc)
        }
        
        public static func bl(_ instr: UInt32, pc: UInt64) -> UInt64? {
            // Make sure this is not a b
            if (instr & 0x80000000) != 0x80000000 {
                return nil
            }
            
            // Checks that this is indeed a branch
            return branch(instr, pc: pc)
        }
        
        public static func adr(_ instruction: UInt32, pc: UInt64) -> UInt64? {
            // Check that this is an adr instruction
            if (instruction & 0x9F000000) != 0x10000000 {
                return nil
            }
            
            // Calculate imm from hi and lo
            var imm_hi_lo = UInt64((instruction >> 3)  & 0x1FFFFC)
            imm_hi_lo    |= UInt64((instruction >> 29) & 0x3)
            if (instruction & 0x800000) != 0 {
                // Sign extend
                imm_hi_lo |= 0xFFFFFFFFFFE00000
            }
            
            // Emulate
            return pc &+ imm_hi_lo
        }
        
        public static func adrp(_ instruction: UInt32, pc: UInt64) -> UInt64? {
            // Check that this is an adrp instruction
            if (instruction & 0x9F000000) != 0x90000000 {
                return nil
            }
            
            // Calculate imm from hi and lo
            var imm_hi_lo = UInt64((instruction >> 3)  & 0x1FFFFC)
            imm_hi_lo    |= UInt64((instruction >> 29) & 0x3)
            if (instruction & 0x800000) != 0 {
                // Sign extend
                imm_hi_lo |= 0xFFFFFFFFFFE00000
            }
            
            // Build real imm
            let imm = imm_hi_lo << 12
            
            // Emulate
            return (pc & ~0xFFF) &+ imm
        }
        
        public static func adrpAdd(adrp adrpInst: UInt32, add: UInt32, pc: UInt64) -> UInt64? {
            guard let adrp_target = adrp(adrpInst, pc: pc) else {
                return nil
            }
            
            guard let addArgs = Args.addImm(add) else {
                return nil
            }
            
            if UInt8(adrpInst & 0x1F) != addArgs.regSrc {
                return nil
            }
            
            // Emulate
            return adrp_target &+ UInt64(addArgs.imm)
        }
        
        public static func adrpLdr(adrp instruction: UInt32, ldr ldrInstruction: UInt32, pc: UInt64) -> UInt64? {
            guard let adrp_target = adrp(instruction, pc: pc) else {
                return nil
            }
            
            if ((instruction & 0x1F) != ((ldrInstruction >> 5) & 0x1F)) {
                return nil
            }
            
            if ((ldrInstruction & 0xFFC00000) != 0xF9400000) {
                return nil
            }
            
            let imm12 = ((ldrInstruction >> 10) & 0xFFF) << 3
            
            // Emulate
            return adrp_target &+ UInt64(imm12);
        }
        
        public static func adrpStr(adrp instruction: UInt32, str strInstruction: UInt32, pc: UInt64) -> UInt64? {
            guard let adrp_target = adrp(instruction, pc: pc) else {
                return nil
            }
            
            if ((instruction & 0x1F) != ((strInstruction >> 5) & 0x1F)) {
                return nil
            }
            
            if ((strInstruction & 0xFFC00000) != 0xF9000000) {
                return nil
            }
            
            let imm12 = ((strInstruction >> 10) & 0xFFF) << 3
            
            // Emulate
            return adrp_target &+ UInt64(imm12);
        }
        
        public static func ldr(_ instruction: UInt32, pc: UInt64) -> UInt64? {
            // Check that this is an ldr instruction
            if ((instruction & 0xFF000000) != 0x18000000) {
                guard ((instruction & 0xFF000000) == 0x58000000) else {
                    return nil
                }
            }
            
            let imm19 = ((instruction >> 5) & 0x7FFFF) << 2
            
            // Emulate
            return pc &+ UInt64(imm19)
        }
        
        public static func conditionalBranch(_ instruction: UInt32, pc: UInt64) -> UInt64? {
            // Check that this is a conditional branch instruction
            guard (instruction & 0xFF000010) == 0x54000000 else {
                return nil
            }
            
            var imm = UInt64(instruction & 0xFFFFE0) >> 3
            if (instruction & 0x800000) != 0 {
                // Sign extend
                imm |= 0xFFFFFFFFFF000000
            }
            
            // Emulate
            return pc &+ imm
        }
        
        public static func compareBranch(_ instruction: UInt32, pc: UInt64) -> UInt64? {
            // Check that this is a conditional branch instruction
            guard (instruction & 0x7E000000) == 0x34000000 else {
                return nil
            }
            
            var imm = UInt64(instruction & 0xFFFFE0) >> 3
            if (instruction & 0x800000) != 0 {
                // Sign extend
                imm |= 0xFFFFFFFFFF000000
            }
            
            // Emulate
            return pc &+ imm
        }
    }
    
    public struct Args {
        public enum ShiftType {
            case lsl
            case lsr
            case asr
            case ror
            
            public static func decode(_ sh: UInt8) -> ShiftType {
                switch sh & 0x3 {
                case 0:
                    return .lsl
                case 1:
                    return .lsr
                case 2:
                    return .asr
                case 3:
                    return .ror
                default:
                    fatalError() // UNREACHABLE
                }
            }
            
            public static func decode(_ sh: UInt32) -> ShiftType {
                return decode(UInt8(sh & 0x3))
            }
        }
        
        public typealias SubsArgs = (is64: Bool, regD: UInt8, regA: UInt8, immOrRegB: UInt32, isImm: Bool, shift: UInt8, shiftType: ShiftType)
        public static func subs(_ instr: UInt32) -> SubsArgs? {
            guard (instr & 0x7F800000) == 0x71000000 || (instr & 0x7F200000) == 0x6B000000 else {
                return nil
            }
            
            let isImm = (instr & 0x7F800000) == 0x71000000
            let is64  = (instr >> 31) == 1
            let regD  = UInt8(instr & 0x1F)
            let regA  = UInt8((instr >> 5) & 0x1F)
            var immOrRegB: UInt32 = 0
            var shift: UInt8 = 0
            var shiftType = ShiftType.lsl
            if isImm {
                immOrRegB = (instr >> 10) & 0xFFF
                if ((instr >> 22) & 1) == 1 {
                    shift = 12
                }
            } else {
                immOrRegB = (instr >> 16) & 0x1F
                shiftType = ShiftType.decode(instr >> 22)
                shift     = UInt8((instr >> 10) & 0x3F)
            }
            
            return (is64: is64, regD: regD, regA: regA, immOrRegB: immOrRegB, isImm: isImm, shift: shift, shiftType: shiftType)
        }
        
        public typealias CmpArgs = (is64: Bool, regA: UInt8, immOrRegB: UInt32, isImm: Bool, shift: UInt8, shiftType: ShiftType)
        public static func cmp(_ instr: UInt32) -> CmpArgs? {
            if let args = subs(instr) {
                if args.regD == 0x1F {
                    return (is64: args.is64, regA: args.regA, immOrRegB: args.immOrRegB, isImm: args.isImm, shift: args.shift, shiftType: args.shiftType)
                }
            }
            
            return nil
        }
        
        public typealias AddImmArgs = (regDst: UInt8, regSrc: UInt8, imm: UInt32)
        public static func addImm(_ instruction: UInt32) -> AddImmArgs? {
            // Check that this is an add instruction with immediate
            if (instruction & 0xFF800000) != 0x91000000 {
                return nil
            }
            
            var imm12 = (instruction & 0x3FFC00) >> 10
            
            let shift = (instruction >> 22) & 1
            if shift == 1 {
                imm12 = imm12 << 12
            }
            
            let regDst = UInt8(instruction & 0x1F)
            let regSrc = UInt8((instruction >> 5) & 0x1F)
            
            return (regDst: regDst, regSrc: regSrc, imm: imm12)
        }
        
        public typealias MovzImmArgs = (regDst: UInt8, imm: UInt16)
        public static func movz(_ instruction: UInt32) -> MovzImmArgs? {
            // Check that this is a movz instruction
            if (instruction & 0x7F800000) != 0x52800000 {
                return nil
            }
            
            let regDst = UInt8(instruction & 0x1F)
            let imm16  = UInt16((instruction >> 5) & 0xFFFF)
            
            return (regDst: regDst, imm: imm16)
        }
        
        public typealias LdrImmArgs = (regDst: UInt8, regSrc: UInt8, imm: UInt16)
        public static func ldr(_ instruction: UInt32) -> LdrImmArgs? {
            if ((instruction & 0xFFC00000) != 0xF9400000) {
                if ((instruction & 0xFFC00000) != 0xF8400000) {
                    return nil
                }
            }
            
            let dst = UInt8(instruction        & 0x1F)
            let src = UInt8((instruction >> 5) & 0x1F)
            
            var imm12 = UInt16(((instruction >> 10) & 0xFFF) << 3)
            if ((instruction & 0xFFC00000) == 0xF8400000) {
                imm12 = imm12 >> 5
            }
            
            return (regDst: dst, regSrc: src, imm: imm12)
        }
        
        public static func ldr32(_ instruction: UInt32) -> LdrImmArgs? {
            if ((instruction & 0xFFC00000) != 0xB9400000) {
                return nil
            }
            
            let dst = UInt8(instruction        & 0x1F)
            let src = UInt8((instruction >> 5) & 0x1F)
            
            var imm12 = UInt16(((instruction >> 10) & 0xFFF) << 2)
            
            return (regDst: dst, regSrc: src, imm: imm12)
        }
        
        public typealias StrImmArgs = (regSrc: UInt8, regDst: UInt8, imm: UInt16)
        public static func str(_ instruction: UInt32) -> StrImmArgs? {
            if ((instruction & 0xFFC00000) != 0xF9000000) {
                return nil
            }
            
            let dst = UInt8((instruction >> 5) & 0x1F)
            let src = UInt8(instruction        & 0x1F)
            
            let imm12 = UInt16(((instruction >> 10) & 0xFFF) << 3)
            
            return (regSrc: src, regDst: dst, imm: imm12)
        }
    }
    
    public static func isAutibsp(_ instr: UInt32) -> Bool {
        return instr == 0xDAC117FE || instr == 0xD50323FF
    }
    
    public static func isPacibsp(_ instr: UInt32, alsoAllowNop: Bool = true) -> Bool {
        var ok = (instr == 0xD503237F || instr == 0xDAC107FE)
        if alsoAllowNop && instr == 0xD503201F {
            // Required to test on Corellium
            ok = true
        }
        
        return ok
    }
}
