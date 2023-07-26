//
//  PatchfinderSegment.swift
//  PatchfinderUtils
//
//  Created by Linus Henze.
//  Copyright © 2022 Pinauten GmbH. All rights reserved.
//

import Foundation
import CFastFind
import SwiftUtils

public enum PatchfinderXrefOptimization {
    /// Perform no optimization and find any xref
    case none
    
    /// Don't check branches
    case noBranches
    
    /// Only check branches
    case onlyBranches
}

public class PatchfinderSegment {
    public let subSegments: [PatchfinderSubSegment]
    public let name: String?
    
    public init(subSegments: [PatchfinderSubSegment], name: String? = nil) {
        self.subSegments = subSegments.sorted(by: { a, b in
            a.baseAddress < b.baseAddress
        })
        
        self.name = name
    }
    
    /**
     * Find a cross reference to some value, optionally starting at a given address.
     *
     * - Parameter to: The value to cross-reference
     * - Parameter startAt: Optional start address for the search, *must* be valid!
     * - Parameter optimization: Optional optimization strategy, see PatchfinderXrefOptimization
     *
     * - Returns: Address which references **to**, if any
     */
    public func findNextXref(to: UInt64, startAt: UInt64? = nil, optimization: PatchfinderXrefOptimization = .none) -> UInt64? {
        var cur = startAt
        
        for s in subSegments {
            if cur == nil {
                cur = s.baseAddress
            }
            
            if cur.unsafelyUnwrapped >= s.baseAddress && cur.unsafelyUnwrapped < s.endAddress {
                if let res = s.findNextXref(to: to, startAt: cur, optimization: optimization) {
                    return res
                }
                
                // Searched this subsegment -> Start at the beginning of the next one
                cur = nil
            }
        }
        
        return nil
    }
    
    /**
     * Find the address of some instructions.
     *
     * - Parameter toFind: The instructions to find
     * - Parameter startAt: The address at which to start the search, defaults to the base address of the first subSegment
     *
     * - Returns: The address at which the instructions where found or nil
     */
    public func addrOf(_ toFind: [UInt32], startAt: UInt64? = nil) -> UInt64? {
        var cur = startAt
        
        for s in subSegments {
            if cur == nil {
                cur = s.baseAddress
            }
            
            if cur.unsafelyUnwrapped >= s.baseAddress && cur.unsafelyUnwrapped < s.endAddress {
                if let res = s.addrOf(toFind, startAt: cur) {
                    return res
                }
                
                // Searched this subsegment -> Start at the beginning of the next one
                cur = nil
            }
        }
        
        return nil
    }
    
    /**
     * Find the address of some string.
     *
     * - Parameter toFind: The string to find
     * - Parameter startAt: The address at which to start the search, defaults to the base address
     *
     * - Returns: The address at which the string was found or nil
     */
    public func addrOf(_ toFind: String, startAt: UInt64? = nil) -> UInt64? {
        var cur = startAt
        
        for s in subSegments {
            if cur == nil {
                cur = s.baseAddress
            }
            
            if cur.unsafelyUnwrapped >= s.baseAddress && cur.unsafelyUnwrapped < s.endAddress {
                if let res = s.addrOf(toFind, startAt: cur) {
                    return res
                }
                
                // Searched this subsegment -> Start at the beginning of the next one
                cur = nil
            }
        }
        
        return nil
    }
    
    /**
     * Get the instruction at some address.
     *
     * - Parameter at: The address of the instruction
     *
     * - Returns: The instruction or nil if **at** is out of bounds
     */
    public func instruction(at: UInt64) -> UInt32? {
        for s in subSegments {
            if at >= s.baseAddress && at < s.endAddress {
                return s.instruction(at: at)
            }
        }
        
        return nil
    }
    
    /**
     * Get the UInt64 value at some address.
     *
     * - Parameter at: The address
     *
     * - Returns: The UInt64 value or nil if **at** is out of bounds
     */
    public func r64(at: UInt64) -> UInt64? {
        for s in subSegments {
            if at >= s.baseAddress && at < s.endAddress {
                return s.r64(at: at)
            }
        }
        
        return nil
    }
}

public class PatchfinderSubSegment {
    public let data: Data
    public var baseAddress: UInt64
    public let name: String?
    
    public var endAddress: UInt64 {
        baseAddress + UInt64(data.count)
    }
    
    public init(data: Data, baseAddress: UInt64, name: String? = nil) {
        self.data        = data
        self.baseAddress = baseAddress
        self.name        = name
    }
    
    /**
     * Find a cross reference to some value, optionally starting at a given address.
     *
     * - Parameter to: The value to cross-reference
     * - Parameter startAt: Optional start address for the search
     * - Parameter optimization: Optional optimization strategy, see PatchfinderXrefOptimization
     *
     * - Returns: Address which references **to**, if any
     */
    public func findNextXref(to: UInt64, startAt: UInt64? = nil, optimization: PatchfinderXrefOptimization = .none) -> UInt64? {
        let startAt = startAt ?? baseAddress

        let off = startAt - baseAddress
        assert((off % 4) == 0)

        guard off < data.count else {
            return nil
        }

        let found = data.withUnsafeBytes { bufPtr -> UInt64 in
            switch optimization {
            case .none:
                return find_xref_to(bufPtr.baseAddress!.advanced(by: Int(off)), bufPtr.baseAddress!.advanced(by: bufPtr.count), to, startAt)
                
            case .noBranches:
                return find_xref_to_data(bufPtr.baseAddress!.advanced(by: Int(off)), bufPtr.baseAddress!.advanced(by: bufPtr.count), to, startAt)
                
            case .onlyBranches:
                return find_xref_branch(bufPtr.baseAddress!.advanced(by: Int(off)), bufPtr.baseAddress!.advanced(by: bufPtr.count), to, startAt)
            }
        }

        guard found != 0 else {
            return nil
        }

        return found
    }
    
    /**
     * Find the address of some instructions.
     *
     * - Parameter toFind: The instructions to find
     * - Parameter startAt: The address at which to start the search, defaults to the base address
     *
     * - Returns: The address at which the instructions where found or nil
     */
    public func addrOf(_ toFind: [UInt32], startAt: UInt64? = nil) -> UInt64? {
        data.withUnsafeBytes { bufPtr in
            let startAt = startAt ?? baseAddress
            let initOff = startAt - baseAddress
            
            guard initOff < bufPtr.count else {
                return nil
            }
            
            var offset: Int = 0
            if CFastFind(bufPtr.baseAddress!.advanced(by: Int(initOff)), bufPtr.count - Int(initOff), toFind, toFind.count, &offset) {
                return UInt64(UInt(bitPattern: offset)) + baseAddress + initOff
            }
            
            return nil
        }
    }
    
    /**
     * Find the address of some string.
     *
     * - Parameter toFind: The string to find
     * - Parameter startAt: The address at which to start the search, defaults to the base address
     *
     * - Returns: The address at which the string was found or nil
     */
    public func addrOf(_ toFind: String, startAt: UInt64? = nil) -> UInt64? {
        let startAt = startAt ?? baseAddress
        let off = startAt - baseAddress

        guard off < data.count else {
            return nil
        }
        
        if let range = data.advanced(by: Int(off)).firstRange(of: toFind.data(using: .utf8)!) {
            return UInt64(range.lowerBound) + off + baseAddress
        }
        
        return nil
    }
    
    /**
     * Get the instruction at some address.
     *
     * - Parameter at: The address of the instruction
     *
     * - Returns: The instruction or nil if **at** is out of bounds
     */
    public func instruction(at: UInt64) -> UInt32? {
        guard at > baseAddress else {
            return nil
        }
        
        guard at < (baseAddress + UInt64(data.count)) else {
            return nil
        }
        
        let off = UInt(at - baseAddress)
        
        return data.getGeneric(type: UInt32.self, offset: off)
    }
    
    /**
     * Get the UInt64 value at some address.
     *
     * - Parameter at: The address
     *
     * - Returns: The UInt64 value or nil if **at** is out of bounds
     */
    public func r64(at: UInt64) -> UInt64? {
        guard at > baseAddress else {
            return nil
        }
        
        guard at < (baseAddress + UInt64(data.count)) else {
            return nil
        }
        
        let off = UInt(at - baseAddress)
        
        return data.getGeneric(type: UInt64.self, offset: off)
    }
}
