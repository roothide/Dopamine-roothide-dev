//
//  Kernel.swift
//  PatchfinderUtils
//
//  Created by Linus Henze.
//  Copyright © 2022 Pinauten GmbH. All rights reserved.
//

import Foundation
import Compression
import SwiftMachO
import CFastFind

// https://github.com/xerub/img4lib/blob/master/libvfs/vfs_lzfse.c
let COMPRESSION_LZFSE_SMALL = compression_algorithm(rawValue: 0x891)

public func loadImg4Kernel(path: String) -> Data? {
    guard let kimg4 = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
        return nil
    }
    
    guard kimg4.count >= 104 else {
        // Yeah, no
        // Kernel should *always* be larger than that
        return nil
    }
    
    // XXX: Instead of parsing the header, this simply finds the "bvx2" magic...
    for i in 0..<100 {
        if kimg4.getGeneric(type: UInt32.self, offset: UInt(i)).bigEndian == 0x62767832 /* bvx2 */ {
            // Got it, now decompress
            // We assume that the output will be four times the size of the input
            var bufLen    = kimg4.count * 4
            var outputBuf = malloc(bufLen)
            guard outputBuf != nil else {
                return nil
            }
            
            return kimg4.withUnsafeBytes { ptr -> Data? in
                while true {
                    let outLen = compression_decode_buffer(outputBuf!.assumingMemoryBound(to: UInt8.self), bufLen, ptr.baseAddress!.advanced(by: i).assumingMemoryBound(to: UInt8.self), ptr.count, nil, COMPRESSION_LZFSE_SMALL)
                    if outLen < bufLen {
                        return Data(bytesNoCopy: outputBuf!, count: outLen, deallocator: .free)
                    }
                    
                    bufLen *= 2
                    
                    // Don't use realloc, no need to copy the data
                    free(outputBuf)
                    outputBuf = malloc(bufLen)
                    guard outputBuf != nil else {
                        return nil
                    }
                }
            }
        }
    }
    
    return nil
}

#if arch(arm64) && (os(macOS) || os(iOS))

public func getKernelcachePath() -> String? {
    let chosen = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen")
    if chosen == 0 {
        return nil
    }
    
    defer { IOObjectRelease(chosen) }
    
    #if os(iOS)
    
    guard let hash = IORegistryEntryCreateCFProperty(chosen, "boot-manifest-hash" as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? Data else {
        return nil
    }
    
    var bmhStr = ""
    for byte in hash {
        bmhStr += String(format: "%02X", byte)
    }
    
    return "/private/preboot/\(bmhStr)/System/Library/Caches/com.apple.kernelcaches/kernelcache"
    
    #else
    
    guard let dat = IORegistryEntryCreateCFProperty(chosen, "boot-objects-path" as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? Data else {
        return nil
    }
    
    if let bop = String(data: dat.dropLast(), encoding: .ascii) {
        return "/System/Volumes/Preboot/\(bop)/System/Library/Caches/com.apple.kernelcaches/kernelcache"
    }
    
    return nil
    
    #endif
}

public func getKernelcacheDecompressedPath() -> String? {
    let chosen = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen")
    if chosen == 0 {
        return nil
    }
    
    defer { IOObjectRelease(chosen) }
    
    #if os(iOS)
    
    guard let hash = IORegistryEntryCreateCFProperty(chosen, "boot-manifest-hash" as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? Data else {
        return nil
    }
    
    var bmhStr = ""
    for byte in hash {
        bmhStr += String(format: "%02X", byte)
    }
    
    return "/private/preboot/\(bmhStr)/kernelcache.decompressed"
    
    #else
    
    guard let dat = IORegistryEntryCreateCFProperty(chosen, "boot-objects-path" as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? Data else {
        return nil
    }
    
    if let bop = String(data: dat.dropLast(), encoding: .ascii) {
        return "/System/Volumes/Preboot/\(bop)/kernelcache.decompressed"
    }
    
    return nil
    
    #endif
}

#endif

public extension MachO {
    static var runningKernel: MachO? {
        #if arch(arm64) && (os(macOS) || os(iOS))
        if let path = getKernelcacheDecompressedPath() {
            if let data = try? Data(contentsOf: URL(fileURLWithPath: path)) {
                if let machO = try? MachO(fromData: data, okToLoadFAT: false) {
                    return machO
                }
            }
        }
        
        if let path = getKernelcachePath() {
            if let decomp = loadImg4Kernel(path: path) {
                return try? MachO(fromData: decomp, okToLoadFAT: false)
            }
        }
        #endif
        
        return nil
    }
}
