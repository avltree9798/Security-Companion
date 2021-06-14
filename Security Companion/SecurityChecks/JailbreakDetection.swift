//
//  JailbreakDetection.swift
//  Security Companion
//
//  Created by Anthony V on 6/10/21.
//

import Foundation
import MachO
import Darwin


internal class JailbreakDetection: DetectionMechanism{
    private var details : [Issue] = []
    private func checkSuspiciousFiles() -> Bool {
        let files = [
            "/Application/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/usr/bin/ssh",
            "/private/var/lib/apt",
            "/private/var/lib/cydia",
            "/private/var/tmp/cydia.log",
            "/Applications/WinterBoard.app",
            "/var/lib/cydia",
            "/private/etc/dpkg/origins/debian",
            "/bin.sh",
            "/private/etc/apt",
            "/etc/ssh/sshd_config",
            "/private/etc/ssh/sshd_config",
            "/Applications/SBSetttings.app",
            "/private/var/mobileLibrary/SBSettingsThemes/",
            "/private/var/stash",
            "/usr/libexec/sftp-server",
            "/usr/libexec/cydia/",
            "/usr/sbin/frida-server",
            "/usr/bin/cycript",
            "/usr/local/bin/cycript",
            "/usr/lib/libcycript.dylib",
            "/System/Library/LaunchDaemons/com.saurik.Cydia.Startup.plist",
            "/System/Library/LaunchDaemons/com.ikey.bbot.plist",
            "/Applications/FakeCarrier.app",
            "/Library/MobileSubstrate/DynamicLibraries/Veency.plist",
            "/Library/MobileSubstrate/DynamicLibraries/LiveClock.plist",
            "/usr/libexec/ssh-keysign",
            "/usr/libexec/sftp-server",
            "/Applications/blackra1n.app",
            "/Applications/IntelliScreen.app",
            "/Applications/Snoop-itConfig.app",
            "/var/checkra1n.dmg",
            "/var/binpack"
        ]
        
        for file in files{
            if FileManager.default.isReadableFile(atPath: file){
                self.details.append(Issue(description: "[-] Found \(file)"))
                return NOT_SAFE
            }
        }
        return SAFE
    }
    
    private func checkSuspiciousDYLIB() -> Bool {
        let dylibs = [
            "cyinject",
            "libcycript",
            "FridaGadget",
            "zzzLiberty.dylib",
            "SSLKillSwitch2.dylib",
            "0Shadow.dylib",
            "MobileSubstrate.dylib",
            "libsparkapplist.dylib",
            "SubstrateInserter.dylib",
            "zzzzzzUnSubdylib",
            "Cephei"
        ]
        for i in 0..<_dyld_image_count() {
            guard let lib = String(validatingUTF8: _dyld_get_image_name(i)) else { continue }
            for dylib in dylibs {
                if lib.lowercased().contains(dylib.lowercased()) {
                    self.details.append(Issue(description: "[-] Found \(lib)"))
                    return NOT_SAFE
                }
            }
        }

        return SAFE
    }
    
    private func checkSymlink() -> Bool {
        let symlinks = [
            "/Applications",
            "/Library/Ringtones",
            "/Library/Wallpaper",
            "/usr/include",
            "/usr/libexec",
            "/usr/share",
            "/usr/arm-apple-darwin9",
            "/var/lib/undecimus/apt"
        ]
        for symlink in symlinks {
            do {
                let result = try FileManager.default.destinationOfSymbolicLink(atPath: symlink)
                if !result.isEmpty {
                    self.details.append(Issue(description: "[-] Found \(symlink)"))
                    return NOT_SAFE
                }
            } catch {}
        }
        return SAFE
    }
    
    private func checkFork() -> Bool {
        let pointer = UnsafeMutableRawPointer(bitPattern: -2)
        let forkPtr = dlsym(pointer, "fork")
        typealias ForkType = @convention(c) () -> pid_t
        let fork = unsafeBitCast(forkPtr, to: ForkType.self)
        let forkResult = fork()

        if forkResult >= 0 {
            if forkResult > 0 {
                kill(forkResult, SIGTERM)
            }
            self.details.append(Issue(description: "[-] Successfully fork process"))
            return NOT_SAFE
        }
        return SAFE
    }
    
    private func checkWritePermission() -> Bool {
        let path = "/private/avltree9798.txt"
        do {
            let newPath = path+UUID().uuidString
            try "AVL was here".write(toFile: newPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: newPath)
            self.details.append(Issue(description: "[-] Was able to write to \(newPath)"))
            return NOT_SAFE
        } catch {}
        return SAFE
    }

    
    public func doScan() -> Bool {
        self.details = []
        return self.checkSuspiciousFiles() && self.checkSuspiciousDYLIB() && self.checkSymlink() && self.checkFork() && self.checkWritePermission()
    }
    
    public func getDetails() -> [Issue] {
        return self.details
    }
}
