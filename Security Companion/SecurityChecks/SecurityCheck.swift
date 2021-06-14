//
//  SecurityCheck.swift
//  Security Companion
//
//  Created by Anthony V on 6/10/21.
//

import Foundation


class SecurityCheck: ObservableObject{
    private var jailbreakDetection: JailbreakDetection
    init() {
        self.jailbreakDetection = JailbreakDetection()
    }
    
    func performScan() -> Bool {
        return self.jailbreakDetection.doScan()
    }
    
    func getDetails() -> [Issue] {
        return self.jailbreakDetection.getDetails()
    }
}
