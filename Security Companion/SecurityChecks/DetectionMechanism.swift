//
//  DetectionMechanism.swift
//  Security Companion
//
//  Created by Anthony V on 6/10/21.
//

import Foundation

protocol DetectionMechanism{
    func doScan() -> Bool
}

extension DetectionMechanism{
    internal var SAFE: Bool {
        get {
            return true
        }
    }
    internal var NOT_SAFE: Bool {
        get {
            return false
        }
    }
}
