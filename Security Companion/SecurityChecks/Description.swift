//
//  Description.swift
//  Security Companion
//
//  Created by Anthony V on 6/11/21.
//

import Foundation

struct Description{
    var isSecure: Bool
    var result: String
    init(isSecure: Bool, result: String){
        self.isSecure = isSecure
        print(self.isSecure)
        self.result = result
    }
    
    var description: String {
        get{
            if self.isSecure {
                return "That means Security Companion app doesn't detect anything unusual / malicious on your phone. Always make sure that you are on the latest version of the iOS / iPadOS"
            }else{
                return "That means Security Companion app detect something unusual / malicious exists on your phone, this usually happens because your device has been Jailbroken. Please reset your phone to the factory settings to eliminate all potential threats."
            }
        }
    }
}
