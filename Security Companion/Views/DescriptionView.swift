//
//  DescriptionView.swift
//  Security Companion
//
//  Created by Anthony V on 6/11/21.
//

import SwiftUI

struct DescriptionView: View {
    @Binding var description: Description
    
    var body: some View {
        VStack{
            Text("What does your device is \(self.description.result.lowercased()) means?").padding()
            Text(self.description.description).multilineTextAlignment(.center).padding()
        }
    }
}
