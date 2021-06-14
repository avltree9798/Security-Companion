//
//  ContentView.swift
//  Security Companion
//
//  Created by Anthony V on 6/10/21.
//

import SwiftUI

struct ContentView: View {
    @State var isSecure: Bool! = false
    @State var isFinishScanning: Bool = false
    @State var text: String = ""
    @State var result: String = ""
    @State var canOpenDescription: Bool = false
    @State var description : Description = Description(isSecure: true, result: "test")
    @ObservedObject var securityCheck : SecurityCheck = SecurityCheck()
    var body: some View {
        VStack{
            Text("Your device is")
                .padding()
            Text(self.result)
                .animation(.easeIn(duration: 1.0))
                .padding()
            Button("Scan now"){
                self.isSecure = securityCheck.performScan()
                if self.isSecure {
                    self.result = "Secure"
                }else {
                    self.result = "At risk"
                }
                self.isFinishScanning = true
                description = Description(isSecure: self.isSecure, result: self.result)
            }
                .frame(width: 100, height: 100)
                .foregroundColor(Color.black)
                .background(Color.blue)
                .clipShape(Circle())
            Spacer()
            Button("Learn more"){
                self.canOpenDescription = true
            }
                .isHidden(!self.isFinishScanning)
                .sheet(isPresented: $canOpenDescription, content: {
                    DescriptionView(description: $description)
                })
            Spacer()
            List(securityCheck.getDetails()){ detail in
                Text(detail.description)
            }
        }
    }
}
