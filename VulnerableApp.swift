import Foundation
import UIKit

// ❌ VULNERABILITY #1: Insecure Credential Storage
class UserAuthManager {
    
    // INSECURE: Storing credentials in UserDefaults (plaintext)
    func saveCredentials(username: String, password: String) {
        UserDefaults.standard.set(username, forKey: "username")
        UserDefaults.standard.set(password, forKey: "password")  // 🔴 INSECURE
        UserDefaults.standard.set(true, forKey: "isLoggedIn")
    }
    
    func getCredentials() -> (username: String, password: String)? {
        guard let username = UserDefaults.standard.string(forKey: "username"),
              let password = UserDefaults.standard.string(forKey: "password") else {
            return nil
        }
        return (username, password)  // 🔴 RETURNING PLAINTEXT PASSWORD
    }
    
    // INSECURE: No token refresh mechanism
    func login(username: String, password: String, completion: @escaping (Bool) -> Void) {
        let urlString = "http://api.example.com/login"  // 🔴 HTTP not HTTPS
        guard let url = URL(string: urlString) else { return }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        let credentials = "\(username):\(password)"
        let encodedCredentials = credentials.data(using: .utf8)?.base64EncodedString()
        request.setValue("Basic \(encodedCredentials ?? "")", forHTTPHeaderField: "Authorization")
        
        URLSession.shared.dataTask(with: request) { data, response, error in
            if let data = data {
                do {
                    let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                    let token = json?["token"] as? String
                    UserDefaults.standard.set(token, forKey: "authToken")  // 🔴 INSECURE
                    completion(true)
                } catch {
                    completion(false)
                }
            }
        }.resume()
    }
}

// ❌ VULNERABILITY #2: SQL Injection / Unsafe String Concatenation
class DatabaseManager {
    
    func getUserData(userId: String) -> [String: Any]? {
        // 🔴 DANGEROUS: Directly concatenating user input in query
        let query = "SELECT * FROM users WHERE id = '\(userId)'"
        // An attacker could pass: "'; DROP TABLE users; --"
        // Query becomes: SELECT * FROM users WHERE id = ''; DROP TABLE users; --'
        
        return executeQuery(query)
    }
    
    func searchUsers(searchTerm: String) -> [[String: Any]] {
        // 🔴 DANGEROUS: No input validation or parameterized queries
        let query = "SELECT * FROM users WHERE name LIKE '%\(searchTerm)%'"
        return executeQueryMultiple(query)
    }
    
    private func executeQuery(_ query: String) -> [String: Any]? {
        // Simulated database execution
        return ["id": "1", "name": "User"]
    }
    
    private func executeQueryMultiple(_ query: String) -> [[String: Any]] {
        return [["id": "1", "name": "User"]]
    }
}

// ❌ VULNERABILITY #3: Weak SSL/TLS Implementation
class NetworkManager {
    
    func makeSecureRequest(url: String) {
        guard let url = URL(string: url) else { return }
        
        var request = URLRequest(url: url)
        
        // 🔴 WEAK: No SSL pinning or certificate validation
        let config = URLSessionConfiguration.default
        config.waitsForConnectivity = true
        
        let session = URLSession(configuration: config, delegate: nil, delegateQueue: nil)
        session.dataTask(with: request) { data, response, error in
            // Process response without validating certificate
        }.resume()
    }
    
    // 🔴 DANGEROUS: Allows any certificate
    func weakSSLDelegate() -> URLSessionDelegate? {
        return WeakSSLDelegate()
    }
}

class WeakSSLDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, 
                   didReceive challenge: URLAuthenticationChallenge,
                   completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // 🔴 CRITICAL: Accepting all certificates
        let credential = URLCredential(trust: challenge.protectionSpace.serverTrust!)
        completionHandler(.useCredential, credential)
    }
}

// ❌ VULNERABILITY #4: Memory Leak - Retain Cycles
class ImageCache {
    static let shared = ImageCache()
    
    // 🔴 Memory leak: Strong reference cycle
    private var cache: [String: UIImage] = [:]
    
    func cacheImage(_ image: UIImage, forKey key: String) {
        cache[key] = image  // 🔴 Never released until app exits
    }
    
    func getImage(forKey key: String) -> UIImage? {
        return cache[key]
    }
    
    // 🔴 No way to clear cache - memory grows infinitely
}

// ❌ VULNERABILITY #5: Insecure Data Logging
class Logger {
    
    static func logUserAction(userId: String, action: String, data: [String: Any]?) {
        let message = "User \(userId) performed action: \(action)"
        // 🔴 DANGEROUS: Logging sensitive data
        if let data = data {
            print("Action data: \(data)")  // May contain passwords, tokens, personal info
        }
        print(message)
    }
    
    static func logNetworkResponse(_ response: Data) {
        // 🔴 DANGEROUS: Logging all network responses
        if let json = try? JSONSerialization.jsonObject(with: response) {
            print("Response: \(json)")  // May contain auth tokens, user data
        }
    }
}

// ❌ VULNERABILITY #6: Unsafe Deserialization
class APIResponseHandler {
    
    func parseUserResponse(_ data: Data) -> [String: Any]? {
        do {
            // 🔴 UNSAFE: No validation of structure
            let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
            return json
        } catch {
            return nil
        }
    }
    
    func loadRemoteConfiguration(_ configURL: String) {
        guard let url = URL(string: configURL) else { return }
        
        URLSession.shared.dataTask(with: url) { data, response, error in
            if let data = data {
                // 🔴 DANGEROUS: Executing arbitrary code from remote config
                do {
                    let config = try JSONSerialization.jsonObject(with: data) as? [String: Any]
                    if let script = config?["executeScript"] as? String {
                        // NEVER DO THIS - Could execute arbitrary code
                        // eval(script)
                    }
                } catch {}
            }
        }.resume()
    }
}

// ❌ VULNERABILITY #7: Race Conditions
class UserDataManager {
    
    private var userData: [String: Any] = [:]
    
    // 🔴 Thread-unsafe access to shared data
    func updateUserData(_ key: String, value: Any) {
        userData[key] = value  // Race condition if called from multiple threads
    }
    
    func getUserData(_ key: String) -> Any? {
        return userData[key]  // Could read incomplete data
    }
    
    // 🔴 No locks or synchronization
}

// ❌ VULNERABILITY #8: Hardcoded Secrets
class APIConfiguration {
    
    // 🔴 CRITICAL: Hardcoded API keys in source code
    let apiKey = "sk_live_51234567890abcdef"
    let apiSecret = "secret_abc123xyz789"
    let databasePassword = "admin123"
    let jwtSecret = "my-super-secret-key"
    
    func getAPIHeaders() -> [String: String] {
        return [
            "Authorization": "Bearer \(apiKey)",
            "X-API-Secret": apiSecret
        ]
    }
}

// ❌ VULNERABILITY #9: Excessive File Permissions
class FileManager {
    
    func saveUserDataToFile(_ data: [String: Any]) {
        let fileName = "userdata.json"
        let paths = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)
        let documentsDirectory = paths[0]
        let filePath = "\(documentsDirectory)/\(fileName)"
        
        do {
            let jsonData = try JSONSerialization.data(withJSONObject: data)
            try jsonData.write(toFile: filePath, options: .atomic)
            
            // 🔴 INSECURE: World-readable file permissions
            // File saved with default permissions allowing other apps to read it
        } catch {
            print("Error saving file")
        }
    }
    
    // 🔴 No file encryption
}

// ❌ VULNERABILITY #10: Unvalidated User Input
class InputValidator {
    
    func processUserInput(_ input: String) -> String {
        // 🔴 NO VALIDATION: Directly using user input
        let processedInput = input.replacingOccurrences(of: " ", with: "")
        return processedInput
    }
    
    func validateEmail(_ email: String) -> Bool {
        // 🔴 WEAK: Simple length check only
        return email.count > 5
    }
    
    func validateURL(_ urlString: String) -> Bool {
        // 🔴 WEAK: No proper URL validation
        return urlString.contains("http")
    }
}
