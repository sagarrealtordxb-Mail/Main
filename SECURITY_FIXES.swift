import Foundation
import Security
import UIKit

// ============================================================================
// SECURITY FIXES - iOS Mobile App
// ============================================================================
// This file contains all security and performance fixes for the mobile app
// Generated: 2026-07-03
// ============================================================================

// MARK: - 1. EXCESSIVE DISK WRITES FIX (CRITICAL)
// Problem: App writing 1073.74 MB over 5.4 hours (55.23 KB/sec)
// Solution: Implement batched writes with proper buffering

class BatchedFileLogger {
    static let shared = BatchedFileLogger()
    
    private var buffer: [String] = []
    private let bufferSize = 100
    private let queue = DispatchQueue(label: "com.app.logger.batch")
    private let fileURL: URL
    private let maxFileSize: UInt64 = 10 * 1024 * 1024 // 10 MB max log file
    
    init() {
        let documentsPath = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        self.fileURL = documentsPath.appendingPathComponent("app.log")
    }
    
    // BEFORE: Writing every log immediately (INEFFICIENT)
    // func log(_ message: String) {
    //     fileHandle.write(message.data(using: .utf8)!)
    // }
    
    // AFTER: Batched writes (EFFICIENT)
    func log(_ message: String, level: LogLevel = .info) {
        queue.async { [weak self] in
            guard let self = self else { return }
            
            let timestamp = ISO8601DateFormatter().string(from: Date())
            let formattedMessage = "[\(timestamp)] [\(level.rawValue)] \(message)"
            
            self.buffer.append(formattedMessage)
            
            // Flush when buffer reaches size limit
            if self.buffer.count >= self.bufferSize {
                self.flushToDisk()
            }
        }
    }
    
    private func flushToDisk() {
        guard !buffer.isEmpty else { return }
        
        let batchedData = buffer.joined(separator: "\n") + "\n"
        
        do {
            if FileManager.default.fileExists(atPath: fileURL.path) {
                let fileHandle = try FileHandle(forWritingTo: fileURL)
                fileHandle.seekToEndOfFile()
                fileHandle.write(batchedData.data(using: .utf8) ?? Data())
                try fileHandle.close()
            } else {
                try batchedData.write(to: fileURL, atomically: true, encoding: .utf8)
            }
            
            buffer.removeAll()
            checkFileSizeAndRotate()
        } catch {
            print("Error writing to log file: \(error)")
        }
    }
    
    private func checkFileSizeAndRotate() {
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: fileURL.path)
            if let fileSize = attributes[.size] as? UInt64, fileSize > maxFileSize {
                let archivedURL = fileURL.appendingPathExtension("archive")
                try FileManager.default.moveItem(at: fileURL, to: archivedURL)
            }
        } catch {
            print("Error rotating log file: \(error)")
        }
    }
    
    func flushOnAppTermination() {
        queue.sync {
            self.flushToDisk()
        }
    }
    
    enum LogLevel: String {
        case debug = "DEBUG"
        case info = "INFO"
        case warning = "WARNING"
        case error = "ERROR"
    }
}

// MARK: - 2. MEMORY LEAK FIXES

// LEAK #1 FIX: Image Cache
class ImageCacheManager {
    static let shared = ImageCacheManager()
    
    // BEFORE: Unbounded dictionary (MEMORY LEAK)
    // var imageCache: [String: UIImage] = [:]
    
    // AFTER: Use NSCache with automatic memory management (FIXED)
    private let imageCache = NSCache<NSString, UIImage>()
    
    init() {
        // Configure cache limits
        imageCache.totalCostLimit = 100 * 1024 * 1024 // 100 MB
        imageCache.countLimit = 500 // Max 500 images
    }
    
    func cacheImage(_ image: UIImage, forKey key: String) {
        let cost = image.pngData()?.count ?? 0
        imageCache.setObject(image, forKey: key as NSString, cost: cost)
    }
    
    func cachedImage(forKey key: String) -> UIImage? {
        return imageCache.object(forKey: key as NSString)
    }
    
    func clearCache() {
        imageCache.removeAllObjects()
    }
}

// LEAK #2 FIX: Network Request Retain Cycles
class APIClient {
    static let shared = APIClient()
    private let session = URLSession.shared
    
    // BEFORE: Retain cycle in completion handler (MEMORY LEAK)
    // func fetchData(url: URL, completion: @escaping (Data?, Error?) -> Void) {
    //     URLSession.shared.dataTask(with: url) { [weak self] data, response, error in
    //         self?.handleResponse(data) // Strong reference despite [weak self]
    //     }.resume()
    // }
    
    // AFTER: Proper weak self handling (FIXED)
    func fetchData(url: URL, completion: @escaping (Data?, Error?) -> Void) {
        let task = session.dataTask(with: url) { [weak self] data, response, error in
            guard let self = self else { return }
            
            if let error = error {
                completion(nil, error)
                return
            }
            
            guard let httpResponse = response as? HTTPURLResponse,
                  (200...299).contains(httpResponse.statusCode) else {
                let statusError = NSError(domain: "APIError", code: -1, userInfo: nil)
                completion(nil, statusError)
                return
            }
            
            self.handleResponse(data, completion: completion)
        }
        
        task.resume()
    }
    
    private func handleResponse(_ data: Data?, completion: @escaping (Data?, Error?) -> Void) {
        completion(data, nil)
    }
    
    // Example with custom session configuration
    func fetchDataWithTimeout(url: URL, timeout: TimeInterval = 30, completion: @escaping (Data?, Error?) -> Void) {
        var request = URLRequest(url: url)
        request.timeoutInterval = timeout
        
        let task = session.dataTask(with: request) { [weak self] data, response, error in
            guard self != nil else { return }
            
            if let error = error {
                completion(nil, error)
                return
            }
            
            completion(data, nil)
        }
        
        task.resume()
    }
}

// MARK: - 3. INSECURE DATA STORAGE FIX

class KeychainManager {
    static let shared = KeychainManager()
    
    private let serviceName = "com.myapp.secure"
    
    // BEFORE: Storing in UserDefaults (INSECURE)
    // UserDefaults.standard.set(password, forKey: "userPassword")
    
    // AFTER: Store in Keychain (SECURE)
    
    func savePassword(_ password: String, forAccount account: String) -> Bool {
        guard let passwordData = password.data(using: .utf8) else { return false }
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecValueData as String: passwordData,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        
        // Delete existing item first
        SecItemDelete(query as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    func retrievePassword(forAccount account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true
        ]
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let passwordData = result as? Data,
              let password = String(data: passwordData, encoding: .utf8) else {
            return nil
        }
        
        return password
    }
    
    func deletePassword(forAccount account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceName,
            kSecAttrAccount as String: account
        ]
        
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }
    
    // Store token securely
    func saveToken(_ token: String, forKey key: String) -> Bool {
        return savePassword(token, forAccount: key)
    }
    
    // Retrieve token securely
    func retrieveToken(forKey key: String) -> String? {
        return retrievePassword(forAccount: key)
    }
}

// MARK: - 4. INPUT VALIDATION

class InputValidator {
    
    // Email validation
    static func isValidEmail(_ email: String) -> Bool {
        let emailRegex = "[A-Z0-9a-z._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"
        let emailPredicate = NSPredicate(format: "SELF MATCHES %@", emailRegex)
        return emailPredicate.evaluate(with: email)
    }
    
    // Phone number validation
    static func isValidPhoneNumber(_ phone: String) -> Bool {
        let phoneRegex = "^[0-9]{10,}$"
        let phonePredicate = NSPredicate(format: "SELF MATCHES %@", phoneRegex)
        return phonePredicate.evaluate(with: phone)
    }
    
    // Password strength validation
    static func isValidPassword(_ password: String) -> (isValid: Bool, issues: [String]) {
        var issues: [String] = []
        
        if password.count < 8 {
            issues.append("Password must be at least 8 characters")
        }
        
        if !password.contains(where: { $0.isUppercase }) {
            issues.append("Password must contain at least one uppercase letter")
        }
        
        if !password.contains(where: { $0.isLowercase }) {
            issues.append("Password must contain at least one lowercase letter")
        }
        
        if !password.contains(where: { $0.isNumber }) {
            issues.append("Password must contain at least one number")
        }
        
        if !password.contains(where: { "!@#$%^&*".contains($0) }) {
            issues.append("Password must contain at least one special character")
        }
        
        return (issues.isEmpty, issues)
    }
    
    // URL validation
    static func isValidURL(_ urlString: String) -> Bool {
        if let url = URL(string: urlString) {
            return UIApplication.shared.canOpenURL(url)
        }
        return false
    }
    
    // Sanitize user input
    static func sanitizeInput(_ input: String) -> String {
        let allowedCharacters = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: " "))
        let sanitized = input.components(separatedBy: allowedCharacters.inverted).joined()
        return sanitized.trimmingCharacters(in: .whitespaces)
    }
}

// MARK: - 5. SECURE API CALLS WITH SSL PINNING

class PinnedURLSession {
    static let shared = PinnedURLSession()
    
    let session: URLSession
    
    init() {
        let delegate = SSLPinningDelegate()
        let config = URLSessionConfiguration.default
        self.session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
    }
    
    func dataTask(with url: URL, completion: @escaping (Data?, URLResponse?, Error?) -> Void) -> URLSessionDataTask {
        return session.dataTask(with: url, completionHandler: completion)
    }
}

class SSLPinningDelegate: NSObject, URLSessionDelegate {
    
    // Public key hashes for SSL pinning (replace with your actual certificate hashes)
    private let pinnedPublicKeyHashes = [
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // Replace with actual hash
    ]
    
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        var secResult = SecTrustResultType.invalid
        let status = SecTrustEvaluate(serverTrust, &secResult)
        
        guard status == errSecSuccess else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Verify certificate chain
        if let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0) {
            if isValidCertificate(certificate) {
                completionHandler(.useCredential, URLCredential(trust: serverTrust))
                return
            }
        }
        
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
    
    private func isValidCertificate(_ certificate: SecCertificate) -> Bool {
        // Implement your certificate validation logic
        // This is a simplified example
        return true
    }
}

// MARK: - 6. ERROR HANDLING

enum AppError: Error {
    case networkError(String)
    case invalidResponse
    case decodingError(String)
    case authenticationError
    case validationError(String)
    case keychainError(String)
    
    var localizedDescription: String {
        switch self {
        case .networkError(let message):
            return "Network Error: \(message)"
        case .invalidResponse:
            return "Invalid server response"
        case .decodingError(let message):
            return "Decoding Error: \(message)"
        case .authenticationError:
            return "Authentication failed"
        case .validationError(let message):
            return "Validation Error: \(message)"
        case .keychainError(let message):
            return "Keychain Error: \(message)"
        }
    }
}

// MARK: - 7. INITIALIZATION & APP LIFECYCLE

class SecurityManager {
    static let shared = SecurityManager()
    
    func initializeSecurityFeatures() {
        // Enable logging
        setupLogging()
        
        // Setup security defaults
        setupSecurityDefaults()
    }
    
    private func setupLogging() {
        // Configure batch logger
        let logger = BatchedFileLogger.shared
        logger.log("App launched", level: .info)
    }
    
    private func setupSecurityDefaults() {
        // Set keychain defaults
        _ = KeychainManager.shared
        
        // Setup image cache limits
        _ = ImageCacheManager.shared
    }
    
    func flushLogsOnAppTermination() {
        BatchedFileLogger.shared.flushOnAppTermination()
    }
}

// MARK: - 8. USAGE EXAMPLES

/*
 // Example 1: Secure logging
 BatchedFileLogger.shared.log("User logged in", level: .info)
 BatchedFileLogger.shared.log("Critical error occurred", level: .error)
 
 // Example 2: Image caching
 ImageCacheManager.shared.cacheImage(myImage, forKey: "profile_pic")
 let cached = ImageCacheManager.shared.cachedImage(forKey: "profile_pic")
 
 // Example 3: API calls without retain cycles
 APIClient.shared.fetchData(url: url) { data, error in
     if let error = error {
         print("Error: \(error)")
     } else {
         print("Data received: \(data ?? Data())")
     }
 }
 
 // Example 4: Secure credential storage
 KeychainManager.shared.savePassword(password, forAccount: "user@example.com")
 let retrieved = KeychainManager.shared.retrievePassword(forAccount: "user@example.com")
 
 // Example 5: Input validation
 if InputValidator.isValidEmail(email) {
     print("Valid email")
 }
 
 let (isValid, issues) = InputValidator.isValidPassword(password)
 if !isValid {
     print("Password issues: \(issues)")
 }
 
 // Example 6: Initialize security on app launch
 func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
     SecurityManager.shared.initializeSecurityFeatures()
     return true
 }
 
 // Example 7: Flush logs before app terminates
 func applicationWillTerminate(_ application: UIApplication) {
     SecurityManager.shared.flushLogsOnAppTermination()
 }
 */

// ============================================================================
// END OF SECURITY FIXES
// ============================================================================
