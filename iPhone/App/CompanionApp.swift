import SwiftUI
import CryptoKit
import LocalAuthentication
import Security
import UserNotifications
import VisionKit
import AVFoundation
import OSLog

enum Diagnostics {
    private static let logger = Logger(subsystem: "dev.selenic.pocketlatch", category: "recovery")
    // Only lifecycle/status metadata: never pass pairing codes, keys, or request payloads.
    static func record(_ message: String) {
        logger.notice("\(message, privacy: .public)")
        print(message)
    }
}

struct Pairing: Codable {
    var secret: Data
    var keys: Data
    var deviceId: String?
    var enrollmentExpires: Date?
}

enum Vault {
    static let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "CdfWifiPrototype", kSecAttrAccount as String: "pairing"]
    private static var backgroundQuery: [String: Any] {
        var q = query; q[kSecAttrAccount as String] = "background-pairing"; return q
    }
    private static func read(_ query: [String: Any]) throws -> Pairing? {
        var q = query; q[kSecReturnData as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        Diagnostics.record("Keychain load result: \(status)")
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw Failure.storage }
        return try JSONDecoder().decode(Pairing.self, from: data)
    }
    static func load() throws -> Pairing? { try read(query) }
    static func loadBackground() throws -> Pairing? {
        guard let p = try read(backgroundQuery), p.keys.isEmpty,
              p.secret.count == 32 else { return nil }
        return p
    }
    private static func write(_ pairing: Pairing, query: [String: Any], accessibility: CFString) throws {
        let data = try JSONEncoder().encode(pairing)
        let values: [String: Any] = [kSecValueData as String: data, kSecAttrAccessible as String: accessibility]
        let status = SecItemUpdate(query as CFDictionary, values as CFDictionary)
        if status == errSecItemNotFound {
            let q = query.merging(values) { _, new in new }
            guard SecItemAdd(q as CFDictionary, nil) == errSecSuccess else { throw Failure.storage }
        } else if status != errSecSuccess { throw Failure.storage }
    }
    static func save(_ pairing: Pairing, automaticUnlock: Bool = false) throws {
        guard pairing.secret.count == 32, pairing.keys.count == 64 else { throw Failure.storage }
        // Invalidate the old wake credential first: a partial save fails closed.
        let removed = SecItemDelete(backgroundQuery as CFDictionary)
        guard removed == errSecSuccess || removed == errSecItemNotFound else { throw Failure.storage }
        try write(pairing, query: query, accessibility: automaticUnlock
            ? kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly : kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
        try saveBackground(pairing)
    }
    static func setAutomaticAccess(_ enabled: Bool) throws {
        let result = SecItemUpdate(query as CFDictionary, [
            kSecAttrAccessible as String: enabled
                ? kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly : kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ] as CFDictionary)
        guard result == errSecSuccess || result == errSecItemNotFound else { throw Failure.storage }
    }
    static func saveBackground(_ pairing: Pairing) throws {
        guard pairing.secret.count == 32, pairing.keys.count == 64 else { throw Failure.storage }
        var wake = pairing; wake.keys = Data(); wake.enrollmentExpires = nil
        try write(wake, query: backgroundQuery, accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
    }
    static func authorizedPairing(for wake: Pairing) throws -> Pairing {
        guard let full = try load(), full.secret == wake.secret,
              full.deviceId == wake.deviceId, full.keys.count == 64 else { throw Failure.denied }
        return full
    }

}

enum ApprovalOptions {
    static func automaticWithoutAuthentication(operation: String, automatic: Bool,
        faceID: Bool) -> Bool {
        operation == "prepareUnlock" && automatic && !faceID
    }
}

enum Failure: Error { case storage, malformed, disconnected, denied }

final class NotificationObserver: NSObject, UNUserNotificationCenterDelegate {
    var onAction: (@MainActor (String, String) -> Void)?
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void) {
        Diagnostics.record("Approval notification presented while foreground")
        completionHandler([.banner, .sound])
    }
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void) {
        let identifier = response.notification.request.identifier
        let action = response.actionIdentifier
        Task { @MainActor in
            self.onAction?(identifier, action)
            completionHandler()
        }
    }
}

@MainActor final class Companion: ObservableObject {
    @Published var status = "Pair with Windows to approve sign-ins on this phone."
    @Published var bluetoothStatus = "Bluetooth stopped"
    @Published var bluetoothEnabled = false
    @Published var bluetoothConnectionState: BLEConnectionState = .stopped
    private let bluetooth = BLECentral()
    private let notificationObserver = NotificationObserver()
    @Published var notificationStatus = "Checking notification settings…"
    private var notificationId: String?
    private var notificationApproval: String?
    private var bleSession: Data?
    private var bleChallenge: Data?
    private var bleDeadline: Task<Void, Never>?
    @Published var code = ""
    @Published var pending: String?
    @Published var enrollment = false
    private var pairing: Pairing?
    private var unlockApproval = UnlockApproval()
    private var work: Task<Void, Never>?
    private var approval: CheckedContinuation<Bool, Never>?
    @Published private(set) var useFaceID = UserDefaults.standard.object(forKey: "UseFaceID") as? Bool ?? true
    @Published private(set) var autoApprove = UserDefaults.standard.bool(forKey: "AutoApprove")
    func setApprovalOptions(faceID: Bool, automatic: Bool) {
        guard pending == nil, bleSession == nil else {
            status = "Wait for the current request to finish before changing approval settings."
            return
        }
        do {
            try Vault.setAutomaticAccess(automatic && !faceID)
            unlockApproval.clear()
            useFaceID = faceID
            autoApprove = automatic
            UserDefaults.standard.set(faceID, forKey: "UseFaceID")
            UserDefaults.standard.set(automatic, forKey: "AutoApprove")
        } catch {
            status = "Could not change key protection. Unlock your phone and try again. Settings were not changed."
        }
    }
    private var registrationPending = false
    private var authContext: LAContext?
    private var expires = Date.distantPast

    init() {
        Diagnostics.record("Process started; pid=\(ProcessInfo.processInfo.processIdentifier); appState=\(UIApplication.shared.applicationState.rawValue); protectedDataAvailable=\(UIApplication.shared.isProtectedDataAvailable)")
        notificationObserver.onAction = { [weak self] id, action in self?.notificationAction(id, action: action) }
        UNUserNotificationCenter.current().setNotificationCategories([
            UNNotificationCategory(identifier: "windows-approval", actions: [
                UNNotificationAction(identifier: "approve", title: "Approve", options: [.foreground]),
                UNNotificationAction(identifier: "deny", title: "Deny", options: [.destructive])
            ], intentIdentifiers: [])
        ])
        UNUserNotificationCenter.current().delegate = notificationObserver
        refreshNotificationSettings()
        do {
            pairing = try Vault.loadBackground() ?? Vault.load()
            try Vault.setAutomaticAccess(autoApprove && !useFaceID)
        }
        catch { status = "Unlock the phone and reopen the app to read its pairing." }
        bluetooth.onStatus = { [weak self] text, state in
            self?.bluetoothStatus = text
            self?.bluetoothConnectionState = state
        }
        bluetooth.onMessage = { [weak self] in self?.receiveBLE($0) }
        bluetooth.onDisconnect = { [weak self] in self?.endBLE("Bluetooth disconnected") }
        if pairing != nil { startBluetooth() }
    }
    private func random(_ count: Int) throws -> Data {
        var data = Data(count: count)
        guard data.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }) == errSecSuccess
        else { throw Failure.storage }
        return data
    }
    func importInvitation(_ text: String) {
        do {
            let invite = try PairingInvitation.parse(text)
            stopBluetooth(); stop()
            let p = Pairing(secret: invite.secret, keys: try random(64), deviceId: invite.deviceId,
                enrollmentExpires: Date(timeIntervalSince1970: Double(invite.expires)))
            try Vault.save(p, automaticUnlock: autoApprove && !useFaceID); pairing = p; code = ""; enrollment = true
            status = "Pairing scanned. Windows will detect this phone once Bluetooth connects."
            startBluetooth()
        } catch { status = "QR pairing is invalid, expired, or could not be saved. Generate a new code on Windows." }
    }
    func newPairing() {
        stopBluetooth(); stop()
        defer { startBluetooth() }
        do {
            let p = Pairing(secret: try random(32), keys: try random(64), deviceId: nil)
            try Vault.save(p, automaticUnlock: autoApprove && !useFaceID); pairing = p
            code = p.secret.map { String(format: "%02x", $0) }.joined()
            enrollment = true
            status = "Enter this code in Windows. Only approve the registration you just started."
        } catch { status = "Could not create pairing." }
    }
    func stop() {
        unlockApproval.clear()
        work?.cancel(); work = nil
        authContext?.invalidate(); authContext = nil
        approval?.resume(returning: false); approval = nil; pending = nil
    }
    private func notificationAction(_ id: String, action: String) {
        guard NotificationAction.isCurrent(id: id, pendingId: notificationId,
            hasApproval: approval != nil, expires: expires), action == "approve" || action == "deny" else {
            Diagnostics.record("Ignored stale or non-action notification response")
            return
        }
        if action == "deny" { decide(false) }
        else {
            notificationApproval = id
            resumeNotificationApproval()
        }
    }
    private func resumeNotificationApproval() {
        guard let id = notificationApproval, UIApplication.shared.applicationState == .active else { return }
        notificationApproval = nil
        guard NotificationAction.isCurrent(id: id, pendingId: notificationId,
            hasApproval: approval != nil, expires: expires) else { return }
        decide(true)
    }
    func decide(_ allow: Bool) {
        guard approval != nil else { return }
        if allow && (authContext != nil || UIApplication.shared.applicationState != .active) { return }
        notificationApproval = nil
        if let notificationId {
            UNUserNotificationCenter.current().removeDeliveredNotifications(withIdentifiers: [notificationId])
        }
        if !allow { authContext?.invalidate(); authContext = nil; Diagnostics.record("User selected Deny"); approval?.resume(returning: false); approval = nil; pending = nil; return }
        Diagnostics.record("BLE approval selected; secondsRemaining=\(Int(expires.timeIntervalSinceNow))")
        if !useFaceID && !registrationPending {
            approval?.resume(returning: Date() < expires)
            approval = nil; pending = nil
            return
        }
        let context = LAContext(); authContext = context
        Task {
            let approved = (try? await context.evaluatePolicy(.deviceOwnerAuthentication,
                localizedReason: "Approve this Windows companion request")) ?? false
            guard authContext === context else { return }
            Diagnostics.record("Local authentication completed: \(approved)")
            authContext = nil
            approval?.resume(returning: approved && Date() < expires)
            approval = nil; pending = nil
        }
    }
    func startBluetooth() {
        guard !bluetoothEnabled else { return }
        stop()
        if let full = try? Vault.load() {
            pairing = full
            do { try Vault.saveBackground(full) }
            catch { status = "Could not enable locked background recovery. Reopen while unlocked." }
        }
        guard pairing != nil else { status = "Create a pairing while the phone is unlocked first."; return }
        bluetoothEnabled = true; UserDefaults.standard.set(true, forKey: "BluetoothEnabled")
        bluetooth.start()
        Task {
            _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
            refreshNotificationSettings()
        }
    }
    func stopBluetooth() {
        unlockApproval.clear()
        bluetoothEnabled = false; UserDefaults.standard.set(false, forKey: "BluetoothEnabled")
        bluetooth.stop(); endBLE("Bluetooth disabled")
    }
    func background() {
        // Keep BLE alive while the app is in the background.
        if !bluetoothEnabled { stop() }
        code = ""
        bluetooth.refreshScan()
    }
    private func refreshNotificationSettings() {
        Task {
            let settings = await UNUserNotificationCenter.current().notificationSettings()
            notificationStatus = "Lock Screen alerts: \(settings.lockScreenSetting == .enabled ? "on" : "off"). Time Sensitive: \(settings.timeSensitiveSetting == .enabled ? "on" : "off")."
            Diagnostics.record("Notification settings: authorization=\(settings.authorizationStatus.rawValue), lockScreen=\(settings.lockScreenSetting.rawValue), alert=\(settings.alertSetting.rawValue), timeSensitive=\(settings.timeSensitiveSetting.rawValue), summary=\(settings.scheduledDeliverySetting.rawValue)")
        }
    }
    func foreground() {
        Diagnostics.record("App foreground; pairingLoaded=\(pairing != nil); protectedDataAvailable=\(UIApplication.shared.isProtectedDataAvailable)")
        refreshNotificationSettings()
        do { try Vault.setAutomaticAccess(autoApprove && !useFaceID) }
        catch { status = "Could not update key protection. Unlock your phone and reopen the app." }
        if let full = try? Vault.load() {
            pairing = full
            do { try Vault.saveBackground(full) }
            catch { status = "Could not enable locked background recovery. Reopen while unlocked." }
        }
        bluetooth.refreshScan()
        resumeNotificationApproval()
        if Date() >= expires, bleSession != nil { endBLE("Request expired before app opened") }
    }
    private func endBLE(_ reason: String) {
        if bleSession != nil {
            Diagnostics.record("BLE request ended: \(reason)")
            status = reason
        }
        bleDeadline?.cancel(); bleDeadline = nil; bleSession = nil; bleChallenge = nil
        work?.cancel(); work = nil
        authContext?.invalidate(); authContext = nil
        approval?.resume(returning: false); approval = nil; pending = nil
        // Keep an unanswered alert visible after expiry; opening it cannot revive the request.
        notificationId = nil
        notificationApproval = nil
    }
    private func receiveBLE(_ message: BLEWire.Message) {
        guard bluetoothEnabled else { return }
        if message.kind == 1, message.payload.isEmpty {
            guard bleSession == nil, pairing != nil else {
                Diagnostics.record("BLE request rejected before challenge; busy=\(bleSession != nil); pairingLoaded=\(pairing != nil); protectedDataAvailable=\(UIApplication.shared.isProtectedDataAvailable)")
                bluetooth.send(kind: 3, session: message.session, payload: Data()); return
            }
            do {
                Diagnostics.record("BLE request started; appState=\(UIApplication.shared.applicationState.rawValue)")
                bleSession = message.session; bleChallenge = try random(32)
                expires = Date().addingTimeInterval(30)
                bluetooth.send(kind: 4, session: message.session, payload: bleChallenge!)
                bleDeadline = Task { [weak self] in
                    try? await Task.sleep(nanoseconds: 30_000_000_000)
                    guard !Task.isCancelled, let self, self.bleSession == message.session else { return }
                    self.bluetooth.send(kind: 3, session: message.session, payload: Data()); self.endBLE("Request expired after 30 seconds")
                }
            } catch { endBLE("Could not create request challenge") }
        } else if message.session == bleSession, message.kind == 3 { endBLE("Windows or bridge ended the request") }
        else if message.session == bleSession, message.kind == 2, work == nil,
                let challenge = bleChallenge, let stored = pairing {
            work = Task {
                do {
                    let result = try await respond(frame: BLEWire.unframe(message.payload), challenge: challenge, stored: stored)
                    guard bleSession == message.session, Date() < expires else { throw Failure.denied }
                    bluetooth.send(kind: 2, session: message.session, payload: BLEWire.framed(result))
                    status = "Approved response sent over Bluetooth. Check Windows."
                } catch {
                    if bleSession == message.session {
                        bluetooth.send(kind: 3, session: message.session, payload: Data())
                        status = "Request denied, expired, or failed validation."
                    }
                }
                if bleSession == message.session { endBLE(status) }
            }
        }
    }
    private func respond(frame: Data, challenge: Data, stored: Pairing) async throws -> Data {
        let plain = try Wire.open(frame, secret: stored.secret, challenge: challenge, direction: "request")
        guard let request = try JSONSerialization.jsonObject(with: plain) as? [String: String],
            let operation = request["operation"], let device = request["deviceId"],
            device.count == 32, device.allSatisfy({ $0.isHexDigit }),
            ["pairingReady", "register", "prepareUnlock", "authenticate"].contains(operation) else { throw Failure.malformed }
        var response = ["operation": operation, "deviceId": device, "status": "approved"]
        func bytes(_ name: String) throws -> Data {
            guard let text = request[name], let bytes = Data(base64Encoded: text), bytes.count == 32 else { throw Failure.malformed }
            return bytes
        }
        if operation == "pairingReady" {
            guard PairingInvitation.canAcknowledge(device: device, pairedDevice: stored.deviceId,
                enrollment: enrollment, expires: stored.enrollmentExpires), Date() < expires else { throw Failure.denied }
            try Task.checkCancellation()
            // Only prove receipt of this invitation; no keys, approval, or unlock grant.
            return try Wire.seal(JSONSerialization.data(withJSONObject: response), secret: stored.secret,
                challenge: challenge, direction: "response")
        }
        if operation == "register" {
            guard enrollment, stored.deviceId == nil || stored.deviceId == device,
                  stored.enrollmentExpires.map({ Date() < $0 }) ?? true else { throw Failure.denied }
        } else {
            guard stored.deviceId == device else { throw Failure.denied }
        }
        if operation == "prepareUnlock" {
            unlockApproval.clear()
            _ = try bytes("serviceNonce")
        }
        if operation == "authenticate" {
            guard unlockApproval.consume(device: device, nonce: try bytes("serviceNonce"), now: Date()) else { throw Failure.denied }
            let full = try Vault.authorizedPairing(for: stored)
            let proof = try CdfProtocol.respond(deviceKey: full.keys.prefix(32),
                authenticationKey: full.keys.suffix(32), serviceNonce: bytes("serviceNonce"),
                deviceNonce: bytes("deviceNonce"), sessionNonce: bytes("sessionNonce"), serviceHmac: bytes("serviceHmac"))
            response["deviceHmac"] = proof.deviceHmac.base64EncodedString()
            response["sessionHmac"] = proof.sessionHmac.base64EncodedString()
            try Task.checkCancellation()
            guard Date() < expires else { throw Failure.denied }
            return try Wire.seal(JSONSerialization.data(withJSONObject: response), secret: stored.secret,
                challenge: challenge, direction: "response")
        }
        try Task.checkCancellation()
        guard Date() < expires else { throw Failure.denied }
        registrationPending = operation == "register"
        if ApprovalOptions.automaticWithoutAuthentication(operation: operation, automatic: autoApprove,
            faceID: useFaceID) {
            _ = try Vault.authorizedPairing(for: stored)
            try unlockApproval.grant(device: device, nonce: bytes("serviceNonce"), now: Date())
            status = "Automatically approved your paired PC."
            return try Wire.seal(JSONSerialization.data(withJSONObject: response), secret: stored.secret,
                challenge: challenge, direction: "response")
        }
        let requestNotificationId = UUID().uuidString
        notificationId = requestNotificationId
        pending = operation == "register" ? "Register this phone with Windows?" : "Unlock your paired Windows PC?"
        if UIApplication.shared.applicationState != .active {
            let content = UNMutableNotificationContent()
            content.title = "Windows approval requested"
            content.body = "Open to approve this Windows sign-in. Expires at \(expires.formatted(date: .omitted, time: .standard)); after that, start a new attempt on Windows."
            content.interruptionLevel = .active
            content.sound = .default
            content.threadIdentifier = "windows-approval"
            content.categoryIdentifier = "windows-approval"
            UNUserNotificationCenter.current().add(UNNotificationRequest(identifier: requestNotificationId, content: content, trigger: nil), withCompletionHandler: { error in
                Diagnostics.record("Approval notification scheduled: \(error == nil ? "success" : "failed")")
            })
        }
        let allowed = await withCheckedContinuation {
            approval = $0
            if operation == "prepareUnlock", autoApprove {
                decide(true)
            }
            if operation == "register", PairingInvitation.canAcknowledge(device: device,
                pairedDevice: stored.deviceId, enrollment: enrollment, expires: stored.enrollmentExpires) {
                // A confirmed, live QR invitation starts authentication; it never bypasses it.
                // decide requires the foreground, so background requests retain manual approval.
                decide(true)
            }
        }
        guard allowed, Date() < expires else { throw Failure.denied }
        try Task.checkCancellation()
        let full = try Vault.authorizedPairing(for: stored)
        if operation == "prepareUnlock" {
            try unlockApproval.grant(device: device, nonce: bytes("serviceNonce"), now: Date())
        }
        if operation == "register" {
            guard stored.enrollmentExpires.map({ Date() < $0 }) ?? true else { throw Failure.denied }
            var enrolled = full; enrolled.deviceId = device; enrolled.enrollmentExpires = nil
            try Vault.save(enrolled, automaticUnlock: autoApprove && !useFaceID); pairing = enrolled
            response["keys"] = full.keys.base64EncodedString()
            enrollment = false; code = ""
        }
        return try Wire.seal(JSONSerialization.data(withJSONObject: response), secret: stored.secret,
            challenge: challenge, direction: "response")
    }

}

@main struct CompanionApp: App {
    @StateObject private var model = Companion()
    @State private var scanning = false
    @State private var scannedCode: String?
    @State private var confirmPairing = false
    @State private var confirmManualPairing = false
    @Environment(\.scenePhase) private var scenePhase
    var body: some Scene {
        WindowGroup {
            NavigationStack {
                Form {
                    if let pending = model.pending {
                        Section {
                            Label("Approval needed", systemImage: "lock.shield")
                                .font(.headline)
                            Text(pending)
                            Button(model.useFaceID || model.enrollment ? "Approve with Face ID or passcode" : "Approve") { model.decide(true) }
                                .buttonStyle(.borderedProminent)
                            Button("Deny", role: .destructive) { model.decide(false) }
                        }
                    }
                    Section {
                        Label(model.bluetoothStatus, systemImage: "antenna.radiowaves.left.and.right")
                            .accessibilityLabel("Bluetooth: " + model.bluetoothStatus)
                    } header: {
                        Text("Connection")
                    } footer: {
                        Text("Keep Bluetooth on and leave PocketLatch in the background.")
                    }
                    Section {
                        Button {
                            Task {
                                guard DataScannerViewController.isSupported,
                                      await AVCaptureDevice.requestAccess(for: .video),
                                      DataScannerViewController.isAvailable else {
                                    model.status = "Camera scanning is unavailable. Check Camera permission or use manual pairing."; return
                                }
                                scannedCode = nil
                                scanning = true
                            }
                        } label: {
                            Label("Scan pairing QR", systemImage: "qrcode.viewfinder")
                        }
                        Text("On Windows, choose Pair your phone. Scan it here, then confirm registration on both devices.")
                            .font(.subheadline).foregroundStyle(.secondary)
                    } header: {
                        Text("Pair with Windows")
                    } footer: {
                        Text("Pair with your own Windows PC over Bluetooth.")
                    }
                    Section("Status") {
                        Text(model.status)
                            .accessibilityLabel("Request status: " + model.status)
                    }
                    Section {
                        NavigationLink("Settings") {
                            Form {
                    Section {
                      DisclosureGroup("Approval settings") {
                        Toggle("Use Face ID", isOn: Binding(get: { model.useFaceID },
                            set: { model.setApprovalOptions(faceID: $0, automatic: model.autoApprove) }))
                        Toggle("Automatically approve unlocks", isOn: Binding(get: { model.autoApprove },
                            set: { model.setApprovalOptions(faceID: model.useFaceID, automatic: $0) }))
                      }
                    } header: {
                        Text("Unlock approval")
                    } footer: {
                        Text(model.autoApprove && !model.useFaceID ? "Your paired PC can unlock without asking, even while this phone is locked." : model.autoApprove ? "Open the notification to authenticate and approve." : "Review each request before approving. Pairing always requires authentication.")
                    }
                    Section("Notifications") {
                        Text(model.notificationStatus)
                        Text("Using Focus or Do Not Disturb? Allow PocketLatch in that Focus’s app list.")
                            .font(.subheadline).foregroundStyle(.secondary)
                    }
                    Section {
                        DisclosureGroup("Manual pairing") {
                            Button("Create manual pairing") { confirmManualPairing = true }
                            if !model.code.isEmpty {
                                Text(model.code).font(.system(.caption, design: .monospaced))
                                    .textSelection(.enabled)
                                    .accessibilityLabel("Manual pairing code: " + model.code)
                                Button("Copy code", systemImage: "doc.on.doc") {
                                    UIPasteboard.general.setItems([[UIPasteboard.typeAutomatic: model.code]],
                                        options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(120)])
                                    model.status = "Pairing code copied. Paste it into Windows manual setup."
                                }
                            }

                        }
                    }
                            }.navigationTitle("Settings")
                        }
                    }
                }.navigationTitle("PocketLatch")
            }.sheet(isPresented: $scanning, onDismiss: { if scannedCode != nil { confirmPairing = true } }) {
                NavigationStack {
                    PairingScanner(found: { text in
                        scannedCode = text; scanning = false
                    }, failed: { message in
                        model.status = message; scannedCode = nil; scanning = false
                    }).navigationTitle("Scan Windows QR")
                        .toolbar { Button("Cancel") { scannedCode = nil; scanning = false } }
                }
            }.alert("Replace pairing with this Windows PC?", isPresented: $confirmPairing) {
                Button("Cancel", role: .cancel) { scannedCode = nil }
                Button("Use scanned pairing") {
                    if let text = scannedCode { model.importInvitation(text) }
                    scannedCode = nil
                }
            } message: {
                Text("Only scan the code displayed on your own PC. Registration still requires Face ID and Windows Hello.")
            }.alert("Replace the current pairing?", isPresented: $confirmManualPairing) {
                Button("Cancel", role: .cancel) { }
                Button("Create pairing", role: .destructive) { model.newPairing() }
            } message: {
                Text("You’ll need to register the new code in Windows. The previous pairing will stop working.")
            }.onChange(of: scenePhase) { phase in
                // Face ID temporarily makes the scene inactive; stop only on background.
                if phase == .background { model.background() }
                if phase == .active { model.foreground() }
            }
        }
    }
}

@MainActor struct PairingScanner: UIViewControllerRepresentable {
    let found: (String) -> Void
    let failed: (String) -> Void
    func makeCoordinator() -> Coordinator { Coordinator(found: found, failed: failed) }
    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(recognizedDataTypes: [.barcode(symbologies: [.qr])],
            recognizesMultipleItems: false, isGuidanceEnabled: true, isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        do { try scanner.startScanning() }
        catch {
            Task { @MainActor in context.coordinator.fail("Camera scanning could not start. Try again or use manual pairing.") }
        }
        return scanner
    }
    func updateUIViewController(_ controller: DataScannerViewController, context: Context) {}
    static func dismantleUIViewController(_ controller: DataScannerViewController, coordinator: Coordinator) {
        controller.stopScanning()
    }
    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        let found: (String) -> Void
        let failed: (String) -> Void
        var consumed = false
        init(found: @escaping (String) -> Void, failed: @escaping (String) -> Void) {
            self.found = found; self.failed = failed
        }
        func fail(_ message: String) {
            guard !consumed else { return }
            consumed = true; failed(message)
        }
        func dataScanner(_ scanner: DataScannerViewController, becameUnavailableWithError error: DataScannerViewController.ScanningUnavailable) {
            fail("Camera scanning is unavailable. Try again or use manual pairing.")
        }
        func dataScanner(_ scanner: DataScannerViewController, didAdd addedItems: [RecognizedItem], allItems: [RecognizedItem]) {
            guard !consumed else { return }
            for item in addedItems {
                if case .barcode(let barcode) = item, let text = barcode.payloadStringValue {
                    guard (try? PairingInvitation.parse(text)) != nil else {
                        scanner.stopScanning()
                        fail("This isn’t a valid, current Windows pairing QR. Show a new code on Windows and try again.")
                        return
                    }
                    consumed = true; scanner.stopScanning(); found(text); return
                }
            }
        }
    }
}
