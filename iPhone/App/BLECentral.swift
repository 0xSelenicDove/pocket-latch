import Foundation
import CoreBluetooth
import UIKit

enum BLEConnectionState { case stopped, unavailable, waiting, connecting, connected }

// CoreBluetooth delegates are delivered on the explicitly selected main queue.
@MainActor final class BLECentral: NSObject, @preconcurrency CBCentralManagerDelegate, @preconcurrency CBPeripheralDelegate {
    var onMessage: ((BLEWire.Message) -> Void)?
    var onDisconnect: (() -> Void)?
    var onStatus: ((String, BLEConnectionState) -> Void)?
    private func status(_ text: String, state: BLEConnectionState = .connecting) {
        Diagnostics.record("BLE: \(text)"); onStatus?(text, state)
    }
    private var manager: CBCentralManager!
    private var peer: CBPeripheral?
    private var uplink: CBCharacteristic?
    private var outgoing = [Data]()
    private var writing = false
    private var receiver = BLEWire.Receiver()
    private var enabled = false
    private var advertisementCount = 0
    func start() {
        enabled = true
        status("Starting Bluetooth…")
        if manager == nil {
            manager = CBCentralManager(delegate: self, queue: .main,
                options: [CBCentralManagerOptionRestoreIdentifierKey: "cdf-ble-central-v1"])
        } else { centralManagerDidUpdateState(manager) }
    }
    func stop() {
        enabled = false; manager?.stopScan()
        if let peer { manager.cancelPeripheralConnection(peer) }
        clear(); status("Bluetooth disconnected", state: .stopped)
    }
    private func clear() {
        peer = nil; uplink = nil; outgoing.removeAll(); writing = false
        receiver = BLEWire.Receiver(); onDisconnect?()
    }
    func refreshScan() {
        guard enabled, manager?.state == .poweredOn, peer == nil else { return }
        manager.stopScan(); scan()
    }
    private func scan() {
        guard enabled, manager.state == .poweredOn, peer == nil else { return }
        status("Waiting for your PC’s next pairing or sign-in request…", state: .waiting)
        advertisementCount = 0
        // Foreground scanning handles changing advertisements.
        // The service and encrypted request still must validate; the name grants no trust.
        let foreground = UIApplication.shared.applicationState == .active
        // Windows can start advertising the service after we first see the PC.
        // Do not let an earlier advertisement without our UUID hide that update.
        manager.scanForPeripherals(withServices: foreground ? nil : [CBUUID(string: BLEWire.service)],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: foreground])
    }
    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        if central.state == .poweredOn {
            if enabled { scan() }
            else { status("Bluetooth disconnected", state: .stopped) }
        } else {
            clear()
            let message: String
            switch central.state {
            case .poweredOff: message = "Bluetooth is off. Turn it on in Settings."
            case .unauthorized: message = "Bluetooth permission is denied. Allow it in Settings."
            case .unsupported: message = "Bluetooth is unavailable on this device."
            default: message = "Bluetooth is temporarily unavailable."
            }
            status(message, state: .unavailable)
        }
    }
    func centralManager(_ central: CBCentralManager, willRestoreState dict: [String: Any]) {
        Diagnostics.record("BLE restoration callback; enabled=\(enabled); peripherals=\((dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral])?.count ?? 0)")
        guard enabled, let restored = (dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral])?.first else { return }
        status("Restoring Bluetooth connection…")
        peer = restored; restored.delegate = self
        if restored.state == .connected { restored.discoverServices([CBUUID(string: BLEWire.service)]) }
        else { central.connect(restored) }
    }
    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard enabled, peer == nil else { return }
        advertisementCount += 1
        let services = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID] ?? []) +
            (advertisementData[CBAdvertisementDataOverflowServiceUUIDsKey] as? [CBUUID] ?? [])
        guard services.contains(CBUUID(string: BLEWire.service)) else {
            if advertisementCount == 1 || advertisementCount % 25 == 0 {
                Diagnostics.record("BLE scan: \(advertisementCount) advertisements seen; companion service not found yet.")
            }
            return
        }
        Diagnostics.record("BLE companion advertisement: connectable=\(String(describing: advertisementData[CBAdvertisementDataIsConnectable])), RSSI=\(RSSI), serviceMatch=\(services.contains(CBUUID(string: BLEWire.service)))")
        status("Companion discovered; connecting…")
        central.stopScan(); peer = peripheral; peripheral.delegate = self; central.connect(peripheral)
    }
    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        guard enabled, peripheral === peer else { return }
        status("Bluetooth link connected; discovering companion service…")
        peripheral.discoverServices([CBUUID(string: BLEWire.service)])
    }
    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        guard peripheral === peer else { return }
        clear(); scan()
    }
    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        guard peripheral === peer else { return }
        clear(); scan()
    }
    func peripheral(_ peripheral: CBPeripheral, didModifyServices invalidatedServices: [CBService]) {
        guard peripheral === peer,
              invalidatedServices.contains(where: { $0.uuid == CBUUID(string: BLEWire.service) }) else { return }
        // Windows publishes its service for each pairing/sign-in operation, not permanently.
        manager.cancelPeripheralConnection(peripheral)
    }
    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        guard enabled, peripheral === peer else { return }
        guard error == nil, let service = peripheral.services?.first(where: { $0.uuid == CBUUID(string: BLEWire.service) }) else { manager.cancelPeripheralConnection(peripheral); return }
        status("Companion service found; discovering characteristics…")
        peripheral.discoverCharacteristics([CBUUID(string: BLEWire.downlink), CBUUID(string: BLEWire.uplink)], for: service)
    }
    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        guard enabled, peripheral === peer else { return }
        guard error == nil, let down = service.characteristics?.first(where: { $0.uuid == CBUUID(string: BLEWire.downlink) }),
              let up = service.characteristics?.first(where: { $0.uuid == CBUUID(string: BLEWire.uplink) }) else { manager.cancelPeripheralConnection(peripheral); return }
        status("Companion characteristics found; subscribing…")
        uplink = up; peripheral.setNotifyValue(true, for: down)
    }
    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        guard enabled, peripheral === peer else { return }
        guard error == nil, characteristic.isNotifying else { manager.cancelPeripheralConnection(peripheral); return }
        status("Bluetooth connected", state: .connected)
    }
    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard peripheral === peer, characteristic.uuid == CBUUID(string: BLEWire.downlink), error == nil, let data = characteristic.value else { return }
        do { if let message = try receiver.append(data) { onMessage?(message) } }
        catch { manager.cancelPeripheralConnection(peripheral) }
    }
    func send(kind: UInt8, session: Data, payload: Data) {
        guard let peer, uplink != nil else { onDisconnect?(); return }
        do {
            let packets = try BLEWire.packets(kind: kind, session: session, payload: payload,
                mtu: peer.maximumWriteValueLength(for: .withResponse))
            guard outgoing.count + packets.count < 650 else { throw BLEWire.Failure.malformed }
            outgoing += packets; drain()
        } catch { manager.cancelPeripheralConnection(peer) }
    }
    private func drain() {
        guard !writing, let peer, let uplink, let packet = outgoing.first else { return }
        writing = true; peer.writeValue(packet, for: uplink, type: .withResponse)
    }
    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        guard peripheral === peer else { return }
        guard error == nil else { manager.cancelPeripheralConnection(peripheral); return }
        if !outgoing.isEmpty { outgoing.removeFirst() }; writing = false; drain()
    }
}
