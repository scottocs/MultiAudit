import SwiftUI
import Foundation
import Darwin
import os
import UniformTypeIdentifiers

private let logger = Logger(subsystem: "org.multiaudit.client", category: "audit")

enum Native {
    static func invoke(_ operation: String, _ arguments: [String: Any] = [:]) throws -> [String: Any] {
        let input = try JSONSerialization.data(withJSONObject: arguments)
        let text = String(decoding: input, as: UTF8.self)
        let pointer = operation.withCString { op in text.withCString { MAInvoke(op, $0) } }
        guard let pointer else { throw AuditError.message("Native client returned no result") }
        defer { MARelease(pointer) }
        let data = Data(String(cString: pointer).utf8)
        guard let response = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw AuditError.message("Invalid native response") }
        if let error = response["error"] as? String { throw AuditError.message(error) }
        return response["result"] as? [String: Any] ?? [:]
    }
}

enum AuditError: LocalizedError {
    case message(String)
    var errorDescription: String? { switch self { case .message(let message): return message } }
}

func monotonicMS() -> Double { Double(DispatchTime.now().uptimeNanoseconds) / 1_000_000 }
func cpuMS() -> Double {
    var usage = rusage(); getrusage(RUSAGE_SELF, &usage)
    return Double(usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) * 1000 + Double(usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1000
}
func footprintBytes() -> UInt64 {
    var info = task_vm_info_data_t()
    var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
    let status = withUnsafeMutablePointer(to: &info) { pointer in
        pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
        }
    }
    return status == KERN_SUCCESS ? info.phys_footprint : 0
}

final class PeakMemory {
    private let lock = NSLock()
    private var timer: DispatchSourceTimer?
    private var peak: UInt64 = 0
    func start() {
        peak = footprintBytes()
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "org.multiaudit.memory"))
        timer.schedule(deadline: .now(), repeating: .milliseconds(5))
        timer.setEventHandler { [weak self] in
            guard let self else { return }; let value = footprintBytes()
            self.lock.lock(); self.peak = max(self.peak, value); self.lock.unlock()
        }
        self.timer = timer; timer.resume()
    }
    func stop() -> UInt64 {
        timer?.cancel(); timer = nil
        lock.lock(); defer { lock.unlock() }; return max(peak, footprintBytes())
    }
}

final class NetworkMetrics: NSObject, URLSessionTaskDelegate {
    private let lock = NSLock()
    private var headers = (sent: Int64(0), received: Int64(0))
    func urlSession(_ session: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
        lock.lock(); defer { lock.unlock() }
        headers = metrics.transactionMetrics.reduce((Int64(0), Int64(0))) { ($0.0 + $1.countOfRequestHeaderBytesSent, $0.1 + $1.countOfResponseHeaderBytesReceived) }
    }
    func snapshot() -> (Int64, Int64) { lock.lock(); defer { lock.unlock() }; return headers }
}

struct StoreRecord: Codable {
    var scheme: String
    var files: Int
    var fileIndex: Int
    var chunks: Int
    var sectors: Int
    var challengedChunks: Int
    var inputKind: String
    var dataMS: Double
    var storeMS: Double
    var encodeMS: Double
    var uploadMS: Double
    var endToEndMS: Double
    var cpuMS: Double
    var peakFootprintBytes: UInt64
    var encodedDataBytes: Int
    var uploadBodyBytes: Int
    var setupMS: Double
    var thermalState: Int
}

struct AuditRecord: Codable, Identifiable {
    var id = UUID().uuidString
    var scheme: String
    var files: Int
    var chunks: Int
    var sectors: Int
    var challengedChunks: Int
    var round: Int
    var warmup: Bool
    var verificationPerformed: Bool
    var accepted: Bool
    var challengeMS: Double
    var roundTripMS: Double
    var decodeMS: Double
    var verifyMS: Double
    var bridgeVerifyMS: Double
    var endToEndMS: Double
    var cpuMS: Double
    var peakFootprintBytes: UInt64
    var uploadBodyBytes: Int
    var downloadBodyBytes: Int
    var requestHeaderBytes: Int64
    var responseHeaderBytes: Int64
    var serverWorkMS: Double
    var registryDigest: String
    var thermalState: Int
}

struct RunMetadata: Codable {
    var application = "MultiAudit"
    var platform = "physical iPhone"
    var model: String
    var operatingSystem: String
    var timestamp: String
    var baseURL: String
    var samplesPerConfiguration: Int
    var warmupsPerConfiguration: Int
    var failureReason: String?
    var notes = "Phone executes owner Setup and sequential Store; cloud imports sectors/tags and executes native ProofGen without the owner trapdoor. Phone Verify is optional. Synthetic benchmark files contain 3907*80 canonical 32-byte sectors; imported files use reversible 31-byte sectors with padding. Peak footprint sampled every 5ms. End-to-end audit time includes challenge/upload, download, decoding and optional verification. No battery-energy estimate."
    var stores: [StoreRecord]
    var records: [AuditRecord]
}

private struct Collection {
    var scheme: String
    var files: Int
    var chunks: Int
    var sectors: Int
    var challengedChunks: Int
    var digest: String
    var ownerKey: String
}

@MainActor final class AuditModel: ObservableObject {
    @Published var server = ProcessInfo.processInfo.environment["MA_URL"] ?? "http://127.0.0.1:8788"
    @Published var accountToken = ProcessInfo.processInfo.environment["MA_ACCOUNT_TOKEN"] ?? ""
    @Published var scheme = "MultiAudit"
    @Published var files = 10
    @Published var verifyLocally = false
    @Published var importedFiles: [URL] = []
    @Published var status = "Store a file collection to begin."
    @Published var running = false
    @Published var records: [AuditRecord] = []
    @Published var stores: [StoreRecord] = []
    @Published var exportURL: URL?
    @Published var registry = ""
    private var collection: Collection?
    private var launched = false

    func startAutomaticIfRequested() {
        guard !launched else { return }; launched = true
        if ProcessInfo.processInfo.environment["MA_AUTORUN"] == "1" { run(benchmark: true) }
    }
    func importFiles(_ result: Result<[URL], Error>) {
        switch result {
        case .success(let urls):
            guard !urls.isEmpty && urls.count <= 40 else { status = "Select between 1 and 40 files."; return }
            importedFiles = urls; files = urls.count; status = "Selected \(urls.count) files for owner preprocessing."
        case .failure(let error): status = error.localizedDescription
        }
    }

    func run(storeOnly: Bool = false, benchmark: Bool = false) {
        guard !running else { return }
        if !benchmark && !storeOnly && collection == nil { status = "Store files before requesting an audit."; return }
        running = true; UIApplication.shared.isIdleTimerDisabled = true
        let endpoint = server.trimmingCharacters(in: .whitespacesAndNewlines)
        let token = accountToken.trimmingCharacters(in: .whitespacesAndNewlines)
        let selectedScheme = scheme; let selectedFiles = files; let imports = importedFiles
        let previousRecords = records; let previousStores = stores
        let existing = collection; let doVerify = benchmark ? ProcessInfo.processInfo.environment["MA_VERIFY"] != "0" : verifyLocally
        let environment = ProcessInfo.processInfo.environment
        let count = benchmark ? Int(environment["MA_REPEATS"] ?? "30") ?? 30 : 1
        let warmups = benchmark ? Int(environment["MA_WARMUPS"] ?? "3") ?? 3 : 0
        let schemes = benchmark ? (environment["MA_SCHEMES"] ?? "MultiAudit,Xu,Yu").split(separator: ",").map(String.init) : [selectedScheme]
        let sizes = benchmark ? (environment["MA_FILES"] ?? "10,20,30,40").split(separator: ",").compactMap { Int($0) } : [selectedFiles]
        Task.detached(priority: .userInitiated) { [weak self] in
            guard let self else { return }
            var rows: [AuditRecord] = benchmark ? [] : previousRecords
            var stored: [StoreRecord] = benchmark ? [] : previousStores
            do {
                _ = try Self.save(rows, stores: stored, endpoint: endpoint, repeats: count, warmups: warmups)
                for (position, m) in sizes.enumerated() {
                    let ordered = Array(schemes.dropFirst(position % schemes.count)) + Array(schemes.prefix(position % schemes.count))
                    for name in ordered {
                        let config = URLSessionConfiguration.ephemeral
                        config.timeoutIntervalForRequest = 600; config.timeoutIntervalForResource = 1800
                        config.requestCachePolicy = .reloadIgnoringLocalCacheData
                        let metrics = NetworkMetrics(); let session = URLSession(configuration: config, delegate: metrics, delegateQueue: nil)
                        defer { session.invalidateAndCancel() }
                        let active: Collection
                        if storeOnly || benchmark {
                            let result = try await Self.store(endpoint: endpoint, token: token, session: session, scheme: name, files: m, imports: benchmark ? [] : imports) { text in
                                await MainActor.run { self.status = text }
                            }
                            active = result.0; stored += result.1
                            await MainActor.run { self.collection = active; self.registry = active.digest; self.stores = stored }
                            _ = try Self.save(rows, stores: stored, endpoint: endpoint, repeats: count, warmups: warmups)
                        } else {
                            guard let existing else { throw AuditError.message("No owner-authenticated collection") }; active = existing
                        }
                        if storeOnly { continue }
                        guard let auditURL = URL(string: endpoint + "/audit") else { throw AuditError.message("Invalid server address") }
                        for index in 0..<(count + warmups) {
                            let warmup = index < warmups
                            await MainActor.run { self.status = "\(active.scheme) · \(active.files) files · \(warmup ? "warmup" : "audit") \(warmup ? index + 1 : index - warmups + 1)/\(warmup ? warmups : count)" }
                            let peak = PeakMemory(); peak.start(); let start = monotonicMS(); let cpu = cpuMS()
                            let challenge = try Native.invoke("challenge")
                            guard let encoded = challenge["wire"] as? String, let body = Data(base64Encoded: encoded) else { throw AuditError.message("Invalid challenge") }
                            var request = URLRequest(url: auditURL); request.httpMethod = "POST"; request.httpBody = body
                            request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
                            let networkStart = monotonicMS(); let (proof, response) = try await session.data(for: request); let roundTrip = monotonicMS() - networkStart
                            guard let http = response as? HTTPURLResponse, http.statusCode == 200 else { throw AuditError.message("Proof request failed: \(String(decoding: proof.prefix(256), as: UTF8.self))") }
                            var result: [String: Any] = [:]; let verifyStart = monotonicMS()
                            if doVerify { result = try Native.invoke("verify", ["proof": proof.base64EncodedString()]) }
                            let verifyBridge = monotonicMS() - verifyStart
                            let accepted = result["accepted"] as? Bool ?? false
                            let elapsed = monotonicMS() - start; let cpuElapsed = cpuMS() - cpu; let memory = peak.stop(); let headers = metrics.snapshot()
                            let row = AuditRecord(scheme: active.scheme, files: active.files, chunks: active.chunks, sectors: active.sectors, challengedChunks: active.challengedChunks, round: warmup ? index + 1 : index - warmups + 1, warmup: warmup, verificationPerformed: doVerify, accepted: accepted, challengeMS: challenge["challenge_ms"] as? Double ?? 0, roundTripMS: roundTrip, decodeMS: result["decode_ms"] as? Double ?? 0, verifyMS: result["verify_ms"] as? Double ?? 0, bridgeVerifyMS: verifyBridge, endToEndMS: elapsed, cpuMS: cpuElapsed, peakFootprintBytes: memory, uploadBodyBytes: body.count, downloadBodyBytes: proof.count, requestHeaderBytes: headers.0, responseHeaderBytes: headers.1, serverWorkMS: Double(http.value(forHTTPHeaderField: "X-Server-Work-Ms") ?? "") ?? 0, registryDigest: active.digest, thermalState: ProcessInfo.processInfo.thermalState.rawValue)
                            rows.append(row)
                            if doVerify && !accepted { throw AuditError.message("Integrity check rejected") }
                            await MainActor.run { self.records = rows }
                            _ = try Self.save(rows, stores: stored, endpoint: endpoint, repeats: count, warmups: warmups)
                        }
                    }
                }
                let url = try Self.save(rows, stores: stored, endpoint: endpoint, repeats: count, warmups: warmups)
                await MainActor.run { self.exportURL = url; self.running = false; UIApplication.shared.isIdleTimerDisabled = false; self.status = storeOnly ? "Store complete: data and tags uploaded; signed roots retained." : (doVerify ? "Completed: \(rows.filter { !$0.warmup }.count) locally verified audits." : "Response received. Local verification was skipped.") }
            } catch {
                let ns = error as NSError
                let detail = "\(ns.domain) [\(ns.code)]: \(error.localizedDescription); \(ns.userInfo)"
                _ = try? Self.save(rows, stores: stored, endpoint: endpoint, repeats: count, warmups: warmups, failure: detail)
                print("MA_FAILURE: \(detail)")
                await MainActor.run { self.running = false; UIApplication.shared.isIdleTimerDisabled = false; self.status = "Stopped: \(error.localizedDescription)" }
            }
        }
    }

    nonisolated private static func post(_ path: String, endpoint: String, body: Data, token: String, ownerKey: String? = nil, session: URLSession) async throws {
        guard let url = URL(string: endpoint + path) else { throw AuditError.message("Invalid server address") }
        var request = URLRequest(url: url); request.httpMethod = "POST"; request.httpBody = body
        request.setValue("Bearer " + token, forHTTPHeaderField: "Authorization")
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        if let ownerKey { request.setValue(ownerKey, forHTTPHeaderField: "X-Owner-Key") }
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw AuditError.message("Upload rejected: \(String(decoding: data.prefix(256), as: UTF8.self))")
        }
    }

    nonisolated private static func store(endpoint: String, token: String, session: URLSession, scheme: String, files: Int, imports: [URL], progress: @escaping (String) async -> Void) async throws -> (Collection, [StoreRecord]) {
        let m = imports.isEmpty ? files : imports.count; let s = 80
        var n = 3907
        if !imports.isEmpty {
            var largest = 0
            for url in imports {
                let access = url.startAccessingSecurityScopedResource(); defer { if access { url.stopAccessingSecurityScopedResource() } }
                largest = max(largest, try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0)
            }
            n = max(1, (largest + 31*s - 1)/(31*s))
        }
        let c = min(690,n)
        await progress("Owner setup on phone: \(scheme), \(m) files…")
        let begin = try Native.invoke("owner_start", ["config": ["scheme": scheme, "m": m, "n": n, "s": s, "c": c]])
        guard let key = begin["owner_key"] as? String, let envelope = begin["envelope"] as? String, let initial = Data(base64Encoded: envelope) else { throw AuditError.message("Owner setup failed") }
        try await post("/owner/start", endpoint: endpoint, body: initial, token: token, ownerKey: key, session: session)
        var rows: [StoreRecord] = []
        for index in 0..<m {
            await progress("Store on phone · \(scheme) · file \(index+1)/\(m)")
            var arguments: [String: Any] = ["index": index]
            if !imports.isEmpty {
                let url = imports[index]; let access = url.startAccessingSecurityScopedResource(); defer { if access { url.stopAccessingSecurityScopedResource() } }
                arguments["real_file"] = true; arguments["file"] = try Data(contentsOf: url).base64EncodedString()
            }
            let peak = PeakMemory(); peak.start(); let start = monotonicMS(); let cpu = cpuMS()
            let result = try Native.invoke("owner_file", arguments)
            guard let encoded = result["wire"] as? String, let wire = Data(base64Encoded: encoded), let measurement = result["measurement"] as? [String: Any] else { throw AuditError.message("Owner Store failed") }
            let uploadStart = monotonicMS(); try await post("/owner/file", endpoint: endpoint, body: wire, token: token, session: session); let upload = monotonicMS()-uploadStart
            rows.append(StoreRecord(scheme: scheme, files: m, fileIndex: index, chunks: n, sectors: s, challengedChunks: c, inputKind: imports.isEmpty ? "canonical synthetic sectors" : "imported file bytes (31-byte sectors)", dataMS: measurement["data_ms"] as? Double ?? 0, storeMS: measurement["store_ms"] as? Double ?? 0, encodeMS: measurement["encode_ms"] as? Double ?? 0, uploadMS: upload, endToEndMS: monotonicMS()-start, cpuMS: cpuMS()-cpu, peakFootprintBytes: peak.stop(), encodedDataBytes: measurement["encoded_data_bytes"] as? Int ?? 0, uploadBodyBytes: wire.count, setupMS: index == 0 ? begin["setup_ms"] as? Double ?? 0 : 0, thermalState: ProcessInfo.processInfo.thermalState.rawValue))
        }
        let end = try Native.invoke("owner_finish")
        guard let encoded = end["envelope"] as? String, let final = Data(base64Encoded: encoded), let digest = end["registry_digest"] as? String else { throw AuditError.message("Missing owner registry") }
        try await post("/owner/finish", endpoint: endpoint, body: final, token: token, session: session)
        return (Collection(scheme: scheme, files: m, chunks: n, sectors: s, challengedChunks: c, digest: digest, ownerKey: key), rows)
    }

    nonisolated private static func save(_ rows: [AuditRecord], stores: [StoreRecord], endpoint: String, repeats: Int, warmups: Int, failure: String? = nil) throws -> URL {
        var system = utsname(); uname(&system)
        let model = withUnsafePointer(to: &system.machine) { pointer in pointer.withMemoryRebound(to: CChar.self, capacity: 256) { String(cString: $0) } }
        let output = RunMetadata(model: model, operatingSystem: ProcessInfo.processInfo.operatingSystemVersionString, timestamp: ISO8601DateFormatter().string(from: Date()), baseURL: endpoint, samplesPerConfiguration: repeats, warmupsPerConfiguration: warmups, failureReason: failure, stores: stores, records: rows)
        let directory = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let url = directory.appendingPathComponent("multiaudit-results.json")
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(output).write(to: url, options: .atomic)
        return url
    }
}

struct ContentView: View {
    @StateObject private var model = AuditModel()
    @State private var choosingFiles = false
    private let blue = Color(red: 0.12, green: 0.30, blue: 0.62)
    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    HStack(spacing: 14) {
                        Image(systemName: "checkmark.shield.fill").font(.system(size: 36)).foregroundStyle(blue)
                        VStack(alignment: .leading) { Text("Your files. Your control.").font(.title2.bold()); Text("Owner Store · Cloud ProofGen · Optional Verify").font(.caption).foregroundStyle(.secondary) }
                    }.padding(.vertical, 8)
                    GroupBox("Cloud connection") {
                        VStack(spacing: 12) {
                            TextField("Proof server address", text: $model.server).textInputAutocapitalization(.never).keyboardType(.URL)
                            Divider()
                            SecureField("Experiment account token", text: $model.accountToken).textInputAutocapitalization(.never).autocorrectionDisabled()
                        }.padding(.vertical, 6)
                    }
                    GroupBox("Owner file collection") {
                        VStack(alignment: .leading, spacing: 10) {
                            Picker("Protocol", selection: $model.scheme) { ForEach(["MultiAudit", "Xu", "Yu"], id: \.self) { Text($0) } }.pickerStyle(.segmented)
                            Button { choosingFiles = true } label: { Label("Import files", systemImage: "doc.badge.plus") }.disabled(model.running)
                            if model.importedFiles.isEmpty {
                                Picker("Synthetic files", selection: $model.files) { ForEach([1,10,20,30,40], id: \.self) { Text("\($0) × 10 MB").tag($0) } }
                                Text("Benchmark data: canonical field sectors.").font(.caption).foregroundStyle(.secondary)
                            } else {
                                ForEach(model.importedFiles, id: \.self) { Text($0.lastPathComponent).font(.caption).lineLimit(1) }
                                Button("Use benchmark files") { model.importedFiles = [] }
                            }
                            Button { model.run(storeOnly: true) } label: { Label("Store and upload", systemImage: "icloud.and.arrow.up").frame(maxWidth: .infinity) }.buttonStyle(.borderedProminent).tint(blue).disabled(model.running)
                        }
                    }
                    GroupBox("Integrity audit") {
                        VStack(spacing: 14) {
                            Toggle("Verify response on this iPhone", isOn: $model.verifyLocally)
                            Button { model.run() } label: { Label("Request audit", systemImage: "arrow.triangle.2.circlepath").frame(maxWidth: .infinity) }.buttonStyle(.bordered).disabled(model.running)
                            Text("ProofGen runs in the cloud. A response is marked verified only after the optional local check succeeds.").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    HStack { if model.running { ProgressView() }; Text(model.status).font(.subheadline).accessibilityIdentifier("auditStatus") }
                    if let last = model.records.last {
                        HStack { stat("Local check", last.verificationPerformed ? (last.accepted ? "Passed" : "Rejected") : "Skipped"); Spacer(); stat("Received", String(format: "%.2f MB", Double(last.downloadBodyBytes)/1e6)); Spacer(); stat("Verify", last.verificationPerformed ? String(format: "%.1f ms", last.verifyMS) : "—") }.padding().background(blue.opacity(0.07), in: RoundedRectangle(cornerRadius: 14))
                    }
                    if !model.registry.isEmpty { VStack(alignment: .leading, spacing: 6) { Text("Owner-signed registry").font(.subheadline.bold()); Text(model.registry).font(.system(.caption2, design: .monospaced)).textSelection(.enabled) } }
                    if let url = model.exportURL { ShareLink(item: url) { Label("Export measurements", systemImage: "square.and.arrow.up") } }
                    Text("Research prototype. Store executes on the phone; only data, tags and public metadata are uploaded. Auditing does not provide data encryption.").font(.caption).foregroundStyle(.secondary)
                }.padding(22)
            }.navigationTitle("MultiAudit").background(Color(.systemGroupedBackground)).task { model.startAutomaticIfRequested() }
            .fileImporter(isPresented: $choosingFiles, allowedContentTypes: [.data], allowsMultipleSelection: true) { model.importFiles($0) }
        }
    }
    private func stat(_ label: String, _ value: String) -> some View { VStack(alignment: .leading, spacing: 5) { Text(label).font(.caption).foregroundStyle(.secondary); Text(value).font(.subheadline.bold()) } }
}
@main struct MultiAuditApp: App { var body: some Scene { WindowGroup { ContentView() } } }
