import FarvaterChaos
import XCTest

/// Each scenario starts the real core against in-process paths behind
/// fault-injecting proxies (devtest/chaos) and checks what the user would see.
final class ChaosTests: XCTestCase {
    func testScenarios() {
        let only = ProcessInfo.processInfo.environment["CHAOS"].flatMap { $0.isEmpty ? nil : $0 }
        let names = (only ?? ChaosScenarios()).split(separator: ",").map(String.init)
        for name in names {
            let json = ChaosRun(name)
            print("CHAOS-RESULT \(json)")
            let obj = (try? JSONSerialization.jsonObject(with: Data(json.utf8))) as? [String: Any]
            XCTAssertEqual(obj?["pass"] as? Bool, true, "\(name): \(json)")
        }
    }
}
