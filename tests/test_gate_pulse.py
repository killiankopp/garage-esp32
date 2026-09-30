"""Execute the production pulse handler with native boundary doubles.

The firmware build validates the complete Arduino translation unit. This small
harness tests the handler itself without Wi-Fi, JWT servers or physical GPIO.
"""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


class GatePulseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("c++")
        if compiler is None:
            raise RuntimeError("A C++ compiler is required for the pulse regression")
        source = (
            Path(__file__).parents[1] / "src/components/WebServerHandler.cpp"
        ).read_text()
        marker = "void WebServerHandler::handleGatePulse()"
        if source.count(marker) != 1:
            raise RuntimeError("Expected one production pulse handler")
        body = source.split(marker, 1)[1].split("\nvoid WebServerHandler::", 1)[0]
        cls.directory = tempfile.TemporaryDirectory()
        directory = Path(cls.directory.name)
        harness = directory / "pulse.cpp"
        harness.write_text(
            """
#include <cassert>
#include <string>
struct GateController {
    int pulses = 0;
    std::string observed;
    void triggerRelay() { ++pulses; }
};
struct WebServerHandler {
    GateController* _gateController;
    bool allowed;
    int status = 0;
    int logs = 0;
    bool loggedAuthorization = false;
    std::string reported;
    bool requireAuthentication() {
        if (!allowed) status = 401;
        return allowed;
    }
    void logGateAction(const char* action, bool authorized) {
        assert(std::string(action) == "pulse");
        ++logs;
        loggedAuthorization = authorized;
    }
    void handleGateStatus() {
        status = 200;
        reported = _gateController->observed;
    }
    void handleGatePulse();
};
void WebServerHandler::handleGatePulse()
"""
            + body
            + """
int main(int argc, char** argv) {
    assert(argc == 3);
    GateController controller;
    controller.observed = argv[2];
    bool authorized = std::string(argv[1]) == "allow";
    WebServerHandler server{&controller, authorized};
    server.handleGatePulse();
    assert(controller.pulses == (authorized ? 1 : 0));
    assert(server.logs == 1);
    assert(server.loggedAuthorization == authorized);
    assert(server.status == (authorized ? 200 : 401));
    assert(controller.observed == argv[2]);
    assert(server.reported == (authorized ? argv[2] : ""));
}
"""
        )
        cls.binary = directory / "pulse"
        subprocess.run(
            [compiler, "-std=c++17", str(harness), "-o", str(cls.binary)], check=True
        )

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_rejected_authentication_never_pulses_or_overwrites_unauthorized(self):
        subprocess.run([str(self.binary), "deny", "closed"], check=True)

    def test_authorized_pulse_reports_observed_state_without_inferring_direction(self):
        for state in ["closed", "open", "unknown"]:
            with self.subTest(state=state):
                subprocess.run([str(self.binary), "allow", state], check=True)


if __name__ == "__main__":
    unittest.main()
