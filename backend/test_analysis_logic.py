import unittest
import tempfile
from pathlib import Path

from scapy.all import IP, Raw, TCP

from backend.main import analyze_pcap, build_findings_and_risk, risk_label_for_score


def server_hello(version, cipher_id):
    body = version.to_bytes(2, "big") + bytes(range(32)) + b"\x00" + cipher_id.to_bytes(2, "big") + b"\x00"
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16" + version.to_bytes(2, "big") + len(handshake).to_bytes(2, "big") + handshake


class AnalysisLogicTests(unittest.TestCase):
    def test_risk_label_thresholds(self):
        self.assertEqual(risk_label_for_score(100), "LOW RISK")
        self.assertEqual(risk_label_for_score(65), "MEDIUM RISK")
        self.assertEqual(risk_label_for_score(35), "HIGH RISK")

    def test_findings_reduce_score_and_raise_high_risk(self):
        sessions = [
            {
                "id": 1,
                "protocol": "SMTP",
                "tls_version": "1.0",
                "cipher": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
                "forward_secrecy": False,
                "starttls": "NO",
                "smtp_auth_without_tls": True,
                "certificates": [{"status": "WEAK"}],
                "anomaly": True,
                "plaintext": True,
            }
        ]
        result = build_findings_and_risk(sessions)
        self.assertGreaterEqual(len(result["findings"]), 1)
        self.assertGreater(result["high_count"], 0)
        self.assertLess(result["posture_score"], 100)
        self.assertEqual(result["risk"], "HIGH RISK")
        self.assertTrue(all(f.get("recommendation") for f in result["findings"]))

    def test_empty_capture_has_no_low_risk_score(self):
        result = build_findings_and_risk([])
        self.assertEqual(result["posture_score"], 0)
        self.assertEqual(result["risk"], "HIGH RISK")

    def test_interleaved_directions_preserve_tls_evidence(self):
        packets = [
            IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=41000, dport=25, flags="PA", seq=1, ack=1) / Raw(load=b"client prefix"),
            IP(src="10.0.0.20", dst="10.0.0.10") / TCP(sport=25, dport=41000, flags="PA", seq=900, ack=1) / Raw(load=server_hello(0x0301, 0x000A)),
        ]
        from scapy.utils import wrpcap

        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as capture:
            capture_path = Path(capture.name)
        try:
            wrpcap(str(capture_path), packets)
            result = analyze_pcap(capture_path.read_bytes())
        finally:
            capture_path.unlink(missing_ok=True)
        session = result["sessions"][0]
        self.assertEqual(session["tls_version"], "1.0")
        self.assertEqual(session["cipher"], "TLS_RSA_WITH_3DES_EDE_CBC_SHA")
        self.assertEqual(result["summary"]["tls_versions"]["1.0"], 1)


if __name__ == "__main__":
    unittest.main()
