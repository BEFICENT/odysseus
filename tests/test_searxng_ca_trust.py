"""Exercise removal using public X.509 certificates, without network access."""

import importlib.util
import json
import re
import hashlib
from pathlib import Path
import ssl
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("searxng_repair", ROOT / "docker/searxng/repair_trust.py")
repair = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repair)
INCIDENT = json.loads((ROOT / "tests/fixtures/ca-trust/incident.json").read_text())


class SearxngTrustTests(unittest.TestCase):
    def test_inventory_matches_all_published_fixture_ca_fingerprints(self):
        expected = set(INCIDENT["roots"]) | set(INCIDENT["intermediates"]) | set(INCIDENT["cross_signed_roots"])
        self.assertEqual(set(repair.BLOCKED), expected)
        self.assertEqual(len(expected), 21)
        for fingerprint in expected:
            self.assertEqual(hashlib.sha256(ssl.PEM_cert_to_DER_cert(INCIDENT["certificates"][fingerprint])).hexdigest(), fingerprint)

    def test_all_known_incident_certificates_are_removed_preserving_other_certificates(self):
        unaffected = (ROOT / "tests/fixtures/ca-trust/emsign-g1.txt").read_text()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bundle.pem"
            for fingerprint in repair.BLOCKED:
                with self.subTest(fingerprint=fingerprint):
                    path.write_text(INCIDENT["certificates"][fingerprint] + "\n" + unaffected)
                    self.assertEqual(repair.filter_bundle(path), 1)
                    self.assertEqual(path.read_text().strip(), unaffected.strip())
                    self.assertEqual(repair.check_bundle(path), 1)
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.load_verify_locations(cafile=str(path))
                    self.assertEqual(len(context.get_ca_certs()), 1)
                    self.assertEqual(repair.filter_bundle(path), 0)

    def test_system_source_is_deleted_so_regeneration_cannot_restore_it(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "root.crt"
            path.write_text(INCIDENT["certificates"][next(iter(repair.BLOCKED))])
            self.assertEqual(repair.filter_bundle(path, allow_empty=True), 1)
            self.assertFalse(path.exists())

    def test_bundle_cannot_be_emptied(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bundle.pem"
            original = INCIDENT["certificates"][next(iter(repair.BLOCKED))]
            path.write_text(original)
            with self.assertRaisesRegex(ValueError, "refusing to empty"):
                repair.filter_bundle(path)
            self.assertEqual(path.read_text(), original)

    def test_derived_base_matches_every_compose_pin(self):
        # The overlay corrects whatever image Compose selects; a pin bump that
        # skips the derived Dockerfile would silently run the older base.
        base = re.search(r"^FROM (\S+) AS base$", (ROOT / "docker/searxng/Dockerfile").read_text(), re.M)
        self.assertIsNotNone(base)
        for name in ("docker-compose.yml", "docker-compose.gpu-amd.yml", "docker-compose.gpu-nvidia.yml"):
            with self.subTest(compose=name):
                pins = re.findall(r"image:\s*(\S*searxng/searxng:\S+)", (ROOT / name).read_text())
                self.assertEqual(pins, [base.group(1)])
        version = base.group(1).split(":", 1)[1].split("-", 1)[0]
        overlay = (ROOT / "docker/searxng/compose.yml").read_text()
        self.assertIn(f"image: localhost/odysseus-searxng:{version}-ca-trust", overlay)

    def test_empty_and_malformed_input_fail_closed(self):
        for text in ("", "not a certificate", "-----BEGIN CERTIFICATE-----\nbroken\n-----END CERTIFICATE-----"):
            with self.subTest(text=text), self.assertRaises((ValueError, OSError)):
                list(repair.certificates(text))


if __name__ == "__main__":
    unittest.main()
