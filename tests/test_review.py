import contextlib
import io
import json
from pathlib import Path
import os
import socket
import tempfile
import unittest
from unittest.mock import patch

from tls_profile_forge import generate
from tls_profile_forge.cli import main
from tls_profile_forge.generator import GUIDELINE_SHA256
from tls_profile_forge.output import write_new
from tls_profile_forge.versions import Version, parse_version


class Versions(unittest.TestCase):
    def test_numeric_lexical_trap(self):
        self.assertGreater(parse_version("1.10"), parse_version("1.9.99"))
        self.assertEqual(parse_version("18"), Version(18))

    def test_openssl_letters(self):
        versions = ["1.0.2", "1.0.2a", "1.0.2l", "1.0.2z", "1.0.3", "1.1.0"]
        self.assertEqual(
            sorted(versions, key=lambda v: parse_version(v, openssl=True)), versions
        )

    def test_unknown_versions(self):
        for v in (
            True,
            None,
            1,
            "",
            "1.02",
            "1.2.3.4",
            "v1.2.3",
            "1.2.3rc1",
            "1.2.3-a",
            " 1.2",
            "1.2\n",
            "10000",
            "1.0.2za",
            "3.0.0a",
        ):
            with self.subTest(v=v), self.assertRaises(ValueError):
                parse_version(v, openssl=True)
        with self.assertRaises(ValueError):
            parse_version("1.0.2a")


class Generation(unittest.TestCase):
    def test_full_matrix(self):
        services = {
            "nginx": ["1.19.3", "1.19.4", "1.28.2", "1.29"],
            "apache": ["2.4.35", "2.4.36", "2.4.66", "2.5"],
            "haproxy": ["2.1.99", "2.2", "2.8", "2.9", "3.0.29", "3.1"],
            "postgresql": ["11.99", "12", "17.6", "18", "18.1", "19"],
            "redis": ["5.9", "6", "7.4.9", "7.5"],
        }
        for service, versions in services.items():
            for version in versions:
                for openssl in ["1.1.1z", "3.0", "3.4.9", "3.5", "4.0.1", "4.1"]:
                    for profile in ("modern", "intermediate"):
                        with self.subTest(
                            service=service,
                            version=version,
                            openssl=openssl,
                            profile=profile,
                        ):
                            a, text = generate(service, version, openssl, profile)
                            b, repeated = generate(service, version, openssl, profile)
                            self.assertEqual((a, text), (b, repeated))
                            self.assertTrue(
                                all(x == "OPEN" for x in a["external"].values())
                            )
                            if text:
                                self.assertIn(GUIDELINE_SHA256, text)
                                self.assertNotIn("@SECLEVEL", text)
                                self.assertNotIn("curl", text)
                                self.assertNotIn("TLSv1.1", text)
                                self.assertEqual(
                                    a["policy"]["protocols"],
                                    ["TLSv1.3"]
                                    if profile == "modern"
                                    else ["TLSv1.2", "TLSv1.3"],
                                )
                                self.assertEqual(
                                    len(a["policy"]["tls12_ciphers"]),
                                    0 if profile == "modern" else 6,
                                )
                            else:
                                self.assertEqual(a["status"], "OPEN")
                                self.assertIsNone(a["configuration_sha256"])

    def test_nginx_protocol_and_independent_cipher_names(self):
        r, c = generate("nginx", "1.28", "3.5")
        self.assertEqual(r["status"], "PASS")
        self.assertIn("ssl_protocols TLSv1.2 TLSv1.3;", c)
        self.assertIn("ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:", c)
        self.assertIn("ssl_conf_command Ciphersuites TLS_AES_128_GCM_SHA256:", c)
        self.assertEqual(
            r["policy"]["tls12_iana"][0], "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        )
        self.assertNotIn("TLS_ECDHE_", c)

    def test_no_tls13_modern_fallback(self):
        r, text = generate("nginx", "1.13", "3.5", "modern")
        self.assertIsNone(text)
        self.assertEqual(r["status"], "OPEN")
        r, c = generate("apache", "2.4.36", "3.5", "modern")
        self.assertEqual(r["status"], "PASS")
        self.assertIn("SSLProtocol -all +TLSv1.3\n", c)
        self.assertNotIn("ECDHE-RSA-", c)

    def test_pq_adaptation_is_explicit(self):
        r, c = generate("apache", "2.4.66", "3.4")
        self.assertEqual(r["status"], "OPEN")
        self.assertEqual(r["adaptations"][0]["feature"], "X25519MLKEM768")
        self.assertNotIn("X25519MLKEM768", c)
        self.assertIn("X25519:prime256v1:secp384r1", c)

    def test_haproxy_both_endpoints_and_boundary(self):
        r, c = generate("haproxy", "2.8", "3.5")
        self.assertIn("haproxy_server_groups_require_2_9", r["issues"])
        self.assertIn("ssl-default-bind-curves", c)
        self.assertNotIn("ssl-default-server-curves", c)
        self.assertIsNone(r["policy"]["configured_groups"])
        self.assertIsNone(r["policy"]["endpoint_groups"]["server"])
        self.assertEqual(len(r["policy"]["endpoint_groups"]["bind"]), 4)
        r, c = generate("haproxy", "2.9", "3.5", "modern")
        self.assertEqual(r["status"], "PASS")
        self.assertIn("ssl-default-server-curves", c)
        self.assertEqual(c.count("ssl-min-ver TLSv1.3 ssl-max-ver TLSv1.3"), 2)

    def test_postgresql_new_and_old_features(self):
        old, c = generate("postgresql", "17.6", "3.5")
        self.assertEqual(old["status"], "OPEN")
        self.assertIsNone(old["policy"]["configured_groups"])
        self.assertNotIn("ssl_groups =", c)
        self.assertNotIn("ssl_tls13_ciphers =", c)
        r, c = generate("postgresql", "18.1", "3.5")
        self.assertEqual(r["status"], "PASS")
        self.assertIn("ssl_groups = 'X25519MLKEM768:X25519:prime256v1:secp384r1'", c)
        self.assertIn("ssl_tls13_ciphers = 'TLS_AES_128_GCM_SHA256:", c)

    def test_redis_unconfigurable_groups_and_plaintext_port(self):
        r, c = generate("redis", "7.4", "3.5")
        self.assertEqual(r["status"], "OPEN")
        self.assertIsNone(r["policy"]["configured_groups"])
        self.assertIn("port 0\n", c)
        self.assertIn("tls-ciphersuites TLS_AES_128_GCM_SHA256:", c)
        self.assertNotIn("ssl_groups", c)

    def test_untrusted_choices_not_rendered(self):
        secret = "PRIVATE_INJECTED\nssl_protocols TLSv1;"
        for args in [
            (secret, "1", "3.5", "modern"),
            ("nginx", secret, "3.5", "modern"),
            ("nginx", "1.28", secret, "modern"),
            ("nginx", "1.28", "3.5", secret),
            ([], "1", "3.5", "modern"),
            ("nginx", "1.28", "3.5", {}),
        ]:
            report, c = generate(*args)
            self.assertIsNone(c)
            self.assertNotIn("PRIVATE_INJECTED", json.dumps(report))

    def test_no_network(self):
        with patch.object(socket, "socket", side_effect=AssertionError("network")):
            self.assertEqual(generate("nginx", "1.28", "3.5")[0]["status"], "PASS")

    def test_fixed_data_integrity(self):
        class BadResource:
            def joinpath(self, unused):
                return self

            def read_bytes(self):
                return b"{}"

        with patch("tls_profile_forge.generator.files", return_value=BadResource()):
            r, c = generate("nginx", "1.28", "3.5")
        self.assertEqual(r["status"], "OPEN")
        self.assertIsNone(c)


class Output(unittest.TestCase):
    def test_new_file_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td).resolve() / "new.conf"
            write_new(str(path), "known\n")
            self.assertEqual(path.read_bytes(), b"known\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(OSError):
                write_new(str(path), "replacement")
            self.assertEqual(path.read_bytes(), b"known\n")

    def test_symlink_every_component(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            (root / "target").mkdir()
            (root / "link").symlink_to(root / "target", target_is_directory=True)
            with self.assertRaises(OSError):
                write_new(str(root / "link/new"), "known")
            (root / "leaf").symlink_to(root / "missing")
            with self.assertRaises(OSError):
                write_new(str(root / "leaf"), "known")
            self.assertEqual(list((root / "target").iterdir()), [])
            self.assertFalse((root / "missing").exists())

    def test_partial_write_and_failure_leaves_new_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = str(Path(td).resolve() / "new")
            real = os.write
            with patch(
                "tls_profile_forge.output.os.write",
                side_effect=lambda fd, data: real(fd, data[:1]),
            ):
                write_new(path, "whole")
            self.assertEqual(Path(path).read_text(), "whole")
            Path(path).unlink()
            with (
                patch(
                    "tls_profile_forge.output.os.write", side_effect=OSError("failure")
                ),
                self.assertRaises(OSError),
            ):
                write_new(path, "whole")
            self.assertTrue(Path(path).exists())
            self.assertEqual(Path(path).read_bytes(), b"")

    def test_failure_does_not_unlink_replacement(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td).resolve() / "new"

            def replace_then_fail(fd, raw):
                path.unlink()
                path.write_text("replacement")
                raise OSError("simulated")

            with (
                patch(
                    "tls_profile_forge.output.os.write", side_effect=replace_then_fail
                ),
                self.assertRaises(OSError),
            ):
                write_new(str(path), "ours")
            self.assertEqual(path.read_text(), "replacement")

    def test_path_budgets_and_traversal(self):
        for path, text in [
            ("", "x"),
            ("a/../new", "x"),
            ("./new", "x"),
            ("/a//b", "x"),
            ("x\0", "x"),
            ("new", "x" * 65537),
            ("new", ""),
        ]:
            with self.assertRaises(ValueError):
                write_new(path, text)

    def test_cli_pass_open_errors(self):
        with tempfile.TemporaryDirectory() as td:
            for index, service in enumerate(("nginx", "redis", "invalid")):
                out = str(Path(td).resolve() / str(index))
                captured = io.StringIO()
                with contextlib.redirect_stdout(captured):
                    rc = main(
                        [
                            "--service",
                            service,
                            "--version",
                            "1.28" if service == "nginx" else "7.4",
                            "--openssl",
                            "3.5",
                            "--out",
                            out,
                        ]
                    )
                report = json.loads(captured.getvalue())
                self.assertEqual(rc, 0 if service == "nginx" else 2)
                self.assertEqual(report["output_created"], service != "invalid")
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                self.assertEqual(main(["--PRIVATE_INJECTED"]), 2)
            self.assertNotIn("PRIVATE_INJECTED", captured.getvalue())


if __name__ == "__main__":
    unittest.main()
