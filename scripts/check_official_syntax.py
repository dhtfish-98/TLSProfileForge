"""Development validation of fixed drafts; never enter a service event loop.

This tool executes trusted, locally built official checkers. It is separate
from the offline public API. All certificates and scaffolding are temporary.
Redis's additional test-only driver calls unchanged official TLS setup code.
"""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import grp
import platform
import pwd
import subprocess
import tempfile

from tls_profile_forge import generate


VERSIONS = {
    "nginx": "1.28.0",
    "apache": "2.4.67",
    "haproxy": "3.0.10",
    "postgresql": "18.1",
    "redis": "7.4.1",
}
REDIS_STOP = "tls-profile-forge-parse-stop 1"
REDIS_PASS = "TLSProfileForge Redis TLS validation PASS before initServer"


def invoke(argv, temporary, build):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=30)
    def clean(text):
        return text.replace(str(temporary), "<temporary>").replace(str(build), "<build>")
    return {"exit": result.returncode, "stdout": clean(result.stdout),
            "stderr": clean(result.stderr)}


def scaffold(service, draft, p, build):
    """Substitute only synthetic certificate paths and checker surroundings."""
    text = draft.replace("/path/to/cert-and-key.pem", str(p / "combined.pem"))
    for name in ("cert", "key", "ca"):
        text = text.replace("/path/to/" + name + ".pem", str(p / (name + ".pem")))
    if service == "nginx":
        # Native -t can briefly bind/listen. Restrict that to an owned Unix path.
        text = text.replace("listen 443 ssl;", "listen unix:" + str(p / "nginx.sock") + " ssl;")
        text = "pid " + str(p / "nginx.pid") + ";\nerror_log stderr;\nevents {}\n" + text
    elif service == "apache":
        modules = build / "prefix/apache/modules"
        group = grp.getgrgid(pwd.getpwnam("nobody").pw_gid).gr_name
        text = "\n".join((
            'ServerRoot "' + str(p) + '"', "ServerName localhost",
            'PidFile "' + str(p / "apache.pid") + '"',
            'ErrorLog "' + str(p / "apache.log") + '"',
            'LoadModule unixd_module "' + str(modules / "mod_unixd.so") + '"',
            'LoadModule ssl_module "' + str(modules / "mod_ssl.so") + '"',
            'LoadModule socache_shmcb_module "' + str(modules / "mod_socache_shmcb.so") + '"',
            "Listen 127.0.0.1:18443", "User nobody", "Group " + group, "")) + text
    elif service == "redis":
        # This external override is a second guard; it is outside the draft.
        # The parser-stop and TLS driver already exit before any listener setup.
        text += "bind 127.0.0.1\ntls-port 0\ndaemonize no\nsave \"\"\nappendonly no\n"
    return text


def check(build, openssl):
    build, openssl = Path(build).resolve(), Path(openssl).resolve()
    binaries = {
        "nginx": build / "prefix/nginx/sbin/nginx",
        "apache": build / "prefix/apache/bin/httpd",
        "haproxy": build / "sources/haproxy-3.0.10/haproxy",
        "postgresql": build / "prefix/postgresql/bin/postgres",
        "redis": build / "prefix/redis/redis-server",
        "redis_tls_harness": build / "prefix/redis/redis-tls-harness",
    }
    record = {"schema_version": 1, "syntax_checks": [], "controls": [],
              "service_event_loop_started": False, "service_configuration_applied": False,
              "actual_handshake": "OPEN", "cvp_eligibility": "OPEN",
              "meaning": "Selected syntax on these exact builds; Redis TLS driver is not native dry-run."}
    record["binaries"] = {name: {"path": str(path.relative_to(build)),
        "sha256": sha256(path.read_bytes()).hexdigest()} for name, path in binaries.items()}
    with tempfile.TemporaryDirectory(prefix="tlsforge-official-") as temp:
        p = Path(temp).resolve()
        (p / "logs").mkdir()
        record["openssl"] = invoke([str(openssl), "version", "-a"], p, build)
        if record["openssl"]["exit"] != 0:
            raise RuntimeError("openssl_identity_unavailable")
        version = record["openssl"]["stdout"].split()[1]
        identity_args = {"nginx": ["-V"], "apache": ["-V"], "haproxy": ["-vv"],
                         "postgresql": ["--version"], "redis": ["--version"],
                         "redis_tls_harness": ["--version"]}
        record["version_observations"] = {
            name: invoke([str(path)] + identity_args[name], p, build)
            for name, path in binaries.items()}
        for name, observation in record["version_observations"].items():
            expected = VERSIONS["redis" if name == "redis_tls_harness" else name]
            if observation["exit"] != 0 or expected not in observation["stdout"] + observation["stderr"]:
                raise RuntimeError("checker_version_identity_mismatch")
        command = "otool" if platform.system() == "Darwin" else "ldd"
        targets = dict(binaries, apache_ssl_module=build / "prefix/apache/modules/mod_ssl.so")
        record["library_link_observations"] = {
            name: invoke([command] + (["-L"] if command == "otool" else []) + [str(path)], p, build)
            for name, path in targets.items()}
        result = invoke([str(openssl), "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "1", "-subj", "/CN=localhost", "-keyout", str(p / "key.pem"),
            "-out", str(p / "cert.pem")], p, build)
        if result["exit"] != 0:
            raise RuntimeError("synthetic_certificate_creation_failed")
        (p / "ca.pem").write_bytes((p / "cert.pem").read_bytes())
        (p / "combined.pem").write_bytes((p / "key.pem").read_bytes() + (p / "cert.pem").read_bytes())
        (p / "combined.pem").chmod(0o600)
        (p / "invalid-cert.pem").write_text("-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n")
        result = invoke([str(openssl), "genrsa", "-out", str(p / "wrong-key.pem"), "2048"], p, build)
        if result["exit"] != 0:
            raise RuntimeError("synthetic_negative_key_creation_failed")
        for service, sv in VERSIONS.items():
            for profile in ("modern", "intermediate"):
                report, draft = generate(service, sv, version, profile)
                if draft is None:
                    raise RuntimeError("fixed_validation_draft_unavailable")
                text = scaffold(service, draft, p, build)
                config = p / (service + ".conf")
                config.write_text(text)
                def run_config(mode="syntax"):
                    if service == "nginx":
                        argv = [str(binaries[service]), "-t", "-p", str(p) + "/", "-c", str(config)]
                    elif service == "apache":
                        argv = [str(binaries[service]), "-t", "-f", str(config)]
                    elif service == "haproxy":
                        argv = [str(binaries[service]), "-c", "-f", str(config)]
                    elif service == "postgresql":
                        argv = [str(binaries[service]), "-D", str(p), "-c", "config_file=" + str(config), "-C", "ssl"]
                    else:
                        key = "redis_tls_harness" if mode == "tls_driver" else "redis"
                        argv = [str(binaries[key]), str(config)]
                    return invoke(argv, p, build)
                modes = ("parser_prefix", "tls_driver") if service == "redis" else ("syntax",)
                for mode in modes:
                    config.write_text(text + (REDIS_STOP + "\n" if mode == "parser_prefix" else ""))
                    result = run_config(mode)
                    if mode == "parser_prefix":
                        line = len(text.splitlines()) + 1
                        passed = result["exit"] == 1 and (">>> '" + REDIS_STOP + "'") in result["stderr"] and (
                            "at line " + str(line) + "\n") in result["stderr"] and "Bad directive or wrong number of arguments" in result["stderr"]
                    elif mode == "tls_driver":
                        passed = result["exit"] == 0 and REDIS_PASS in result["stdout"]
                    else:
                        passed = result["exit"] == 0
                    record["syntax_checks"].append({"service": service, "service_version": sv,
                        "openssl_assertion": version, "profile": profile, "mode": mode,
                        "draft_status": report["status"], "draft_sha256": sha256(draft.encode()).hexdigest(),
                        "checked_sha256": sha256(config.read_bytes()).hexdigest(),
                        "status": "PASS" if passed else "OPEN", **result})
                # A bad selected protocol tests actual argument validation.
                if service == "postgresql":
                    bad = text.replace("ssl_min_protocol_version = 'TLSv1.", "ssl_min_protocol_version = 'INVALID.")
                elif service == "redis":
                    bad = text.replace('tls-protocols "', 'tls-protocols "INVALID ')
                elif service == "nginx":
                    bad = text.replace("ssl_protocols ", "ssl_protocols INVALID ")
                elif service == "apache":
                    bad = text.replace("SSLProtocol -all", "SSLProtocol INVALID -all")
                else:
                    bad = text.replace("ssl-min-ver TLS", "ssl-min-ver INVALID")
                config.write_text(bad)
                result = run_config("tls_driver" if service == "redis" else "syntax")
                message = {
                    "nginx": 'invalid value "INVALID"',
                    "apache": "Illegal protocol 'INVALID'",
                    "haproxy": "unknown ssl/tls version",
                    "postgresql": 'invalid value for parameter "ssl_min_protocol_version"',
                    "redis": "Invalid tls-protocols specified",
                }[service]
                record["controls"].append({"service": service, "profile": profile,
                    "case": "invalid_protocol", "status": "PASS" if result["exit"] == 1 and message in
                    result["stdout"] + result["stderr"] else "FAIL", **result})
                if service == "redis":
                    controls = [("invalid_tls13_suite", text, "Failed to configure ciphersuites"),
                                ("invalid_certificate", text.replace(str(p / "cert.pem"), str(p / "invalid-cert.pem")), "Failed to load certificate"),
                                ("mismatched_key", text.replace(str(p / "key.pem"), str(p / "wrong-key.pem")), "Failed to load private key")]
                    if profile == "intermediate":
                        controls.append(("invalid_tls12_cipher", text, "Failed to configure ciphers"))
                    for label, bad, message in controls:
                        # A mixed unknown + valid cipher list may be accepted by
                        # OpenSSL. Require an entirely invalid suite expression.
                        if label == "invalid_tls13_suite":
                            bad = "\n".join("tls-ciphersuites INVALID" if line.startswith("tls-ciphersuites ") else line
                                            for line in text.splitlines()) + "\n"
                        elif label == "invalid_tls12_cipher":
                            bad = "\n".join("tls-ciphers INVALID" if line.startswith("tls-ciphers ") else line
                                            for line in text.splitlines()) + "\n"
                        config.write_text(bad)
                        result = run_config("tls_driver")
                        record["controls"].append({"service": service, "profile": profile,
                            "case": label, "status": "PASS" if result["exit"] == 1 and message in result["stdout"]
                            and "TLSProfileForge Redis TLS validation FAILED before initServer" in result["stderr"]
                            and REDIS_PASS not in result["stdout"] else "FAIL", **result})
    record["status"] = "PASS" if all(x["status"] == "PASS" for x in record["syntax_checks"] + record["controls"]) else "OPEN"
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", required=True, help="trusted fixed local checker build directory")
    parser.add_argument("--openssl", required=True, help="trusted OpenSSL executable matching the local checker development library")
    args = parser.parse_args()
    record = check(args.build, args.openssl)
    print(json.dumps(record, indent=2))
    return 0 if record["status"] == "PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
