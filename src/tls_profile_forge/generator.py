"""Finite, deterministic TLSRef 6.0 template adaptation, without service access."""

from hashlib import sha256
from importlib.resources import files
import json

from .versions import Version, parse_version

GUIDELINE_SHA256 = "d687ec847524adbba61d46be40182f6cafdd72d8d3720a53b6dfb982acb5c228"
RULE_VERSION = "tls-profile-forge-1"
# Capability bounds, not support-lifecycle assertions or binary observations.
WINDOWS = {
    "nginx": (Version(1, 19, 4), (1, 28)),
    "apache": (Version(2, 4, 36), (2, 4)),
    "haproxy": (Version(2, 2), (3, 0)),
    "postgresql": (Version(12), (18, 9999)),
    "redis": (Version(6), (7, 4)),
}


def _guideline():
    raw = files("tls_profile_forge").joinpath("data/guideline-6.0.json").read_bytes()
    if len(raw) != 3135 or sha256(raw).hexdigest() != GUIDELINE_SHA256:
        raise ValueError("guideline_integrity")
    data = json.loads(raw)
    if data["version"] != 6 or set(data["configurations"]) != {
        "modern",
        "intermediate",
    }:
        raise ValueError("guideline_schema")
    return data


def _report():
    return {
        "schema_version": "1",
        "status": "OPEN",
        "rule_version": RULE_VERSION,
        "guideline": {
            "version": "6.0",
            "sha256": GUIDELINE_SHA256,
            "source_commit": "27fecb740fd3e7bbdd2ec04ae75d60177f309f8d",
        },
        "issues": [],
        "adaptations": [],
        "configuration_sha256": None,
        "external": {
            "linked_library_identity": "OPEN",
            "service_build_capabilities": "OPEN",
            "certificate_policy": "OPEN",
            "full_guideline_compliance": "OPEN",
            "syntax_on_caller_binary": "OPEN",
            "actual_handshake": "OPEN",
            "deployment_security": "OPEN",
            "cvp_eligibility": "OPEN",
        },
    }


def generate(service, version, openssl_version, profile="intermediate"):
    """Return (JSON-serializable report, draft text or None); never apply config."""
    report = _report()
    if not isinstance(service, str) or service not in WINDOWS:
        report["issues"].append("unsupported_service")
        return report, None
    if not isinstance(profile, str) or profile not in {"modern", "intermediate"}:
        report["issues"].append("unsupported_profile")
        return report, None
    try:
        sv = parse_version(version)
        ov = parse_version(openssl_version, openssl=True)
        guideline = _guideline()["configurations"][profile]
    except (ValueError, OSError, KeyError, TypeError, UnicodeError):
        report["issues"].append("invalid_version_or_guideline")
        return report, None
    low, high = WINDOWS[service]
    # One-component PostgreSQL versions 12..18 normalize to major.0.0.
    if sv < low or (sv.major, sv.minor) > high:
        report["issues"].append("service_outside_capability_window")
        return report, None
    if ov < Version(3) or (ov.major, ov.minor) > (4, 0):
        report["issues"].append("openssl_outside_capability_window")
        return report, None
    report.update(
        service=service,
        service_version=sv.text(),
        openssl_version=ov.text(),
        profile=profile,
    )
    protocols = list(guideline["tls_versions"])
    curves = list(guideline["tls_curves"])
    if ov < Version(3, 5):
        curves.remove("X25519MLKEM768")
        report["adaptations"].append(
            {
                "feature": "X25519MLKEM768",
                "reason": "requires_openssl_3_5",
                "status": "OPEN",
            }
        )
    ciphers = list(guideline["ciphers"]["openssl"])
    report["policy"] = {
        "protocols": protocols,
        "tls12_ciphers": ciphers,
        "tls12_iana": list(guideline["ciphers"]["iana"]),
        "tls13_ciphersuites": list(guideline["ciphersuites"]),
        "configured_groups": curves,
        "server_preferred_order": False,
    }
    cs, tls13, groups = (
        ":".join(ciphers),
        ":".join(guideline["ciphersuites"]),
        ":".join(curves),
    )
    minimum = protocols[0]
    lines = [
        f"# TLSProfileForge {RULE_VERSION}; TLSRef 6.0 sha256={GUIDELINE_SHA256}",
        f"# draft for {service} {sv.text()}, asserted OpenSSL {ov.text()}, {profile}",
        "# Replace certificate placeholders and review surrounding config; deployment is unverified.",
    ]
    if service == "nginx":
        lines += [
            "http {",
            "    ssl_protocols " + " ".join(protocols) + ";",
            "    ssl_ecdh_curve " + groups + ";",
            "    ssl_conf_command Ciphersuites " + tls13 + ";",
            "    ssl_prefer_server_ciphers off;",
            "    server {",
            "        listen 443 ssl;",
            "        ssl_certificate /path/to/cert.pem;",
            "        ssl_certificate_key /path/to/key.pem;",
            "    }",
            "}",
        ]
        if cs:
            lines.insert(4, "    ssl_ciphers " + cs + ";")
    elif service == "apache":
        lines += [
            "SSLProtocol -all +" + " +".join(protocols),
            "SSLOpenSSLConfCmd Curves " + groups,
            "SSLCipherSuite TLSv1.3 " + tls13,
            "SSLHonorCipherOrder off",
            "<VirtualHost *:443>",
            "    SSLEngine on",
            "    SSLCertificateFile /path/to/cert.pem",
            "    SSLCertificateKeyFile /path/to/key.pem",
            "</VirtualHost>",
        ]
        if cs:
            lines.insert(4, "SSLCipherSuite " + cs)
    elif service == "haproxy":
        lines += ["global"]
        for endpoint in ("bind", "server"):
            prefix = "    ssl-default-" + endpoint + "-"
            if cs:
                lines.append(prefix + "ciphers " + cs)
            lines.append(prefix + "ciphersuites " + tls13)
            if endpoint == "bind" or sv >= Version(2, 9):
                lines.append(prefix + "curves " + groups)
            else:
                report["issues"].append("haproxy_server_groups_require_2_9")
            options = "ssl-min-ver " + minimum + " ssl-max-ver TLSv1.3 no-tls-tickets"
            if endpoint == "bind":
                options += " prefer-client-ciphers"
            lines.append(prefix + "options " + options)
        lines += [
            "defaults",
            "    mode tcp",
            "    timeout connect 5s",
            "    timeout client 30s",
            "    timeout server 30s",
            "frontend tls_frontend",
            "    bind :443 ssl crt /path/to/cert-and-key.pem",
        ]
    elif service == "postgresql":
        lines += [
            "ssl = on",
            "ssl_cert_file = '/path/to/cert.pem'",
            "ssl_key_file = '/path/to/key.pem'",
            "ssl_min_protocol_version = '" + minimum + "'",
            "ssl_max_protocol_version = 'TLSv1.3'",
            "ssl_prefer_server_ciphers = off",
        ]
        if cs:
            lines.append("ssl_ciphers = '" + cs + "'")
        if sv >= Version(18):
            lines += [
                "ssl_groups = '" + groups + "'",
                "ssl_tls13_ciphers = '" + tls13 + "'",
            ]
        else:
            report["issues"] += [
                "postgresql_groups_require_18",
                "postgresql_tls13_ciphers_require_18",
            ]
    else:
        lines += [
            "port 0",
            "tls-port 6379",
            "tls-cert-file /path/to/cert.pem",
            "tls-key-file /path/to/key.pem",
            "tls-ca-cert-file /path/to/ca.pem",
            'tls-protocols "' + " ".join(protocols) + '"',
            "tls-prefer-server-ciphers no",
            "tls-ciphersuites " + tls13,
        ]
        if cs:
            lines.append("tls-ciphers " + cs)
        report["issues"].append("redis_group_selection_not_exposed")
    # Requested groups are not represented as configured if the template lacks a directive.
    if service == "redis" or (service == "postgresql" and sv < Version(18)):
        report["policy"]["configured_groups"] = None
        report["policy"]["requested_groups"] = curves
    if service == "haproxy":
        report["policy"]["endpoint_groups"] = {
            "bind": curves,
            "server": curves if sv >= Version(2, 9) else None,
        }
        if sv < Version(2, 9):
            report["policy"]["configured_groups"] = None
            report["policy"]["requested_groups"] = curves
    config = "\n".join(lines) + "\n"
    report["configuration_sha256"] = sha256(config.encode()).hexdigest()
    report["configuration_bytes"] = len(config.encode())
    report["status"] = "OPEN" if report["issues"] or report["adaptations"] else "PASS"
    return report, config
