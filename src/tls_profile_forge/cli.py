import argparse
import json

from .generator import generate
from .output import write_new


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("arguments")


def main(argv=None):
    p = Parser(
        description="Generate an offline TLS configuration draft and JSON evidence."
    )
    for option in ("service", "version", "openssl", "out"):
        p.add_argument("--" + option, required=True)
    p.add_argument("--profile", default="intermediate")
    try:
        args = p.parse_args(argv)
        report, text = generate(args.service, args.version, args.openssl, args.profile)
        report["output_created"] = False
        report["output_path_identity"] = "OPEN"
        if text is not None:
            write_new(args.out, text)
            report["output_created"] = True
    except (ValueError, OSError, UnicodeError):
        report = {
            "schema_version": "1",
            "status": "OPEN",
            "issues": ["arguments_or_output_error"],
            "output_created": False,
            "output_file_may_exist": True,
            "output_path_identity": "OPEN",
            "external_claims": "OPEN",
        }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "PASS" else 2
