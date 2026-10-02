"""Build fixed upstream checkers in a fresh local directory, without services.

Development-only Python 3.14 tooling. Requires a trusted existing OpenSSL
development prefix, PCRE2 and Expat development files, C compiler and make.
Downloads, sources, binaries and logs stay in the requested build directory.
Nothing is installed to the system and no service is started or signaled.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import time
from urllib.request import urlopen


SCRIPT = Path(__file__).resolve().parent
REDIS_ANCHOR = "    if (server.sentinel_mode) sentinelCheckConfigFile();\n"
# This Redis-only driver/patch is offered under RSALv2 OR SSPLv1, as
# selected by the fixed Redis 7.4.1 source. Other tooling is MPL-2.0.
REDIS_DRIVER = """    /* TLSProfileForge test-only driver: no initServer/listener/event loop. */
    if (connTypeConfigure(connectionTypeTls(), &server.tls_ctx_config, 1) == C_ERR) {
        fprintf(stderr, "TLSProfileForge Redis TLS validation FAILED before initServer\\n");
        exit(1);
    }
    fprintf(stdout, "TLSProfileForge Redis TLS validation PASS before initServer\\n");
    exit(0);
"""
REDIS_ORIGINAL = "4d8edc7646d68b292928c34e411bb1be176be50d900f867fff10a6e09ee37d8a"
REDIS_PATCHED = "8de01dc23c1e011dc125b10bb7f392b88d4b3ec0a21edee6f3403e5de502b231"


def build_checkers(root, openssl_prefix, pcre_config, archive_cache=None):
    root, ssl = Path(root).resolve(), Path(openssl_prefix).resolve()
    if platform.system() not in ("Darwin", "Linux"):
        raise RuntimeError("unsupported_build_platform")
    if root.exists() and any(root.iterdir()):
        raise RuntimeError("fresh_build_directory_required")
    root.mkdir(parents=True, exist_ok=True)
    for name in ("downloads", "sources", "prefix", "build-logs"):
        (root / name).mkdir()
    manifest = json.loads((SCRIPT / "checker-sources.json").read_text())
    def download(row):
        path = root / "downloads" / (row["name"] + ".tar.gz")
        cached = Path(archive_cache) / path.name if archive_cache else None
        if cached and cached.is_file():
            if cached.stat().st_size != row["bytes"]:
                raise RuntimeError("fixed_download_size_mismatch")
            shutil.copyfile(cached, path)
        else:
            with urlopen(row["url"], timeout=60) as response:
                raw = response.read(40_000_001)
            path.write_bytes(raw)
        raw = path.read_bytes()
        if len(raw) != row["bytes"] or sha256(raw).hexdigest() != row["sha256"]:
            raise RuntimeError("fixed_download_identity_mismatch")
        return path
    with ThreadPoolExecutor(max_workers=4) as pool:
        archives = list(pool.map(download, manifest["sources"]))
    # The fixed byte identities precede any extraction or source execution.
    for archive in archives:
        with tarfile.open(archive, "r:gz") as source:
            source.extractall(root / "sources", filter="data")
    src, prefix = root / "sources", root / "prefix"
    env = dict(os.environ, GIT_CEILING_DIRECTORIES=str(src), SOURCE_DATE_EPOCH="1")
    steps = []
    def run(label, argv, cwd):
        log = root / "build-logs" / (str(len(steps)) + "-" + label + ".log")
        started = time.monotonic()
        with log.open("w") as output:
            result = subprocess.run(argv, cwd=cwd, env=env, stdout=output,
                stderr=subprocess.STDOUT, timeout=900)
        steps.append({"label": label, "argv": argv, "cwd": str(cwd.relative_to(root)),
                      "log": str(log.relative_to(root)), "exit": result.returncode,
                      "seconds": round(time.monotonic() - started, 2)})
        (root / "builds.json").write_text(json.dumps(steps, indent=2) + "\n")
        if result.returncode:
            raise RuntimeError("checker_build_failed")
    def configure_make(label, directory, options):
        run(label + "-configure", ["./configure"] + options, directory)
        run(label + "-make", ["make", "-j4"], directory)
        run(label + "-install-local", ["make", "install"], directory)
    configure_make("nginx", src / "nginx-1.28.0", [
        "--prefix=" + str(prefix / "nginx"), "--without-http_rewrite_module",
        "--without-http_gzip_module", "--with-http_ssl_module",
        "--with-cc-opt=-I" + str(ssl / "include"),
        "--with-ld-opt=-L" + str(ssl / "lib") + " -Wl,-rpath," + str(ssl / "lib")])
    configure_make("apr", src / "apr-1.7.6", ["--prefix=" + str(prefix / "apr")])
    configure_make("apr-util", src / "apr-util-1.6.3", [
        "--prefix=" + str(prefix / "apr-util"), "--with-apr=" + str(prefix / "apr")])
    configure_make("apache", src / "httpd-2.4.67", [
        "--prefix=" + str(prefix / "apache"), "--with-apr=" + str(prefix / "apr/bin/apr-1-config"),
        "--with-apr-util=" + str(prefix / "apr-util/bin/apu-1-config"),
        "--with-pcre=" + str(Path(pcre_config).resolve()), "--enable-ssl",
        "--with-ssl=" + str(ssl), "--enable-so", "--with-mpm=prefork"])
    haproxy = src / "haproxy-3.0.10"
    run("haproxy", ["make", "-j4", "TARGET=" + ("osx" if platform.system() == "Darwin" else "linux-glibc"),
        "USE_OPENSSL=1", "SSL_INC=" + str(ssl / "include"), "SSL_LIB=" + str(ssl / "lib")], haproxy)
    configure_make("postgresql", src / "postgresql-18.1", [
        "--prefix=" + str(prefix / "postgresql"), "--without-icu", "--without-readline",
        "--without-zlib", "--with-ssl=openssl", "CPPFLAGS=-I" + str(ssl / "include"),
        "LDFLAGS=-L" + str(ssl / "lib")])
    redis = src / "redis-7.4.1"
    redis_args = ["make", "-j4", "BUILD_TLS=yes", "MALLOC=libc", "OPENSSL_PREFIX=" + str(ssl)]
    run("redis-official", redis_args, redis)
    (prefix / "redis").mkdir()
    shutil.copy2(redis / "src/redis-server", prefix / "redis/redis-server")
    server = redis / "src/server.c"
    original = server.read_bytes()
    if sha256(original).hexdigest() != REDIS_ORIGINAL or original.decode().count(REDIS_ANCHOR) != 1:
        raise RuntimeError("redis_driver_source_identity_mismatch")
    patched = original.decode().replace(REDIS_ANCHOR, REDIS_DRIVER + REDIS_ANCHOR).encode()
    if sha256(patched).hexdigest() != REDIS_PATCHED:
        raise RuntimeError("redis_driver_patch_identity_mismatch")
    server.write_bytes(patched)
    run("redis-tls-driver", redis_args, redis)
    shutil.copy2(redis / "src/redis-server", prefix / "redis/redis-tls-harness")
    license_paths = {
        "nginx": ["nginx-1.28.0/LICENSE"],
        "apache": ["httpd-2.4.67/LICENSE", "httpd-2.4.67/NOTICE"],
        "apr": ["apr-1.7.6/LICENSE", "apr-1.7.6/NOTICE"],
        "apr-util": ["apr-util-1.6.3/LICENSE", "apr-util-1.6.3/NOTICE"],
        "haproxy": ["haproxy-3.0.10/LICENSE", "haproxy-3.0.10/doc/gpl.txt", "haproxy-3.0.10/doc/lgpl.txt"],
        "postgresql": ["postgresql-18.1/COPYRIGHT"],
        "redis": ["redis-7.4.1/LICENSE.txt"],
    }
    licenses = {name: [{"path": path, "sha256": sha256((src / path).read_bytes()).hexdigest()}
                       for path in paths] for name, paths in license_paths.items()}
    record = {"status": "PASS", "build_steps": len(steps), "sources": manifest,
        "platform": platform.platform(), "python": platform.python_version(),
        "openssl_prefix": str(ssl), "pcre_config": str(Path(pcre_config).resolve()),
        "upstream_license_files_preserved": licenses,
        "redis_driver": {"original_server_c_sha256": REDIS_ORIGINAL,
            "patched_server_c_sha256": REDIS_PATCHED,
            "patch_sha256": sha256((SCRIPT / "redis_tls_driver.patch").read_bytes()).hexdigest(),
            "meaning": "Test-only official TLS function driver before initServer; not native dry-run"},
        "service_started": False, "install_scope": "requested local prefix only",
        "detached_source_authenticity": "OPEN"}
    (root / "build-summary.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--openssl-prefix", required=True)
    parser.add_argument("--pcre-config", required=True)
    parser.add_argument("--archive-cache")
    args = parser.parse_args()
    print(json.dumps(build_checkers(args.root, args.openssl_prefix, args.pcre_config, args.archive_cache), indent=2))


if __name__ == "__main__":
    main()
