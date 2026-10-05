> Historical validation for v0.1.3. Current release v0.1.4 is validated separately by its exact-commit CI and published artifacts.

## Current version 0.1.3: applicable material notices, 2026-10-03

New implementation author and maintainer: dhtfish98. Package version: `0.1.3`.

This revision removes 11 unused reference-only license/notice copies and reconciles current material provenance and packaging. Actual embedded third-party data, converted vectors, frozen test-oracle source, applicable licenses and the scoped Redis patch/terms remain unchanged where present. The project's own LICENSE is unchanged. Runtime behavior is unchanged; only its version constant advances.

The current source suite passes 22 tests on Python 3.14/macOS arm64. Publication gates also require the same nonzero suite on a fresh wheel consumer and an independent consumer of a wheel rebuilt offline from the source archive. Separate receipts bind actual outcomes, installed origins, runtime/data/license bytes, wheel RECORD, CLI contracts and exact artifact hashes; no self-referential package hash is embedded here.

Historical reference/native/oracle measurements below are retained as prior evidence and are not new measurements for this material-only revision. Current file identities are in SOURCE_MANIFEST.json. Matching remote CI/publication, deployment security, applicant identity and CVP approval require separate evidence and remain OPEN here.

## Prior verification evidence

## Current version 0.1.2: attribution and bounded verification, 2026-10-03

New implementation author and maintainer: dhtfish98. Package version: `0.1.2`.

Required local reader/writer protection flags now require positive non-Boolean integers. Missing, zero, None, Boolean, string and floating-point values yield controlled OPEN/error before requested filesystem input/output. Existing fixed-source provenance and parser/generation scope are retained.

The current source suite passes 22 tests on Python 3.14/macOS arm64. Final wheel and sdist are built from the final files. A fresh consumer installation also passes 22 tests. Installed/source/wheel runtime bytes, licenses, retained upstream notices, RECORD and command contracts are verified separately before publication. Exact package hashes and execution receipts are recorded externally rather than embedded in this self-referential document.

These tests verify the documented finite profile. Historical native/reference measurements below are preserved; they are not new runs for this revision. Matching remote CI, actual deployments, applicant identity and CVP approval remain OPEN until separately evidenced.

The current directory-relative file contract also requires `os.supports_dir_fd` to be a set or frozenset containing the actual `os.open`. Missing, None, malformed and incomplete declarations yield the existing controlled OPEN/error before requested filesystem I/O. The output identity check additionally requires `os.stat` directory-relative and no-follow support. The same current suite covers these API and real installed CLI contrasts, including normal frozenset capability declarations. Trusted CLI and standard-library imports are warmed before simulated capability mutation; this test isolates the application gate rather than a damaged standard-library import. Source archive offline rebuilding and another fresh consumer verify the same suite and all uncompressed wheel payload bytes.

## Prior verification evidence

# Local evidence and remaining checks

19 test methods pass on local Python 3.14/macOS. The version/capability matrix includes 288 combinations across all five services, two profiles and six OpenSSL versions, including both sides of known boundaries. Repeated generation is byte-identical. Additional cases check numeric/letter ordering, unknown/injected input, data integrity drift, two cipher naming formats, exact modern protocol retention, explicit PQ filtering, HAProxy endpoint differences, PostgreSQL 18 additions, Redis limitations, network prohibition, output budgets/symlinks/overwrite refusal, partial writes and a concurrent replacement failure that must not delete the replacement.

A separate implementation review read the new runtime and checked primary capability references. Its two requested changes—accurate HAProxy endpoint-group evidence and removal of non-atomic failure cleanup—are implemented and regression-tested. This is not independent human review or a formal server-security audit.

The original local inventory found system Apache/2.4.67 at /usr/sbin/httpd. All four isolated -t attempts rejected TLSv1.3 as an illegal protocol. That system module still does not satisfy the asserted TLS capability profile, and its actual linked library remains OPEN. This failure has not been relabeled as a passing check or worked around by removing TLS 1.3.

Separate compatible checkers were then built from seven exact official source archives into a fresh local prefix, with no system service changes. A full rebuild completed all 18 recorded build steps. The resulting Nginx 1.28.0, Apache 2.4.67, HAProxy 3.0.10 and PostgreSQL 18.1 native check modes accepted both generated profiles (8 checks). Redis 7.4.1 accepted both generated syntax prefixes up to a deliberate parser stop (2 checks), and a seven-line test-only entry executed its unchanged official TLS configuration function before initServer/listeners/event loop (2 checks). All 17 negative controls were rejected with the expected official error, including invalid protocols on all five services and Redis invalid suites, malformed certificates and mismatched keys. Total: 12 positive checks and 17 negative controls, all PASS on these exact local builds with observed OpenSSL 3.6.2. These executions validate selected syntax and the Redis TLS values exercised by that driver. They do not validate every value, every capability-window patch version, or actual TLS traffic.

Nginx -t can briefly bind/listen; this scaffold restricts it to an owned temporary Unix socket and never enters its event loop or accepts requests. Apache uses -t, HAProxy uses -c, and PostgreSQL uses -C without an initialized cluster. Redis's parser-stop run exits before server initialization; its modified test-only driver exits immediately after official TLS setup. Redis's native complete dry-run and actual service behavior remain OPEN. Temporary synthetic keys/certificates and complete checker build trees are excluded from published source and packages. See [SYNTAX_VALIDATION.md](SYNTAX_VALIDATION.md) for source identities, exact reproduction and limitations.

CI defines source/build/offline consumer jobs for Python 3.11 and 3.14 and a separate fixed-source official syntax job. That job records the actual runner OpenSSL version; lower-than-3.5 adaptations remain OPEN in the generator report even if syntax is accepted. Remote checks remain OPEN until a matching commit actually completes. Artifact identity and measured local results are recorded outside the source package to avoid a self-hash cycle.

Remaining OPEN: syntax on caller binaries and versions not executed here, source detached-signature authenticity, full dynamic-loader/provider/module identity, real handshakes, full guideline/certificate policy, actual deployment, all concurrent filesystem races, unsupported versions/services, independent human review and CVP eligibility.
