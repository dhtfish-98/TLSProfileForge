# TLSProfileForge

Generate deterministic offline TLS configuration drafts for Nginx, Apache, HAProxy, PostgreSQL and Redis using the unchanged fixed TLSRef 6.0 guideline. This new implementation performs strict version comparison, explicit capability checks and service template adaptation. It writes one caller-selected new file, emits a JSON report, and never applies configuration, starts a service or contacts a server.

```sh
python -m pip install .
tls-profile-forge --service nginx --version 1.28.0 --openssl 3.5.0 --profile intermediate --out /absolute/existing-directory/new.conf
```

Python 3.11+; no runtime dependencies. `modern` enables TLS 1.3 only; `intermediate` enables TLS 1.2 and 1.3. Cipher suites, the OpenSSL and IANA naming correspondence, groups and ordering are taken from the bundled exact data. There is no old/weak profile, remote update, cipher selector, HSTS policy, OCSP automation or automatic application command. Other services and unstable/loosely formatted versions are explicitly unsupported.

```python
from tls_profile_forge import generate
report, draft = generate("postgresql", "18.1", "3.5", "modern")
# Pure library API; returns data and text without any file write.
```

| Service | Frozen capability window | Explicit differences |
| --- | --- | --- |
| Nginx | 1.19.4 through 1.28.x | Explicit TLS 1.3 suites via ssl_conf_command; groups and protocol allowlist |
| Apache | 2.4.36 through 2.4.x | mod_ssl and OpenSSL required; explicit TLS 1.3 suite and group commands |
| HAProxy | 2.2 through 3.0.x | Both endpoint defaults; outbound groups require 2.9; older versions stay OPEN |
| PostgreSQL | 12 through 18.x | Multiple groups and TLS 1.3 suites require 18; older drafts retain those gaps as OPEN |
| Redis | 6 through 7.4.x | Protocol/suite/order controls; no selected group directive, so always OPEN |

The separate OpenSSL capability window is 3.0 through 4.0.x. Versions below 3.5 explicitly omit X25519MLKEM768 and mark that adaptation OPEN. Protocols and cipher lists are never silently weakened. Future versions outside these finite windows are OPEN with no draft. The windows describe a source-based capability model, not lifecycle support, observed binary identity, arbitrary build options or a claim that every patch was executed. Version strings are caller assertions. PostgreSQL modern major.patch spelling such as 18.1 is accepted and normalized to three components for comparison.

PASS/exit 0 means the selected template was generated within this model with no capability gap. OPEN/exit 2 means unsupported input, missing capabilities, data integrity or output error. A supported partial draft can still be written with an OPEN report. `output_created` means the new file descriptor was successfully written and its path identity was checked at that observation; current path identity always remains OPEN. Report includes immutable rule version, guideline commit/hash, protocols, both cipher formats, explicitly configured/requested groups and configuration digest.

Certificate/key paths are static placeholders; replace them and review the surrounding configuration manually. Certificate type, key/signature/lifetime policy, certificate trust, HSTS and OCSP operational policy are not implemented by this TLS directive generator. Full guideline compliance, service build/library identity, actual syntax on the caller's binary, handshake behavior, deployment security and CVP eligibility are OPEN on every report. A draft is not a running secure service.

Output creation requires existing real directory components, POSIX directory-relative open and O_NOFOLLOW. Existing paths, symlink components, raw dot/parent components and missing directories are rejected. On macOS, aliases such as /tmp and /var are symlinks: supply their physical /private paths. File mode is 0600; text is capped at 64 KiB. Writes loop until complete and fsync the descriptor; observed path replacement is OPEN. Failed writes can leave a partial newly created file. No failure cleanup deletes a path, and no protection against all concurrent renames or post-return replacements is claimed. Ordinary/error output uses sanitized JSON; explicit --help is informational.

See [ORIGIN.md](ORIGIN.md), [DEFENSIVE_SCOPE.md](DEFENSIVE_SCOPE.md), [VALIDATION.md](VALIDATION.md) and the separate development-only [official syntax validation](SYNTAX_VALIDATION.md). Engineering tests and syntax evidence do not establish applicant identity, an actual safeguard obstacle or CVP approval.
