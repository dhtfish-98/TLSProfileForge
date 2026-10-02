# Defensive contract

Offline five-service template generation and compatibility explanation. Only fixed modern/intermediate data is accepted; its exact bytes are checked before use. There is no network API, telemetry, remote dependency/data import, target execution, service discovery, credential handling, client scan, restart, configuration application or legacy-protocol security reduction. The pure library function performs no output write.

Version input is bounded to 32 characters and strict numeric components; arbitrary flags, suffixes, prereleases, command text and vendor build strings are unsupported. Stable single-letter OpenSSL 0.x/1.x ordering is parsed, but those versions are outside this generation profile. Partial capability gaps are distinct from parse errors. Known supported drafts with gaps remain available for manual review and always report OPEN.

The fixed JSON is 3135 bytes and exact hash-gated. Generator output is deterministic, with no timestamps/current-date or machine-specific paths. Configuration values originate from fixed data/constants and strictly normalized service/version choices. API output includes requested/actually configured groups, with HAProxy endpoint differences and Redis/PostgreSQL gaps preserved.

New output is bounded to 64 KiB and created with O_EXCL/O_NOFOLLOW and held directory descriptors. Existing content is never opened for overwrite; all parent symlinks and traversal are refused. No recursive directory creation or deletions occur. A write failure can leave a partial new file and ordinary CLI error reports that a file may exist. Identity checks observe only a point in time; concurrent filesystem changes and current pathname contents remain OPEN.

PASS refers to the finite generation contract. Required modules, provider availability, actual linked OpenSSL, syntax validation on a particular binary, certificate policy, every guideline property, real protocol/cipher negotiation and deployment security require separate evidence. No identity, organization, real safeguard rejection, applicant qualification or provider approval follows from these artifacts.
