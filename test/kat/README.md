# Test vectors

| Files | Source | License |
|-------|--------|---------|
| `mlkem_*_prompt.json`, `mldsa_*_prompt.json` | NIST ACVP (usnistgov/ACVP-Server) | Public domain |
| `slhdsa_{keygen,siggen,sigver}.json.gz` | NIST ACVP (usnistgov/ACVP-Server) `gen-val/json-files/SLH-DSA-*-FIPS205/internalProjection.json`, commit 112690e8 (2025-06-12), re-encoded (below) | Public domain |
| `falcon_sign_kat.json`, `falcon_samplerz_kat.json` | tprest/falcon.py `scripts/` (round-3 C implementation outputs) | MIT, © 2018 Thomas Prest |
| `wycheproof/*.json.gz` | C2SP/wycheproof `testvectors_v1`, commit 3fa63dd0 (2026-09-02) | Apache-2.0 |
| `cctv/*` | C2SP/CCTV `ML-KEM/{strcmp,unluckysample,modulus}` | CC0-1.0 |

The SLH-DSA files hold all 1,248 ACVP tests, re-encoded to 7.4 MB from 69 MB of JSON. KeyGen is
unchanged. SigGen keeps every input and replaces the expected signature with its SHA-256 and length.
SigVer keeps every input, including the secret key and randomness ACVP publishes for each test, and
stores the signature as one of: `edit` (byte changes to the signature regenerated from those
inputs), `truncate`, `extend` (bytes appended), or `full` — the 72 "modified message" tests, whose
signature belongs to a message not in the file. Each test records the SHA-256 of the original
signature, which the tests check after rebuilding it.

The CCTV unlucky vectors were generated for FIPS 203 ipd, whose K-PKE.KeyGen hashes `G(d)`
without the `k` byte; the tests use their `ek`/`dk`/`c`/`K` (Encaps re-derives the unlucky
matrix from `ek`), not their `d`.
