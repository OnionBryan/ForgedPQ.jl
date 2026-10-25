# Choosing a scheme

| Need | Use | Sizes (bytes) |
|------|-----|---------------|
| Key exchange, general purpose | `MLKEM768` | pk 1184, ct 1088, ss 32 |
| Key exchange, hedged against a lattice break | `XWing` (X25519 + ML-KEM-768) | pk 1216, ct 1120, ss 32 |
| Key exchange, highest security level | `MLKEM1024` | pk 1568, ct 1568, ss 32 |
| Signatures, general purpose | `MLDSA65` | pk 1952, sig 3309 |
| Signatures, smallest | `Falcon512` | pk 897, sig 666 |
| Signatures, highest security level | `MLDSA87` or `Falcon1024` | pk 2592 / 1793, sig 4627 / 1280 |
| Signatures that survive a break of lattice problems | `SLHDSA_SHA2_128s` (or any SLH-DSA set) | pk 32, sig 7856 |
| Hash-based signatures, fast signing | `SLHDSA_SHA2_128f` | pk 32, sig 17088 |

## ML-KEM or X-Wing

ML-KEM is the NIST standard. X-Wing combines it with X25519, so a session stays confidential
unless *both* are broken: a classical attacker must break X25519 and a quantum one ML-KEM-768.
X-Wing is an Internet-Draft, not yet an RFC; its wire format may still change.

## ML-DSA or Falcon

ML-DSA is the NIST standard and the simpler scheme to implement safely. Falcon gives signatures
about a fifth the size, at the cost of a more delicate signer (Gaussian sampling over floating
point, emulated in integers here). FN-DSA, NIST's standard based on Falcon, is not yet
published; this package implements the Falcon round-3 specification, with options for the
changes NIST has announced ([Security](security.md)).

## SLH-DSA

ML-DSA, ML-KEM and Falcon all rest on lattice problems; SLH-DSA rests only on the security of its
hash function, the most conservative assumption available. The price is size and signing time:
signatures of 8–50 KB, and signing that takes 0.4–0.8 s in the small (`s`) sets or 20–90 ms in
the fast (`f`) sets. It suits signatures made rarely and kept long — firmware, root certificates,
archives — and pairs with ML-DSA where a second, independent assumption is wanted.

The SHA2 and SHAKE sets are equally secure; choose the hash your platform already relies on.
`s` sets give the smaller signature and `f` sets the faster signer. Keys are tiny either way
(public key 32–64 bytes).

## Pure or pre-hash signing

`MLDSA65.sign` signs the message itself. `MLDSA65.sign_prehash` (HashML-DSA) signs a hash of
it, for messages too large to hold in memory or when the signer only sees a digest. The two
produce different signatures, and a verifier must use the matching function.

## Context strings

ML-DSA binds an optional context (up to 255 bytes) into the signature: a signature made with
`context = b"app-v1"` verifies only with the same context. Use one per protocol or purpose to
keep signatures from being replayed across them.
