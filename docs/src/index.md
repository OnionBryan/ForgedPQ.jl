# ForgedPQ.jl

Post-quantum cryptography in pure Julia: the three NIST post-quantum standards — ML-KEM
(FIPS 203), ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) — Falcon (the basis of FN-DSA, to be
standardized as FIPS 206), the X-Wing hybrid KEM, X25519 and Shamir secret sharing. The only
runtime dependencies are Julia's standard libraries.

ML-KEM, ML-DSA and SLH-DSA pass all 2,103 NIST ACVP vectors for every interface, and ML-KEM and
ML-DSA the Wycheproof vectors; Falcon signing is byte-exact with the round-3 C reference. CI
checks interoperability with liboqs on every push.

## Installation

```julia
using Pkg
Pkg.add(url = "https://github.com/OnionBryan/ForgedPQ.jl")
```

## Quick start

```jldoctest quickstart
julia> using ForgedPQ

julia> msg = Vector{UInt8}("hello");

julia> pk, sk = MLKEM768.keygen();           # key encapsulation

julia> ct, ss = MLKEM768.encaps(pk);

julia> MLKEM768.decaps(sk, ct) == ss
true

julia> pk, sk = MLDSA65.keygen();            # lattice signatures

julia> MLDSA65.verify(pk, msg, MLDSA65.sign(sk, msg))
true

julia> pk, sk = SLHDSA_SHA2_128f.keygen();   # hash-based signatures

julia> SLHDSA_SHA2_128f.verify(pk, msg, SLHDSA_SHA2_128f.sign(sk, msg))
true

julia> pk, sk = XWing.keygen();              # hybrid KEM: secure if X25519 or ML-KEM-768 is

julia> ct, ss = XWing.encaps(pk);

julia> XWing.decaps(sk, ct) == ss
true
```

Keys, ciphertexts and signatures are `Vector{UInt8}` in the encodings of the standards, so they
interoperate with other implementations; arguments may be any `AbstractVector{UInt8}` (views,
`Memory`). Results destructure positionally or by name: `kp = MLKEM768.keygen(); kp.public_key`.
More in [Examples](examples.md).

## Conventions

- **Argument order** follows the standards: `decaps(sk, ct)`, `sign(sk, msg)`, `verify(pk, msg, sig)`.
- **Randomness** comes from the operating system (`Random.RandomDevice`). Passing a seed or the
  randomness explicitly (`keygen(seed)`, `encaps(pk, m)`, `sign(sk, msg, rnd)`) makes an
  operation deterministic, for known-answer tests and key derivation.
- **Invalid input** — a malformed key or a wrong-length ciphertext — throws `ArgumentError`;
  verification of malformed input returns `false`. An ML-KEM ciphertext of the right length
  never throws: one that fails re-encryption gives the implicit-rejection secret.
- **Secrets** the package holds are zeroed before it returns, on every path, exceptions
  included. Call [`wipe!`](@ref) on secret buffers you own when you are done with them.
