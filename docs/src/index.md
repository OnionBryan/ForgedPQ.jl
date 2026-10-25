# ForgedPQ.jl

Post-quantum cryptography in pure Julia: the NIST lattice standards ML-KEM (FIPS 203) and ML-DSA
(FIPS 204), Falcon (the basis of FN-DSA, to be standardized as FIPS 206), the X-Wing hybrid KEM,
X25519 and Shamir secret sharing. The only runtime dependencies are Julia's standard libraries.

ML-KEM and ML-DSA pass the 855 NIST ACVP vectors for every interface and the Wycheproof vectors;
Falcon signing is byte-exact with the round-3 C reference. CI checks interoperability with
liboqs on every push.

## Installation

```julia
using Pkg
Pkg.add(url = "https://github.com/OnionBryan/ForgedPQ.jl")
```

## Quick start

```julia
using ForgedPQ
msg = Vector{UInt8}("hello")

# Key encapsulation
pk, sk = MLKEM768.keygen()
ct, ss = MLKEM768.encaps(pk)
MLKEM768.decaps(sk, ct) == ss            # true

# Signatures
pk, sk = MLDSA65.keygen()
sig = MLDSA65.sign(sk, msg)
MLDSA65.verify(pk, msg, sig)             # true

# Hybrid KEM: secure if either X25519 or ML-KEM-768 is
pk, sk = XWing.keygen()
ct, ss = XWing.encaps(pk)
XWing.decaps(sk, ct) == ss               # true
```

Keys, ciphertexts and signatures are `Vector{UInt8}` in the encodings of the standards, so they
interoperate with other implementations. Results destructure positionally or by name:
`kp = MLKEM768.keygen(); kp.public_key`.

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
