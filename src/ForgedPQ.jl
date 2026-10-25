"""
    ForgedPQ.jl — Post-Quantum Cryptography for Julia

Implementations of NIST FIPS post-quantum cryptographic standards:
- **ML-KEM** (FIPS 203): Module-Lattice Key Encapsulation (Kyber) — 512/768/1024
- **ML-DSA** (FIPS 204): Module-Lattice Digital Signatures (Dilithium) — 44/65/87
- **FN-DSA** (Falcon): NTRU-lattice signatures — Falcon-512 / Falcon-1024; exact key certificate,
  float-free keygen, message recovery (FALCON-MRM)
- **X25519** (RFC 7748) and **X-Wing** (X25519 + ML-KEM-768 hybrid KEM)
- **Shamir**: (k,n)-threshold secret sharing over GF(2^521-1)

ML-KEM and ML-DSA pass 855 NIST ACVP vectors across every interface; Falcon signing is
byte-exact with the round-3 C reference implementation.

## Quick Start

```julia
using ForgedPQ

# ML-KEM-768 key encapsulation
pk, sk = MLKEM768.keygen()
ct, ss = MLKEM768.encaps(pk)
@assert MLKEM768.decaps(sk, ct) == ss

# ML-DSA-65 signatures
pk, sk = MLDSA65.keygen()
msg = Vector{UInt8}("hello")
sig = MLDSA65.sign(sk, msg)
MLDSA65.verify(pk, msg, sig)  # true

# Falcon-512 signatures
pk, sk = Falcon512.keygen()
sig = Falcon512.sign(sk, msg)
Falcon512.verify(pk, msg, sig)  # true
```

The per-level modules (`MLKEM.Category3.kyber_kem_keypair`, ...) remain available.
"""
module ForgedPQ

include("wipe.jl")
using .Wipe
export wipe!

# Byte concatenation without Base.vcat (see src/bytes.jl)
include("bytes.jl")

# Keccak-f[1600]: SHAKE128/256 and SHA3-256/512 for every scheme
include("keccak.jl")

# ML-KEM (FIPS 203) — Kyber Key Encapsulation
include("mlkem.jl")
using .MLKEM

# ML-DSA (FIPS 204) — Dilithium Digital Signatures
include("mldsa.jl")
using .MLDSA

# FN-DSA (Falcon) — NTRU-lattice hash-and-sign signatures
include("fndsa.jl")
using .FNDSA

# X25519 (RFC 7748) and the X-Wing hybrid KEM (X25519 + ML-KEM-768)
include("x25519.jl")
using .X25519
include("xwing.jl")
using .XWing

# Re-export modules
export MLKEM, MLDSA, FNDSA, X25519, XWing

# One module per parameter set under its standard name (src/api.jl)
include("api.jl")
export MLKEM512, MLKEM768, MLKEM1024, MLDSA44, MLDSA65, MLDSA87, Falcon512, Falcon1024

# Shamir Secret Sharing
include("shamir.jl")
export shamir_share, shamir_reconstruct, shamir_share_bytes, shamir_reconstruct_bytes

include("precompile.jl")

end # module ForgedPQ
