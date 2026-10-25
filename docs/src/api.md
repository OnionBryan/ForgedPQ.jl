# API

## ML-KEM (FIPS 203)

`MLKEM512`, `MLKEM768` and `MLKEM1024` have the same functions; `MLKEM768` is shown.

```@docs
MLKEM768.keygen
MLKEM768.encaps
MLKEM768.decaps
MLKEM768.check_public_key
MLKEM768.check_secret_key
```

## ML-DSA (FIPS 204)

`MLDSA44`, `MLDSA65` and `MLDSA87` have the same functions; `MLDSA65` is shown.

```@docs
MLDSA65.keygen
MLDSA65.sign
MLDSA65.verify
MLDSA65.sign_prehash
MLDSA65.verify_prehash
```

## Falcon

`Falcon512` and `Falcon1024` have the same functions; `Falcon512` is shown.

```@docs
Falcon512.keygen
Falcon512.sign
Falcon512.verify
```

## X-Wing

```@docs
XWing.keygen
XWing.encaps
XWing.decaps
```

## X25519

```@docs
X25519.x25519
X25519.x25519_base
X25519.x25519_keypair
```

## Secret sharing and memory

```@docs
shamir_share
shamir_reconstruct
shamir_share_bytes
shamir_reconstruct_bytes
wipe!
```

## Hashing (FIPS 202)

The package's own Keccak, used by every scheme; byte-identical to SHA.jl.

```@docs
ForgedPQ.Keccak.shake128
ForgedPQ.Keccak.shake256
ForgedPQ.Keccak.sha3_224
ForgedPQ.Keccak.sha3_256
ForgedPQ.Keccak.sha3_384
ForgedPQ.Keccak.sha3_512
```

## Per-level modules

The standard-name modules wrap these, which expose the full interface, including the
deterministic variants under their FIPS names and, for ML-DSA, the internal and external-μ
interfaces. Levels other than the one shown have the same functions.

```@docs
MLKEM
MLDSA
FNDSA
X25519
XWing
```

### ML-KEM

```@docs
MLKEM.Category3.kyber_kem_keypair
MLKEM.Category3.kyber_kem_keypair_derand
MLKEM.Category3.kyber_kem_enc
MLKEM.Category3.kyber_kem_enc_derand
MLKEM.Category3.kyber_kem_dec
MLKEM.Category3.kyber_ek_check
MLKEM.Category3.kyber_dk_check
```

### ML-DSA

```@docs
MLDSA.Category3.dilithium_keygen
MLDSA.Category3.dilithium_keygen_derand
MLDSA.Category3.dilithium_sign
MLDSA.Category3.dilithium_sign_derand
MLDSA.Category3.dilithium_verify
MLDSA.Category3.dilithium_sign_prehash
MLDSA.Category3.dilithium_sign_prehash_derand
MLDSA.Category3.dilithium_verify_prehash
MLDSA.Category3.dilithium_sign_internal
MLDSA.Category3.dilithium_sign_internal_mu
MLDSA.Category3.dilithium_verify_internal
MLDSA.Category3.dilithium_verify_mu
```

### Falcon

```@docs
FNDSA.Falcon512.falcon_keygen
FNDSA.Falcon512.falcon_sign
FNDSA.Falcon512.falcon_verify
FNDSA.Falcon512.falcon_expand_sk
FNDSA.Falcon512.falcon_wipe!
FNDSA.Falcon512.falcon_certify
FNDSA.Falcon512.falcon_mrm_sign
FNDSA.Falcon512.falcon_mrm_verify
```

### X-Wing

```@docs
XWing.xwing_keypair
XWing.xwing_keypair_derand
XWing.xwing_encaps
XWing.xwing_encaps_derand
XWing.xwing_decaps
```
