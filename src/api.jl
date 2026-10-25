# Standard-name API: one module per parameter set, named as in FIPS 203/204 and the Falcon
# specification, with argument order as in those documents. Each wraps the per-level modules
# (MLKEM.Category*, MLDSA.Category*, FNDSA.Falcon*), which remain available unchanged.

for (name, level) in ((:MLKEM512, :Category1), (:MLKEM768, :Category3), (:MLKEM1024, :Category5))
    @eval module $name
    import ..MLKEM
    const L = MLKEM.$level

    "Parameter set name, as in FIPS 203."
    const NAME = L.IDENTIFIER
    "Encapsulation (public) key length in bytes."
    const PUBLIC_KEY_BYTES = L.KYBER_PUBLICKEYBYTES
    "Decapsulation (secret) key length in bytes."
    const SECRET_KEY_BYTES = L.KYBER_SECRETKEYBYTES
    "Ciphertext length in bytes."
    const CIPHERTEXT_BYTES = L.KYBER_CIPHERTEXTBYTES
    "Shared secret length in bytes."
    const SHARED_SECRET_BYTES = L.KYBER_SSBYTES
    "Length of the `keygen(seed)` seed, d ‖ z, in bytes."
    const SEED_BYTES = 2 * MLKEM.KYBER_SYMBYTES

    """
        keygen() -> (; public_key, secret_key)
        keygen(seed) -> (; public_key, secret_key)

    ML-KEM.KeyGen (FIPS 203 Alg. 19). Without `seed`, d and z come from the OS CSPRNG. With a
    $(2 * MLKEM.KYBER_SYMBYTES)-byte `seed` = d ‖ z, the key pair is deterministic
    (ML-KEM.KeyGen_internal, Alg. 16). Destructures as `pk, sk = keygen()`.
    """
    keygen() = ((pk, sk) = L.kyber_kem_keypair(); (; public_key = pk, secret_key = sk))
    keygen(seed::Vector{UInt8}) = ((pk, sk) = L.kyber_kem_keypair_derand(seed); (; public_key = pk, secret_key = sk))

    """
        encaps(public_key) -> (; ciphertext, shared_secret)
        encaps(public_key, m) -> (; ciphertext, shared_secret)

    ML-KEM.Encaps (FIPS 203 Alg. 20) after the encapsulation key check of §7.2; an invalid key
    throws `ArgumentError`. With a 32-byte `m`, encapsulation is deterministic
    (ML-KEM.Encaps_internal, Alg. 17). Destructures as `ct, ss = encaps(pk)`.
    """
    encaps(public_key::Vector{UInt8}) =
        ((ct, ss) = L.kyber_kem_enc(public_key); (; ciphertext = ct, shared_secret = ss))
    encaps(public_key::Vector{UInt8}, m::Vector{UInt8}) =
        ((ct, ss) = L.kyber_kem_enc_derand(public_key, m); (; ciphertext = ct, shared_secret = ss))

    """
        decaps(secret_key, ciphertext) -> shared_secret

    ML-KEM.Decaps (FIPS 203 Alg. 21) after the decapsulation key check of §7.3. A ciphertext of
    the right length that fails re-encryption gives the implicit-rejection secret, not an error.
    """
    decaps(secret_key::Vector{UInt8}, ciphertext::Vector{UInt8}) = L.kyber_kem_dec(ciphertext, secret_key)

    "Encapsulation key check (FIPS 203 §7.2): length and every coefficient below q."
    check_public_key(public_key::AbstractVector{UInt8}) = L.kyber_ek_check(public_key)
    "Decapsulation key check (FIPS 203 §7.3): length and the stored H(ek)."
    check_secret_key(secret_key::AbstractVector{UInt8}) = L.kyber_dk_check(secret_key)
    end
end

for (name, level) in ((:MLDSA44, :Category2), (:MLDSA65, :Category3), (:MLDSA87, :Category5))
    @eval module $name
    import ..MLDSA
    const L = MLDSA.$level

    "Parameter set name, as in FIPS 204."
    const NAME = L.IDENTIFIER
    "Public key length in bytes."
    const PUBLIC_KEY_BYTES = L.PK_BYTES
    "Secret key length in bytes."
    const SECRET_KEY_BYTES = L.SK_BYTES
    "Signature length in bytes."
    const SIGNATURE_BYTES = L.SIG_BYTES
    "Length of the `keygen(seed)` seed ξ in bytes."
    const SEED_BYTES = L.SEEDBYTES

    """
        keygen() -> (; public_key, secret_key)
        keygen(seed) -> (; public_key, secret_key)

    ML-DSA.KeyGen (FIPS 204 Alg. 1). Without `seed`, ξ comes from the OS CSPRNG; with a 32-byte
    `seed` = ξ the key pair is deterministic (ML-DSA.KeyGen_internal, Alg. 6).
    """
    keygen() = ((pk, sk) = L.dilithium_keygen(); (; public_key = pk, secret_key = sk))
    keygen(seed::Vector{UInt8}) = ((pk, sk) = L.dilithium_keygen_derand(seed); (; public_key = pk, secret_key = sk))

    """
        sign(secret_key, message; context = UInt8[], hedged = true) -> signature
        sign(secret_key, message, rnd; context = UInt8[]) -> signature

    ML-DSA.Sign (FIPS 204 Alg. 2), pure mode. Hedged by default (rnd from the OS CSPRNG);
    `hedged = false` is the deterministic variant. A 32-byte `rnd` fixes the randomness.
    `context` is at most 255 bytes.
    """
    sign(secret_key::Vector{UInt8}, message::Vector{UInt8}; context::Vector{UInt8} = UInt8[], hedged::Bool = true) =
        L.dilithium_sign(message, secret_key; hedged, context)
    sign(secret_key::Vector{UInt8}, message::Vector{UInt8}, rnd::Vector{UInt8}; context::Vector{UInt8} = UInt8[]) =
        L.dilithium_sign_derand(message, secret_key, rnd; context)

    """
        verify(public_key, message, signature; context = UInt8[]) -> Bool

    ML-DSA.Verify (FIPS 204 Alg. 3), pure mode. Malformed inputs return `false`.
    """
    verify(public_key::Vector{UInt8}, message::Vector{UInt8}, signature::Vector{UInt8}; context::Vector{UInt8} = UInt8[]) =
        L.dilithium_verify(message, signature, public_key; context)

    """
        sign_prehash(secret_key, message, hash; context = UInt8[], hedged = true) -> signature

    HashML-DSA.Sign (FIPS 204 Alg. 4). `hash` names the pre-hash function, e.g. `"SHA2-256"`,
    `"SHA2-512"`, `"SHA3-256"`, `"SHAKE-128"`, `"SHAKE-256"`.
    """
    sign_prehash(secret_key::Vector{UInt8}, message::Vector{UInt8}, hash::String;
                 context::Vector{UInt8} = UInt8[], hedged::Bool = true) =
        L.dilithium_sign_prehash(message, secret_key, hash; hedged, context)

    """
        verify_prehash(public_key, message, signature, hash; context = UInt8[]) -> Bool

    HashML-DSA.Verify (FIPS 204 Alg. 5).
    """
    verify_prehash(public_key::Vector{UInt8}, message::Vector{UInt8}, signature::Vector{UInt8}, hash::String;
                   context::Vector{UInt8} = UInt8[]) =
        L.dilithium_verify_prehash(message, signature, public_key, hash; context)
    end
end

for (name, level) in ((:Falcon512, :Falcon512), (:Falcon1024, :Falcon1024))
    @eval module $name
    import ..FNDSA
    const L = FNDSA.$level

    "Parameter set name. Falcon round-3 specification v1.2; FN-DSA (FIPS 206) is not yet published."
    const NAME = L.IDENTIFIER
    "Public key length in bytes."
    const PUBLIC_KEY_BYTES = L.PK_BYTES
    "Secret key length in bytes."
    const SECRET_KEY_BYTES = L.SK_BYTES
    "Signature length in bytes (the padded format: compressed s₂ zero-padded to a fixed length)."
    const SIGNATURE_BYTES = L.SIG_BYTES

    """
        keygen(; certified = false, fips206 = false, fixedpoint = false) -> (; public_key, secret_key)

    Falcon key generation. `certified = true` returns only keys that pass the exact certificate;
    `fips206 = true` also applies the tighter Gram–Schmidt bound of NIST's 2025 status update;
    `fixedpoint = true` generates without floating point.
    """
    keygen(; certified::Bool = false, fips206::Bool = false, fixedpoint::Bool = false) =
        ((pk, sk) = L.falcon_keygen(; certified, fips206, fixedpoint); (; public_key = pk, secret_key = sk))

    """
        sign(secret_key, message) -> signature

    Falcon signature (salt ‖ compressed s₂) with a fresh salt and sampler seed from the OS CSPRNG.
    """
    sign(secret_key::AbstractVector{UInt8}, message::AbstractVector{UInt8}) = L.falcon_sign(message, secret_key)

    """
        verify(public_key, message, signature) -> Bool

    Falcon verification. Malformed inputs return `false`.
    """
    verify(public_key::AbstractVector{UInt8}, message::AbstractVector{UInt8}, signature::AbstractVector{UInt8}) =
        L.falcon_verify(message, signature, public_key)
    end
end
