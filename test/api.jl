# test/api.jl — the standard-name modules (src/api.jl) give the same bytes as the per-level
# modules they wrap, destructure positionally and by name, and reject swapped arguments.
using Test, ForgedPQ

@testset "Standard-name API: $(M.NAME)" for (M, L) in ((MLKEM512, MLKEM.Category1), (MLKEM768, MLKEM.Category3),
                                                       (MLKEM1024, MLKEM.Category5))
    seed = rand(UInt8, M.SEED_BYTES); m = rand(UInt8, 32)
    kp = M.keygen(seed)
    @test (kp.public_key, kp.secret_key) == L.kyber_kem_keypair_derand(seed)
    pk, sk = kp
    @test length(pk) == M.PUBLIC_KEY_BYTES && length(sk) == M.SECRET_KEY_BYTES
    e = M.encaps(pk, m)
    @test (e.ciphertext, e.shared_secret) == L.kyber_kem_enc_derand(pk, m)
    ct, ss = e
    @test length(ct) == M.CIPHERTEXT_BYTES && length(ss) == M.SHARED_SECRET_BYTES
    @test M.decaps(sk, ct) == ss == L.kyber_kem_dec(ct, sk)
    @test M.check_public_key(pk) && M.check_secret_key(sk)
    r = M.keygen(); c = M.encaps(r.public_key)
    @test M.decaps(r.secret_key, c.ciphertext) == c.shared_secret
    @test_throws ArgumentError M.decaps(ct, sk)                  # swapped arguments
    @test_throws ArgumentError M.encaps(sk)
end

@testset "Standard-name API: $(M.NAME)" for (M, L) in ((MLDSA44, MLDSA.Category2), (MLDSA65, MLDSA.Category3),
                                                       (MLDSA87, MLDSA.Category5))
    seed = rand(UInt8, M.SEED_BYTES); msg = rand(UInt8, 77); rnd = rand(UInt8, 32); ctx = rand(UInt8, 9)
    kp = M.keygen(seed)
    @test (kp.public_key, kp.secret_key) == L.dilithium_keygen_derand(seed)
    pk, sk = kp
    @test length(pk) == M.PUBLIC_KEY_BYTES && length(sk) == M.SECRET_KEY_BYTES
    sig = M.sign(sk, msg, rnd; context = ctx)
    @test sig == L.dilithium_sign_derand(msg, sk, rnd; context = ctx)
    @test length(sig) == M.SIGNATURE_BYTES
    @test M.verify(pk, msg, sig; context = ctx)
    @test !M.verify(pk, msg, sig)                                  # context is bound
    @test M.sign(sk, msg; hedged = false) == L.dilithium_sign_derand(msg, sk, zeros(UInt8, 32))
    @test M.verify(pk, msg, M.sign(sk, msg))
    ps = M.sign_prehash(sk, msg, "SHA2-512")
    @test M.verify_prehash(pk, msg, ps, "SHA2-512") && !M.verify_prehash(pk, msg, ps, "SHA2-256")
    @test !M.verify(sig, msg, pk)                                  # swapped arguments
    @test_throws ArgumentError M.sign(pk, msg)
end

@testset "Standard-name API: $(M.NAME)" for (M, L) in ((Falcon512, FNDSA.Falcon512), (Falcon1024, FNDSA.Falcon1024))
    pk, sk = M.keygen()
    @test length(pk) == M.PUBLIC_KEY_BYTES && length(sk) == M.SECRET_KEY_BYTES
    msg = rand(UInt8, 50)
    sig = M.sign(sk, msg)
    @test length(sig) == M.SIGNATURE_BYTES
    @test M.verify(pk, msg, sig) && L.falcon_verify(msg, sig, pk)
    @test !M.verify(pk, rand(UInt8, 50), sig)
    @test !M.verify(sig, msg, pk)                                  # swapped arguments
end

# The SHA-512/t computed from SHA-512 with the FIPS 180-4 initial values, which HashML-DSA uses
# where SHA.jl lacks sha2_512_224/256 (Julia 1.10, 1.11), against the FIPS 180-4 "abc" values.
@testset "SHA-512/224 and SHA-512/256 pre-hash" begin
    M = ForgedPQ.Prehash; abc = Vector{UInt8}("abc")
    @test bytes2hex(M.sha512t(abc, M.SHA512_224_IV, 28)) == "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
    @test bytes2hex(M.sha512t(abc, M.SHA512_256_IV, 32)) == "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
    for len in (0, 111, 112, 127, 128, 129, 1000)
        d = rand(UInt8, len)
        @test M.sha512_224(d) == M.sha512t(d, M.SHA512_224_IV, 28)
        @test M.sha512_256(d) == M.sha512t(d, M.SHA512_256_IV, 32)
    end
end

@testset "Standard-name API: X-Wing" begin
    seed = rand(UInt8, 32); eseed = rand(UInt8, 64)
    kp = XWing.keygen(seed)
    @test (kp.public_key, kp.secret_key) == XWing.xwing_keypair_derand(seed)
    e = XWing.encaps(kp.public_key, eseed)
    @test (e.ciphertext, e.shared_secret) == XWing.xwing_encaps_derand(kp.public_key, eseed)
    @test XWing.decaps(kp.secret_key, e.ciphertext) == e.shared_secret
    pk, sk = XWing.keygen(); ct, ss = XWing.encaps(pk)
    @test XWing.decaps(sk, ct) == ss
    @test_throws ArgumentError XWing.decaps(ct, sk)
end
