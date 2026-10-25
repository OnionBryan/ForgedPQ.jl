# test/components.jl — component functions the end-to-end vectors do not reach, each against an
# independent oracle: the ML-KEM PRF, XOF, base multiplication and K-PKE; ML-DSA SampleInBall when
# its first SHAKE block runs out; and the error paths of the helpers.
using Test, ForgedPQ

@testset "Components" begin
    K = MLKEM.Category3; D = MLDSA.Category5

    @testset "ML-KEM PRF and XOF = SHAKE" begin
        for len in (1, 64, 200, 500)
            s = rand(UInt8, 32); nonce = rand(UInt8)
            @test K.kyber_prf(s, nonce, len) == oracle_shake256(vcat(s, nonce), len)
            @test K.kyber_xof(s, len) == oracle_shake128(s, len)
        end
    end

    # Pair i of the NTT domain is a polynomial mod X² − ζᵢ, ζᵢ = ±KYBER_ZETAS[65 + i ÷ 2] (stored
    # as ζR mod q); the product carries one Montgomery factor R⁻¹.
    @testset "ML-KEM basemul = (a·b mod X² − ζ)·R⁻¹ mod q" begin
        q = 3329; R = 1 << 16; Rinv = invmod(R, q)
        for _ in 1:20
            a = Int16.(rand(-q+1:q-1, 256)); b = Int16.(rand(-q+1:q-1, 256))
            r = zeros(Int16, 256)
            K.kyber_poly_basemul_montgomery!(r, a, b)
            ok = true
            for p in 0:127
                z = Int(MLKEM.KYBER_ZETAS[65 + p ÷ 2]) * (iseven(p) ? 1 : -1)
                ζ = mod(z * Rinv, q)
                a0, a1, b0, b1 = Int(a[2p+1]), Int(a[2p+2]), Int(b[2p+1]), Int(b[2p+2])
                want = mod.([a0 * b0 + a1 * b1 * ζ, a0 * b1 + a1 * b0] .* Rinv, q)
                ok &= mod.(Int.(r[2p+1:2p+2]), q) == want
            end
            @test ok
        end
    end

    @testset "ML-KEM rejection sampling" begin
        buf = rand(UInt8, 3 * 200)
        ref = Int16[]
        for i in 1:3:length(buf)
            d1 = Int(buf[i]) | (Int(buf[i+1]) & 0x0f) << 8; d2 = Int(buf[i+1]) >> 4 | Int(buf[i+2]) << 4
            d1 < 3329 && push!(ref, d1); d2 < 3329 && push!(ref, d2)
        end
        r = zeros(Int16, 256)
        n = K.kyber_rej_uniform!(r, buf)
        @test n == min(256, length(ref)) && r[1:n] == ref[1:n]
    end

    @testset "K-PKE keygen / encrypt / decrypt" begin
        pk, sk = K.kyber_indcpa_keypair()
        @test length(pk) == K.KYBER_INDCPA_PUBLICKEYBYTES
        m = rand(UInt8, 32)
        @test K.kyber_indcpa_dec(K.kyber_indcpa_enc(m, pk, rand(UInt8, 32)), sk) == m
        s = K.kyber_unpack_sk(sk, K.KYBER_K)
        @test K.kyber_pack_sk(s, K.KYBER_K) == sk
        @test_throws ErrorException K.kyber_poly_compress!(zeros(UInt8, 128), zeros(Int16, 256), 3)
        @test_throws ErrorException K.kyber_poly_decompress!(zeros(Int16, 256), zeros(UInt8, 128), 3)
    end

    # FIPS 204 Algorithm 29 on a stream long enough for any seed; returns c and the bytes used.
    function sample_in_ball_ref(seed, τ)
        h = oracle_shake256(seed, 4096); c = zeros(Int, 256); pos = 9
        for i in 256-τ:255
            j = Int(h[pos]); pos += 1
            while j > i; j = Int(h[pos]); pos += 1; end
            c[i+1] = c[j+1]
            c[j+1] = (h[1 + (i + τ - 256) ÷ 8] >> ((i + τ - 256) % 8)) & 1 == 1 ? -1 : 1
        end
        c, pos - 1
    end

    # A second SHAKE block is needed only when 60 draws reject more than 68 bytes, which no
    # random seed reaches in practice; the comparison covers the common path.
    @testset "ML-DSA SampleInBall = FIPS 204 Algorithm 29" begin
        for _ in 1:200
            seed = rand(UInt8, D.CTILDEBYTES)
            ref, _ = sample_in_ball_ref(seed, D.TAU)
            c = D.poly_challenge!(zeros(Int32, 256), seed)
            @test mod.(Int.(c), 8380417) == mod.(ref, 8380417)
        end
    end

    @testset "ML-DSA unpack_sk" begin
        pk, sk = D.dilithium_keygen_derand(zeros(UInt8, 32))
        ρ, key, tr, s1, s2, t0 = D.unpack_sk(sk)
        @test ρ == pk[1:32] && tr == ForgedPQ.Keccak.shake256(pk, UInt64(64))
        @test key == sk[33:64]
    end

    @testset "X25519 key pair" begin
        pa, sa = X25519.x25519_keypair(); pb, sb = X25519.x25519_keypair()
        @test pa == X25519.x25519_base(sa)
        @test X25519.x25519(sa, pb) == X25519.x25519(sb, pa)
    end

    @testset "Helper error paths and conversions" begin
        @test_throws ArgumentError ForgedPQ.Prehash.prehash_message(UInt8[1], "MD5")
        @test_throws ArgumentError wipe!(view(['a', 'b', 'c'], [1, 3]))
        v = view(rand(UInt8, 8), [1, 3]); wipe!(v); @test all(iszero, v)
        x = Any[1, 2]; @test_throws ArgumentError wipe!(x)
        FP = ForgedPQ.FNDSA.FalconFpr
        @test FP.fpr_of(Int32(-7)) == FP.fpr_of(-7)
        r = ForgedPQ.FNDSA.FalconSampler.RNG()
        @test length(r.seed) == 32
    end
end
