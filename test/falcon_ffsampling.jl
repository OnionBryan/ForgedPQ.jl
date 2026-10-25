# test/falcon_ffsampling.jl — the ffSampling signer and fast NTRU solver against their references:
# Karatsuba negamul = schoolbook; ffSampling signatures verify, satisfy s0 = c − s1·h, reject
# forgeries, and have the norm distribution of the Klein/GPV sampler.
using Statistics, ForgedPQ

@testset "Falcon ffSampling vs references" begin
    F = ForgedPQ.FNDSA.Falcon; NG = ForgedPQ.FNDSA.FalconNTRUGen

    @testset "Karatsuba negamul = schoolbook" begin
        for n in (1, 2, 4, 16, 32, 64, 128, 512), _ in 1:6
            bits = rand((4, 60, 300, 3000))
            a = [rand(-big(2)^bits:big(2)^bits) for _ in 1:n]
            b = [rand(-big(2)^bits:big(2)^bits) for _ in 1:n]
            @test NG.negamul(a, b) == NG.negamul_school(a, b)
        end
    end

    @testset "ffSampling vs Klein/GPV, n = $n" for n in (16, 64)
        sk = F.keygen(n); pk = sk.h
        gs = F.sign_setup(sk); gk = F.sign_setup_klein(sk)
        nf = Float64[]; nk = Float64[]; bad = 0
        for i in 1:400
            msg = Vector{UInt8}("m$i")
            s = F.sign_poly(sk, gs, msg)
            F.verify_poly(pk, n, msg, s) || (bad += 1)
            c = F.hash_to_point(msg, s.salt, n)
            s.s0 == F.centermod.(c .- F.poly_mul_modq(s.s1, pk)) || (bad += 1)
            F.verify_poly(pk, n, Vector{UInt8}("x$i"), s) && (bad += 1)
            push!(nf, s.norm2)
            push!(nk, F.sign_poly_klein(sk, gk, msg).norm2)
        end
        @test bad == 0
        @test abs(mean(nf) - mean(nk)) / sqrt(var(nf) / 400 + var(nk) / 400) < 4
    end
end
