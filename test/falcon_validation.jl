# test/falcon_validation.jl — the Falcon building blocks against ground truth: the FFT and NTT
# against schoolbook negacyclic multiplication, SamplerZ against its target moments, the NTRU
# equation, the signature encoding, and keygen → sign → verify at small n.
using Statistics, ForgedPQ

@testset "Falcon building blocks vs ground truth" begin
    FF = ForgedPQ.FNDSA.FalconFFT; FS = ForgedPQ.FNDSA.FalconSampler
    FE = ForgedPQ.FNDSA.FalconEncoding; F = ForgedPQ.FNDSA.Falcon

    @testset "FFT / NTT = schoolbook negacyclic multiply" begin
        @test FF.validate(verbose = false)
        a = rand(0:FF.q-1, 256); b = rand(0:FF.q-1, 256)
        ref = mod.(FF.negacyclic_mul(a, b), FF.q)
        @test FF.ntt_mul_fast(a, b) == ref
        @test FF.ntt_mul(a[1:32], b[1:32]) == mod.(FF.negacyclic_mul(a[1:32], b[1:32]), FF.q)
        x = randn(16); y = randn(16)
        @test real.(FF.ifft(FF.add_fft(FF.fft(x), FF.fft(y)))) ≈ x .+ y
        @test real.(FF.ifft(FF.sub_fft(FF.fft(x), FF.fft(y)))) ≈ x .- y
        @test FF.div_fft(FF.mul_fft(FF.fft(x), FF.fft(y)), FF.fft(y)) ≈ FF.fft(x)
        xr = [x[1]; -reverse(x[2:end])]                               # f(1/x) mod xⁿ + 1
        @test FF.adj_fft(FF.fft(x)) ≈ FF.fft(xr)
        @test FF.sqnorm([3, 4], [12]) == 169
        @test FF.roots(3) ≈ FF.rootsof(3)
        @test_throws AssertionError FF.psi_2n(5)                    # 10 ∤ q − 1
    end

    @testset "SamplerZ moments" begin
        r = FS.RNG(collect(UInt8, 1:32))
        s = [FS.samplerz(0.3, 1.7, 1.2778, r) for _ in 1:200_000]
        @test abs(mean(s) - 0.3) < 0.03
        @test abs(var(s) - 1.7^2) < 0.06
    end

    @testset "NTRU equation f·G − g·F = q" begin
        solved = 0
        for n in (8, 16, 32), _ in 1:4
            f = BigInt.(rand(-5:5, n)); g = BigInt.(rand(-5:5, n))
            sol = try F.NG.ntru_solve(f, g) catch e; e isa F.NG.NTRUSolveFailure || rethrow(); nothing end
            sol === nothing && continue                               # not coprime: keygen resamples
            @test F.NG.ntru_check(f, g, sol...)
            solved += 1
        end
        @test solved > 0
    end

    @testset "Signature encoding" begin
        s = round.(Int, 60 .* randn(512))
        enc = FE.compress(s, (666 - 41) * 8)
        @test enc !== nothing && length(enc) == 625
        @test FE.decompress(enc, (666 - 41) * 8, 512) == s
    end

    @testset "keygen → sign → verify, n = $n" for n in (8, 16, 32)
        sk = F.keygen(n); gs = F.sign_setup(sk)
        for t in 1:4
            msg = Vector{UInt8}("falcon validation $t")
            sig = F.sign_poly(sk, gs, msg)
            @test F.verify_poly(sk.h, n, msg, sig)
            @test !F.verify_poly(sk.h, n, Vector{UInt8}("forged"), sig)
        end
    end
end
