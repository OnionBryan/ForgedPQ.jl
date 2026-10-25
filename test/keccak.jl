# Keccak (src/keccak.jl) against SHA.jl (SHAKE against `oracle_shake*`, test/shake_reader.jl):
# every input length through three blocks of each rate, outputs at and across the rate
# boundaries, non-Vector inputs, the streaming API, and the FIPS 202 empty-string values.
using SHA
isdefined(Main, :oracle_shake256) || include("shake_reader.jl")

@testset "Keccak vs SHA.jl" begin
    K = ForgedPQ.Keccak
    @test bytes2hex(K.sha3_256(UInt8[])) == "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    @test bytes2hex(K.shake128(UInt8[], 16)) == "7f9c2ba4e88f827d616045507605853e"
    bad = 0
    for len in 0:3 * 168 + 1
        d = rand(UInt8, len)
        K.sha3_256(d) == oracle_sha3(d, 32) || (bad += 1)
        K.sha3_512(d) == oracle_sha3(d, 64) || (bad += 1)
        K.sha3_224(d) == oracle_sha3(d, 28) || (bad += 1)
        K.sha3_384(d) == oracle_sha3(d, 48) || (bad += 1)
        for out in (0, 1, 32, 64, 135, 136, 137, 167, 168, 169, 672, 840)
            K.shake128(d, out) == oracle_shake128(d, out) || (bad += 1)
            K.shake256(d, out) == oracle_shake256(d, out) || (bad += 1)
        end
        v = @view vcat(UInt8[0xaa], d)[2:end]
        K.shake256(v, 100) == oracle_shake256(d, 100) || (bad += 1)
    end
    @test bad == 0
    d = rand(UInt8, 33)
    @test K.shake256(d, 10_000) == oracle_shake256(d, 10_000)
end

@testset "Keccak streaming API" begin
    K = ForgedPQ.Keccak
    for len in (0, 1, 33, 135, 136, 167, 168, 400)
        d = rand(UInt8, len)
        for (absorb, rate, ref) in ((K.shake128_absorb, K.SHAKE128_RATE, K.shake128),
                                    (K.shake256_absorb, K.SHAKE256_RATE, K.shake256))
            st = absorb(d); out = UInt8[]; blk = Vector{UInt8}(undef, rate)
            for b in 1:5
                append!(out, K.squeeze_block!(blk, st, rate)); st = K.keccak_f1600(st)
            end
            @test out == ref(d, 5rate)
        end
        buf = fill(0xee, 300)
        @test K.shake256!(buf, d, 200)[1:200] == K.shake256(d, 200) && all(==(0xee), buf[201:end])
    end
    @test_throws BoundsError K.squeeze_block!(zeros(UInt8, 10), K.shake128_absorb(UInt8[]), 11)
    @test_throws BoundsError K.shake256!(zeros(UInt8, 10), UInt8[], 11)
end

# Where SHA.jl is the reference, check the independent sponge the oracles fall back to.
if SHA_IS_REFERENCE
    @testset "Test sponge vs SHA.jl" begin
        for len in (0, 1, 71, 72, 103, 104, 135, 136, 137, 143, 144, 167, 168, 169, 500)
            d = rand(UInt8, len)
            for bits in (128, 256)
                f = bits == 128 ? SHA.shake128 : SHA.shake256
                @test take!(ShakeReader(d; bits), 700) == f(d, UInt(700))
            end
            for (n, f) in ((28, SHA.sha3_224), (32, SHA.sha3_256), (48, SHA.sha3_384), (64, SHA.sha3_512))
                @test take!(sponge(d, 200 - 2n, 0x06), n) == f(d)
            end
        end
    end
end
