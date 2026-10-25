# test/slhdsa.jl — SLH-DSA (FIPS 205): the NIST ACVP vectors for all twelve parameter sets
# (test/kat/slhdsa_*.json.gz; provenance in test/kat/README.md), the SHA-2 midstate engine
# (src/sha2.jl) against SHA.jl, and the standard-name API.
using Test, ForgedPQ, JSON, SHA, CodecZlib

const SLH_LONG = get(ENV, "FORGEDPQ_LONG_TESTS", "") == "1"
slh_kat(f) = JSON.parse(String(transcode(GzipDecompressor, read(joinpath(@__DIR__, "kat", f)))))
slh_mod(ps) = getfield(ForgedPQ, Symbol(replace(ps, "SLH-DSA-" => "SLHDSA_", "-" => "_")))
slh_hex(x) = hex2bytes(x)
# A signature in a small (s) set takes about a second. By default each s-set group runs its first
# test, plus the sigVer tests that need no signing; FORGEDPQ_LONG_TESTS=1 runs every test.
slh_all(ps) = SLH_LONG || endswith(ps, "f")

function slh_sign_as(M, iface, ph, sk, msg, ctx, hash, rnd)
    iface == "internal" && return M.sign_internal(sk, msg, rnd)
    if ph == "pure"
        rnd === nothing ? M.sign(sk, msg; context = ctx, hedged = false) : M.sign(sk, msg, rnd; context = ctx)
    else
        rnd === nothing ? M.sign_prehash(sk, msg, hash; context = ctx, hedged = false) :
                          M.sign_prehash(sk, msg, hash, rnd; context = ctx)
    end
end

@testset "SHA-256/512 midstate engine vs SHA.jl" begin
    S2 = ForgedPQ.Sha2; s = S2.Scratch()
    @test S2.K256[1] == 0x428a2f98 && S2.K512[80] == 0x6c44198c4a475817 && S2.IV512[8] == 0x5be0cd19137e2179
    bad = 0
    for len in 0:300
        d = rand(UInt8, len)
        S2.sha256(d, s) == SHA.sha256(d) || (bad += 1)
        S2.sha512(d, s) == SHA.sha512(d) || (bad += 1)
    end
    @test bad == 0
    blk = rand(UInt8, 128)
    for len in (0, 22, 55, 56, 64, 111, 112, 200)
        m = rand(UInt8, len)
        @test S2.finish256!(zeros(UInt8, 32), 32, S2.midstate256(blk, s), m, len, 64, s) == SHA.sha256(vcat(blk[1:64], m))
        @test S2.finish512!(zeros(UInt8, 64), 64, S2.midstate512(blk, s), m, len, 128, s) == SHA.sha512(vcat(blk, m))
    end
end

for g in slh_kat("slhdsa_keygen.json.gz")
    M = slh_mod(g["set"])
    @testset "$(g["set"]) ACVP KeyGen ($(length(g["tests"])))" begin
        for tc in g["tests"]
            kp = M.keygen(vcat(slh_hex(tc["skSeed"]), slh_hex(tc["skPrf"]), slh_hex(tc["pkSeed"])))
            @test kp.public_key == slh_hex(tc["pk"])
            @test kp.secret_key == slh_hex(tc["sk"])
        end
    end
end

for g in slh_kat("slhdsa_siggen.json.gz")
    M = slh_mod(g["set"]); tests = slh_all(g["set"]) ? g["tests"] : first(g["tests"], 1)
    label = "$(g["set"]) ACVP SigGen $(g["interface"])/$(g["preHash"])$(g["deterministic"] ? " det" : "") ($(length(tests)))"
    @testset "$label" begin
        for tc in tests
            rnd = isempty(tc["addrnd"]) ? nothing : slh_hex(tc["addrnd"])
            sig = slh_sign_as(M, g["interface"], g["preHash"], slh_hex(tc["sk"]), slh_hex(tc["message"]),
                              slh_hex(tc["context"]), tc["hashAlg"], rnd)
            @test length(sig) == tc["sigLen"] == M.SIGNATURE_BYTES
            @test bytes2hex(sha256(sig)) == tc["sigSha256"]
        end
    end
end

for g in slh_kat("slhdsa_sigver.json.gz")
    M = slh_mod(g["set"])
    tests = slh_all(g["set"]) ? g["tests"] : [tc for (i, tc) in enumerate(g["tests"]) if i == 1 || tc["kind"] == "full"]
    @testset "$(g["set"]) ACVP SigVer $(g["interface"])/$(g["preHash"]) ($(length(tests)))" begin
        for tc in tests
            msg = slh_hex(tc["message"]); ctx = slh_hex(tc["context"])
            sig = if tc["kind"] == "full"
                slh_hex(tc["signature"])
            else
                rnd = isempty(tc["addrnd"]) ? nothing : slh_hex(tc["addrnd"])
                base = slh_sign_as(M, g["interface"], g["preHash"], slh_hex(tc["sk"]), msg, ctx, tc["hashAlg"], rnd)
                tc["kind"] == "truncate" ? base[1:tc["sigLen"]] :
                tc["kind"] == "extend" ? vcat(base, slh_hex(tc["extend"])) :
                (for (i, b) in tc["edits"]; base[i] = UInt8(b); end; base)
            end
            @test bytes2hex(sha256(sig)) == tc["sigSha256"]        # the ACVP signature, rebuilt exactly
            pk = slh_hex(tc["pk"])
            ok = g["interface"] == "internal" ? M.verify_internal(pk, msg, sig) :
                 g["preHash"] == "pure" ? M.verify(pk, msg, sig; context = ctx) :
                 M.verify_prehash(pk, msg, sig, tc["hashAlg"]; context = ctx)
            @test ok == tc["testPassed"]
        end
    end
end

# Secret buffers, checked in a child process (the spies redefine package methods): every signing
# and key-generation context is zeroed on return and on an exception, and so are the OS random
# bytes (keygen seed, hedged addrnd) and HMAC's key blocks.
const SLH_WIPE_CHILD = raw"""
using ForgedPQ, Random
const S = ForgedPQ.SLHDSA
const SPY = Ref(false); const CTXS = S.Ctx[]; const RNDS = Vector{UInt8}[]; const WIPED = Vector{UInt8}[]
S.new_ctx(p::S.Params, pkseed::Vector{UInt8}, skseed::Vector{UInt8}) = (c = S.Ctx(p, pkseed, skseed); SPY[] && push!(CTXS, c); c)
function ForgedPQ.Wipe.wipe!(x::Vector{UInt8})
    SPY[] && push!(WIPED, x)
    invoke(ForgedPQ.Wipe.wipe!, Tuple{Array}, x)
end
function Random.rand(rd::RandomDevice, ::Type{UInt8}, n::Int)
    r = invoke(rand, Tuple{Random.AbstractRNG, Type{UInt8}, Integer}, rd, UInt8, n)
    SPY[] && push!(RNDS, r); r
end
# Every byte or word array in the context and its SHA-2 scratch, except PK.seed and the ADRS copy
# (public), found by reflection so a buffer added later is covered without editing this list.
arrays(x) = [getfield(x, f) for f in fieldnames(typeof(x)) if getfield(x, f) isa Vector && f ∉ (:pkseed, :adrs2)]
zeroed(c::S.Ctx) = all(b -> all(iszero, b), vcat(arrays(c), arrays(c.s)))
function spied(f)
    foreach(empty!, (CTXS, RNDS, WIPED)); SPY[] = true
    try f() catch e e finally SPY[] = false end
end
check(id, M, ok) = (println("CHECK\t", id, "\t", M.NAME, "\t", ok); flush(stdout))
for M in (SLHDSA_SHA2_128f, SLHDSA_SHAKE_128f, SLHDSA_SHA2_192f)
    kp = spied(() -> M.keygen())
    check("keygen", M, kp isa NamedTuple && length(CTXS) == 1 && zeroed(CTXS[1]) && length(CTXS[1].skseed) == M.SEED_BYTES ÷ 3 &&
                       length(RNDS) == 1 && all(iszero, RNDS[1]))
    msg = rand(UInt8, 33)
    sig = spied(() -> M.sign(kp.secret_key, msg))
    check("sign", M, sig isa Vector{UInt8} && length(CTXS) == 1 && zeroed(CTXS[1]) && length(CTXS[1].skseed) == M.SEED_BYTES ÷ 3 &&
                     length(RNDS) == 1 && all(iszero, RNDS[1]))
    # HMAC (SHA2 sets): its key blocks are among the wiped buffers, zero afterwards
    check("hmac", M, !occursin("SHA2", M.NAME) || (count(b -> length(b) in (64, 128) && all(iszero, b), WIPED) >= 3))
    e = spied(() -> M.sign_prehash(kp.secret_key, msg, "SHA2-256"; hedged = false))
    check("prehash", M, e isa Vector{UInt8} && length(CTXS) == 1 && zeroed(CTXS[1]))
end
"""

@testset "SLH-DSA secret buffers wiped (child process)" begin
    proj = Base.active_project()
    projflag = proj === nothing ? String[] : ["--project=$proj"]
    cmd = addenv(`$(Base.julia_cmd()) --startup-file=no $projflag -e $SLH_WIPE_CHILD`,
                 "JULIA_LOAD_PATH" => join(LOAD_PATH, Sys.iswindows() ? ';' : ':'))
    out = IOBuffer(); err = IOBuffer()
    proc = run(pipeline(ignorestatus(cmd); stdout = out, stderr = err))
    got = Dict{Tuple{String, String}, Bool}()
    for l in eachline(seekstart(out))
        f = split(l, '\t')
        length(f) == 4 && f[1] == "CHECK" && (got[(f[2], f[3])] = f[4] == "true")
    end
    success(proc) || print(stderr, String(take!(err)))
    @test success(proc)
    for set in ("SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f", "SLH-DSA-SHA2-192f"), id in ("keygen", "sign", "hmac", "prehash")
        @test (set, id, get(got, (id, set), false)) == (set, id, true)
    end
end

@testset "SLH-DSA API: $(M.NAME)" for M in (SLHDSA_SHA2_128f, SLHDSA_SHAKE_128f, SLHDSA_SHA2_192f, SLHDSA_SHAKE_192f,
                                          SLHDSA_SHA2_256f, SLHDSA_SHAKE_256f,
                                          (SLH_LONG ? (SLHDSA_SHA2_128s, SLHDSA_SHAKE_128s, SLHDSA_SHA2_192s,
                                                       SLHDSA_SHAKE_192s, SLHDSA_SHA2_256s, SLHDSA_SHAKE_256s) : ())...)
    pk, sk = M.keygen()
    @test (length(pk), length(sk)) == (M.PUBLIC_KEY_BYTES, M.SECRET_KEY_BYTES)
    msg = rand(UInt8, 100); ctx = rand(UInt8, 7)
    sig = M.sign(sk, msg; context = ctx)
    @test length(sig) == M.SIGNATURE_BYTES
    @test M.verify(pk, msg, sig; context = ctx)
    @test !M.verify(pk, msg, sig)                                   # context is bound
    @test !M.verify(pk, rand(UInt8, 100), sig; context = ctx)
    s2 = copy(sig); s2[end ÷ 2] ⊻= 0x01
    @test !M.verify(pk, msg, s2; context = ctx)
    @test M.sign(sk, msg; hedged = false) == M.sign(sk, msg; hedged = false)   # deterministic variant
    @test M.sign(sk, msg) != M.sign(sk, msg)                                  # hedged
    ps = M.sign_prehash(sk, msg, "SHA2-256")
    @test M.verify_prehash(pk, msg, ps, "SHA2-256") && !M.verify_prehash(pk, msg, ps, "SHA2-512")
    @test !M.verify(pk, msg, ps)                                    # pure and pre-hash are separated
    si = M.sign_internal(sk, msg)
    @test M.verify_internal(pk, msg, si) && !M.verify(pk, msg, si)
    @test !M.verify(sig, msg, pk)                                   # swapped arguments
    @test_throws ArgumentError M.sign(pk, msg)
    @test_throws ArgumentError M.sign(sk, msg; context = zeros(UInt8, 256))
    @test !M.verify(pk, msg, sig; context = zeros(UInt8, 256))
    @test_throws ArgumentError M.keygen(rand(UInt8, M.SEED_BYTES - 1))
    v = view(vcat(UInt8[0], msg), 2:101)                            # non-Vector inputs
    @test M.verify(view(pk, :), v, view(sig, :); context = ctx)
end
