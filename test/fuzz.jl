# test/fuzz.jl — malformed input through every public operation. Random bytes at boundary and
# random lengths must give a normal result (`false` from a verifier) or an ArgumentError; any other
# exception (BoundsError, InexactError, MethodError, ...) is a failure.
using Test, ForgedPQ, Random

const FUZZ_N = parse(Int, get(ENV, "FORGEDPQ_FUZZ_N", get(ENV, "FORGEDPQ_LONG_TESTS", "") == "1" ? "1000" : "40"))

lengths(n) = unique(filter(>=(0), [0, 1, n - 1, n, n + 1, 2n, rand(0:3n)]))
garbage(n) = rand(UInt8, n)

# :ok, or the exception if it is not an ArgumentError
function outcome(f)
    try
        f(); :ok
    catch e
        e isa ArgumentError ? :ok : e
    end
end

function fuzz!(bad, name, f)
    r = outcome(f)
    r === :ok || push!(bad, "$name: $(typeof(r)): $(sprint(showerror, r)[1:min(end, 120)])")
end

@testset "Malformed input: $(M.NAME)" for M in (MLKEM512, MLKEM768, MLKEM1024)
    pk, sk = M.keygen(); ct, _ = M.encaps(pk); bad = String[]
    for _ in 1:FUZZ_N
        for n in lengths(M.PUBLIC_KEY_BYTES)
            fuzz!(bad, "encaps(pk[$n])", () -> M.encaps(garbage(n)))
            fuzz!(bad, "encaps(pk[$n], m)", () -> M.encaps(garbage(n), garbage(32)))
            fuzz!(bad, "check_public_key[$n]", () -> M.check_public_key(garbage(n)) isa Bool || error("not Bool"))
        end
        for n in lengths(M.SECRET_KEY_BYTES)
            fuzz!(bad, "decaps(sk[$n], ct)", () -> M.decaps(garbage(n), ct))
            fuzz!(bad, "check_secret_key[$n]", () -> M.check_secret_key(garbage(n)) isa Bool || error("not Bool"))
        end
        for n in lengths(M.CIPHERTEXT_BYTES)
            fuzz!(bad, "decaps(sk, ct[$n])", () -> M.decaps(sk, garbage(n)))
        end
        for n in lengths(M.SEED_BYTES)
            fuzz!(bad, "keygen(seed[$n])", () -> M.keygen(garbage(n)))
        end
        for n in lengths(32)
            fuzz!(bad, "encaps(pk, m[$n])", () -> M.encaps(pk, garbage(n)))
        end
    end
    @test isempty(bad) || (foreach(println, unique(bad)); false)
end

@testset "Malformed input: $(M.NAME)" for M in (MLDSA44, MLDSA65, MLDSA87)
    pk, sk = M.keygen(); msg = garbage(40); sig = M.sign(sk, msg); bad = String[]
    for _ in 1:FUZZ_N
        for n in lengths(M.SIGNATURE_BYTES)
            fuzz!(bad, "verify(sig[$n])", () -> M.verify(pk, msg, garbage(n)) && error("forged signature accepted"))
            fuzz!(bad, "verify_prehash(sig[$n])", () -> M.verify_prehash(pk, msg, garbage(n), "SHA2-256") && error("accepted"))
        end
        for n in lengths(M.PUBLIC_KEY_BYTES)
            fuzz!(bad, "verify(pk[$n])", () -> M.verify(garbage(n), msg, sig) && error("accepted under a random key"))
        end
        for n in lengths(M.SECRET_KEY_BYTES)
            fuzz!(bad, "sign(sk[$n])", () -> M.sign(garbage(n), msg))
            fuzz!(bad, "sign_prehash(sk[$n])", () -> M.sign_prehash(garbage(n), msg, "SHA2-512"))
        end
        for n in lengths(M.SEED_BYTES)
            fuzz!(bad, "keygen(seed[$n])", () -> M.keygen(garbage(n)))
        end
        for n in lengths(32)
            fuzz!(bad, "sign(rnd[$n])", () -> M.sign(sk, msg, garbage(n)))
        end
        for n in (0, 255, 256, rand(257:600))
            fuzz!(bad, "sign(context[$n])", () -> M.sign(sk, msg; context = garbage(n)))
            fuzz!(bad, "verify(context[$n])", () -> M.verify(pk, msg, sig; context = garbage(n)))
        end
        fuzz!(bad, "sign_prehash(hash)", () -> M.sign_prehash(sk, msg, randstring(rand(0:12))))
        fuzz!(bad, "verify_prehash(hash)", () -> M.verify_prehash(pk, msg, sig, randstring(rand(0:12))))
    end
    @test isempty(bad) || (foreach(println, unique(bad)); false)
end

@testset "Malformed input: $(M.NAME)" for M in (Falcon512, Falcon1024)
    pk, sk = M.keygen(); msg = garbage(40); sig = M.sign(sk, msg); bad = String[]
    for _ in 1:max(1, FUZZ_N ÷ 4)
        for n in lengths(M.SIGNATURE_BYTES)
            fuzz!(bad, "verify(sig[$n])", () -> M.verify(pk, msg, garbage(n)) && error("forged signature accepted"))
        end
        for n in lengths(M.PUBLIC_KEY_BYTES)
            fuzz!(bad, "verify(pk[$n])", () -> M.verify(garbage(n), msg, sig) && error("accepted under a random key"))
        end
        for n in lengths(M.SECRET_KEY_BYTES)
            fuzz!(bad, "sign(sk[$n])", () -> M.sign(garbage(n), msg))
        end
    end
    @test isempty(bad) || (foreach(println, unique(bad)); false)
end

@testset "Malformed input: X-Wing and X25519" begin
    pk, sk = XWing.keygen(); ct, _ = XWing.encaps(pk); bad = String[]
    for _ in 1:FUZZ_N
        for n in lengths(1216)
            fuzz!(bad, "XWing.encaps(pk[$n])", () -> XWing.encaps(garbage(n)))
        end
        for n in lengths(1120)
            fuzz!(bad, "XWing.decaps(sk, ct[$n])", () -> XWing.decaps(sk, garbage(n)))
        end
        for n in lengths(32)
            fuzz!(bad, "XWing.decaps(sk[$n], ct)", () -> XWing.decaps(garbage(n), ct))
            fuzz!(bad, "XWing.keygen(seed[$n])", () -> XWing.keygen(garbage(n)))
            fuzz!(bad, "x25519(k[$n], u)", () -> X25519.x25519(garbage(n), garbage(32)))
            fuzz!(bad, "x25519(k, u[$n])", () -> X25519.x25519(garbage(32), garbage(n)))
            fuzz!(bad, "x25519_base(k[$n])", () -> X25519.x25519_base(garbage(n)))
        end
        for n in lengths(64)
            fuzz!(bad, "XWing.encaps(pk, eseed[$n])", () -> XWing.encaps(pk, garbage(n)))
        end
    end
    @test isempty(bad) || (foreach(println, unique(bad)); false)
end

@testset "Malformed input: Shamir" begin
    bad = String[]
    for _ in 1:FUZZ_N
        k = rand(-2:6); n = rand(-2:8); s = garbage(rand(0:70))
        fuzz!(bad, "shamir_share_bytes(k=$k, n=$n, $(length(s)) bytes)", () -> shamir_share_bytes(s, k, n))
        shares = [(rand(-5:20), big(rand(UInt128))) for _ in 1:rand(0:6)]
        fuzz!(bad, "shamir_reconstruct(k=$k)", () -> shamir_reconstruct(shares, k))
        fuzz!(bad, "shamir_reconstruct_bytes(k=$k)", () -> shamir_reconstruct_bytes(shares, k, rand(-1:70)))
    end
    @test isempty(bad) || (foreach(println, unique(bad)); false)
end
