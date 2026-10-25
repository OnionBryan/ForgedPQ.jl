# test/constant_time.jl — the machine code of the secret-data primitives SECURITY.md lists as
# constant-time, as compiled on this machine (x86-64 or AArch64): no conditional branch at all,
# except one loop test in the two loops of fixed trip count (Falcon's integer div and sqrt), and
# no call that would hide code from the check. An `if` on data adds a branch. CI runs it on both
# architectures.
using Test, ForgedPQ, InteractiveUtils

const CT_D = MLDSA.Category3
const CT_FP = ForgedPQ.FNDSA.FalconFpr
const CT_X = X25519

# (name, function, argument types, fixed-count loops allowed)
const CT_PRIMITIVES = [
    ("ML-KEM fqmul", MLKEM.fqmul, (Int16, Int16), false),
    ("ML-KEM montgomery_reduce", MLKEM.montgomery_reduce, (Int32,), false),
    ("ML-KEM barrett_reduce", MLKEM.barrett_reduce, (Int16,), false),
    ("ML-KEM caddq", MLKEM.caddq, (Int16,), false),
    ("ML-KEM kyber_cmov_int16", MLKEM.kyber_cmov_int16, (Int16, Int16, UInt16), false),
    ("ML-DSA montgomery_reduce", MLDSA.montgomery_reduce, (Int64,), false),
    ("ML-DSA caddq", MLDSA.caddq, (Int32,), false),
    ("ML-DSA power2round", MLDSA.power2round, (Int32,), false),
    ("ML-DSA decompose", CT_D.decompose, (Int32,), false),
    ("ML-DSA make_hint", CT_D.make_hint, (Int32, Int32), false),
    ("X25519 fe_add", CT_X.fe_add, (CT_X.Fe, CT_X.Fe), false),
    ("X25519 fe_sub", CT_X.fe_sub, (CT_X.Fe, CT_X.Fe), false),
    ("X25519 fe_mul", CT_X.fe_mul, (CT_X.Fe, CT_X.Fe), false),
    ("Falcon fpr add", CT_FP.add, (CT_FP.Fpr, CT_FP.Fpr), false),
    ("Falcon fpr mul", CT_FP.mul, (CT_FP.Fpr, CT_FP.Fpr), false),
    ("Falcon fpr div", CT_FP.div, (CT_FP.Fpr, CT_FP.Fpr), true),     # 55 iterations
    ("Falcon fpr sqrt", sqrt, (CT_FP.Fpr,), true),                    # 54 iterations
    ("Falcon fpr rint", CT_FP.rint, (CT_FP.Fpr,), false),
    ("Falcon fpr floor", floor, (CT_FP.Fpr,), false),
    ("Falcon fpr lt", CT_FP.lt, (CT_FP.Fpr, CT_FP.Fpr), false),
    ("Falcon fpr_of", CT_FP.fpr_of, (Int64,), false),
]

const CONDBR = r"^\s+(j(?!mp\b)[a-z]+|b\.[a-z]+|cbn?z|tbn?z)\s"
const CALL = r"^\s+(bl|blr|call[a-z]*)\s"

# Conditional branch and call instructions in the native code of f.
function branches(f, T)
    lines = split(sprint(io -> code_native(io, f, T; debuginfo = :none)), '\n')
    [strip(l) for l in lines if occursin(CONDBR, l)], [strip(l) for l in lines if occursin(CALL, l)]
end

if Sys.ARCH in (:x86_64, :aarch64)
    @testset "Constant-time machine code ($(Sys.ARCH)): $name" for (name, f, T, loop) in CT_PRIMITIVES
        conds, calls = branches(f, T)
        @test isempty(calls)
        @test length(conds) <= (loop ? 1 : 0)
    end
else
    @info "Constant-time machine-code check skipped on $(Sys.ARCH)"
end
