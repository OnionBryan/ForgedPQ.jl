"""
SLH-DSA (FIPS 205): the stateless hash-based signature standard, in all twelve parameter sets
(SHA2 and SHAKE, at security categories 1, 3 and 5, each small (`s`) or fast (`f`)). Its security
rests only on the hash function. Generates SLHDSA.SHA2_128s ... SLHDSA.SHAKE_256f.

Function and step names follow the FIPS 205 algorithms they implement. ADRS is a 32-byte
buffer mutated in place, as in the specification.
"""
module SLHDSA

using Random
import SHA
import ..Keccak, ..Sha2
using ..Wipe: wipe!
using ..Bytes: catbytes
import ..Prehash: HASH_OIDS, prehash_message

struct Params
    name::String
    sha2::Bool
    n::Int; h::Int; d::Int; hp::Int; a::Int; k::Int; m::Int
    cat::Int
end

# FIPS 205 Table 2. w = 16 (lg_w = 4) in every set, so len1 = 2n and len2 = 3.
const LGW = 4
const W = 16
wlen(p::Params) = 2p.n + 3
pk_bytes(p::Params) = 2p.n
sk_bytes(p::Params) = 4p.n
sig_bytes(p::Params) = (1 + p.k * (1 + p.a) + p.h + p.d * wlen(p)) * p.n

const PARAMS = Pair{Symbol, Params}[]
for (hash, sha2) in (("SHA2", true), ("SHAKE", false)),
    (lv, n, h, d, hp, a, k, m, cat) in (("128s", 16, 63, 7, 9, 12, 14, 30, 1), ("128f", 16, 66, 22, 3, 6, 33, 34, 1),
                                         ("192s", 24, 63, 7, 9, 14, 17, 39, 3), ("192f", 24, 66, 22, 3, 8, 33, 42, 3),
                                         ("256s", 32, 64, 8, 8, 14, 22, 47, 5), ("256f", 32, 68, 17, 4, 9, 35, 49, 5))
    push!(PARAMS, Symbol(hash, "_", lv) => Params("SLH-DSA-$hash-$lv", sha2, n, h, d, hp, a, k, m, cat))
end

# ── ADRS (FIPS 205 §4.2) ──────────────────────────────────────────────────────
const WOTS_HASH, WOTS_PK, TREE, FORS_TREE, FORS_ROOTS, WOTS_PRF, FORS_PRF = 0, 1, 2, 3, 4, 5, 6

@inline function put32!(a::Vector{UInt8}, off::Int, v::Integer)
    x = UInt32(v)
    @inbounds a[off+1] = (x >> 24) % UInt8; a[off+2] = (x >> 16) % UInt8
    @inbounds a[off+3] = (x >> 8) % UInt8;  a[off+4] = x % UInt8
    a
end
@inline get32(a::Vector{UInt8}, off::Int) =
    @inbounds UInt32(a[off+1]) << 24 | UInt32(a[off+2]) << 16 | UInt32(a[off+3]) << 8 | UInt32(a[off+4])

set_layer!(a, l) = put32!(a, 0, l)
set_tree!(a, t::UInt64) = (put32!(a, 4, 0); put32!(a, 8, t >> 32); put32!(a, 12, t % UInt32))
set_type!(a, y) = (put32!(a, 16, y); fill!(view(a, 21:32), 0x00); a)     # setTypeAndClear
set_keypair!(a, i) = put32!(a, 20, i)
set_chain!(a, i) = put32!(a, 24, i)
set_height!(a, z) = put32!(a, 24, z)
set_hash!(a, i) = put32!(a, 28, i)
set_index!(a, i) = put32!(a, 28, i)
get_keypair(a) = get32(a, 20)
get_index(a) = get32(a, 28)

# ── Hash functions (FIPS 205 §11) ─────────────────────────────────────────────
# Per signing or verifying call: PK.seed, SK.seed (empty when verifying), the midstates of
# PK.seed ‖ zero padding (SHA2) and scratch, none of it shared between calls.
mutable struct Ctx
    p::Params
    pkseed::Vector{UInt8}
    skseed::Vector{UInt8}
    buf::Vector{UInt8}      # hash input
    node::Vector{UInt8}     # n-byte SHAKE output
    pair::Vector{UInt8}     # H input lnode ‖ rnode
    tbuf::Vector{UInt8}     # WOTS chain values, FORS roots
    adrs2::Vector{UInt8}    # skADRS, wotspkADRS, forspkADRS
    mid256::Sha2.State256
    mid512::Sha2.State512
    s::Sha2.Scratch
end
function Ctx(p::Params, pkseed::Vector{UInt8}, skseed::Vector{UInt8})
    s = Sha2.Scratch(); n = p.n
    blk = zeros(UInt8, 128); copyto!(blk, 1, pkseed, 1, n)
    tl = max(wlen(p), p.k) * n
    Ctx(p, pkseed, skseed, zeros(UInt8, 128 + 32 + tl), zeros(UInt8, n), zeros(UInt8, 2n), zeros(UInt8, tl),
        zeros(UInt8, 32), Sha2.midstate256(blk, s), Sha2.midstate512(blk, s), s)
end
wipe_ctx!(c::Ctx) = wipe!(c.skseed, c.buf, c.node, c.pair, c.tbuf, c.s.w32, c.s.w64, c.s.pad)
# Every context is made here (test/slhdsa.jl hooks it to check the wiping).
new_ctx(p::Params, pkseed::Vector{UInt8}, skseed::Vector{UInt8}) = Ctx(p, pkseed, skseed)

# Hash(PK.seed, ADRS, M) truncated to n bytes, into out[1:n]: F, H and T_l, and PRF with M =
# SK.seed. SHAKE: SHAKE256(PK.seed ‖ ADRS ‖ M). SHA2: SHA-256(PK.seed ‖ 0^(64−n) ‖ ADRSc ‖ M),
# with SHA-512(PK.seed ‖ 0^(128−n) ‖ ADRSc ‖ M) for H and T (`wide`) in categories 3 and 5.
function thash!(out::AbstractVector{UInt8}, c::Ctx, adrs::Vector{UInt8}, msg::AbstractVector{UInt8},
                mlen::Int, wide::Bool)
    p = c.p; n = p.n; buf = c.buf
    checkbounds(msg, 1:mlen); checkbounds(buf, 1:n+32+mlen)
    if p.sha2
        # ADRSc = ADRS[3] ‖ ADRS[8:16] ‖ ADRS[19] ‖ ADRS[20:32] (0-based byte ranges)
        @inbounds begin
            buf[1] = adrs[4]
            for i in 1:8; buf[1+i] = adrs[8+i]; end
            buf[10] = adrs[20]
            for i in 1:12; buf[10+i] = adrs[20+i]; end
            for i in 1:mlen; buf[22+i] = msg[i]; end
        end
        if wide && p.cat > 1
            Sha2.finish512!(out, n, c.mid512, buf, 22 + mlen, 128, c.s)
        else
            Sha2.finish256!(out, n, c.mid256, buf, 22 + mlen, 64, c.s)
        end
    else
        @inbounds begin
            for i in 1:n; buf[i] = c.pkseed[i]; end
            for i in 1:32; buf[n+i] = adrs[i]; end
            for i in 1:mlen; buf[n+32+i] = msg[i]; end
        end
        Keccak.shake256!(c.node, view(buf, 1:n+32+mlen), n)
        copyto!(out, 1, c.node, 1, n)
    end
    out
end
f!(out, c::Ctx, adrs, x) = thash!(out, c, adrs, x, c.p.n, false)
prf!(out, c::Ctx, adrs) = thash!(out, c, adrs, c.skseed, c.p.n, false)
function h!(out, c::Ctx, adrs, l, r)
    n = c.p.n
    copyto!(c.pair, 1, l, 1, n); copyto!(c.pair, n + 1, r, 1, n)
    thash!(out, c, adrs, c.pair, 2n, true)
end

hash_full(p::Params, data, s::Sha2.Scratch = Sha2.Scratch()) = p.cat == 1 ? Sha2.sha256(data, s) : Sha2.sha512(data, s)

# HMAC-SHA-256 or HMAC-SHA-512 (FIPS 198-1). The key blocks, both hash inputs and the SHA-2 scratch
# that held them are wiped.
function hmac(p::Params, key::AbstractVector{UInt8}, msg::AbstractVector{UInt8})
    B = p.cat == 1 ? 64 : 128
    k0 = zeros(UInt8, B); copyto!(k0, 1, key, 1, length(key))
    ipad = k0 .⊻ 0x36; opad = k0 .⊻ 0x5c
    s = Sha2.Scratch(); a = UInt8[]; inner = UInt8[]; b = UInt8[]
    try
        a = catbytes(ipad, msg)
        inner = hash_full(p, a, s)
        b = catbytes(opad, inner)
        return hash_full(p, b, s)
    finally
        wipe!(k0, ipad, opad, a, inner, b, s.w32, s.w64, s.pad)
    end
end

function mgf1(p::Params, seed::Vector{UInt8}, len::Int)
    out = UInt8[]; ctr = UInt32(0)
    while length(out) < len
        append!(out, hash_full(p, catbytes(seed, UInt8[(ctr >> 24) % UInt8, (ctr >> 16) % UInt8, (ctr >> 8) % UInt8, ctr % UInt8])))
        ctr += 1
    end
    out[1:len]
end

"PRF_msg(SK.prf, opt_rand, M); the copies holding SK.prf are wiped."
function prf_msg(p::Params, skprf, optrand, M)
    p.sha2 && return hmac(p, skprf, catbytes(optrand, M))[1:p.n]
    inp = catbytes(skprf, optrand, M)
    try
        Keccak.shake256(inp, p.n)
    finally
        wipe!(inp)
    end
end

"H_msg(R, PK.seed, PK.root, M)"
h_msg(p::Params, R, pkseed, pkroot, M) =
    p.sha2 ? mgf1(p, catbytes(R, pkseed, hash_full(p, catbytes(R, pkseed, pkroot, M))), p.m) :
             Keccak.shake256(catbytes(R, pkseed, pkroot, M), p.m)

# ── Algorithm 4: base_2b ─────────────────────────────────────────────────────
function base_2b(x::AbstractVector{UInt8}, b::Int, outlen::Int)
    out = Vector{Int}(undef, outlen); i = 1; bits = 0; total = UInt64(0)
    for o in 1:outlen
        while bits < b
            total = (total << 8) | x[i]; i += 1; bits += 8
        end
        bits -= b
        out[o] = Int((total >> bits) & ((UInt64(1) << b) - 1))
        total &= (UInt64(1) << bits) - 1
    end
    out
end

# ── WOTS+ (Algorithms 5–8) ───────────────────────────────────────────────────
# Base-16 digits of M and of its checksum, shifted left by (8 − (len2·lg_w mod 8)) mod 8 = 4.
function wots_digits(p::Params, M::AbstractVector{UInt8})
    msg = base_2b(M, LGW, 2p.n)
    csum = 0
    for v in msg; csum += W - 1 - v; end
    csum <<= 4
    append!(msg, base_2b(UInt8[(csum >> 8) % UInt8, csum % UInt8], LGW, 3))
end

function chain!(x, c::Ctx, i::Int, s::Int, adrs)
    for j in i:i+s-1
        set_hash!(adrs, j)
        f!(x, c, adrs, x)
    end
    x
end

function wots_pkgen!(out, c::Ctx, adrs)
    n = c.p.n; L = wlen(c.p); a2 = c.adrs2; tb = c.tbuf
    copyto!(a2, adrs); set_type!(a2, WOTS_PRF); set_keypair!(a2, get_keypair(adrs))
    for i in 0:L-1
        set_chain!(a2, i)
        x = view(tb, i*n+1:(i+1)*n)
        prf!(x, c, a2)
        set_chain!(adrs, i)
        chain!(x, c, 0, W - 1, adrs)
    end
    copyto!(a2, adrs); set_type!(a2, WOTS_PK); set_keypair!(a2, get_keypair(adrs))
    thash!(out, c, a2, tb, L * n, true)
end

function wots_sign(c::Ctx, M, adrs)
    n = c.p.n; L = wlen(c.p); msg = wots_digits(c.p, M); a2 = c.adrs2
    sig = Vector{UInt8}(undef, L * n)
    copyto!(a2, adrs); set_type!(a2, WOTS_PRF); set_keypair!(a2, get_keypair(adrs))
    for i in 0:L-1
        set_chain!(a2, i)
        x = view(sig, i*n+1:(i+1)*n)
        prf!(x, c, a2)
        set_chain!(adrs, i)
        chain!(x, c, 0, msg[i+1], adrs)
    end
    sig
end

function wots_pk_from_sig!(out, c::Ctx, sig, M, adrs)
    n = c.p.n; L = wlen(c.p); msg = wots_digits(c.p, M); tb = c.tbuf; a2 = c.adrs2
    for i in 0:L-1
        set_chain!(adrs, i)
        x = view(tb, i*n+1:(i+1)*n)
        copyto!(x, 1, sig, i*n + 1, n)
        chain!(x, c, msg[i+1], W - 1 - msg[i+1], adrs)
    end
    copyto!(a2, adrs); set_type!(a2, WOTS_PK); set_keypair!(a2, get_keypair(adrs))
    thash!(out, c, a2, tb, L * n, true)
end

# ── XMSS (Algorithms 9–11) ───────────────────────────────────────────────────
function xmss_node(c::Ctx, i::Integer, z::Int, adrs)
    node = Vector{UInt8}(undef, c.p.n)
    if z == 0
        set_type!(adrs, WOTS_HASH); set_keypair!(adrs, i)
        wots_pkgen!(node, c, adrs)
    else
        l = xmss_node(c, 2i, z - 1, adrs)
        r = xmss_node(c, 2i + 1, z - 1, adrs)
        set_type!(adrs, TREE); set_height!(adrs, z); set_index!(adrs, i)
        h!(node, c, adrs, l, r)
    end
    node
end

function xmss_sign(c::Ctx, M, idx::UInt32, adrs)
    n = c.p.n; hp = c.p.hp
    auth = Vector{UInt8}(undef, hp * n)
    for j in 0:hp-1
        copyto!(auth, j*n + 1, xmss_node(c, (idx >> j) ⊻ 0x1, j, adrs), 1, n)
    end
    set_type!(adrs, WOTS_HASH); set_keypair!(adrs, idx)
    append!(wots_sign(c, M, adrs), auth)
end

function xmss_pk_from_sig(c::Ctx, idx::UInt32, sigx, M, adrs)
    n = c.p.n; L = wlen(c.p)
    node = Vector{UInt8}(undef, n)
    set_type!(adrs, WOTS_HASH); set_keypair!(adrs, idx)
    wots_pk_from_sig!(node, c, view(sigx, 1:L*n), M, adrs)
    set_type!(adrs, TREE); set_index!(adrs, idx)
    for k in 0:c.p.hp-1
        set_height!(adrs, k + 1)
        auth = view(sigx, (L + k)*n + 1 : (L + k + 1)*n)
        if (idx >> k) & 0x1 == 0
            set_index!(adrs, get_index(adrs) ÷ 2); h!(node, c, adrs, node, auth)
        else
            set_index!(adrs, (get_index(adrs) - 1) ÷ 2); h!(node, c, adrs, auth, node)
        end
    end
    node
end

# ── Hypertree (Algorithms 12–13) ─────────────────────────────────────────────
leaf_mask(p::Params) = (UInt64(1) << p.hp) - 1

function ht_sign(c::Ctx, M, idx_tree::UInt64, idx_leaf::UInt32)
    p = c.p
    adrs = zeros(UInt8, 32); set_tree!(adrs, idx_tree)
    sig = xmss_sign(c, M, idx_leaf, adrs)
    root = xmss_pk_from_sig(c, idx_leaf, sig, M, adrs)
    for j in 1:p.d-1
        idx_leaf = (idx_tree & leaf_mask(p)) % UInt32; idx_tree >>= p.hp
        set_layer!(adrs, j); set_tree!(adrs, idx_tree)
        s = xmss_sign(c, root, idx_leaf, adrs)
        append!(sig, s)
        j < p.d - 1 && (root = xmss_pk_from_sig(c, idx_leaf, s, root, adrs))
    end
    sig
end

function ht_verify(c::Ctx, M, sight, idx_tree::UInt64, idx_leaf::UInt32, pkroot)
    p = c.p; xl = (wlen(p) + p.hp) * p.n
    adrs = zeros(UInt8, 32); set_tree!(adrs, idx_tree)
    node = xmss_pk_from_sig(c, idx_leaf, view(sight, 1:xl), M, adrs)
    for j in 1:p.d-1
        idx_leaf = (idx_tree & leaf_mask(p)) % UInt32; idx_tree >>= p.hp
        set_layer!(adrs, j); set_tree!(adrs, idx_tree)
        node = xmss_pk_from_sig(c, idx_leaf, view(sight, j*xl+1:(j+1)*xl), node, adrs)
    end
    node == pkroot
end

# ── FORS (Algorithms 14–17) ──────────────────────────────────────────────────
function fors_skgen!(out, c::Ctx, adrs, idx::Integer)
    a2 = c.adrs2
    copyto!(a2, adrs); set_type!(a2, FORS_PRF); set_keypair!(a2, get_keypair(adrs)); set_index!(a2, idx)
    prf!(out, c, a2)
end

function fors_node(c::Ctx, i::Integer, z::Int, adrs)
    n = c.p.n; node = Vector{UInt8}(undef, n)
    if z == 0
        sk = Vector{UInt8}(undef, n)
        fors_skgen!(sk, c, adrs, i)
        set_height!(adrs, 0); set_index!(adrs, i)
        f!(node, c, adrs, sk)
        wipe!(sk)
    else
        l = fors_node(c, 2i, z - 1, adrs)
        r = fors_node(c, 2i + 1, z - 1, adrs)
        set_height!(adrs, z); set_index!(adrs, i)
        h!(node, c, adrs, l, r)
    end
    node
end

function fors_sign(c::Ctx, md, adrs)
    p = c.p; n = p.n; idxs = base_2b(md, p.a, p.k)
    sig = sizehint!(UInt8[], p.k * (p.a + 1) * n)
    for i in 0:p.k-1
        sk = Vector{UInt8}(undef, n)
        fors_skgen!(sk, c, adrs, (i << p.a) + idxs[i+1])
        append!(sig, sk)
        for j in 0:p.a-1
            append!(sig, fors_node(c, (i << (p.a - j)) + ((idxs[i+1] >> j) ⊻ 1), j, adrs))
        end
    end
    sig
end

function fors_pk_from_sig(c::Ctx, sigf, md, adrs)
    p = c.p; n = p.n; idxs = base_2b(md, p.a, p.k); roots = c.tbuf
    node = Vector{UInt8}(undef, n)
    for i in 0:p.k-1
        off = i * (p.a + 1) * n
        set_height!(adrs, 0); set_index!(adrs, (i << p.a) + idxs[i+1])
        f!(node, c, adrs, view(sigf, off+1:off+n))
        for j in 0:p.a-1
            auth = view(sigf, off + (j + 1)*n + 1 : off + (j + 2)*n)
            set_height!(adrs, j + 1)
            if (idxs[i+1] >> j) & 1 == 0
                set_index!(adrs, get_index(adrs) ÷ 2); h!(node, c, adrs, node, auth)
            else
                set_index!(adrs, (get_index(adrs) - 1) ÷ 2); h!(node, c, adrs, auth, node)
            end
        end
        copyto!(roots, i*n + 1, node, 1, n)
    end
    a2 = c.adrs2
    copyto!(a2, adrs); set_type!(a2, FORS_ROOTS); set_keypair!(a2, get_keypair(adrs))
    pk = Vector{UInt8}(undef, n)
    thash!(pk, c, a2, roots, p.k * n, true)
end

# ── SLH-DSA internal functions (Algorithms 18–20) ────────────────────────────
# md, idx_tree and idx_leaf from the message digest (Algorithm 19, lines 7–12).
function split_digest(p::Params, digest)
    ka = cld(p.k * p.a, 8); tb = cld(p.h - p.hp, 8); lb = cld(p.hp, 8)
    t = UInt64(0)
    for i in 1:tb; t = t << 8 | digest[ka+i]; end
    p.h - p.hp < 64 && (t &= (UInt64(1) << (p.h - p.hp)) - 1)
    l = UInt64(0)
    for i in 1:lb; l = l << 8 | digest[ka+tb+i]; end
    digest[1:ka], t, (l & leaf_mask(p)) % UInt32
end

"""Algorithm 18, slh_keygen_internal: `(pk, sk)` from SK.seed, SK.prf and PK.seed (n bytes each)."""
function keygen_internal(p::Params, skseed::AbstractVector{UInt8}, skprf::AbstractVector{UInt8}, pkseed::AbstractVector{UInt8})
    n = p.n
    (length(skseed), length(skprf), length(pkseed)) == (n, n, n) ||
        throw(ArgumentError("$(p.name) key generation takes three $n-byte seeds"))
    c = new_ctx(p, collect(UInt8, pkseed), collect(UInt8, skseed))
    try
        adrs = zeros(UInt8, 32); set_layer!(adrs, p.d - 1)
        root = xmss_node(c, 0, p.hp, adrs)
        return catbytes(c.pkseed, root), catbytes(skseed, skprf, c.pkseed, root)
    finally
        wipe_ctx!(c)
    end
end

"""Algorithm 19, slh_sign_internal: signs M as given. `addrnd` (n bytes) hedges the signature;
`nothing` is the deterministic variant (opt_rand = PK.seed)."""
function sign_internal(p::Params, M::AbstractVector{UInt8}, sk::AbstractVector{UInt8}, addrnd)
    n = p.n
    length(sk) == sk_bytes(p) || throw(ArgumentError("$(p.name) secret key must be $(sk_bytes(p)) bytes"))
    addrnd === nothing || length(addrnd) == n || throw(ArgumentError("$(p.name) addrnd must be $n bytes"))
    pkseed = sk[2n+1:3n]; pkroot = sk[3n+1:4n]; skprf = sk[n+1:2n]
    c = new_ctx(p, pkseed, sk[1:n])
    try
        R = prf_msg(p, skprf, addrnd === nothing ? pkseed : addrnd, M)
        md, idx_tree, idx_leaf = split_digest(p, h_msg(p, R, pkseed, pkroot, M))
        adrs = zeros(UInt8, 32)
        set_tree!(adrs, idx_tree); set_type!(adrs, FORS_TREE); set_keypair!(adrs, idx_leaf)
        sigf = fors_sign(c, md, adrs)
        pkf = fors_pk_from_sig(c, sigf, md, adrs)
        sig = sizehint!(UInt8[], sig_bytes(p))
        return append!(sig, R, sigf, ht_sign(c, pkf, idx_tree, idx_leaf))
    finally
        wipe!(skprf); wipe_ctx!(c)
    end
end

"""Algorithm 20, slh_verify_internal. Malformed input returns `false`."""
function verify_internal(p::Params, M::AbstractVector{UInt8}, sig::AbstractVector{UInt8}, pk::AbstractVector{UInt8})
    n = p.n
    (length(pk) == pk_bytes(p) && length(sig) == sig_bytes(p)) || return false
    pkseed = pk[1:n]; pkroot = pk[n+1:2n]
    c = new_ctx(p, pkseed, UInt8[])
    fl = p.k * (p.a + 1) * n
    R = sig[1:n]
    md, idx_tree, idx_leaf = split_digest(p, h_msg(p, R, pkseed, pkroot, M))
    adrs = zeros(UInt8, 32)
    set_tree!(adrs, idx_tree); set_type!(adrs, FORS_TREE); set_keypair!(adrs, idx_leaf)
    pkf = fors_pk_from_sig(c, view(sig, n+1:n+fl), md, adrs)
    ht_verify(c, pkf, view(sig, n+fl+1:length(sig)), idx_tree, idx_leaf, pkroot)
end

# ── External functions (Algorithms 21–25) ────────────────────────────────────
# M′ = 0x00 ‖ |ctx| ‖ ctx ‖ M (pure) or 0x01 ‖ |ctx| ‖ ctx ‖ OID ‖ PH(M) (pre-hash).
pure_mprime(M, ctx) = catbytes(0x00, UInt8(length(ctx)), ctx, M)
function prehash_mprime(M, hash::String, ctx)
    haskey(HASH_OIDS, hash) || throw(ArgumentError("Unknown hash algorithm: $hash"))
    catbytes(0x01, UInt8(length(ctx)), ctx, HASH_OIDS[hash], prehash_message(collect(UInt8, M), hash))
end
check_context(ctx) = length(ctx) <= 255 || throw(ArgumentError("Context string must be ≤ 255 bytes (FIPS 205 §10.2)"))

function hedged_sign(p::Params, mprime, sk, hedged::Bool)
    hedged || return sign_internal(p, mprime, sk, nothing)
    addrnd = rand(RandomDevice(), UInt8, p.n)
    try
        sign_internal(p, mprime, sk, addrnd)
    finally
        wipe!(addrnd)
    end
end

for (name, params) in PARAMS
    @eval module $name
    import ..SLHDSA
    # sign_internal and verify_internal are defined here anew, as functions of this module, and
    # call SLHDSA's by qualified name: importing them would add these methods to SLHDSA's
    # functions, where each parameter set would overwrite the last.
    import ..SLHDSA: Params, keygen_internal, pure_mprime, prehash_mprime, check_context, hedged_sign,
                     pk_bytes, sk_bytes, sig_bytes
    using Random
    const P = $params

    "Parameter set name, as in FIPS 205."
    const NAME = P.name
    "Public key length in bytes (PK.seed ‖ PK.root)."
    const PUBLIC_KEY_BYTES = pk_bytes(P)
    "Secret key length in bytes (SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root)."
    const SECRET_KEY_BYTES = sk_bytes(P)
    "Signature length in bytes."
    const SIGNATURE_BYTES = sig_bytes(P)
    "Length of the `keygen(seed)` seed SK.seed ‖ SK.prf ‖ PK.seed in bytes."
    const SEED_BYTES = 3 * P.n

    """
        keygen() -> (; public_key, secret_key)
        keygen(seed) -> (; public_key, secret_key)

    SLH-DSA key generation (FIPS 205 Alg. 21). Without `seed`, SK.seed, SK.prf and PK.seed come
    from the OS CSPRNG; a $(3 * P.n)-byte `seed` = SK.seed ‖ SK.prf ‖ PK.seed makes it deterministic
    (slh_keygen_internal, Alg. 18).
    """
    function keygen(seed::AbstractVector{UInt8})
        length(seed) == 3 * P.n || throw(ArgumentError("$NAME seed must be $(3 * P.n) bytes"))
        n = P.n
        pk, sk = keygen_internal(P, view(seed, 1:n), view(seed, n+1:2n), view(seed, 2n+1:3n))
        (; public_key = pk, secret_key = sk)
    end
    function keygen()
        seed = rand(RandomDevice(), UInt8, 3 * P.n)
        try
            keygen(seed)
        finally
            SLHDSA.wipe!(seed)
        end
    end

    """
        sign(secret_key, message; context = UInt8[], hedged = true) -> signature
        sign(secret_key, message, addrnd; context = UInt8[]) -> signature

    slh_sign (FIPS 205 Alg. 22), pure mode. Hedged by default (addrnd from the OS CSPRNG);
    `hedged = false` is the deterministic variant. A $(P.n)-byte `addrnd` fixes the randomness.
    `context` is at most 255 bytes.
    """
    function sign(secret_key::AbstractVector{UInt8}, message::AbstractVector{UInt8};
                  context::AbstractVector{UInt8} = UInt8[], hedged::Bool = true)
        check_context(context)
        hedged_sign(P, pure_mprime(message, context), secret_key, hedged)
    end
    function sign(secret_key::AbstractVector{UInt8}, message::AbstractVector{UInt8}, addrnd::AbstractVector{UInt8};
                  context::AbstractVector{UInt8} = UInt8[])
        check_context(context)
        SLHDSA.sign_internal(P, pure_mprime(message, context), secret_key, addrnd)
    end

    """
        verify(public_key, message, signature; context = UInt8[]) -> Bool

    slh_verify (FIPS 205 Alg. 24), pure mode. Malformed inputs return `false`.
    """
    verify(public_key::AbstractVector{UInt8}, message::AbstractVector{UInt8}, signature::AbstractVector{UInt8};
           context::AbstractVector{UInt8} = UInt8[]) =
        length(context) <= 255 && SLHDSA.verify_internal(P, pure_mprime(message, context), signature, public_key)

    """
        sign_prehash(secret_key, message, hash; context = UInt8[], hedged = true) -> signature
        sign_prehash(secret_key, message, hash, addrnd; context = UInt8[]) -> signature

    hash_slh_sign (FIPS 205 Alg. 23). `hash` names the pre-hash function, e.g. `"SHA2-256"`,
    `"SHA2-512"`, `"SHA3-256"`, `"SHAKE-128"`, `"SHAKE-256"`.
    """
    function sign_prehash(secret_key::AbstractVector{UInt8}, message::AbstractVector{UInt8}, hash::String;
                          context::AbstractVector{UInt8} = UInt8[], hedged::Bool = true)
        check_context(context)
        hedged_sign(P, prehash_mprime(message, hash, context), secret_key, hedged)
    end
    function sign_prehash(secret_key::AbstractVector{UInt8}, message::AbstractVector{UInt8}, hash::String,
                          addrnd::AbstractVector{UInt8}; context::AbstractVector{UInt8} = UInt8[])
        check_context(context)
        SLHDSA.sign_internal(P, prehash_mprime(message, hash, context), secret_key, addrnd)
    end

    """
        verify_prehash(public_key, message, signature, hash; context = UInt8[]) -> Bool

    hash_slh_verify (FIPS 205 Alg. 25). Malformed inputs and unknown hash names return `false`.
    """
    function verify_prehash(public_key::AbstractVector{UInt8}, message::AbstractVector{UInt8},
                            signature::AbstractVector{UInt8}, hash::String; context::AbstractVector{UInt8} = UInt8[])
        (length(context) <= 255 && haskey(SLHDSA.HASH_OIDS, hash)) || return false
        SLHDSA.verify_internal(P, prehash_mprime(message, hash, context), signature, public_key)
    end

    """
        sign_internal(secret_key, message, addrnd = nothing) -> signature

    slh_sign_internal (FIPS 205 Alg. 19): signs `message` as given, with no domain separator.
    `addrnd = nothing` is the deterministic variant.
    """
    sign_internal(secret_key::AbstractVector{UInt8}, message::AbstractVector{UInt8}, addrnd = nothing) =
        SLHDSA.sign_internal(P, message, secret_key, addrnd)

    """
        verify_internal(public_key, message, signature) -> Bool

    slh_verify_internal (FIPS 205 Alg. 20).
    """
    verify_internal(public_key::AbstractVector{UInt8}, message::AbstractVector{UInt8}, signature::AbstractVector{UInt8}) =
        SLHDSA.verify_internal(P, message, signature, public_key)
    end
end

end # module SLHDSA
