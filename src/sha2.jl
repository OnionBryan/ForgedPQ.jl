"""SHA-256 and SHA-512 (FIPS 180-4) from a caller-held state. SLH-DSA hashes millions of inputs
that share their first block, PK.seed ‖ zero padding: that block is compressed once into a
midstate and each hash is finished from it, with caller-owned scratch and no allocation.
Byte-identical to SHA.jl (test/slhdsa.jl)."""
module Sha2

# Round constants and initial values: the leading bits of the fractional parts of the cube roots
# of the first 64 (SHA-256) or 80 (SHA-512) primes, and of the square roots of the first 8.
function first_primes(k)
    ps = Int[]; c = 2
    while length(ps) < k
        all(c % p != 0 for p in ps if p * p <= c) && push!(ps, c)
        c += 1
    end
    ps
end
frac_bits(x::BigFloat, bits) = UInt128(floor((x - floor(x)) * BigFloat(2)^bits))
const K256, IV256, K512, IV512 = setprecision(BigFloat, 512) do
    ps = first_primes(80)
    (Tuple(UInt32(frac_bits(cbrt(BigFloat(p)), 32)) for p in ps[1:64]),
     Tuple(UInt32(frac_bits(sqrt(BigFloat(p)), 32)) for p in ps[1:8]),
     Tuple(UInt64(frac_bits(cbrt(BigFloat(p)), 64)) for p in ps),
     Tuple(UInt64(frac_bits(sqrt(BigFloat(p)), 64)) for p in ps[1:8]))
end

const State256 = NTuple{8, UInt32}
const State512 = NTuple{8, UInt64}

# One 64-byte block at blk[off+1 : off+64]; `w` is a 64-word scratch.
function compress256(st::State256, blk::AbstractVector{UInt8}, off::Int, w::Vector{UInt32})
    checkbounds(blk, off+1:off+64); checkbounds(w, 1:64)
    @inbounds for t in 1:16
        o = off + 4(t - 1)
        w[t] = UInt32(blk[o+1]) << 24 | UInt32(blk[o+2]) << 16 | UInt32(blk[o+3]) << 8 | UInt32(blk[o+4])
    end
    @inbounds for t in 17:64
        x = w[t-15]; y = w[t-2]
        s0 = bitrotate(x, -7) ⊻ bitrotate(x, -18) ⊻ (x >> 3)
        s1 = bitrotate(y, -17) ⊻ bitrotate(y, -19) ⊻ (y >> 10)
        w[t] = w[t-16] + s0 + w[t-7] + s1
    end
    a, b, c, d, e, f, g, h = st
    @inbounds for t in 1:64
        t1 = h + (bitrotate(e, -6) ⊻ bitrotate(e, -11) ⊻ bitrotate(e, -25)) + ((e & f) ⊻ (~e & g)) + K256[t] + w[t]
        t2 = (bitrotate(a, -2) ⊻ bitrotate(a, -13) ⊻ bitrotate(a, -22)) + ((a & b) ⊻ (a & c) ⊻ (b & c))
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2
    end
    (st[1] + a, st[2] + b, st[3] + c, st[4] + d, st[5] + e, st[6] + f, st[7] + g, st[8] + h)
end

# One 128-byte block at blk[off+1 : off+128]; `w` is an 80-word scratch.
function compress512(st::State512, blk::AbstractVector{UInt8}, off::Int, w::Vector{UInt64})
    checkbounds(blk, off+1:off+128); checkbounds(w, 1:80)
    @inbounds for t in 1:16
        o = off + 8(t - 1); v = UInt64(0)
        for j in 1:8; v = v << 8 | UInt64(blk[o+j]); end
        w[t] = v
    end
    @inbounds for t in 17:80
        x = w[t-15]; y = w[t-2]
        s0 = bitrotate(x, -1) ⊻ bitrotate(x, -8) ⊻ (x >> 7)
        s1 = bitrotate(y, -19) ⊻ bitrotate(y, -61) ⊻ (y >> 6)
        w[t] = w[t-16] + s0 + w[t-7] + s1
    end
    a, b, c, d, e, f, g, h = st
    @inbounds for t in 1:80
        t1 = h + (bitrotate(e, -14) ⊻ bitrotate(e, -18) ⊻ bitrotate(e, -41)) + ((e & f) ⊻ (~e & g)) + K512[t] + w[t]
        t2 = (bitrotate(a, -28) ⊻ bitrotate(a, -34) ⊻ bitrotate(a, -39)) + ((a & b) ⊻ (a & c) ⊻ (b & c))
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2
    end
    (st[1] + a, st[2] + b, st[3] + c, st[4] + d, st[5] + e, st[6] + f, st[7] + g, st[8] + h)
end

"""Scratch for one caller: message schedules and the padding block."""
struct Scratch
    w32::Vector{UInt32}
    w64::Vector{UInt64}
    pad::Vector{UInt8}
end
Scratch() = Scratch(Vector{UInt32}(undef, 64), Vector{UInt64}(undef, 80), zeros(UInt8, 256))

"""SHA-256 of (prefix ‖ data[1:len]) into out[1:nout], from `st`, the state after `prefix` bytes
(a multiple of 64)."""
function finish256!(out::AbstractVector{UInt8}, nout::Int, st::State256, data::AbstractVector{UInt8},
                    len::Int, prefix::Int, s::Scratch)
    checkbounds(out, 1:nout); checkbounds(data, 1:len); 0 <= nout <= 32 || throw(ArgumentError("nout"))
    off = 0
    while len - off >= 64
        st = compress256(st, data, off, s.w32); off += 64
    end
    r = len - off; pad = s.pad
    fill!(view(pad, 1:128), 0x00)
    @inbounds for i in 1:r; pad[i] = data[off+i]; end
    pad[r+1] = 0x80
    nb = r + 9 <= 64 ? 64 : 128
    bits = UInt64(8) * UInt64(prefix + len)
    @inbounds for i in 1:8; pad[nb-8+i] = (bits >> (8(8 - i))) % UInt8; end
    st = compress256(st, pad, 0, s.w32)
    nb == 128 && (st = compress256(st, pad, 64, s.w32))
    @inbounds for i in 1:nout
        out[i] = (st[(i - 1) >> 2 + 1] >> (8(3 - ((i - 1) & 3)))) % UInt8
    end
    out
end

"""SHA-512 of (prefix ‖ data[1:len]) into out[1:nout], from `st`, the state after `prefix` bytes
(a multiple of 128)."""
function finish512!(out::AbstractVector{UInt8}, nout::Int, st::State512, data::AbstractVector{UInt8},
                    len::Int, prefix::Int, s::Scratch)
    checkbounds(out, 1:nout); checkbounds(data, 1:len); 0 <= nout <= 64 || throw(ArgumentError("nout"))
    off = 0
    while len - off >= 128
        st = compress512(st, data, off, s.w64); off += 128
    end
    r = len - off; pad = s.pad
    fill!(pad, 0x00)
    @inbounds for i in 1:r; pad[i] = data[off+i]; end
    pad[r+1] = 0x80
    nb = r + 17 <= 128 ? 128 : 256
    bits = UInt128(8) * UInt128(prefix + len)
    @inbounds for i in 1:16; pad[nb-16+i] = (bits >> (8(16 - i))) % UInt8; end
    st = compress512(st, pad, 0, s.w64)
    nb == 256 && (st = compress512(st, pad, 128, s.w64))
    @inbounds for i in 1:nout
        out[i] = (st[(i - 1) >> 3 + 1] >> (8(7 - ((i - 1) & 7)))) % UInt8
    end
    out
end

sha256(data::AbstractVector{UInt8}, s::Scratch = Scratch()) =
    finish256!(Vector{UInt8}(undef, 32), 32, IV256, data, length(data), 0, s)
sha512(data::AbstractVector{UInt8}, s::Scratch = Scratch()) =
    finish512!(Vector{UInt8}(undef, 64), 64, IV512, data, length(data), 0, s)

"""State after the 64-byte block blk[1:64] (SHA-256) or 128-byte block blk[1:128] (SHA-512)."""
midstate256(blk::AbstractVector{UInt8}, s::Scratch) = compress256(IV256, blk, 0, s.w32)
midstate512(blk::AbstractVector{UInt8}, s::Scratch) = compress512(IV512, blk, 0, s.w64)

end # module Sha2
