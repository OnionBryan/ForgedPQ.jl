# test/shake_reader.jl — a second, independent SHAKE for the tests: an incremental reader for
# randomness streams (SHA.jl's shake128/shake256 recurse once per output block, so multi-megabyte
# streams overflow the stack), and the reference `oracle_shake128/256` used where SHA.jl has no
# SHAKE (the SHA stdlib of Julia 1.10 and 1.11).
import SHA
const KECCAK_RC = UInt64[0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000a, 0x000000008000808b, 0x800000000000008b,
    0x8000000000008089, 0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800a,
    0x800000008000000a, 0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
# KECCAK_ROT[y+1, x+1] = Keccak ρ offset r[x][y].
const KECCAK_ROT = [0 1 62 28 27; 36 44 6 55 20; 3 10 43 25 39; 41 45 15 21 8; 18 2 61 56 14]
rotl64(x, n) = n == 0 ? x : (x << n) | (x >> (64 - n))

function keccakf!(A::Matrix{UInt64})
    B = similar(A); C = Vector{UInt64}(undef, 5)
    for rc in KECCAK_RC
        for x in 1:5; C[x] = A[x,1] ⊻ A[x,2] ⊻ A[x,3] ⊻ A[x,4] ⊻ A[x,5]; end
        for x in 1:5, y in 1:5; A[x,y] ⊻= C[mod1(x-1,5)] ⊻ rotl64(C[mod1(x+1,5)], 1); end
        for x in 1:5, y in 1:5; B[y, mod1(2(x-1)+3(y-1)+1, 5)] = rotl64(A[x,y], KECCAK_ROT[y,x]); end
        for x in 1:5, y in 1:5; A[x,y] = B[x,y] ⊻ (~B[mod1(x+1,5),y] & B[mod1(x+2,5),y]); end
        A[1,1] ⊻= rc
    end
end

mutable struct ShakeReader
    A::Matrix{UInt64}
    rate::Int
    buf::Vector{UInt8}
    pos::Int
end

"SHAKE128 (`bits=128`) or SHAKE256 (`bits=256`) of `seed`, read incrementally with `take!`."
ShakeReader(seed::AbstractVector{UInt8}; bits::Int=256) = sponge(seed, bits == 128 ? 168 : 136, 0x1f)

# Keccak sponge at `rate` bytes with domain byte `ds` (0x1f SHAKE, 0x06 SHA3), ready to squeeze.
function sponge(seed::AbstractVector{UInt8}, rate::Int, ds::UInt8)
    data = collect(UInt8, seed); nfull = length(data) ÷ rate
    A = zeros(UInt64, 5, 5)
    for b in 0:nfull                       # nfull whole blocks, then the padded tail
        blk = zeros(UInt8, rate)
        if b < nfull
            blk .= data[b*rate+1:(b+1)*rate]
        else
            nrem = length(data) - nfull * rate
            blk[1:nrem] = data[nfull*rate+1:end]; blk[nrem+1] ⊻= ds; blk[rate] ⊻= 0x80
        end
        w = reinterpret(UInt64, blk)
        for i in 1:rate÷8; A[mod1(i,5), (i-1)÷5+1] ⊻= ltoh(w[i]); end
        keccakf!(A)
    end
    r = ShakeReader(A, rate, UInt8[], 1); squeeze!(r); r
end

# SHA.jl 0.7.0, the SHA stdlib of Julia 1.10 and 1.11, has no SHAKE and gives wrong SHA3 digests
# for some inputs (a 135-byte message among them). The references below use SHA.jl only in its
# later versions, recognised by having SHAKE, and the sponge above otherwise.
const SHA_IS_REFERENCE = isdefined(SHA, :shake256)

"SHA3 reference with an `outbytes`-byte digest (28, 32, 48 or 64)."
oracle_sha3(data, outbytes::Int) =
    SHA_IS_REFERENCE ? (outbytes == 28 ? SHA.sha3_224 : outbytes == 32 ? SHA.sha3_256 :
                        outbytes == 48 ? SHA.sha3_384 : SHA.sha3_512)(collect(UInt8, data)) :
                       take!(sponge(data, 200 - 2outbytes, 0x06), outbytes)

"SHAKE128/256 reference: SHA.jl where it has SHAKE, otherwise the ShakeReader above."
oracle_shake128(data, n::Integer) = isdefined(SHA, :shake128) ? SHA.shake128(collect(UInt8, data), UInt(n)) :
                                                               take!(ShakeReader(data; bits=128), n)
oracle_shake256(data, n::Integer) = isdefined(SHA, :shake256) ? SHA.shake256(collect(UInt8, data), UInt(n)) :
                                                               take!(ShakeReader(data; bits=256), n)
squeeze!(r::ShakeReader) =
    (r.buf = collect(reinterpret(UInt8, [htol(r.A[mod1(i,5), (i-1)÷5+1]) for i in 1:r.rate÷8])); r.pos = 1)
function Base.take!(r::ShakeReader, k::Integer)
    out = Vector{UInt8}(undef, k)
    for i in 1:k
        r.pos > r.rate && (keccakf!(r.A); squeeze!(r))
        out[i] = r.buf[r.pos]; r.pos += 1
    end
    out
end
