"""Pre-hash functions and their DER-encoded OIDs, shared by HashML-DSA (FIPS 204 §5.4) and
HashSLH-DSA (FIPS 205 §10.2)."""
module Prehash

import SHA
import ..Keccak

# All 11 bytes: 06 09 60 86 48 01 65 03 04 02 X (NIST hash algorithm arc 2.16.840.1.101.3.4.2.X)
const HASH_OIDS = Dict{String, Vector{UInt8}}(
    "SHA2-256"    => UInt8[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01],
    "SHA2-384"    => UInt8[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02],
    "SHA2-512"    => UInt8[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03],
    "SHA3-256"    => UInt8[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x08],
    "SHA3-384"    => UInt8[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x09],
    "SHA3-512"    => UInt8[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0A],
    "SHAKE-128"   => UInt8[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0B],
    "SHAKE-256"   => UInt8[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x0C],
    "SHA2-224"    => UInt8[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x04],
    "SHA3-224"    => UInt8[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x07],
    "SHA2-512/224" => UInt8[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x05],
    "SHA2-512/256" => UInt8[0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x06],
)

# SHA-512/224 and SHA-512/256 (FIPS 180-4 §5.3.6): SHA-512 from their own initial hash values,
# truncated. SHA.jl provides them only in its later versions (not the SHA stdlib of Julia 1.10/1.11).
const SHA512_224_IV = UInt64[0x8c3d37c819544da2, 0x73e1996689dcd4d6, 0x1dfab7ae32ff9c82, 0x679dd514582f9fcf,
                             0x0f6d2b697bd44da8, 0x77e36f7304c48942, 0x3f9d85a86a1d36c8, 0x1112e6ad91d692a1]
const SHA512_256_IV = UInt64[0x22312194fc2bf72c, 0x9f555fa3c84c64c2, 0x2393b86b6f53b151, 0x963877195940eabd,
                             0x96283ee2a88effe3, 0xbe5e1e2553863992, 0x2b0199fc2c85b8aa, 0x0eb72ddc81c52ca2]
function sha512t(msg::Vector{UInt8}, iv::Vector{UInt64}, nbytes::Int)
    ctx = SHA.SHA2_512_CTX()
    copyto!(ctx.state, iv)
    SHA.update!(ctx, msg)
    return SHA.digest!(ctx)[1:nbytes]
end
@static if isdefined(SHA, :sha2_512_224)
    sha512_224(msg::Vector{UInt8}) = SHA.sha2_512_224(msg)
    sha512_256(msg::Vector{UInt8}) = SHA.sha2_512_256(msg)
else
    sha512_224(msg::Vector{UInt8}) = sha512t(msg, SHA512_224_IV, 28)
    sha512_256(msg::Vector{UInt8}) = sha512t(msg, SHA512_256_IV, 32)
end

"""PH(M) for a pre-hash algorithm named as in ACVP ("SHA2-256", "SHAKE-128", ...). SHAKE-128
gives 256 bits and SHAKE-256 512 bits (FIPS 204 Alg. 4, FIPS 205 Alg. 23)."""
function prehash_message(msg::Vector{UInt8}, hash_alg::String)::Vector{UInt8}
    if hash_alg == "SHA2-256"
        return SHA.sha256(msg)
    elseif hash_alg == "SHA2-384"
        return SHA.sha384(msg)
    elseif hash_alg == "SHA2-512"
        return SHA.sha512(msg)
    elseif hash_alg == "SHA3-256"
        return Keccak.sha3_256(msg)
    elseif hash_alg == "SHA3-384"
        return Keccak.sha3_384(msg)
    elseif hash_alg == "SHA3-512"
        return Keccak.sha3_512(msg)
    elseif hash_alg == "SHAKE-128"
        return Keccak.shake128(msg, UInt64(32))
    elseif hash_alg == "SHAKE-256"
        return Keccak.shake256(msg, UInt64(64))
    elseif hash_alg == "SHA2-224"
        return SHA.sha224(msg)
    elseif hash_alg == "SHA3-224"
        return Keccak.sha3_224(msg)
    elseif hash_alg == "SHA2-512/224"
        return sha512_224(msg)
    elseif hash_alg == "SHA2-512/256"
        return sha512_256(msg)
    else
        throw(ArgumentError("Unsupported hash algorithm: $hash_alg"))
    end
end

end # module Prehash
