# Compile the public operations into the package image, so a first call does not compile them.
let V = Vector{UInt8}
    for M in (MLKEM512, MLKEM768, MLKEM1024)
        precompile(M.keygen, ()); precompile(M.keygen, (V,))
        precompile(M.encaps, (V,)); precompile(M.encaps, (V, V)); precompile(M.decaps, (V, V))
        precompile(M.check_public_key, (V,)); precompile(M.check_secret_key, (V,))
    end
    for M in (MLDSA44, MLDSA65, MLDSA87)
        precompile(M.keygen, ()); precompile(M.keygen, (V,))
        precompile(M.sign, (V, V)); precompile(M.sign, (V, V, V)); precompile(M.verify, (V, V, V))
        precompile(M.sign_prehash, (V, V, String)); precompile(M.verify_prehash, (V, V, V, String))
    end
    for M in (Falcon512, Falcon1024)
        precompile(M.keygen, ()); precompile(M.sign, (V, V)); precompile(M.verify, (V, V, V))
    end
    precompile(XWing.keygen, ()); precompile(XWing.keygen, (V,))
    precompile(XWing.encaps, (V,)); precompile(XWing.encaps, (V, V)); precompile(XWing.decaps, (V, V))
    precompile(X25519.x25519, (V, V)); precompile(X25519.x25519_base, (V,)); precompile(X25519.x25519_keypair, ())
    precompile(shamir_share_bytes, (V, Int, Int)); precompile(shamir_reconstruct_bytes, (Vector{Tuple{Int, BigInt}}, Int, Int))
end
