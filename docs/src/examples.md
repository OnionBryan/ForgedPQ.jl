# Examples

Every example on this page runs as a doctest when the documentation is built.

```@meta
DocTestSetup = :(using ForgedPQ)
```

## Key exchange and a session key

Alice publishes an encapsulation key; Bob encapsulates to it and sends the ciphertext; both end
with the same 32-byte secret. Derive working keys from it with a KDF and a label, rather than
using it directly.

```jldoctest
julia> alice = MLKEM768.keygen();          # Alice publishes alice.public_key

julia> bob = MLKEM768.encaps(alice.public_key);   # Bob sends bob.ciphertext

julia> secret = MLKEM768.decaps(alice.secret_key, bob.ciphertext);

julia> secret == bob.shared_secret
true

julia> session_key = ForgedPQ.Keccak.shake256(vcat(secret, codeunits("example app v1: session key")), 32);

julia> length(session_key)
32
```

A ciphertext altered in transit does not raise an error: decapsulation returns a different,
pseudorandom secret (implicit rejection), and the session fails at the first authenticated
message.

```jldoctest
julia> alice = MLKEM768.keygen(); bob = MLKEM768.encaps(alice.public_key);

julia> ct = copy(bob.ciphertext); ct[1] ⊻= 0x01;

julia> MLKEM768.decaps(alice.secret_key, ct) == bob.shared_secret
false
```

## Signatures with a context string

A context binds a signature to one protocol or purpose; it must match at verification.

```jldoctest
julia> pk, sk = MLDSA65.keygen();

julia> msg = Vector{UInt8}("release 1.0.0");

julia> sig = MLDSA65.sign(sk, msg; context = Vector{UInt8}("releases"));

julia> MLDSA65.verify(pk, msg, sig; context = Vector{UInt8}("releases"))
true

julia> MLDSA65.verify(pk, msg, sig; context = Vector{UInt8}("logins"))
false
```

## Deterministic keys for tests

A seed fixes the key pair, so tests can pin known outputs.

```jldoctest
julia> bytes2hex(MLKEM768.keygen(zeros(UInt8, 64)).public_key[1:8])
"254a797885c63b14"

julia> bytes2hex(MLDSA65.keygen(zeros(UInt8, 32)).public_key[1:8])
"424b2f267e58d5b3"

julia> bytes2hex(SLHDSA_SHAKE_128f.keygen(zeros(UInt8, 48)).public_key)
"00000000000000000000000000000000bdc73e8e9e492cf677ee2360e6c14958"
```

## Two independent signatures

ML-DSA rests on lattice problems and SLH-DSA on the hash function alone. Requiring both
signatures keeps a document authentic unless both assumptions fail.

```jldoctest
julia> lat = MLDSA65.keygen(); hsh = SLHDSA_SHA2_128f.keygen();

julia> doc = Vector{UInt8}("firmware image");

julia> sigs = (MLDSA65.sign(lat.secret_key, doc), SLHDSA_SHA2_128f.sign(hsh.secret_key, doc));

julia> MLDSA65.verify(lat.public_key, doc, sigs[1]) && SLHDSA_SHA2_128f.verify(hsh.public_key, doc, sigs[2])
true
```

## Storing keys

Keys, ciphertexts and signatures are byte vectors in the standards' encodings: store them as
they are, or as text.

```jldoctest
julia> pk, sk = MLDSA44.keygen();

julia> text = bytes2hex(pk);

julia> length(text) == 2 * MLDSA44.PUBLIC_KEY_BYTES
true

julia> hex2bytes(text) == pk
true
```

## Erasing secrets you hold

The package zeroes the secrets it allocates. Secret keys and shared secrets it returns are
yours to erase when done.

```jldoctest
julia> pk, sk = MLKEM512.keygen();

julia> wipe!(sk);

julia> all(iszero, sk)
true
```

## Splitting a key among custodians

Shamir sharing splits a secret so that any 3 of 5 shares recover it and 2 reveal nothing.

```jldoctest
julia> key = rand(UInt8, 32);

julia> shares = shamir_share_bytes(key, 3, 5);

julia> shamir_reconstruct_bytes(shares[[1, 4, 5]], 3, 32) == key
true
```

```@meta
DocTestSetup = nothing
```
