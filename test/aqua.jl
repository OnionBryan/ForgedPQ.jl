# test/aqua.jl — package hygiene (Aqua.jl): method ambiguities, unbound type parameters,
# undefined exports, stale dependencies, compat bounds, type piracy, persistent tasks.
using Aqua, ForgedPQ

Aqua.test_all(ForgedPQ; ambiguities = true)
