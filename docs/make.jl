using Documenter, ForgedPQ

# SECURITY.md and CHANGELOG.md are the sources of truth; copy them in so the site cannot drift.
# Links between the two repository files point at the copies.
for (src, dst) in (("SECURITY.md", "security.md"), ("CHANGELOG.md", "changelog.md"))
    text = read(joinpath(@__DIR__, "..", src), String)
    text = replace(text, "](SECURITY.md" => "](security.md", "](CHANGELOG.md" => "](changelog.md",
                   "](README.md" => "](https://github.com/OnionBryan/ForgedPQ.jl/blob/main/README.md")
    write(joinpath(@__DIR__, "src", dst), text)
end

makedocs(;
    sitename = "ForgedPQ.jl",
    modules = [ForgedPQ],
    format = Documenter.HTML(; prettyurls = get(ENV, "CI", nothing) == "true",
                             canonical = "https://onionbryan.github.io/ForgedPQ.jl/stable/"),
    pages = ["Home" => "index.md",
             "Choosing a scheme" => "choosing.md",
             "API" => "api.md",
             "Security" => "security.md",
             "Changelog" => "changelog.md"],
    checkdocs = :exports,
    warnonly = [:missing_docs, :cross_references],
)

deploydocs(; repo = "github.com/OnionBryan/ForgedPQ.jl.git", devbranch = "main", push_preview = false)
