defmodule Scrypt.MixProject do
  use Mix.Project

  def project do
    [
      app: :scrypt_elixir,
      compilers: [:elixir_make] ++ Mix.compilers(),
      version: "0.1.0",
      elixir: "~> 1.9",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: "Native Elixir wrapper for the Scrypt KDF",
      name: "ScryptElixir",
      package: package(),
      docs: docs(),
      source_url: "https://github.com/christianjgreen/scrypt_elixir"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:dialyxir, "~> 1.0", only: [:dev], runtime: false},
      {:elixir_make, "~> 0.4", runtime: false},
      {:ex_doc, "~> 0.21", only: :dev, runtime: false}
    ]
  end

  defp package do
    [
      maintainers: ["Christian Green"],
      licenses: ["Apache 2.0"],
      links: %{"GitHub" => "https://github.com/christianjgreen/scrypt_elixir"},
      files: ~w(lib c_src mix.exs README.md Makefile scrypt/lib scrypt/libcperciva)
    ]
  end

  defp docs do
    [
      extras: ["README.md"],
      main: "readme"
    ]
  end
end
