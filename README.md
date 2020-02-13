# ScryptElixir

Elixir wrapper for the Scrypt key derivation function. 
https://www.tarsnap.com/scrypt.html

## Usage

This library provides raw scrypt hashing functionality as well as an implementation of the original suggested KDF.

* `hash/6` is a lower level function that allows for a custom salt length and derived key length. The result is the raw binary scrypt hash. This function allows for custom salts derived and key lengths.
* `kdf/4` is a function that creates an scrypt header that utilizes HMAC to ensure hash integrity. This implementation enforces a 32 byte salt length and 64 byte derived key length.

Both functions rely on a core set of parameters:
* `password` - the core binary being hashed
* `salt` - a pseudo-randomly generated string of bytes used for hashing
* `logN` - exponent for CPU/memory cost (2^logN)
* `r` - blocksize

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `scrypt_elixir` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:scrypt_elixir, "~> 0.1.0"}
  ]
end
```

Documentation can be generated with [ExDoc](https://github.com/elixir-lang/ex_doc)
and published on [HexDocs](https://hexdocs.pm). Once published, the docs can
be found at [https://hexdocs.pm/scrypt_elixir](https://hexdocs.pm/scrypt_elixir).

