defmodule Scrypt do
  @moduledoc """
  This module provides the base functionality to work with the Scrypt KDF.
  """
  use Bitwise

  alias Scrypt.NIF

  @doc """
  Creates an Scrypt hash from the given parameters, allowing a custom salt
  and key length.


  ## Examples

      iex> Scrypt.hash("hunter2", "oftheearth", 14, 8, 1, 64)
      <<66, 229, 151, 70, 35, 13, 211, 30, 1, 153, 91, 172, 42, 194, 249, 50, 229, 34,
        92, 157, 115, 218, 91, 163, 223, 167, 219, 42, 90, 20, 93, 163, 101, 225, 98,
        198, 152, 96, 97, 86, 50, 220, 91, 22, 5, 160, 199, 150, 150, 253, ...>>
  """
  @spec hash(String.t(), String.t(), integer(), integer(), integer(), integer()) ::
          String.t() | none()
  def hash(password, salt, log_n, r, p, key_length) do
    case NIF.hash_nif(password, salt, log_n, r, p, key_length) do
      hash when is_binary(hash) -> hash
      error -> raise ArgumentError, handle_error(error)
    end
  end

  @doc """
  Verifies an Scrypt hash.


  ## Examples


      iex(1)> hash = Scrypt.hash("hunter2", "oftheearth", 14, 8, 1, 64)
      <<66, 229, 151, 70, 35, 13, 211, 30, 1, 153, 91, 172, 42, 194, 249, 50, 229, 34,
        92, 157, 115, 218, 91, 163, 223, 167, 219, 42, 90, 20, 93, 163, 101, 225, 98,
        198, 152, 96, 97, 86, 50, 220, 91, 22, 5, 160, 199, 150, 150, 253, ...>>
      iex(2)> Scrypt.verify?(hash, "hunter2", "oftheearth", 14, 8, 1)
      true
  """
  @spec verify?(String.t(), String.t(), String.t(), integer(), integer(), integer()) :: boolean()
  def verify?(base_hash, password, salt, log_n, r, p) when is_binary(base_hash) do
    password
    |> Scrypt.hash(salt, log_n, r, p, byte_size(base_hash))
    |> secure_compare(base_hash)
  end

  @doc """
  Generates an Scrypt header from the given parameters, using 32 bytes
  hash and a 64 bytes key length. If a salt is not given, one is generated with
  :crypto.strong_rand_bytes(n :: non_neg_integer())

  ## Examples


      iex> Scrypt.kdf("hunter2", 14, 8, 1)
      <<115, 99, 114, 121, 112, 116, 0, 14, 0, 0, 0, 8, 0, 0, 0, 1, 166, 59, 141, 39,
        16, 29, 92, 191, 50, 7, 102, 174, 27, 240, 229, 27, 121, 234, 97, 111, 98,
        182, 29, 158, 117, 43, 9, 141, 172, 189, 106, 88, 213, 152, ...>>

      iex> Scrypt.kdf("hunter2", :crypto.strong_rand_bytes(32), 14, 8, 1)
      <<115, 99, 114, 121, 112, 116, 0, 14, 0, 0, 0, 8, 0, 0, 0, 1, 120, 127, 46, 232,
        104, 21, 51, 3, 154, 50, 72, 127, 172, 43, 131, 37, 182, 149, 168, 88, 27,
        146, 85, 169, 52, 134, 20, 143, 37, 97, 197, 66, 148, 182, ...>>
  """
  @spec kdf(String.t(), integer(), integer(), integer()) :: String.t()
  def kdf(password, log_n, r, p), do: kdf(password, :crypto.strong_rand_bytes(32), log_n, r, p)

  @spec kdf(String.t(), salt :: <<_::256>>, integer(), integer(), integer()) :: String.t()
  def kdf(password, salt, log_n, r, p) when byte_size(salt) == 32 do
    hash = Scrypt.hash(password, salt, log_n, r, p, 64)
    enc_r = encode_unsigned_padded(r)
    enc_p = encode_unsigned_padded(p)

    scrypt_header(hash, salt, log_n, enc_r, enc_p)
  end

  @doc """
  Decodes and verifies an Scrypt header using a supplied password,
  following the documented specs.

  ```plain
  +----------+--------+----------------------------------------------------------+
  |   offset | length |                        assignment                        |
  +----------+--------+----------------------------------------------------------+
  |   0      | 6      | "scrypt"                                                 |
  |   6      | 1      | scrypt data file version number (== 0)                   |
  |   7      | 1      | log2(N) (must be between 1 and 63 inclusive)             |
  |   8      | 4      | r (big-endian integer; must satisfy r * p < 2^30)        |
  |   12     | 4      | p (big-endian integer; must satisfy r * p < 2^30)        |
  |   16     | 32     | salt                                                     |
  |   48     | 16     | first 16 bytes of SHA256(bytes 0 .. 47)                  |
  |   64     | 32     | HMAC-SHA256(bytes 0 .. 63)                               |
  |   96     | X      | data xor AES256-CTR key stream generated with nonce == 0 |
  |   96+X   | 32     | HMAC-SHA256(bytes 0 .. 96 + (X - 1))                     |
  +----------+--------+----------------------------------------------------------+
  ```

  ## Examples

      iex(1)> header = Scrypt.kdf("hunter2", 14, 8, 1)
      <<115, 99, 114, 121, 112, 116, 0, 14, 0, 0, 0, 8, 0, 0, 0, 1, 66, 223, 14, 146,
        240, 251, 4, 70, 177, 59, 232, 159, 183, 134, 188, 127, 72, 170, 70, 224, 134,
        201, 74, 15, 188, 227, 34, 222, 250, 192, 153, 226, 42, 189, ...>>
      iex(2)> Scrypt.verify_kdf?(header, "hunter2")
      true
  """
  @spec verify_kdf?(header :: <<_::768>>, String.t()) :: boolean()
  def verify_kdf?(
        <<_scrypt::binary-size(6), 0, log_n::integer-size(8), enc_r::binary-size(4),
          enc_p::binary-size(4), salt::binary-size(32), _sha::binary-size(16),
          hmac::binary-size(32)>>,
        password
      ) do
    r = :binary.decode_unsigned(enc_r)
    p = :binary.decode_unsigned(enc_p)

    hash = Scrypt.hash(password, salt, log_n, r, p, 64)

    <<_::binary-size(64), base_hmac::binary>> = scrypt_header(hash, salt, log_n, enc_r, enc_p)

    secure_compare(base_hmac, hmac)
  end

  defp encode_unsigned_padded(int) do
    int_bin = :binary.encode_unsigned(int)
    bin_size = byte_size(int_bin)
    padding = (4 - bin_size) * 8
    <<0::size(padding), int_bin::binary>>
  end

  defp scrypt_header(
         <<_::binary-size(32), hmac_key::binary-size(32)>>,
         salt,
         log_n,
         <<enc_r::binary-size(4)>>,
         <<enc_p::binary-size(4)>>
       ) do
    first_chunk = <<"scrypt", 0, log_n, enc_r::binary, enc_p::binary, salt::binary>>
    <<first_sha::binary-size(16), _::binary>> = :crypto.hash(:sha256, first_chunk)
    second_chunk = <<first_chunk::binary, first_sha::binary>>
    hmac = :crypto.mac(:hmac, :sha256, hmac_key, second_chunk)
    <<second_chunk::binary, hmac::binary>>
  end

  # ENOMEM
  defp handle_error(12), do: "Scrypt parameters too large: ENOMEM"
  # EINVAL
  defp handle_error(22), do: "Invalid scrypt parameters"
  # EFBIG
  defp handle_error(27), do: "Scrypt parameters too large: EFBIG"
  # Uknown
  defp handle_error(error), do: "unknown error code: #{error}"

  @doc """
  Copied from: https://github.com/elixir-plug/plug/blob/v1.5.0-rc.2/lib/plug/crypto.ex#L102

  Compares the two binaries in constant-time to avoid timing attacks.
  See: http://codahale.com/a-lesson-in-timing-attacks/
  """
  def secure_compare(left, right) do
    if byte_size(left) == byte_size(right) do
      secure_compare(left, right, 0) == 0
    else
      false
    end
  end

  defp secure_compare(<<x, left::binary>>, <<y, right::binary>>, acc) do
    secure_compare(left, right, acc ||| Bitwise.bxor(x, y))
  end

  defp secure_compare(<<>>, <<>>, acc) do
    acc
  end
end
