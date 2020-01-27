defmodule Scrypt do
  use Bitwise

  alias Scrypt.NIF

  def hash(password, salt, log_n, r, p, key_length) do
    case NIF.hash_nif(password, salt, log_n, r, p, key_length) do
      hash when is_binary(hash) -> hash
      error -> raise ArgumentError, handle_error(error)
    end
  end

  def verify?(base_hash, password, salt, log_n, r, p) when is_binary(base_hash) do
    password
    |> Scrypt.hash(salt, log_n, r, p, byte_size(base_hash))
    |> secure_compare(base_hash)
  end

  def kdf(password, log_n, r, p), do: kdf(password, :crypto.strong_rand_bytes(32), log_n, r, p)

  def kdf(password, salt, log_n, r, p) when byte_size(salt) == 32 do
    hash = Scrypt.hash(password, salt, log_n, r, p, 64)
    enc_r = encode_unsigned_padded(r)
    enc_p = encode_unsigned_padded(p)

    scrypt_header(hash, salt, log_n, enc_r, enc_p)
  end

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

  def encode_unsigned_padded(x) do
    x_bin = :binary.encode_unsigned(x)
    bin_size = byte_size(x_bin)
    padding = (4 - bin_size) * 8
    <<0::size(padding), x_bin::binary>>
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
    hmac = :crypto.hmac(:sha256, hmac_key, second_chunk)
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
    secure_compare(left, right, acc ||| x ^^^ y)
  end

  defp secure_compare(<<>>, <<>>, acc) do
    acc
  end
end
