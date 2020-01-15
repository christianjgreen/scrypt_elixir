defmodule Scrypt do
  alias Scrypt.NIF

  def hash(password, salt, log_n, r, p, key_length) do
    case NIF.hash_nif(password, salt, log_n, r, p, key_length) do
      hash when is_binary(hash) -> {:ok, hash}
      error -> {:error, error}
    end
  end

  def verify(hash, password, salt, log_n, r, p) do
    case NIF.verify_nif(hash, password, salt, log_n, r, p) do
      result when is_boolean(result) -> result
      error -> {:error, error}
    end
  end

  def kdf(password, log_n, r, p), do: kdf(password, :crypto.strong_rand_bytes(32), log_n, r, p)

  def kdf(password, salt, log_n, r, p) when byte_size(salt) == 32 do
    case NIF.kdf_nif(password, salt, log_n, r, p) do
      hash when is_binary(hash) -> {:ok, hash}
      error -> {:error, error}
    end
  end

  def verify_kdf(hash, password) do
    case NIF.verify_kdf_nif(hash, password) do
      result when is_boolean(result) -> result
      error -> {:error, error}
    end
  end
end
