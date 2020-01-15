defmodule ScryptElixir do
  @compile {:autoload, false}
  @on_load {:init, 0}

  def init do
    :erlang.load_nif('./priv/scrypt_nif', 0)
  end

  def kdf_nif(_, _, _, _, _)
  def kdf_nif(_, _, _, _, _), do: exit(:nif_not_loaded)

  def hash_nif(_, _, _, _, _, _)
  def hash_nif(_, _, _, _, _, _), do: exit(:nif_not_loaded)

  def verify_kdf_nif(_, _)
  def verify_kdf_nif(_, _), do: exit(:nif_not_loaded)

  def verify_nif(_, _, _, _, _, _)
  def verify_nif(_, _, _, _, _, _), do: exit(:nif_not_loaded)
end
